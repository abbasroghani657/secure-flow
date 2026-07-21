"""Infrastructure-as-Code (IaC) misconfiguration scanning.

Static analysis of an uploaded IaC file — Terraform (HCL/JSON), CloudFormation
(YAML/JSON), Kubernetes manifests (YAML), a Dockerfile, or a docker-compose file.
Detects the cloud- and container-security misconfigurations that are the leading
root cause of breaches (public storage, wide-open network access, missing
encryption, over-broad IAM, privileged containers, hardcoded secrets).

Purely lexical/structural — no cloud credentials required. This is the
Checkov / tfsec / kube-score category, built in-house.
"""

from __future__ import annotations

import json
import re

import yaml

from .checks import Finding

# Reuse the same hardcoded-secret detectors the mobile/iOS scanners use.
try:
    from .mobile_scanner import SECRET_PATTERNS
except Exception:  # pragma: no cover - defensive
    SECRET_PATTERNS = []


# --------------------------------------------------------------------------- #
# File-type detection
# --------------------------------------------------------------------------- #
def detect_kind(filename: str, content: str) -> str:
    """Best-effort classification of the uploaded IaC file."""
    f = (filename or "").lower()
    base = f.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]

    if base == "dockerfile" or base.startswith("dockerfile") or f.endswith(".dockerfile"):
        return "dockerfile"
    if base in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
        return "compose"
    if f.endswith(".tf") or f.endswith(".tf.json") or f.endswith(".hcl"):
        return "terraform"

    head = content[:4000]
    # Content sniffing when the name is ambiguous.
    if re.search(r"^\s*FROM\s+\S+", head, re.MULTILINE) and re.search(r"^\s*(RUN|CMD|COPY|ADD|ENTRYPOINT)\b", head, re.MULTILINE):
        return "dockerfile"
    if re.search(r'"?AWSTemplateFormatVersion"?', head) or re.search(r'"?Resources"?\s*:', head) and "Type" in head and "AWS::" in head:
        return "cloudformation"
    if re.search(r"^\s*resource\s+\"", head, re.MULTILINE) or re.search(r"^\s*provider\s+\"", head, re.MULTILINE):
        return "terraform"
    if re.search(r"^\s*apiVersion\s*:", head, re.MULTILINE) and re.search(r"^\s*kind\s*:", head, re.MULTILINE):
        return "kubernetes"
    if re.search(r"^\s*services\s*:", head, re.MULTILINE):
        return "compose"
    if "AWS::" in content:
        return "cloudformation"
    return "unknown"


def _line_of(content: str, match_start: int) -> int:
    return content.count("\n", 0, match_start) + 1


def _f(check_id: str, title: str, severity: str, kind: str, line: int,
       description: str, remediation: str, impact: str = "", evidence: str = "") -> Finding:
    return Finding(
        check_id=check_id, title=title, severity=severity,
        url=f"{kind}:L{line}" if line else kind,
        description=description, impact=impact,
        evidence=evidence or (f"line {line}" if line else ""),
        remediation=remediation, compliance_ref="OWASP A05:2021",
    )


# --------------------------------------------------------------------------- #
# Shared: hardcoded secrets (any text IaC file)
# --------------------------------------------------------------------------- #
def _scan_secrets(content: str, kind: str) -> list[Finding]:
    out: list[Finding] = []
    seen: set[str] = set()
    data = content.encode("utf-8", "replace")
    for name, rx, sev in SECRET_PATTERNS:
        for m in rx.finditer(data):
            token = m.group(0).decode("utf-8", "replace")
            key = f"{name}:{token[:12]}"
            if key in seen:
                continue
            seen.add(key)
            pos = content.find(token)
            line = _line_of(content, pos) if pos >= 0 else 0
            out.append(_f(
                f"iac-secret-{name}".lower().replace(' ', '-').replace('/', '-'),
                f"Hardcoded secret in IaC ({name})", sev if sev != "info" else "high", kind,
                line,
                description=f"A {name} appears to be committed directly in the IaC file.",
                impact="Secrets in version-controlled IaC leak to anyone with repo access and end up in state files/CI logs.",
                remediation="Move the secret to a secrets manager (AWS Secrets Manager, Vault) or a CI secret variable; never commit it.",
                evidence=f"{token[:6]}… at line {line}",
            ))
    # Generic assignment-style secrets common to IaC (password/secret_key = "literal").
    for m in re.finditer(
        r'(?i)(password|passwd|secret[_-]?key|access[_-]?key|private[_-]?key|token)\s*[=:]\s*["\']([^"\'\s${}]{6,})["\']',
        content,
    ):
        val = m.group(2)
        if val.lower() in ("changeme", "password", "example", "your-password", "redacted") or "var." in val or "REPLACE" in val.upper():
            continue
        if re.fullmatch(r"[A-Za-z0-9_\-]{6,}", val) and not val.startswith(("arn:", "http")):
            key = f"assign:{val[:12]}"
            if key in seen:
                continue
            seen.add(key)
            out.append(_f(
                "iac-hardcoded-credential", "Hardcoded credential in IaC", "high", kind,
                _line_of(content, m.start()),
                description=f"A `{m.group(1)}` is assigned a literal value in the IaC file.",
                impact="Plaintext credentials in IaC are exposed via the repo, Terraform state, and CI output.",
                remediation="Reference a variable/secret store instead of embedding the literal value.",
                evidence=f"{m.group(1)} = \"{val[:4]}…\" at line {_line_of(content, m.start())}",
            ))
    return out


# --------------------------------------------------------------------------- #
# Terraform (HCL / tf.json) — regex/lexical rules
# --------------------------------------------------------------------------- #
_SENSITIVE_PORTS = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL",
                    6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch", 1433: "MSSQL"}


def _scan_terraform(content: str) -> list[Finding]:
    out: list[Finding] = []
    k = "terraform"

    # Public S3 ACL.
    for m in re.finditer(r'acl\s*=\s*"(public-read|public-read-write)"', content):
        out.append(_f("iac-tf-public-bucket", "S3 bucket with public ACL", "high", k,
                      _line_of(content, m.start()),
                      description=f'A bucket ACL is set to "{m.group(1)}", exposing objects publicly.',
                      impact="World-readable buckets are the classic cause of mass data leaks.",
                      remediation='Set acl = "private" and use bucket policies / pre-signed URLs for controlled access.',
                      evidence=m.group(0)))

    # Security group open to the world on a sensitive port.
    for block in re.finditer(r'ingress\s*\{([^}]*)\}', content, re.DOTALL):
        body = block.group(1)
        if not re.search(r'cidr_blocks\s*=\s*\[[^\]]*"0\.0\.0\.0/0"', body):
            continue
        fp = re.search(r'from_port\s*=\s*(\d+)', body)
        tp = re.search(r'to_port\s*=\s*(\d+)', body)
        line = _line_of(content, block.start())
        from_p = int(fp.group(1)) if fp else -1
        to_p = int(tp.group(1)) if tp else -1
        hit = [name for port, name in _SENSITIVE_PORTS.items() if from_p <= port <= to_p]
        if from_p == 0 and to_p == 0:
            hit = ["ALL"]
        if from_p <= 0 and to_p >= 65535:
            hit = ["ALL"]
        if hit:
            out.append(_f("iac-tf-open-security-group",
                          f"Security group open to 0.0.0.0/0 ({', '.join(hit)})", "high", k, line,
                          description=f"An ingress rule allows the whole internet (0.0.0.0/0) to reach {', '.join(hit)}.",
                          impact="Internet-exposed management/database ports are scanned and brute-forced within minutes.",
                          remediation="Restrict cidr_blocks to known admin IP ranges or use a bastion/VPN.",
                          evidence=f"from_port={from_p} to_port={to_p} cidr=0.0.0.0/0"))

    # Publicly accessible RDS.
    for m in re.finditer(r'publicly_accessible\s*=\s*true', content):
        out.append(_f("iac-tf-public-database", "Database instance is publicly accessible", "high", k,
                      _line_of(content, m.start()),
                      description="An RDS/database instance sets publicly_accessible = true.",
                      impact="A public database endpoint dramatically enlarges the attack surface.",
                      remediation="Set publicly_accessible = false and place the DB in a private subnet.",
                      evidence=m.group(0)))

    # Unencrypted storage.
    if re.search(r'resource\s+"aws_ebs_volume"', content) and not re.search(r'encrypted\s*=\s*true', content):
        m = re.search(r'resource\s+"aws_ebs_volume"', content)
        out.append(_f("iac-tf-unencrypted-storage", "EBS volume without encryption", "medium", k,
                      _line_of(content, m.start()),
                      description="An aws_ebs_volume does not set encrypted = true.",
                      impact="Data at rest is unencrypted; a snapshot or disk leak exposes it in cleartext.",
                      remediation="Set encrypted = true (and a kms_key_id) on the volume.",
                      evidence="aws_ebs_volume without encrypted=true"))
    if re.search(r'resource\s+"aws_db_instance"', content) and not re.search(r'storage_encrypted\s*=\s*true', content):
        m = re.search(r'resource\s+"aws_db_instance"', content)
        out.append(_f("iac-tf-unencrypted-database", "RDS instance without storage encryption", "medium", k,
                      _line_of(content, m.start()),
                      description="An aws_db_instance does not set storage_encrypted = true.",
                      impact="Unencrypted database storage fails PCI/HIPAA and exposes data if the volume leaks.",
                      remediation="Set storage_encrypted = true on the aws_db_instance.",
                      evidence="aws_db_instance without storage_encrypted=true"))

    out.extend(_scan_iam_wildcard(content, k))
    return out


def _scan_iam_wildcard(content: str, kind: str) -> list[Finding]:
    """Over-broad IAM: Action:* together with Resource:* (works for TF and CFN)."""
    out: list[Finding] = []
    # Look at statement-ish windows so we don't pair an Action:* in one policy
    # with a Resource:* in an unrelated one.
    for stmt in re.finditer(r'\{[^{}]*?[Aa]ction[^{}]*?[Rr]esource[^{}]*?\}', content, re.DOTALL):
        body = stmt.group(0)
        action_star = re.search(r'"[Aa]ction"\s*:\s*(\[?\s*")\*"', body) or re.search(r'[Aa]ction\s*=\s*\[?\s*"\*"', body)
        resource_star = re.search(r'"[Rr]esource"\s*:\s*(\[?\s*")\*"', body) or re.search(r'[Rr]esource\s*=\s*\[?\s*"\*"', body)
        if action_star and resource_star:
            out.append(_f("iac-iam-wildcard", 'IAM policy grants "*" on "*" (full admin)', "high", kind,
                          _line_of(content, stmt.start()),
                          description='An IAM policy statement allows Action "*" on Resource "*".',
                          impact="A wildcard-on-wildcard grant violates least privilege; any compromise becomes full account takeover.",
                          remediation="Scope the policy to the specific actions and resource ARNs actually required.",
                          evidence='Action:"*" + Resource:"*"'))
            break
    return out


# --------------------------------------------------------------------------- #
# CloudFormation (YAML/JSON)
# --------------------------------------------------------------------------- #
def _scan_cloudformation(content: str) -> list[Finding]:
    out: list[Finding] = []
    k = "cloudformation"

    for m in re.finditer(r'AccessControl\s*:\s*(PublicRead|PublicReadWrite)', content):
        out.append(_f("iac-cfn-public-bucket", "S3 bucket with public AccessControl", "high", k,
                      _line_of(content, m.start()),
                      description=f"AccessControl is {m.group(1)}, exposing the bucket publicly.",
                      impact="World-readable buckets are the classic cause of mass data leaks.",
                      remediation="Use AccessControl: Private plus an explicit, least-privilege bucket policy.",
                      evidence=m.group(0)))

    for m in re.finditer(r'CidrIp\s*:\s*["\']?0\.0\.0\.0/0', content):
        # find a nearby ToPort
        window = content[max(0, m.start() - 200):m.start() + 200]
        tp = re.search(r'ToPort\s*:\s*["\']?(\d+)', window)
        port = int(tp.group(1)) if tp else -1
        name = _SENSITIVE_PORTS.get(port)
        sev = "high" if (name or port in (-1, 0)) else "medium"
        out.append(_f("iac-cfn-open-security-group",
                      f"Security group open to 0.0.0.0/0{f' ({name})' if name else ''}", sev, k,
                      _line_of(content, m.start()),
                      description="A security-group ingress rule allows 0.0.0.0/0 (the whole internet).",
                      impact="Internet-exposed ports are continuously scanned and attacked.",
                      remediation="Restrict CidrIp to specific trusted ranges.",
                      evidence=f"CidrIp: 0.0.0.0/0{f' ToPort {port}' if port>0 else ''}"))

    # Unencrypted (best-effort): an Encryption/StorageEncrypted flag set to false.
    for m in re.finditer(r'(StorageEncrypted|Encrypted)\s*:\s*(false|False)', content):
        out.append(_f("iac-cfn-unencrypted", "Resource with encryption explicitly disabled", "medium", k,
                      _line_of(content, m.start()),
                      description=f"{m.group(1)} is set to false.",
                      impact="Disabling encryption at rest exposes data if the underlying storage leaks.",
                      remediation=f"Set {m.group(1)}: true.",
                      evidence=m.group(0)))

    out.extend(_scan_iam_wildcard(content, k))
    return out


# --------------------------------------------------------------------------- #
# Kubernetes manifests (structured YAML)
# --------------------------------------------------------------------------- #
_DANGEROUS_CAPS = {"SYS_ADMIN", "NET_ADMIN", "ALL", "SYS_PTRACE", "SYS_MODULE"}


def _iter_containers(spec: dict):
    """Yield (container_dict, pod_security_context) for a pod spec."""
    pod_sc = spec.get("securityContext") or {}
    for key in ("containers", "initContainers"):
        for c in (spec.get(key) or []):
            if isinstance(c, dict):
                yield c, pod_sc


def _pod_specs(doc: dict):
    """Yield pod specs from common workload kinds."""
    kind = (doc.get("kind") or "").lower()
    if kind == "pod":
        spec = doc.get("spec") or {}
        if spec:
            yield spec
    elif kind in ("deployment", "statefulset", "daemonset", "replicaset", "job", "replicationcontroller"):
        spec = (((doc.get("spec") or {}).get("template") or {}).get("spec")) or {}
        if spec:
            yield spec
    elif kind == "cronjob":
        spec = (((((doc.get("spec") or {}).get("jobTemplate") or {}).get("spec") or {}).get("template") or {}).get("spec")) or {}
        if spec:
            yield spec


def _scan_kubernetes(content: str) -> list[Finding]:
    out: list[Finding] = []
    k = "kubernetes"
    try:
        docs = [d for d in yaml.safe_load_all(content) if isinstance(d, dict)]
    except yaml.YAMLError:
        return out

    for doc in docs:
        wl_name = (doc.get("metadata") or {}).get("name", "?")
        for spec in _pod_specs(doc):
            if spec.get("hostNetwork") is True or spec.get("hostPID") is True or spec.get("hostIPC") is True:
                shared = [n for n in ("hostNetwork", "hostPID", "hostIPC") if spec.get(n) is True]
                out.append(_f("iac-k8s-host-namespace", f"Pod shares host namespace ({', '.join(shared)})",
                              "high", k, 0,
                              description=f"Workload '{wl_name}' sets {', '.join(shared)} = true.",
                              impact="Sharing host namespaces breaks container isolation and can expose the node.",
                              remediation="Remove hostNetwork/hostPID/hostIPC unless strictly required.",
                              evidence=", ".join(shared)))
            for vol in (spec.get("volumes") or []):
                if isinstance(vol, dict) and vol.get("hostPath"):
                    path = (vol.get("hostPath") or {}).get("path", "?")
                    out.append(_f("iac-k8s-hostpath", "Pod mounts a host path volume", "medium", k, 0,
                                  description=f"Workload '{wl_name}' mounts hostPath {path}.",
                                  impact="hostPath mounts can read/write the node filesystem and enable container escape.",
                                  remediation="Avoid hostPath; use PVCs/emptyDir. Never mount / or the docker socket.",
                                  evidence=f"hostPath: {path}"))

            for c, pod_sc in _iter_containers(spec):
                cname = c.get("name", "?")
                sc = {**pod_sc, **(c.get("securityContext") or {})}
                if sc.get("privileged") is True:
                    out.append(_f("iac-k8s-privileged", "Privileged container", "critical", k, 0,
                                  description=f"Container '{cname}' in '{wl_name}' runs privileged.",
                                  impact="A privileged container is effectively root on the node — trivial host takeover.",
                                  remediation="Remove privileged: true; grant only the specific capabilities needed.",
                                  evidence=f"{wl_name}/{cname}: privileged=true"))
                if sc.get("allowPrivilegeEscalation") is True:
                    out.append(_f("iac-k8s-privilege-escalation", "Container allows privilege escalation",
                                  "medium", k, 0,
                                  description=f"Container '{cname}' sets allowPrivilegeEscalation: true.",
                                  impact="Allows a process to gain more privileges than its parent (e.g. via setuid).",
                                  remediation="Set allowPrivilegeEscalation: false.",
                                  evidence=f"{wl_name}/{cname}"))
                runs_as_root = sc.get("runAsUser") == 0 or (
                    sc.get("runAsNonRoot") is not True and "runAsUser" not in sc and sc.get("runAsNonRoot") is False
                )
                if sc.get("runAsUser") == 0:
                    out.append(_f("iac-k8s-run-as-root", "Container explicitly runs as root (UID 0)",
                                  "medium", k, 0,
                                  description=f"Container '{cname}' sets runAsUser: 0.",
                                  impact="Running as root inside the container widens the blast radius of any escape.",
                                  remediation="Run as a non-root UID and set runAsNonRoot: true.",
                                  evidence=f"{wl_name}/{cname}: runAsUser=0"))
                caps = ((sc.get("capabilities") or {}).get("add") or [])
                dangerous = [c2 for c2 in caps if str(c2).upper() in _DANGEROUS_CAPS]
                if dangerous:
                    out.append(_f("iac-k8s-dangerous-capability",
                                  f"Container adds dangerous capability ({', '.join(dangerous)})", "high", k, 0,
                                  description=f"Container '{cname}' adds Linux capability {', '.join(dangerous)}.",
                                  impact="Powerful capabilities (SYS_ADMIN/NET_ADMIN/ALL) approach full root on the node.",
                                  remediation="Drop ALL capabilities and add back only the minimal required ones.",
                                  evidence=", ".join(str(c2) for c2 in dangerous)))
                image = c.get("image", "")
                if image and (":" not in image.rsplit("/", 1)[-1] or image.endswith(":latest")):
                    out.append(_f("iac-k8s-latest-tag", "Container image uses ':latest' or no tag",
                                  "low", k, 0,
                                  description=f"Container '{cname}' image '{image}' is not pinned to an immutable tag/digest.",
                                  impact="Mutable tags make deployments non-reproducible and can silently pull malicious updates.",
                                  remediation="Pin images to a specific version tag or, ideally, a sha256 digest.",
                                  evidence=image))
    return out


# --------------------------------------------------------------------------- #
# Dockerfile
# --------------------------------------------------------------------------- #
def _scan_dockerfile(content: str) -> list[Finding]:
    out: list[Finding] = []
    k = "dockerfile"
    lines = content.splitlines()

    has_user_nonroot = False
    for i, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        upper = line.upper()

        if upper.startswith("FROM "):
            image = line.split(None, 1)[1].split(" AS ")[0].split(" as ")[0].strip()
            ref = image.rsplit("/", 1)[-1]
            if image.lower() != "scratch" and (":" not in ref or image.endswith(":latest")):
                out.append(_f("iac-docker-latest-tag", "Base image is unpinned (':latest' or no tag)",
                              "low", k, i,
                              description=f"FROM {image} is not pinned to an immutable tag/digest.",
                              impact="Unpinned base images make builds non-reproducible and can pull in malicious updates.",
                              remediation="Pin the base image to a version tag or sha256 digest.",
                              evidence=line))

        if upper.startswith("USER "):
            user = line.split(None, 1)[1].strip().strip('"')
            has_user_nonroot = user not in ("root", "0") and not user.startswith("0:")

        if upper.startswith("ADD "):
            arg = line.split(None, 1)[1] if len(line.split(None, 1)) > 1 else ""
            if re.search(r'https?://', arg):
                out.append(_f("iac-docker-add-remote", "ADD used to fetch a remote URL", "low", k, i,
                              description="ADD is used with a remote URL instead of COPY.",
                              impact="ADD auto-extracts archives and fetches unverified URLs — a supply-chain risk.",
                              remediation="Use COPY for local files; fetch remote content with curl and verify a checksum.",
                              evidence=line[:100]))

        if re.search(r'(curl|wget)\s+[^|]*\|\s*(sudo\s+)?(ba)?sh', line):
            out.append(_f("iac-docker-curl-bash", "Remote script piped directly into a shell", "medium", k, i,
                          description="A RUN step pipes a downloaded script straight into sh/bash.",
                          impact="Executing unverified remote scripts at build time is a code-execution/supply-chain risk.",
                          remediation="Download to a file, verify a checksum/signature, then execute.",
                          evidence=line[:100]))

        if re.search(r'^(ENV|ARG)\b', upper) and re.search(
                r'(?i)(pass(word|wd)?|secret|api[_-]?key|access[_-]?key|token|private[_-]?key)\s*[=\s]\s*["\']?[^\s"\']{6,}', line):
            if not re.search(r'\$\{?[A-Za-z_]', line):  # not just referencing a build-arg
                out.append(_f("iac-docker-secret-in-env", "Secret baked into an image ENV/ARG", "high", k, i,
                              description="A password/secret/token is set as a literal in an ENV or ARG instruction.",
                              impact="ENV values persist in image layers and `docker history` — anyone with the image gets the secret.",
                              remediation="Use build secrets (--secret / BuildKit) or inject at runtime; never bake secrets into layers.",
                              evidence=re.sub(r'(["\']?[^\s"\']{6,})(["\']?)\s*$', r'…\2', line)[:80]))

    if not has_user_nonroot and re.search(r"^\s*FROM\b", content, re.MULTILINE):
        out.append(_f("iac-docker-runs-as-root", "Container runs as root (no non-root USER)", "medium", k, 0,
                     description="The Dockerfile never switches to a non-root USER, so the container runs as root.",
                     impact="A root container that is breached gives the attacker root inside the container and an easier host escape.",
                     remediation="Add a non-root user and a `USER <name>` instruction before the entrypoint.",
                     evidence="no non-root USER instruction"))
    return out


# --------------------------------------------------------------------------- #
# docker-compose
# --------------------------------------------------------------------------- #
def _scan_compose(content: str) -> list[Finding]:
    out: list[Finding] = []
    k = "compose"
    try:
        doc = yaml.safe_load(content)
    except yaml.YAMLError:
        return out
    if not isinstance(doc, dict):
        return out
    services = doc.get("services") or {}
    if not isinstance(services, dict):
        return out

    for name, svc in services.items():
        if not isinstance(svc, dict):
            continue
        if svc.get("privileged") is True:
            out.append(_f("iac-compose-privileged", "Service runs in privileged mode", "high", k, 0,
                          description=f"Service '{name}' sets privileged: true.",
                          impact="A privileged container has near-root access to the host.",
                          remediation="Remove privileged: true; add only the specific cap_add entries needed.",
                          evidence=f"{name}: privileged=true"))
        if svc.get("network_mode") == "host":
            out.append(_f("iac-compose-host-network", "Service uses host networking", "medium", k, 0,
                          description=f"Service '{name}' uses network_mode: host.",
                          impact="Host networking removes network isolation between the container and the node.",
                          remediation="Use a bridge/overlay network and publish only the required ports.",
                          evidence=f"{name}: network_mode=host"))
        for vol in (svc.get("volumes") or []):
            vs = vol if isinstance(vol, str) else (vol.get("source", "") if isinstance(vol, dict) else "")
            if "docker.sock" in str(vs):
                out.append(_f("iac-compose-docker-socket", "Docker socket mounted into a container",
                              "high", k, 0,
                              description=f"Service '{name}' mounts /var/run/docker.sock.",
                              impact="Access to the Docker socket is equivalent to root on the host.",
                              remediation="Avoid mounting docker.sock; use a socket proxy with a restricted API if unavoidable.",
                              evidence=f"{name}: {vs}"))
        for cap in (svc.get("cap_add") or []):
            if str(cap).upper() in _DANGEROUS_CAPS:
                out.append(_f("iac-compose-dangerous-capability",
                              f"Service adds dangerous capability ({cap})", "high", k, 0,
                              description=f"Service '{name}' adds capability {cap}.",
                              impact="Powerful Linux capabilities approach full root on the host.",
                              remediation="Drop capabilities to the minimum; avoid SYS_ADMIN/NET_ADMIN/ALL.",
                              evidence=f"{name}: cap_add {cap}"))
    return out


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
_SCANNERS = {
    "terraform": _scan_terraform,
    "cloudformation": _scan_cloudformation,
    "kubernetes": _scan_kubernetes,
    "dockerfile": _scan_dockerfile,
    "compose": _scan_compose,
}


def run_iac_scan(filename: str, content: str) -> list[Finding]:
    """Analyse a single IaC file and return findings (secrets + type-specific)."""
    kind = detect_kind(filename, content)
    if kind == "unknown":
        return [Finding(
            "iac-unrecognized", "Could not recognise the IaC file type", "info", filename,
            description="The uploaded file did not match Terraform, CloudFormation, Kubernetes, Dockerfile, or compose.",
            remediation="Upload a .tf/.yaml/.json IaC file, a Dockerfile, or a docker-compose file.",
            compliance_ref="OWASP A05:2021", passed=True,
        )]

    findings: list[Finding] = []
    findings.extend(_scan_secrets(content, kind))
    findings.extend(_SCANNERS[kind](content))

    if not findings:
        findings.append(Finding(
            f"iac-clean", f"No misconfigurations found ({kind})", "info", kind,
            description=f"The {kind} file passed all IaC security checks.",
            remediation="Keep scanning IaC on every change in CI.",
            compliance_ref="OWASP A05:2021", passed=True,
        ))
    return findings
