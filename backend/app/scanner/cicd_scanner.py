"""CI/CD pipeline security scanning.

Upload a GitHub Actions workflow, a GitLab CI file, or a ZIP containing them;
detect the supply-chain and configuration weaknesses that turn a build pipeline
into an attack path (the SolarWinds / Codecov / dependency-confusion class):
unpinned third-party actions, dangerous `pull_request_target` + PR checkout,
script injection from untrusted event data, over-broad `GITHUB_TOKEN`
permissions, `curl | bash`, and secrets printed to logs.

Purely static YAML analysis — this is the poutine / octoscan / StepSecurity
category, built in-house.
"""

from __future__ import annotations

import io
import re
import zipfile

import yaml

from .checks import Finding

# Contexts an attacker can control on a fork PR; interpolating them into a shell
# `run:` step is a classic CI script-injection sink.
_UNTRUSTED_CTX = re.compile(
    r"\$\{\{\s*(github\.event\.(issue|pull_request|comment|review|"
    r"discussion|head_commit)\.[\w.]*(title|body|message|name|email|label|ref)"
    r"|github\.head_ref"
    r"|github\.event\.commits\[[0-9]+\]\.message)"
    , re.IGNORECASE)

# A ref that is NOT a 40-hex SHA → the action is not pinned to an immutable commit.
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
# Trusted first-party publishers where a version tag is broadly acceptable.
_FIRST_PARTY = ("actions/", "github/", "docker/", "azure/", "aws-actions/",
                "hashicorp/", "google-github-actions/")


def _f(check_id: str, title: str, severity: str, where: str, description: str,
       remediation: str, impact: str = "", evidence: str = "") -> Finding:
    return Finding(
        check_id=check_id, title=title, severity=severity, url=where,
        description=description, impact=impact, evidence=evidence,
        remediation=remediation, compliance_ref="OWASP A08:2021",
    )


def _is_github_workflow(name: str, content: str) -> bool:
    n = name.lower().replace("\\", "/")
    if "/.github/workflows/" in n or n.startswith(".github/workflows/"):
        return True
    if re.search(r"^\s*on\s*:", content, re.MULTILINE) and re.search(r"^\s*jobs\s*:", content, re.MULTILINE):
        return True
    return False


def _is_gitlab_ci(name: str, content: str) -> bool:
    n = name.lower().replace("\\", "/")
    if n.endswith(".gitlab-ci.yml") or n == ".gitlab-ci.yml":
        return True
    return bool(re.search(r"^\s*stages\s*:", content, re.MULTILINE) and "script:" in content)


# --------------------------------------------------------------------------- #
# GitHub Actions
# --------------------------------------------------------------------------- #
def _norm_triggers(on) -> set[str]:
    if isinstance(on, str):
        return {on}
    if isinstance(on, list):
        return {str(x) for x in on}
    if isinstance(on, dict):
        return {str(k) for k in on}
    return set()


def scan_github_workflow(path: str, content: str) -> list[Finding]:
    out: list[Finding] = []
    try:
        doc = yaml.safe_load(content)
    except yaml.YAMLError:
        return out
    if not isinstance(doc, dict):
        return out

    # PyYAML parses the bare key `on:` as boolean True — handle both.
    on = doc.get("on", doc.get(True))
    triggers = _norm_triggers(on)
    jobs = doc.get("jobs") or {}
    if not isinstance(jobs, dict):
        jobs = {}

    top_perms = doc.get("permissions")

    dangerous_trigger = "pull_request_target" in triggers or "workflow_run" in triggers

    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        runs_on = job.get("runs-on", "")
        steps = job.get("steps") or []
        job_perms = job.get("permissions", top_perms)

        # Self-hosted runner (risky on public repos — untrusted PRs can run on it).
        if "self-hosted" in str(runs_on):
            out.append(_f("cicd-gha-self-hosted-runner", "Self-hosted runner used", "low",
                          f"{path}:{job_name}",
                          description=f"Job '{job_name}' runs on a self-hosted runner.",
                          impact="On a public repo, a fork PR can execute code on your self-hosted runner and pivot into your network.",
                          remediation="Use ephemeral/isolated runners, and never run untrusted PR code on a persistent self-hosted runner.",
                          evidence=f"runs-on: {runs_on}"))

        # pull_request_target that also checks out the PR head = code exec with secrets.
        for step in steps:
            if not isinstance(step, dict):
                continue
            uses = str(step.get("uses", ""))
            run = step.get("run")

            if dangerous_trigger and uses.startswith("actions/checkout"):
                with_ref = str((step.get("with") or {}).get("ref", ""))
                if "head" in with_ref or "github.event.pull_request" in with_ref or "merge" in with_ref:
                    out.append(_f("cicd-gha-pr-target-checkout",
                                  "pull_request_target checks out untrusted PR code", "critical",
                                  f"{path}:{job_name}",
                                  description="A privileged pull_request_target/workflow_run workflow checks out the PR head ref.",
                                  impact="Fork PR code runs WITH access to repository secrets — full repo/secret compromise (the Codecov-style attack).",
                                  remediation="Do not check out PR head under pull_request_target. Split into an untrusted build (pull_request) and a privileged, code-free step.",
                                  evidence=f"ref: {with_ref}"))

            # Script injection: untrusted context interpolated into a shell step.
            if isinstance(run, str):
                m = _UNTRUSTED_CTX.search(run)
                if m:
                    out.append(_f("cicd-gha-script-injection",
                                  "Script injection from untrusted event data", "high",
                                  f"{path}:{job_name}",
                                  description=f"Step in '{job_name}' interpolates attacker-controllable `{m.group(0)}` directly into a run script.",
                                  impact="An attacker sets the PR/issue title (etc.) to shell metacharacters and runs arbitrary commands on the runner.",
                                  remediation="Pass the value via an `env:` variable and reference \"$VAR\" in the script, instead of inlining ${{ ... }}.",
                                  evidence=m.group(0)))
                if re.search(r"(curl|wget)\s+[^|&;]*\|\s*(sudo\s+)?(ba)?sh", run):
                    out.append(_f("cicd-gha-curl-bash", "Remote script piped into a shell in CI", "medium",
                                  f"{path}:{job_name}",
                                  description=f"A step in '{job_name}' pipes a downloaded script straight into sh/bash.",
                                  impact="A compromised or MITM'd URL executes arbitrary code inside your pipeline.",
                                  remediation="Pin and checksum-verify anything you download before executing it.",
                                  evidence=re.search(r"(curl|wget).{0,60}", run).group(0)))
                if re.search(r"echo\s+[\"']?\$\{\{\s*secrets\.", run) or re.search(r"secrets\.[A-Z_]+\s*\}\}.{0,20}(>>|tee|cat)", run):
                    out.append(_f("cicd-gha-secret-in-logs", "Secret may be printed to build logs", "medium",
                                  f"{path}:{job_name}",
                                  description=f"A step in '{job_name}' appears to echo a secret.",
                                  impact="Secrets printed to logs are visible to anyone who can read the build output.",
                                  remediation="Never echo secrets; rely on GitHub's masking and pass secrets only via env to the tool that needs them.",
                                  evidence="echo ${{ secrets... }}"))

            # Unpinned action (third-party not pinned to a commit SHA).
            if uses and "@" in uses and not uses.startswith("./") and not uses.startswith("docker://"):
                action, _, ref = uses.partition("@")
                ref = ref.strip()
                if not _SHA_RE.match(ref):
                    first_party = action.startswith(_FIRST_PARTY)
                    sev = "low" if first_party else "high"
                    # A moving branch ref is riskier than a version tag for anyone.
                    if ref in ("main", "master", "HEAD"):
                        sev = "medium" if first_party else "high"
                    out.append(_f("cicd-gha-unpinned-action",
                                  f"Third-party action not pinned to a commit SHA ({action}@{ref})", sev,
                                  f"{path}:{job_name}",
                                  description=f"Action `{uses}` is referenced by a mutable tag/branch, not an immutable commit SHA.",
                                  impact="If the action's tag is moved (or the account is compromised), malicious code runs in your pipeline with your secrets.",
                                  remediation=f"Pin to a full 40-char commit SHA: `uses: {action}@<sha>  # {ref}`.",
                                  evidence=uses))

        # Over-broad token permissions at job level.
        if job_perms == "write-all":
            out.append(_f("cicd-gha-broad-permissions", "GITHUB_TOKEN granted write-all", "medium",
                          f"{path}:{job_name}",
                          description=f"'{job_name}' (or the workflow) sets permissions: write-all.",
                          impact="A compromised step gets full write access to the repo, releases, packages and more.",
                          remediation="Set least-privilege permissions (default to `contents: read`) and grant only what each job needs.",
                          evidence="permissions: write-all"))

    # No explicit top-level permissions at all → inherits broad default on many repos.
    if top_perms is None and jobs and not any(
        isinstance(j, dict) and j.get("permissions") is not None for j in jobs.values()
    ):
        out.append(_f("cicd-gha-default-permissions", "No explicit GITHUB_TOKEN permissions set", "low",
                      path,
                      description="The workflow does not declare a `permissions:` block.",
                      impact="Depending on repo settings the token may default to broad read/write, more than the workflow needs.",
                      remediation="Add a top-level `permissions:` block scoped to the minimum (e.g. `contents: read`).",
                      evidence="no permissions: block"))

    if re.search(r"ACTIONS_ALLOW_UNSECURE_COMMANDS", content):
        out.append(_f("cicd-gha-unsecure-commands", "Deprecated unsecure workflow commands enabled", "medium",
                     path,
                     description="ACTIONS_ALLOW_UNSECURE_COMMANDS is enabled.",
                     impact="Re-enables the deprecated set-env/add-path commands that allow environment-injection attacks.",
                     remediation="Remove ACTIONS_ALLOW_UNSECURE_COMMANDS and migrate to the $GITHUB_ENV / $GITHUB_PATH files.",
                     evidence="ACTIONS_ALLOW_UNSECURE_COMMANDS"))
    return out


# --------------------------------------------------------------------------- #
# GitLab CI
# --------------------------------------------------------------------------- #
def scan_gitlab_ci(path: str, content: str) -> list[Finding]:
    out: list[Finding] = []
    try:
        doc = yaml.safe_load(content)
    except yaml.YAMLError:
        return out
    if not isinstance(doc, dict):
        return out

    for job_name, job in doc.items():
        if not isinstance(job, dict):
            continue
        # Unpinned image (mutable :latest / no tag).
        image = job.get("image")
        image_name = image if isinstance(image, str) else (image or {}).get("name", "") if isinstance(image, dict) else ""
        if image_name:
            ref = image_name.rsplit("/", 1)[-1]
            if ("@sha256:" not in image_name) and (":" not in ref or image_name.endswith(":latest")):
                out.append(_f("cicd-gitlab-unpinned-image",
                              f"CI image not pinned ({image_name})", "low", f"{path}:{job_name}",
                              description=f"Job '{job_name}' uses image '{image_name}' with a mutable tag.",
                              impact="A moved tag can silently introduce malicious tooling into the pipeline.",
                              remediation="Pin the image to a digest (image@sha256:…) or an immutable version tag.",
                              evidence=f"image: {image_name}"))
        # curl|bash in scripts.
        script_lines = []
        for key in ("before_script", "script", "after_script"):
            val = job.get(key)
            if isinstance(val, list):
                script_lines += [str(x) for x in val]
            elif isinstance(val, str):
                script_lines.append(val)
        for line in script_lines:
            if re.search(r"(curl|wget)\s+[^|&;]*\|\s*(sudo\s+)?(ba)?sh", line):
                out.append(_f("cicd-gitlab-curl-bash", "Remote script piped into a shell in CI", "medium",
                              f"{path}:{job_name}",
                              description=f"Job '{job_name}' pipes a downloaded script into sh/bash.",
                              impact="A compromised or MITM'd URL executes arbitrary code inside your pipeline.",
                              remediation="Download, checksum-verify, then execute.",
                              evidence=re.search(r"(curl|wget).{0,60}", line).group(0)))
                break
    return out


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
def _scan_one(path: str, content: str) -> list[Finding]:
    if _is_github_workflow(path, content):
        return scan_github_workflow(path, content)
    if _is_gitlab_ci(path, content):
        return scan_gitlab_ci(path, content)
    return []


def run_cicd_scan(filename: str, data: bytes) -> list[Finding]:
    """Scan an uploaded workflow file or a ZIP of a repo's CI configuration."""
    findings: list[Finding] = []
    files = 0

    if data[:2] == b"PK":
        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
        except zipfile.BadZipFile:
            zf = None
        if zf is not None:
            for info in zf.infolist():
                if info.is_dir() or info.file_size > 512_000:
                    continue
                n = info.filename.lower()
                if not (n.endswith((".yml", ".yaml"))):
                    continue
                try:
                    text = zf.read(info).decode("utf-8", "replace")
                except (zipfile.BadZipFile, RuntimeError, OSError):
                    continue
                if _is_github_workflow(info.filename, text) or _is_gitlab_ci(info.filename, text):
                    files += 1
                    findings.extend(_scan_one(info.filename, text))
    else:
        text = data.decode("utf-8", "replace")
        files = 1
        findings.extend(_scan_one(filename, text))

    if files == 0:
        return [Finding("cicd-unrecognized", "No CI/CD workflow recognised", "info", filename,
                        description="No GitHub Actions or GitLab CI configuration was found in the upload.",
                        remediation="Upload a .github/workflows/*.yml file, a .gitlab-ci.yml, or a ZIP containing them.",
                        compliance_ref="OWASP A08:2021", passed=True)]
    if not findings:
        findings.append(Finding("cicd-clean", f"No CI/CD misconfigurations found ({files} workflow(s))", "info",
                                filename, description="The scanned CI/CD workflow(s) passed all pipeline-security checks.",
                                remediation="Keep pinning actions to SHAs and scanning pipelines on every change.",
                                compliance_ref="OWASP A08:2021", passed=True))
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: (f.passed, order.get(f.severity, 5)))
    return findings
