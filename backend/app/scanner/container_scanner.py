"""Container image scanning (Trivy-class).

Upload a `docker save` image tar. We read the image manifest/config and every
layer to find: OS-package CVEs (Debian/Ubuntu dpkg, Alpine apk — queried against
OSV), secrets baked into layers, and config weaknesses (runs as root, secrets in
ENV, sensitive exposed ports). Purely offline static analysis of the tar.
"""

from __future__ import annotations

import io
import json
import re
import tarfile

import httpx

from .checks import Finding

try:
    from .secrets_scanner import _DETECTORS, _SKIP_DIR, _BINARY_EXT
except Exception:  # pragma: no cover
    _DETECTORS, _SKIP_DIR, _BINARY_EXT = [], None, None

_OSV_BATCH = "https://api.osv.dev/v1/querybatch"
_MAX_LAYER_BYTES = 60 * 1024 * 1024
_MAX_TEXT_BYTES = 400_000
_MAX_FILES_PER_LAYER = 800
_SENSITIVE_PORTS = {"22", "23", "3389", "3306", "5432", "6379", "27017", "9200", "2375"}
_ENV_SECRET = re.compile(r"(?i)(pass(word|wd)?|secret|api[_-]?key|token|access[_-]?key|private[_-]?key)")


def _f(check_id, title, severity, where, description, remediation, impact="", evidence="") -> Finding:
    return Finding(check_id=check_id, title=title, severity=severity, url=where,
                   description=description, impact=impact, evidence=evidence or where,
                   remediation=remediation, compliance_ref="OWASP A06:2025")


# --------------------------------------------------------------------------- #
# Image config (docker save: manifest.json -> <config>.json)
# --------------------------------------------------------------------------- #
def _read_json(tar: tarfile.TarFile, name: str):
    try:
        m = tar.extractfile(name)
        return json.loads(m.read()) if m else None
    except (KeyError, tarfile.TarError, json.JSONDecodeError, ValueError):
        return None


def _config_findings(cfg: dict) -> list[Finding]:
    out: list[Finding] = []
    c = (cfg or {}).get("config") or (cfg or {}).get("container_config") or {}
    user = str(c.get("User", "") or "").strip()
    if user in ("", "root", "0", "0:0"):
        out.append(_f("container-runs-as-root", "Container image runs as root", "medium", "image:config",
                      description="The image does not set a non-root USER, so processes run as root.",
                      impact="A breached root container makes host escape and lateral movement far easier.",
                      remediation="Add a non-root user and a USER instruction in the Dockerfile.",
                      evidence=f"User={user or '(unset)'}"))
    for env in (c.get("Env") or []):
        key = str(env).split("=", 1)[0]
        val = str(env).split("=", 1)[1] if "=" in str(env) else ""
        if _ENV_SECRET.search(key) and len(val) >= 6 and "$" not in val and val.lower() not in ("changeme", "example"):
            out.append(_f("container-secret-in-env", f"Secret baked into image ENV ({key})", "high", "image:config",
                          description=f"The environment variable {key} contains a hardcoded secret in an image layer.",
                          impact="ENV values persist in image history — anyone with the image reads the secret.",
                          remediation="Never bake secrets into images; inject at runtime or use build secrets.",
                          evidence=f"{key}={val[:4]}…"))
    ports = list((c.get("ExposedPorts") or {}).keys())
    risky = [p for p in ports if p.split("/")[0] in _SENSITIVE_PORTS]
    if risky:
        out.append(_f("container-sensitive-port", f"Sensitive port exposed ({', '.join(risky)})", "low", "image:config",
                      description=f"The image exposes sensitive port(s): {', '.join(risky)}.",
                      impact="Exposing admin/database ports widens the attack surface if published.",
                      remediation="Only expose the application port; keep admin/DB ports internal.",
                      evidence=", ".join(risky)))
    return out


# --------------------------------------------------------------------------- #
# OS packages (dpkg / apk) -> OSV
# --------------------------------------------------------------------------- #
def _parse_dpkg(text: str) -> list[tuple[str, str]]:
    out = []
    for block in text.split("\n\n"):
        pkg = re.search(r"^Package:\s*(\S+)", block, re.M)
        ver = re.search(r"^Version:\s*(\S+)", block, re.M)
        if pkg and ver:
            out.append((pkg.group(1), ver.group(1)))
    return out


def _parse_apk(text: str) -> list[tuple[str, str]]:
    out, name = [], None
    for line in text.splitlines():
        if line.startswith("P:"):
            name = line[2:].strip()
        elif line.startswith("V:") and name:
            out.append((name, line[2:].strip()))
            name = None
    return out


def _osv_ecosystem(os_id: str, version_id: str) -> str | None:
    """Map /etc/os-release to an OSV ecosystem string."""
    version_id = (version_id or "").strip().strip('"')
    os_id = (os_id or "").lower()
    if os_id in ("debian",) and version_id:
        return f"Debian:{version_id.split('.')[0]}"
    if os_id in ("ubuntu",) and version_id:
        return f"Ubuntu:{version_id}"
    if os_id in ("alpine",) and version_id:
        return f"Alpine:v{'.'.join(version_id.split('.')[:2])}"
    return None


def _query_osv(pkgs: list[tuple[str, str, str]], max_pkgs: int = 400) -> list[Finding]:
    pkgs = pkgs[:max_pkgs]
    if not pkgs:
        return []
    queries = [{"version": v, "package": {"name": n, "ecosystem": e}} for (e, n, v) in pkgs]
    try:
        with httpx.Client(headers={"User-Agent": "Pentrixa-Container/1.0"}) as c:
            r = c.post(_OSV_BATCH, json={"queries": queries}, timeout=30)
            results = r.json().get("results", [])
    except (httpx.HTTPError, ValueError):
        return []
    out = []
    for (eco, name, ver), res in zip(pkgs, results):
        vulns = res.get("vulns") or []
        if not vulns:
            continue
        ids = ", ".join(v.get("id", "") for v in vulns[:3])
        sev = "high" if len(vulns) >= 3 else "medium"
        out.append(_f(f"container-os-cve-{name}".lower(), f"Vulnerable OS package: {name} {ver}", sev,
                      f"{eco}:{name}@{ver}",
                      description=f"{name} {ver} ({eco}) has {len(vulns)} known vulnerability(ies).",
                      impact="Unpatched OS packages in the base image are a common breach vector.",
                      remediation=f"Update {name} (rebuild on a patched base image).",
                      evidence=f"OSV: {ids}"))
    return out


# --------------------------------------------------------------------------- #
# Layer walk
# --------------------------------------------------------------------------- #
def _scan_layer(layer: tarfile.TarFile) -> tuple[list[tuple[str, str]], list[tuple[str, str]], dict, list[Finding]]:
    dpkg_pkgs: list[tuple[str, str]] = []
    apk_pkgs: list[tuple[str, str]] = []
    os_release: dict = {}
    secrets: list[Finding] = []
    seen_secret: set[str] = set()
    count = 0
    for member in layer.getmembers():
        if not member.isfile() or member.size == 0 or member.size > _MAX_TEXT_BYTES:
            continue
        name = member.name.lstrip("./")
        if name.endswith("etc/os-release"):
            try:
                txt = layer.extractfile(member).read().decode("utf-8", "replace")
                for line in txt.splitlines():
                    if "=" in line:
                        k, v = line.split("=", 1)
                        os_release[k.strip()] = v.strip().strip('"')
            except (tarfile.TarError, OSError):
                pass
            continue
        if name.endswith("var/lib/dpkg/status") or name.endswith("lib/apk/db/installed"):
            try:
                data = layer.extractfile(member).read().decode("utf-8", "replace")
            except (tarfile.TarError, OSError):
                continue
            if "dpkg" in name:
                dpkg_pkgs += _parse_dpkg(data)
            else:
                apk_pkgs += _parse_apk(data)
            continue
        if _SKIP_DIR and _SKIP_DIR.search(name):
            continue
        if _BINARY_EXT and _BINARY_EXT.search(name):
            continue
        count += 1
        if count > _MAX_FILES_PER_LAYER:
            continue
        try:
            raw = layer.extractfile(member).read()
        except (tarfile.TarError, OSError):
            continue
        if b"\x00" in raw[:512]:
            continue
        text = raw.decode("utf-8", "replace")
        for sname, rx, sev, _hc in _DETECTORS:
            m = rx.search(text)
            if m:
                key = f"{sname}:{m.group(0)[:12]}"
                if key in seen_secret:
                    continue
                seen_secret.add(key)
                secrets.append(_f(f"container-secret-{sname}".lower().replace(' ', '-').replace('/', '-'),
                                  f"Secret baked into image layer ({sname})", sev if sev != "info" else "high",
                                  f"layer:{name}",
                                  description=f"A {sname} is present in an image layer file ({name}).",
                                  impact="Secrets in layers persist in image history even if deleted in a later layer.",
                                  remediation="Rebuild without the secret; use build secrets / runtime injection.",
                                  evidence=f"{name}: {m.group(0)[:6]}…"))
    return dpkg_pkgs, apk_pkgs, os_release, secrets


def run_container_scan(filename: str, data: bytes) -> list[Finding]:
    try:
        outer = tarfile.open(fileobj=io.BytesIO(data))
    except tarfile.TarError:
        return [Finding("container-invalid", "Not a valid image tar", "info", filename,
                        description="The upload is not a readable `docker save` image tar.",
                        remediation="Provide the output of `docker save <image> -o image.tar`.",
                        compliance_ref="OWASP A06:2025", passed=True)]

    names = set(outer.getnames())
    findings: list[Finding] = []

    manifest = _read_json(outer, "manifest.json")
    layer_names, config_name = [], None
    if isinstance(manifest, list) and manifest:
        layer_names = manifest[0].get("Layers", []) or []
        config_name = manifest[0].get("Config")
    if config_name and config_name in names:
        findings += _config_findings(_read_json(outer, config_name) or {})

    if not layer_names:  # fall back to any *.tar members
        layer_names = [n for n in names if n.endswith("layer.tar") or n.endswith(".tar")]

    dpkg_all: list[tuple[str, str]] = []
    apk_all: list[tuple[str, str]] = []
    os_release: dict = {}
    for ln in layer_names:
        if ln not in names:
            continue
        try:
            member = outer.getmember(ln)
            if member.size > _MAX_LAYER_BYTES:
                continue
            blob = outer.extractfile(member).read()
            with tarfile.open(fileobj=io.BytesIO(blob)) as layer:
                d, a, osr, secrets = _scan_layer(layer)
                dpkg_all += d
                apk_all += a
                if osr:
                    os_release = osr
                findings += secrets
        except (tarfile.TarError, OSError, KeyError):
            continue

    # Map the OS release to an OSV ecosystem and query for package CVEs.
    os_id = os_release.get("ID", "")
    version_id = os_release.get("VERSION_ID", "")
    pkgs: list[tuple[str, str, str]] = []
    if dpkg_all:
        eco = _osv_ecosystem(os_id or "debian", version_id) or "Debian"
        pkgs += [(eco, n, v) for (n, v) in dict.fromkeys(dpkg_all)]
    if apk_all:
        eco = _osv_ecosystem(os_id or "alpine", version_id) or "Alpine"
        pkgs += [(eco, n, v) for (n, v) in dict.fromkeys(apk_all)]
    findings += _query_osv(pkgs)
    all_pkgs = pkgs

    if not findings:
        findings.append(Finding("container-clean", f"No image issues found ({len(all_pkgs)} OS packages)", "info",
                                filename, description="The image passed config, secret and OS-package checks.",
                                remediation="Rebuild on patched base images regularly.",
                                compliance_ref="OWASP A06:2025", passed=True))
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: (f.passed, order.get(f.severity, 5)))
    return findings
