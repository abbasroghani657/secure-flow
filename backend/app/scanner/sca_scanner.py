"""Software Composition Analysis (SCA) + SBOM.

Parses a dependency manifest, queries the free OSV.dev database for known
vulnerabilities in those exact versions, and emits findings plus a CycloneDX SBOM.
No credentials required — OSV is a public, open vulnerability database.
"""

from __future__ import annotations

import json
import re

import httpx

from .checks import Finding

_OSV_BATCH = "https://api.osv.dev/v1/querybatch"
_OSV_VULN = "https://api.osv.dev/v1/vulns/"

# OSV severity (CVSS) → our severity buckets.
_SEV_MAP = [(9.0, "critical"), (7.0, "high"), (4.0, "medium"), (0.1, "low")]


def _ecosystem(filename: str) -> str | None:
    f = filename.lower()
    if f in ("package.json", "package-lock.json") or f.endswith("package-lock.json"):
        return "npm"
    if f in ("requirements.txt",) or f.endswith("requirements.txt") or f == "poetry.lock" or f == "pipfile.lock":
        return "PyPI"
    if f == "go.mod" or f == "go.sum":
        return "Go"
    if f == "gemfile.lock":
        return "RubyGems"
    if f == "composer.lock":
        return "Packagist"
    if f == "cargo.lock":
        return "crates.io"
    return None


def parse_dependencies(filename: str, content: str) -> list[tuple[str, str, str]]:
    """Return [(ecosystem, name, version)] parsed from the manifest."""
    eco = _ecosystem(filename)
    if eco is None:
        return []
    out: list[tuple[str, str, str]] = []
    f = filename.lower()

    try:
        if f.endswith("package-lock.json"):
            data = json.loads(content)
            pkgs = data.get("packages") or {}
            for path, meta in pkgs.items():
                name = path.split("node_modules/")[-1] if path else meta.get("name", "")
                if name and meta.get("version"):
                    out.append(("npm", name, meta["version"]))
            if not pkgs:  # lockfile v1
                for name, meta in (data.get("dependencies") or {}).items():
                    if meta.get("version"):
                        out.append(("npm", name, meta["version"]))
        elif f.endswith("package.json"):
            data = json.loads(content)
            for section in ("dependencies", "devDependencies"):
                for name, ver in (data.get(section) or {}).items():
                    v = re.sub(r"^[\^~>=<\s]+", "", str(ver)).split(" ")[0]
                    if re.match(r"\d+\.\d+", v):
                        out.append(("npm", name, v))
        elif eco == "PyPI":
            for line in content.splitlines():
                m = re.match(r"^([A-Za-z0-9_.\-]+)\s*==\s*([0-9][\w.\-]*)", line.strip())
                if m:
                    out.append(("PyPI", m.group(1), m.group(2)))
        elif eco == "Go":
            for m in re.finditer(r"^\s*([\w./\-]+)\s+v([0-9][\w.\-]+)", content, re.MULTILINE):
                out.append(("Go", m.group(1), "v" + m.group(2)))
        elif eco == "RubyGems":
            for m in re.finditer(r"^\s{4}([\w\-]+)\s+\(([0-9][\w.\-]+)\)", content, re.MULTILINE):
                out.append(("RubyGems", m.group(1), m.group(2)))
        elif eco == "Packagist":
            data = json.loads(content)
            for pkg in (data.get("packages", []) + data.get("packages-dev", [])):
                if pkg.get("name") and pkg.get("version"):
                    out.append(("Packagist", pkg["name"], pkg["version"].lstrip("v")))
    except (json.JSONDecodeError, ValueError):
        return []
    # de-dupe
    return list(dict.fromkeys(out))


def _severity(vuln: dict) -> str:
    score = 0.0
    for s in vuln.get("severity", []) or []:
        try:
            # CVSS vector or score
            val = s.get("score", "")
            m = re.search(r"(\d+\.\d+)", str(val))
            if m:
                score = max(score, float(m.group(1)))
        except (ValueError, AttributeError):
            continue
    for th, name in _SEV_MAP:
        if score >= th:
            return name
    return "medium"


def _fixed_version(vuln: dict, name: str) -> str:
    for aff in vuln.get("affected", []) or []:
        for rng in aff.get("ranges", []) or []:
            for ev in rng.get("events", []) or []:
                if ev.get("fixed"):
                    return ev["fixed"]
    return ""


def query_osv(client: httpx.Client, deps: list[tuple[str, str, str]], max_deps: int = 200) -> list[Finding]:
    deps = deps[:max_deps]
    queries = [{"version": v, "package": {"name": n, "ecosystem": e}} for (e, n, v) in deps]
    try:
        r = client.post(_OSV_BATCH, json={"queries": queries}, timeout=30)
        results = r.json().get("results", [])
    except (httpx.HTTPError, json.JSONDecodeError):
        return []

    findings: list[Finding] = []
    detail_cache: dict[str, dict] = {}
    for (eco, name, version), res in zip(deps, results):
        vulns = res.get("vulns") or []
        if not vulns:
            continue
        ids = [v["id"] for v in vulns[:3]]
        worst = "low"
        fixed = ""
        summaries = []
        cve_aliases: list[str] = []
        for vid in ids:
            if vid not in detail_cache:
                try:
                    detail_cache[vid] = client.get(_OSV_VULN + vid, timeout=15).json()
                except (httpx.HTTPError, json.JSONDecodeError):
                    detail_cache[vid] = {}
            d = detail_cache[vid]
            sev = _severity(d)
            if _SEV_MAP_ORDER(sev) > _SEV_MAP_ORDER(worst):
                worst = sev
            fixed = fixed or _fixed_version(d, name)
            summaries.append(d.get("summary") or vid)
            # CVE aliases enable CISA-KEV / EPSS enrichment in the triage layer.
            for alias in d.get("aliases", []):
                if isinstance(alias, str) and alias.upper().startswith("CVE-"):
                    cve_aliases.append(alias.upper())
        # Prefer showing CVE IDs (what users search for), keep GHSA/OSV IDs too.
        shown = list(dict.fromkeys(cve_aliases)) + [i for i in ids if i not in cve_aliases]
        aliases = ", ".join(shown)
        findings.append(Finding(
            check_id=f"sca-{eco}-{name}".lower(), title=f"Vulnerable dependency: {name} {version}",
            severity=worst, url=f"{eco}:{name}@{version}",
            description=f"{name} {version} ({eco}) has {len(vulns)} known vulnerability(ies): {summaries[0][:120]}",
            impact="Known-vulnerable dependencies are a top breach vector (exploited via public CVEs).",
            evidence=f"OSV: {aliases}",
            remediation=f"Upgrade {name} to {fixed or 'a patched version'}." if fixed else f"Upgrade {name} to a patched version.",
            compliance_ref="OWASP A06:2021",
        ))
    return findings


def _SEV_MAP_ORDER(s: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(s, 0)


def generate_sbom(deps: list[tuple[str, str, str]]) -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {"type": "library", "name": n, "version": v,
             "purl": f"pkg:{e.lower()}/{n}@{v}"}
            for (e, n, v) in deps
        ],
    }


# Public registry existence endpoints for dependency-confusion checks.
_REGISTRY = {
    "npm": "https://registry.npmjs.org/{name}",
    "PyPI": "https://pypi.org/pypi/{name}/json",
}


def check_dependency_confusion(client: httpx.Client, deps: list[tuple[str, str, str]],
                               max_checks: int = 120) -> list[Finding]:
    """Flag manifest packages that do NOT exist on the public registry.

    If a build can fall back to the public registry, an attacker can publish a
    malicious package under that internal name — the dependency-confusion attack.
    """
    out: list[Finding] = []
    seen: set[str] = set()
    checked = 0
    for eco, name, _version in deps:
        url_tmpl = _REGISTRY.get(eco)
        if not url_tmpl or name in seen:
            continue
        seen.add(name)
        checked += 1
        if checked > max_checks:
            break
        try:
            r = client.get(url_tmpl.format(name=name), timeout=10)
        except httpx.HTTPError:
            continue
        if r.status_code == 404:
            scoped = name.startswith("@")
            out.append(Finding(
                check_id=f"sca-dependency-confusion-{name}".lower(),
                title=f"Dependency confusion risk: {name}", severity="medium",
                url=f"{eco}:{name}",
                description=f"'{name}' is required but is not published on the public {eco} registry"
                            f"{' (unclaimed scope)' if scoped else ''}.",
                impact="If your build can resolve from the public registry, an attacker can publish a malicious "
                       "package under this name and have it pulled into your builds (supply-chain compromise).",
                evidence=f"GET public {eco} registry for '{name}' returned 404 (not found).",
                remediation="Pin the package to your private registry with scope/namespace protection; reserve "
                            "the name on the public registry, and disable public fallback for internal scopes.",
                compliance_ref="OWASP A06:2021",
            ))
    return out


def run_sca_scan(filename: str, content: str) -> tuple[list[Finding], dict, int]:
    deps = parse_dependencies(filename, content)
    if not deps:
        return ([Finding("sca-unparsed", "Could not parse dependency manifest", "info", filename,
                         description="No dependencies could be read from the uploaded file.",
                         remediation="Upload a package.json / requirements.txt / go.mod / lock file.",
                         compliance_ref="OWASP A06:2021", passed=True)], {}, 0)
    with httpx.Client(headers={"User-Agent": "SecureFlow-SCA/1.0"}) as client:
        findings = query_osv(client, deps)
        findings.extend(check_dependency_confusion(client, deps))
    if not findings:
        findings.append(Finding("sca-clean", f"No known-vulnerable dependencies ({len(deps)} scanned)", "info",
                                filename, description="All parsed dependencies passed the OSV vulnerability check.",
                                remediation="Keep dependencies updated.", compliance_ref="OWASP A06:2021", passed=True))
    return (findings, generate_sbom(deps), len(deps))
