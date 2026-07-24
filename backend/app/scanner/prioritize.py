"""Triage layer: confidence scoring + risk-based prioritization.

Raw findings are noisy — a scanner that dumps 400 issues gets abandoned. This
module answers two questions security teams actually ask:

  1. "How sure are you?"  -> a `confidence` of confirmed / firm / tentative,
     derived from *how* the finding was proven (an exploit marker and a timing
     delta are confirmed; a missing header is firm; a static heuristic is tentative).

  2. "What do I fix first?" -> a 0-100 `priority` that blends severity, confidence,
     and real-world exploitation intelligence: CISA KEV (is it being exploited in
     the wild?) and EPSS (predicted exploitation probability). Both are free.
"""

from __future__ import annotations

import re

import httpx

from .checks import Finding

# --------------------------------------------------------------------------- #
# Confidence
# --------------------------------------------------------------------------- #
# Proof-of-exploit / exact-match checks: a marker reflected, a timing delta, an
# error signature, leaked file contents, a provider-specific secret, a CVE that
# matches an exact version, or a live service that answered a probe.
_CONFIRMED_PREFIXES = (
    "sqli-", "xss-reflected-", "cmdi-", "ssrf-", "ssti-", "csti-", "ssi-injection-",
    "path-traversal-", "open-redirect-", "crlf-", "ldap-injection-", "xpath-injection-",
    "nosqli-", "nosql-", "stored-xss", "xxe", "webshell-upload", "unrestricted-file-upload",
    "secret-", "sca-", "exposed-", "redos-", "bola-", "bfla-", "nuclei-CVE-",
    "cspm-", "iac-secret-", "ios-secret-", "mobile-secret-",
)
# Heuristic / needs-a-human: static source→sink, design flaws, timing-only
# smuggling, fingerprint guesses, and every explicit manual-review advisory.
_TENTATIVE_SUBSTR = (
    "-advisory", "manual-review", "dom-xss", "business-logic", "deserialization",
    "smuggling", "subdomain-takeover", "mass-assignment", "prototype-pollution",
    "excessive-data-exposure", "shadow-api", "js-libraries",
)


def assign_confidence(f: Finding) -> str:
    cid = f.check_id.lower()
    if any(s in cid for s in _TENTATIVE_SUBSTR):
        return "tentative"
    if cid.startswith(_CONFIRMED_PREFIXES):
        return "confirmed"
    return "firm"


# --------------------------------------------------------------------------- #
# Priority score
# --------------------------------------------------------------------------- #
_SEV_BASE = {"critical": 90, "high": 70, "medium": 45, "low": 20, "info": 5}
_CONF_MULT = {"confirmed": 1.0, "firm": 0.85, "tentative": 0.6}
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def _cves_of(f: Finding) -> set[str]:
    blob = f"{f.check_id} {f.title} {f.evidence} {f.description}"
    return {m.group(0).upper() for m in _CVE_RE.finditer(blob)}


def compute_priority(f: Finding, kev_hit: bool = False, epss: float = 0.0) -> int:
    if f.passed:
        return 0
    base = _SEV_BASE.get(str(f.severity), 5)
    score = base * _CONF_MULT.get(f.confidence, 0.85)
    if kev_hit:
        score += 15   # actively exploited in the wild — jump the queue
    if epss:
        score += round(epss * 15)   # up to +15 for near-certain exploitation
    return max(0, min(100, round(score)))


# --------------------------------------------------------------------------- #
# Exploitation intelligence — CISA KEV + EPSS (both free, no key)
# --------------------------------------------------------------------------- #
_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_EPSS_URL = "https://api.first.org/data/v1/epss"
_kev_cache: set[str] | None = None


def _load_kev(client: httpx.Client) -> set[str]:
    global _kev_cache
    if _kev_cache is not None:
        return _kev_cache
    try:
        data = client.get(_KEV_URL, timeout=15).json()
        _kev_cache = {v["cveID"].upper() for v in data.get("vulnerabilities", [])}
    except (httpx.HTTPError, ValueError, KeyError):
        _kev_cache = set()
    return _kev_cache


def _load_epss(client: httpx.Client, cves: list[str]) -> dict[str, float]:
    out: dict[str, float] = {}
    for i in range(0, len(cves), 100):
        chunk = cves[i:i + 100]
        try:
            data = client.get(_EPSS_URL, params={"cve": ",".join(chunk)}, timeout=15).json()
            for row in data.get("data", []):
                out[row["cve"].upper()] = float(row.get("epss", 0) or 0)
        except (httpx.HTTPError, ValueError, KeyError):
            continue
    return out


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
def prioritize_findings(findings: list[Finding]) -> None:
    """Assign confidence + priority to every finding in place, enriching any
    CVE-bearing findings with CISA KEV / EPSS exploitation intelligence."""
    for f in findings:
        f.confidence = assign_confidence(f)

    # Collect CVEs across all findings and enrich once.
    cve_map: dict[int, set[str]] = {}
    all_cves: set[str] = set()
    for idx, f in enumerate(findings):
        if f.passed:
            continue
        cves = _cves_of(f)
        if cves:
            cve_map[idx] = cves
            all_cves |= cves

    kev: set[str] = set()
    epss: dict[str, float] = {}
    if all_cves:
        try:
            with httpx.Client(headers={"User-Agent": "SecureFlow-Triage/1.0"}) as client:
                kev = _load_kev(client)
                epss = _load_epss(client, sorted(all_cves))
        except httpx.HTTPError:
            kev, epss = set(), {}

    for idx, f in enumerate(findings):
        cves = cve_map.get(idx, set())
        kev_hit = bool(cves & kev)
        best_epss = max((epss.get(c, 0.0) for c in cves), default=0.0)
        f.priority = compute_priority(f, kev_hit=kev_hit, epss=best_epss)
        # Surface the intel in the evidence so the report can explain the ranking.
        notes = []
        if kev_hit:
            notes.append("CISA KEV: actively exploited in the wild")
        if best_epss >= 0.10:
            notes.append(f"EPSS {best_epss:.0%} exploitation probability")
        if notes:
            f.evidence = (f.evidence + "  ·  " if f.evidence else "") + " · ".join(notes)
