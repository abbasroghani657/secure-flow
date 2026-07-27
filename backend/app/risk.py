"""Unified risk register + attack-path correlation (ASPM).

Detection is commodity; the value is turning 15 separate scan reports into one
prioritised, deduplicated view of an owner's real risk, and correlating
individual findings into the attack *paths* an adversary would actually walk.

Everything here is deterministic and rule-based, no model, no guesswork:

- ``build_register`` folds the latest completed scan per target into a
  deduplicated, priority-sorted list of risks (one row per issue class, with the
  targets it affects and how many times it recurs).
- ``build_attack_paths`` looks at the *combination* of capabilities an attacker
  would gain from the open findings and emits the chains that matter, e.g. a
  leaked cloud key plus an over-permissive role equals account takeover.
"""

from __future__ import annotations

from sqlmodel import select

from .models import Finding, Scan, ScanStatus

# Triaged-away states never count as live risk.
_RESOLVED = {"false_positive", "fixed"}

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
# Priority floor per severity, so an unscored critical never sinks below a
# scored medium in the register.
_SEV_FLOOR = {"critical": 85, "high": 65, "medium": 40, "low": 20, "info": 5}


def _effective_priority(priority: int, severity: str) -> int:
    return max(priority or 0, _SEV_FLOOR.get(severity, 0))


# --------------------------------------------------------------------------- #
# Register
# --------------------------------------------------------------------------- #

def _latest_scan_per_target(session, user_id: int) -> list[Scan]:
    """Most recent completed scan for each distinct target the user owns."""
    scans = session.exec(
        select(Scan)
        .where(Scan.owner_id == user_id, Scan.status == ScanStatus.completed)
        .order_by(Scan.created_at.desc())
    ).all()
    seen: dict[str, Scan] = {}
    for s in scans:
        key = f"{s.scan_type}:{s.target_url}"
        if key not in seen:
            seen[key] = s
    return list(seen.values())


def _open_findings(session, scans: list[Scan]) -> list[tuple[Scan, Finding]]:
    out: list[tuple[Scan, Finding]] = []
    for scan in scans:
        rows = session.exec(
            select(Finding).where(
                Finding.scan_id == scan.id,
                Finding.passed == False,  # noqa: E712
            )
        ).all()
        for f in rows:
            if (f.status or "open") in _RESOLVED:
                continue
            out.append((scan, f))
    return out


def build_register(session, user_id: int) -> dict:
    """One deduplicated, prioritised row per issue class across every target."""
    scans = _latest_scan_per_target(session, user_id)
    pairs = _open_findings(session, scans)

    risks: dict[str, dict] = {}
    for scan, f in pairs:
        r = risks.get(f.check_id)
        if r is None:
            r = {
                "check_id": f.check_id,
                "title": f.title,
                "severity": f.severity.value if hasattr(f.severity, "value") else f.severity,
                "priority": f.priority or 0,
                "owasp": f.owasp, "cwe": f.cwe, "layer": f.layer,
                "confidence": f.confidence,
                "count": 0,
                "targets": {},   # target_url -> scan_id (dedup)
                "accepted": True,
            }
            risks[f.check_id] = r
        sev = f.severity.value if hasattr(f.severity, "value") else f.severity
        if _SEV_RANK.get(sev, 5) < _SEV_RANK.get(r["severity"], 5):
            r["severity"] = sev
            r["title"] = f.title
        r["priority"] = max(r["priority"], f.priority or 0)
        r["count"] += 1
        r["targets"][scan.target_url] = scan.id
        if (f.status or "open") != "accepted":
            r["accepted"] = False

    rows = []
    for r in risks.values():
        rows.append({
            "check_id": r["check_id"], "title": r["title"], "severity": r["severity"],
            "priority": r["priority"], "owasp": r["owasp"], "cwe": r["cwe"],
            "layer": r["layer"], "confidence": r["confidence"], "count": r["count"],
            "targets": sorted(r["targets"].keys()),
            "target_count": len(r["targets"]),
            "accepted": r["accepted"],
        })
    # Fix-first: severity floor keeps criticals on top, priority (KEV/EPSS) orders within.
    rows.sort(key=lambda x: (-_effective_priority(x["priority"], x["severity"]),
                             _SEV_RANK.get(x["severity"], 5), -x["count"]))

    by_sev = {s: 0 for s in _SEV_RANK}
    for x in rows:
        by_sev[x["severity"]] = by_sev.get(x["severity"], 0) + 1

    return {
        "targets_covered": len({s.target_url for s in scans}),
        "scans_considered": len(scans),
        "total_risks": len(rows),
        "by_severity": by_sev,
        "risks": rows,
    }


# --------------------------------------------------------------------------- #
# Attack-path correlation
# --------------------------------------------------------------------------- #

def _capabilities(f: Finding) -> set[str]:
    """What an attacker gains from this finding, in coarse capability terms."""
    text = f"{f.check_id} {f.title}".lower()
    ev = (f.evidence or "").lower()
    caps: set[str] = set()

    def has(*keys):
        return any(k in text for k in keys)

    if has("secret", "hardcoded", "api-key", "apikey", "aws-key", "private-key",
            "credential", "token-expos", "exposed-key", "access-key"):
        caps.add("secret")
    if has("s3", "bucket", "blob-container", "public-read", "public-storage", "public bucket"):
        caps.add("public_storage")
    if "ssrf" in text:
        caps.add("ssrf")
    if has("metadata", "169.254", "imds"):
        caps.add("metadata")
    if has("sql-injection", "sqli", "command-injection", "rce", "code-injection",
            "ssti", "deserial", "xxe", "template-injection", "webshell", "file-upload"):
        caps.add("rce_or_injection")
    if "xss" in text:
        caps.add("xss")
    if has("idor", "bola", "bfla", "access-control", "privilege", "mass-assignment"):
        caps.add("broken_access")
    if has("jwt", "session", "auth", "password", "mfa", "login", "oauth", "credential-stuff"):
        caps.add("weak_auth")
    if "kev" in ev or "exploited in the wild" in ev:
        caps.add("kev")
    if has("cve-", "vulnerable dependency", "outdated", "known-vuln"):
        caps.add("known_cve")
    if has("open-port", "exposed-service", "database-exposed", ".env", "backup",
            "config-exposure", "disclosure", "directory-listing", "git-exposed"):
        caps.add("exposure")
    if has("iam", "mfa-disabled", "guardduty", "security-group", "open-sg",
            "cloudtrail", "kms", "root-account", "flow-log", "over-privileg"):
        caps.add("cloud_misconfig")
    if has("missing-hsts", "clickjack", "csp", "cookie", "cors", "security-header"):
        caps.add("web_hardening")
    return caps


# Each rule fires only when every required capability is present in the open
# findings. Order is the story an attacker follows.
_RULES = [
    {
        "id": "cloud-takeover-leaked-key",
        "title": "Cloud account takeover via a leaked credential",
        "severity": "critical",
        "requires": ["secret", "cloud_misconfig"],
        "story": "A hardcoded cloud key is exposed, and the cloud account is loosely "
                 "configured. An attacker lifts the key and pivots straight into your "
                 "cloud, where weak IAM and missing guardrails let them escalate.",
        "steps": [
            ("secret", "Harvest the exposed credential"),
            ("cloud_misconfig", "Authenticate and escalate in the cloud account"),
        ],
    },
    {
        "id": "ssrf-to-cloud-creds",
        "title": "SSRF to cloud credential theft",
        "severity": "critical",
        "requires": ["ssrf"],
        "requires_any": ["metadata", "cloud_misconfig"],
        "story": "A server-side request forgery reaches the cloud metadata service, "
                 "handing the attacker temporary IAM credentials, then the same weak "
                 "cloud posture lets them move laterally.",
        "steps": [
            ("ssrf", "Force the server to call internal endpoints"),
            ("metadata", "Read IAM credentials from the metadata service"),
            ("cloud_misconfig", "Use the stolen role to reach data"),
        ],
    },
    {
        "id": "data-breach-public-storage",
        "title": "Data exfiltration from public storage",
        "severity": "high",
        "requires": ["public_storage"],
        "requires_any": ["exposure", "secret"],
        "story": "A publicly readable bucket sits alongside exposed files or secrets. "
                 "An attacker enumerates the bucket and walks off with the data, no "
                 "authentication required.",
        "steps": [
            ("public_storage", "Discover the public storage bucket"),
            ("exposure", "Enumerate and download exposed objects"),
        ],
    },
    {
        "id": "db-compromise-injection",
        "title": "Database compromise via injection",
        "severity": "critical",
        "requires": ["rce_or_injection"],
        "story": "An injection or remote-code flaw lets an attacker run their own "
                 "queries or commands against the application, reaching the database "
                 "and everything it holds.",
        "steps": [
            ("rce_or_injection", "Exploit the injection / RCE sink"),
            ("exposure", "Read or exfiltrate backend data"),
        ],
    },
    {
        "id": "account-takeover-auth-chain",
        "title": "Account takeover via broken auth and access control",
        "severity": "high",
        "requires": ["weak_auth", "broken_access"],
        "story": "Weak authentication gets an attacker a foothold, and broken access "
                 "control lets them reach other users' data or admin functions once "
                 "they are in.",
        "steps": [
            ("weak_auth", "Abuse weak authentication to get a session"),
            ("broken_access", "Pivot to other users' data via IDOR / BFLA"),
        ],
    },
    {
        "id": "session-hijack-xss",
        "title": "Session hijack via XSS and weak session hardening",
        "severity": "high",
        "requires": ["xss", "web_hardening"],
        "story": "A cross-site scripting flaw plus missing cookie and header hardening "
                 "lets an attacker steal a live session from a victim's browser.",
        "steps": [
            ("xss", "Land script execution in a victim's browser"),
            ("web_hardening", "Exfiltrate the session (no HttpOnly / weak headers)"),
        ],
    },
    {
        "id": "known-exploited-cve",
        "title": "Remote exploitation of a known-exploited vulnerability",
        "severity": "critical",
        "requires": ["kev"],
        "story": "A dependency carries a vulnerability that is being exploited in the "
                 "wild right now (on the CISA KEV list). This is opportunistic, "
                 "automated, and happening at internet scale.",
        "steps": [
            ("kev", "Exploit the known-exploited CVE"),
            ("exposure", "Establish access to the host"),
        ],
    },
]


def build_attack_paths(session, user_id: int) -> list[dict]:
    scans = _latest_scan_per_target(session, user_id)
    pairs = _open_findings(session, scans)

    # capability -> representative findings (title + target)
    cap_findings: dict[str, list[dict]] = {}
    present: set[str] = set()
    for scan, f in pairs:
        for cap in _capabilities(f):
            present.add(cap)
            sev = f.severity.value if hasattr(f.severity, "value") else f.severity
            cap_findings.setdefault(cap, []).append(
                {"title": f.title, "target": scan.target_url, "severity": sev}
            )

    paths = []
    for rule in _RULES:
        if not all(c in present for c in rule["requires"]):
            continue
        any_reqs = rule.get("requires_any")
        if any_reqs and not any(c in present for c in any_reqs):
            continue

        steps = []
        for cap, label in rule["steps"]:
            ev = cap_findings.get(cap)
            if not ev:
                continue  # optional step whose capability isn't present
            steps.append({"label": label, "evidence": ev[0]})
        if len(steps) < 2:
            continue  # a "path" needs at least two links to be a chain

        paths.append({
            "id": rule["id"],
            "title": rule["title"],
            "severity": rule["severity"],
            "story": rule["story"],
            "steps": steps,
        })

    paths.sort(key=lambda p: _SEV_RANK.get(p["severity"], 5))
    return paths


def build_risk_overview(session, user_id: int) -> dict:
    reg = build_register(session, user_id)
    reg["attack_paths"] = build_attack_paths(session, user_id)
    return reg
