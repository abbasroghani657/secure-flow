"""Compliance readiness — the GRC layer (Vanta / Drata play).

Maps an organization's open findings onto the technical controls of the major
frameworks and scores how ready they are. A control is *met* when no open finding
contradicts it, and *at risk* when one does, with the offending findings attached
so an auditor (or the team) can see exactly why.

Honest scope: this assesses the technically-detectable controls a scanner can
observe. Full certification also needs policies, processes and human attestation,
which this does not replace, and the UI says so.
"""

from __future__ import annotations

from datetime import datetime, timezone

from .risk import _latest_scan_per_target, _open_findings


# --------------------------------------------------------------------------- #
# Finding -> compliance domain classification
# --------------------------------------------------------------------------- #

def _domains(f) -> set[str]:
    text = f"{f.check_id} {f.title}".lower()
    owasp = (f.owasp or "").upper()
    ev = (f.evidence or "").lower()
    d: set[str] = set()

    def has(*ks):
        return any(k in text for k in ks)

    if has("hsts", "https", "tls", "ssl", "cleartext", "http is not redirect", "mixed-content"):
        d.add("encryption_transit")
    if has("weak crypto", "weak-crypto", "ecb", "3des", " des", "md5", "sha1",
            "insecure storage", "unencrypted", "cipher"):
        d.add("encryption_storage")
    if has("idor", "bola", "bfla", "access control", "access-control", "privilege",
            "mass-assignment", "authorization") or owasp.startswith("A01"):
        d.add("access_control")
    if has("jwt", "session", "auth", "password", "mfa", "login", "oauth", "credential-stuff",
            "2fa", "brute") or owasp.startswith("A07"):
        d.add("authentication")
    if has("sql-injection", "sqli", "xss", "ssti", "command-injection", "code-injection",
            "xxe", "csti", "ssi", "deserial", "template-injection", "injection") or owasp.startswith("A05"):
        d.add("injection")
    if (has("misconfig", "header", "cookie", "cors", "clickjack", "default", "directory-listing",
            "csp", "permissions-policy", "referrer-policy") or owasp.startswith("A02")):
        d.add("secure_config")
    if has("vulnerable dependency", "cve-", "outdated", "known-vuln", "end-of-life", "eol"):
        d.add("vuln_management")
    if has("secret", "hardcoded", "api-key", "apikey", "private-key", "access-key", "credential in"):
        d.add("secrets")
    if has("disclosure", "backup", ".env", "exposed", "public bucket", "public-read",
            "s3", "directory-listing", "git-exposed", "source disclosure", "info leak"):
        d.add("data_exposure")
    if has("logging", "audit", "monitor", "alerting", "cloudtrail", "flow-log") or owasp.startswith("A09"):
        d.add("logging_monitoring")
    if has("dependency", "sca", "cicd", "ci/cd", "integrity", "unpinned", "supply chain",
            "sbom", "pipeline") or owasp.startswith("A03") or owasp.startswith("A08"):
        d.add("supply_chain")
    if has("open-port", "security-group", "open-sg", "exposed-service", "0.0.0.0/0",
            "database-exposed", "network"):
        d.add("network")
    if has("iam", "mfa-disabled", "guardduty", "kms", "root-account", "over-privileg",
            "public bucket", "s3", "security group"):
        d.add("cloud_posture")
    return d


# --------------------------------------------------------------------------- #
# Frameworks — technically-assessable controls
# --------------------------------------------------------------------------- #

# control = (id, title, description, [domains])
FRAMEWORKS = [
    {
        "key": "pci-dss", "name": "PCI DSS", "version": "v4.0",
        "blurb": "Payment Card Industry Data Security Standard.",
        "controls": [
            ("2", "Secure configurations", "Systems are hardened; no insecure defaults or unnecessary exposure.", ["secure_config", "network"]),
            ("3", "Protect stored account data", "Sensitive data is encrypted at rest; no secrets in code.", ["encryption_storage", "secrets"]),
            ("4", "Encrypt data in transit", "Cardholder data is encrypted over open networks (TLS/HSTS).", ["encryption_transit"]),
            ("6.2", "Secure software development", "Applications are free of common injection and web flaws.", ["injection"]),
            ("6.3", "Remove known vulnerabilities", "Components are patched; no known-vulnerable dependencies.", ["vuln_management", "supply_chain"]),
            ("7", "Restrict access by need-to-know", "Access control enforces least privilege.", ["access_control"]),
            ("8", "Strong authentication", "Authentication is strong (MFA, no weak credentials).", ["authentication"]),
            ("10", "Log and monitor access", "Security events are logged and monitored.", ["logging_monitoring"]),
        ],
    },
    {
        "key": "soc2", "name": "SOC 2", "version": "Type II (Security)",
        "blurb": "AICPA Trust Services Criteria, security principle.",
        "controls": [
            ("CC6.1", "Logical access controls", "Access is restricted to authorized users.", ["access_control", "authentication"]),
            ("CC6.6", "Boundary protection", "The system perimeter is protected against threats.", ["network", "secure_config"]),
            ("CC6.7", "Data in transit", "Data is encrypted when transmitted.", ["encryption_transit"]),
            ("CC6.8", "Unauthorized software", "Malicious or unauthorized software is prevented.", ["supply_chain", "secrets"]),
            ("CC7.1", "Vulnerability detection", "Vulnerabilities are identified and evaluated.", ["vuln_management"]),
            ("CC7.2", "Security monitoring", "Anomalies and security events are monitored.", ["logging_monitoring"]),
            ("CC8.1", "Change management", "Changes are managed through a controlled pipeline.", ["supply_chain"]),
        ],
    },
    {
        "key": "iso-27001", "name": "ISO/IEC 27001", "version": "2022 (Annex A)",
        "blurb": "International information-security management standard.",
        "controls": [
            ("A.5.15", "Access control", "Access to information is controlled by policy.", ["access_control"]),
            ("A.5.17", "Authentication information", "Authentication secrets are managed securely.", ["authentication", "secrets"]),
            ("A.8.8", "Technical vulnerabilities", "Technical vulnerabilities are managed.", ["vuln_management"]),
            ("A.8.9", "Configuration management", "Secure configuration is enforced.", ["secure_config"]),
            ("A.8.24", "Use of cryptography", "Cryptography protects data in transit and at rest.", ["encryption_transit", "encryption_storage"]),
            ("A.8.25", "Secure development lifecycle", "Software is developed securely.", ["injection"]),
            ("A.8.15", "Logging", "Events are logged to support monitoring.", ["logging_monitoring"]),
            ("A.5.14", "Information transfer / exposure", "Information is not disclosed to unauthorized parties.", ["data_exposure"]),
        ],
    },
    {
        "key": "gdpr", "name": "GDPR", "version": "Article 32",
        "blurb": "EU security-of-processing obligations.",
        "controls": [
            ("32(1)(a)", "Encryption of personal data", "Personal data is encrypted in transit and at rest.", ["encryption_transit", "encryption_storage"]),
            ("32(1)(b)-C", "Confidentiality", "Access to personal data is restricted.", ["access_control", "authentication"]),
            ("32(1)(b)-I", "Integrity", "Data cannot be tampered with via injection.", ["injection"]),
            ("32(1)(d)", "Regular testing", "Security is tested and evaluated regularly.", ["vuln_management"]),
            ("5(1)(f)", "Prevent unauthorized disclosure", "Personal data is not exposed.", ["data_exposure", "secrets"]),
        ],
    },
    {
        "key": "hipaa", "name": "HIPAA", "version": "Security Rule §164.312",
        "blurb": "US healthcare technical safeguards.",
        "controls": [
            ("164.312(a)", "Access control", "ePHI access is restricted to authorized users.", ["access_control"]),
            ("164.312(c)", "Integrity", "ePHI is protected from improper alteration.", ["injection"]),
            ("164.312(d)", "Person/entity authentication", "Users are authenticated before access.", ["authentication"]),
            ("164.312(e)", "Transmission security", "ePHI is encrypted in transit.", ["encryption_transit"]),
        ],
    },
]


def build_compliance(session, org_id: int) -> dict:
    scans = _latest_scan_per_target(session, org_id)
    pairs = _open_findings(session, scans)

    domain_findings: dict[str, list[dict]] = {}
    for scan, f in pairs:
        sev = f.severity.value if hasattr(f.severity, "value") else f.severity
        item = {"title": f.title, "target": scan.target_url, "severity": sev, "cwe": f.cwe}
        for d in _domains(f):
            domain_findings.setdefault(d, []).append(item)

    frameworks = []
    for fw in FRAMEWORKS:
        controls = []
        met = 0
        for cid, title, desc, domains in fw["controls"]:
            hits: list[dict] = []
            for d in domains:
                hits.extend(domain_findings.get(d, []))
            # de-dup by (title, target)
            seen = set()
            uniq = []
            for h in hits:
                k = (h["title"], h["target"])
                if k not in seen:
                    seen.add(k)
                    uniq.append(h)
            status = "at_risk" if uniq else "met"
            if status == "met":
                met += 1
            controls.append({
                "id": cid, "title": title, "description": desc, "status": status,
                "issue_count": len(uniq), "findings": uniq[:8],
            })
        total = len(fw["controls"])
        frameworks.append({
            "key": fw["key"], "name": fw["name"], "version": fw["version"], "blurb": fw["blurb"],
            "controls_total": total, "controls_met": met,
            "readiness": round(100 * met / total) if total else 0,
            "controls": controls,
        })

    frameworks.sort(key=lambda x: -x["readiness"])
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "targets_covered": len({s.target_url for s in scans}),
        "frameworks": frameworks,
    }
