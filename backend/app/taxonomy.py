"""Central mapping of scanner checks to industry standards.

Every finding is tagged with its OWASP Top 10:2025 category, a CWE ID, and the
affected layer. Mapping lives in one place so it is easy to audit and extend.
"""

from __future__ import annotations

# OWASP Top 10:2025 category names (for display).
OWASP_2025 = {
    "A01:2025": "Broken Access Control",
    "A02:2025": "Security Misconfiguration",
    "A03:2025": "Software Supply Chain Failures",
    "A04:2025": "Cryptographic Failures",
    "A05:2025": "Injection",
    "A06:2025": "Insecure Design",
    "A07:2025": "Identification & Authentication Failures",
    "A08:2025": "Software & Data Integrity Failures",
    "A09:2025": "Logging & Alerting Failures",
    "A10:2025": "Mishandling of Exceptional Conditions",
}

# Exact check_id -> (owasp, cwe, layer)
_EXACT = {
    # A04 Cryptographic Failures
    "no-https": ("A04:2025", "CWE-319", "infra"),
    "no-http-redirect": ("A04:2025", "CWE-319", "infra"),
    "missing-hsts": ("A04:2025", "CWE-319", "infra"),
    "weak-hsts": ("A04:2025", "CWE-319", "infra"),
    "mixed-content": ("A04:2025", "CWE-319", "frontend"),
    "cert-expired": ("A04:2025", "CWE-295", "infra"),
    "cert-expiring": ("A04:2025", "CWE-295", "infra"),
    # A02 Security Misconfiguration
    "missing-csp": ("A02:2025", "CWE-1021", "frontend"),
    "weak-csp": ("A02:2025", "CWE-1021", "frontend"),
    "missing-x-frame-options": ("A02:2025", "CWE-1021", "frontend"),
    "missing-x-content-type-options": ("A02:2025", "CWE-693", "frontend"),
    "missing-referrer-policy": ("A02:2025", "CWE-200", "frontend"),
    "missing-permissions-policy": ("A02:2025", "CWE-693", "frontend"),
    "dangerous-http-methods": ("A02:2025", "CWE-650", "infra"),
    "directory-listing": ("A02:2025", "CWE-548", "infra"),
    "missing-spf": ("A02:2025", "CWE-16", "infra"),
    "missing-dmarc": ("A02:2025", "CWE-16", "infra"),
    "weak-dmarc": ("A02:2025", "CWE-16", "infra"),
    "graphql-introspection": ("A02:2025", "CWE-200", "api"),
    "sensitive-comment": ("A02:2025", "CWE-615", "frontend"),
    # A01 Broken Access Control
    "cors-wildcard-credentials": ("A01:2025", "CWE-942", "api"),
    "missing-csrf-token": ("A01:2025", "CWE-352", "backend"),
    "reverse-tabnabbing": ("A01:2025", "CWE-1022", "frontend"),
    "subdomain-takeover": ("A01:2025", "CWE-350", "infra"),
    "broken-access-control": ("A01:2025", "CWE-284", "backend"),
    "bola-same-account": ("A01:2025", "CWE-639", "api"),
    "open-cloud-bucket": ("A02:2025", "CWE-668", "infra"),
    "dom-xss": ("A05:2025", "CWE-79", "frontend"),
    "xxe": ("A05:2025", "CWE-611", "backend"),
    # A08 Software & Data Integrity Failures
    "missing-sri": ("A08:2025", "CWE-353", "frontend"),
    # A07 Identification & Authentication Failures
    "session-in-url": ("A07:2025", "CWE-598", "backend"),
    # A10 Mishandling of Exceptional Conditions
    "verbose-error": ("A10:2025", "CWE-209", "backend"),
    # informational / passed
    "security-txt-present": ("A09:2025", "CWE-778", "infra"),
    "missing-security-txt": ("A09:2025", "CWE-778", "infra"),
    # OWASP LLM Top 10:2025 (AI/LLM applications)
    "llm-prompt-injection": ("LLM01:2025", "CWE-1427", "api"),
    "llm-jailbreak": ("LLM01:2025", "CWE-1427", "api"),
    "llm-system-prompt-leak": ("LLM07:2025", "CWE-200", "api"),
    "llm-insecure-output": ("LLM05:2025", "CWE-79", "api"),
    "llm-sensitive-disclosure": ("LLM02:2025", "CWE-200", "api"),
    # OWASP Mobile Top 10:2024 (Android APK static analysis)
    "mobile-debuggable": ("M8:2024", "CWE-489", "mobile"),
    "mobile-allow-backup": ("M9:2024", "CWE-530", "mobile"),
    "mobile-cleartext": ("M5:2024", "CWE-319", "mobile"),
    "mobile-exported-component": ("M8:2024", "CWE-926", "mobile"),
    "mobile-low-min-sdk": ("M8:2024", "CWE-1104", "mobile"),
}

# check_id prefix -> (owasp, cwe, layer). Checked when no exact match.
_PREFIX = {
    "sqli-": ("A05:2025", "CWE-89", "database"),
    "nosqli-": ("A05:2025", "CWE-943", "database"),
    "xss-reflected-": ("A05:2025", "CWE-79", "frontend"),
    "ssti-": ("A05:2025", "CWE-1336", "backend"),
    "crlf-": ("A05:2025", "CWE-113", "backend"),
    "cmdi-": ("A05:2025", "CWE-78", "backend"),
    "ssrf-": ("A01:2025", "CWE-918", "backend"),
    "host-header-": ("A05:2025", "CWE-644", "backend"),
    "path-traversal-": ("A01:2025", "CWE-22", "backend"),
    "open-redirect-": ("A01:2025", "CWE-601", "backend"),
    "bola-": ("A01:2025", "CWE-639", "api"),
    "outdated-js-": ("A03:2025", "CWE-1104", "frontend"),
    "mobile-secret-": ("M1:2024", "CWE-798", "mobile"),
    "cookie-flags-": ("A02:2025", "CWE-614", "backend"),
    "cookie-secure-": ("A02:2025", "CWE-614", "backend"),
    "banner-": ("A02:2025", "CWE-200", "infra"),
    "exposed-": ("A02:2025", "CWE-538", "infra"),
    "nuclei-CVE-": ("A03:2025", "", "infra"),   # known CVE → supply chain
    "nuclei-": ("A06:2025", "", "infra"),        # other nuclei templates
    "hsts-": ("A04:2025", "CWE-319", "infra"),
    "csp-": ("A02:2025", "CWE-1021", "frontend"),
    "cert-": ("A04:2025", "CWE-295", "infra"),
    "spf-": ("A02:2025", "CWE-16", "infra"),
    "dmarc-": ("A02:2025", "CWE-16", "infra"),
}


def classify(check_id: str) -> tuple[str, str, str]:
    if check_id in _EXACT:
        return _EXACT[check_id]
    for prefix, val in _PREFIX.items():
        if check_id.startswith(prefix):
            return val
    return ("", "", "")


def enrich(finding) -> None:
    """Fill owasp/cwe/layer on a Finding-like object if not already set."""
    if getattr(finding, "owasp", ""):
        return
    owasp, cwe, layer = classify(finding.check_id)
    finding.owasp = owasp
    # If the finding already carries a CVE/CWE in compliance_ref, keep the CWE.
    ref = getattr(finding, "compliance_ref", "") or ""
    if ref.upper().startswith("CWE-") and not cwe:
        cwe = ref
    finding.cwe = cwe
    finding.layer = layer
