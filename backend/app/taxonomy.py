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
    "session-not-invalidated": ("A07:2025", "CWE-613", "backend"),
    "webshell-upload": ("A04:2025", "CWE-434", "backend"),
    "unrestricted-file-upload": ("A04:2025", "CWE-434", "backend"),
    "open-cloud-bucket": ("A02:2025", "CWE-668", "infra"),
    "open-firebase-db": ("A02:2025", "CWE-668", "infra"),
    "dom-xss": ("A05:2025", "CWE-79", "frontend"),
    "xxe": ("A05:2025", "CWE-611", "backend"),
    "missing-coop": ("A02:2025", "CWE-693", "frontend"),
    "missing-coep-corp": ("A02:2025", "CWE-693", "frontend"),
    "internal-ip-disclosure": ("A01:2025", "CWE-200", "infra"),
    "source-code-disclosure": ("A02:2025", "CWE-540", "infra"),
    "missing-caa": ("A02:2025", "CWE-16", "infra"),
    "dns-zone-transfer": ("A02:2025", "CWE-200", "infra"),
    # TLS / crypto
    "weak-cert-signature": ("A04:2025", "CWE-327", "infra"),
    "weak-cert-key": ("A04:2025", "CWE-326", "infra"),
    "self-signed-cert": ("A04:2025", "CWE-295", "infra"),
    "cert-hostname-mismatch": ("A04:2025", "CWE-295", "infra"),
    "deprecated-tls-10": ("A04:2025", "CWE-327", "infra"),
    "deprecated-tls-11": ("A04:2025", "CWE-327", "infra"),
    "weak-tls-cipher": ("A04:2025", "CWE-327", "infra"),
    # exposed services / dashboards
    "exposed-redis": ("A02:2025", "CWE-668", "infra"),
    "exposed-memcached": ("A02:2025", "CWE-668", "infra"),
    "exposed-elasticsearch": ("A02:2025", "CWE-668", "infra"),
    # JWT / auth
    "jwt-alg-none": ("A07:2025", "CWE-347", "backend"),
    "jwt-weak-secret": ("A07:2025", "CWE-347", "backend"),
    # client-side
    "postmessage-no-origin": ("A08:2025", "CWE-346", "frontend"),
    "sensitive-web-storage": ("A07:2025", "CWE-922", "frontend"),
    "prototype-pollution": ("A08:2025", "CWE-1321", "frontend"),
    "insecure-jsonp": ("A05:2025", "CWE-79", "frontend"),
    # mobile (batch 2)
    "mobile-weak-crypto": ("M10:2024", "CWE-327", "mobile"),
    "mobile-insecure-webview": ("M4:2024", "CWE-749", "mobile"),
    # LLM (batch 2)
    "llm-unbounded-consumption": ("LLM10:2025", "CWE-770", "api"),
    "llm-excessive-agency": ("LLM06:2025", "CWE-250", "api"),
    "insecure-deserialization": ("A08:2025", "CWE-502", "backend"),
    "viewstate-exposed": ("A08:2025", "CWE-502", "backend"),
    "http-request-smuggling": ("A05:2025", "CWE-444", "infra"),
    "race-condition": ("A04:2025", "CWE-362", "backend"),
    "xml-entity-expansion": ("A05:2025", "CWE-776", "backend"),
    "cors-origin-reflection": ("A01:2025", "CWE-942", "api"),
    "excessive-data-exposure": ("A01:2025", "CWE-213", "api"),
    "mass-assignment": ("A04:2025", "CWE-915", "api"),
    "websocket-no-origin-check": ("A01:2025", "CWE-1385", "api"),
    "no-brute-force-protection": ("A07:2025", "CWE-307", "backend"),
    "user-enumeration": ("A07:2025", "CWE-203", "backend"),
    "csp-weak-directives": ("A02:2025", "CWE-1021", "frontend"),
    "stored-xss": ("A05:2025", "CWE-79", "frontend"),
    "exposed-api-docs": ("A02:2025", "CWE-668", "api"),
    "shadow-api-version": ("A02:2025", "CWE-1059", "api"),
    "file-upload-surface": ("A04:2025", "CWE-434", "backend"),
    "jwks-exposed": ("A07:2025", "CWE-347", "backend"),
    "oauth-missing-state": ("A01:2025", "CWE-352", "backend"),
    "oauth-open-redirect-uri": ("A01:2025", "CWE-601", "backend"),
    "manual-review-advisory": ("A06:2025", "", ""),
    "llm-manual-review-advisory": ("LLM03:2025", "", "api"),
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
    "mobile-no-cert-pinning": ("M5:2024", "CWE-295", "mobile"),
    "mobile-no-tamper-detection": ("M7:2024", "CWE-919", "mobile"),
    "mobile-external-storage": ("M9:2024", "CWE-312", "mobile"),
    "mobile-unencrypted-sqlite": ("M9:2024", "CWE-312", "mobile"),
    "mobile-excessive-permissions": ("M6:2024", "CWE-250", "mobile"),
    "mobile-open-firebase": ("M9:2024", "CWE-668", "mobile"),
    "ios-ats-disabled": ("M5:2024", "CWE-319", "mobile"),
    "ios-ats-exception": ("M5:2024", "CWE-319", "mobile"),
    "ios-url-scheme": ("M4:2024", "CWE-939", "mobile"),
    "ios-no-pie": ("M7:2024", "CWE-121", "mobile"),
    "ios-no-stack-canary": ("M7:2024", "CWE-121", "mobile"),
    "ios-no-jailbreak-detection": ("M7:2024", "CWE-919", "mobile"),
    "llm-indirect-injection": ("LLM08:2025", "CWE-1427", "api"),
    "llm-misinformation": ("LLM09:2025", "CWE-345", "api"),
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
    "csti-": ("A05:2025", "CWE-1336", "frontend"),
    "ssi-injection-": ("A05:2025", "CWE-97", "backend"),
    "crlf-": ("A05:2025", "CWE-113", "backend"),
    "cmdi-": ("A05:2025", "CWE-78", "backend"),
    "ssrf-": ("A01:2025", "CWE-918", "backend"),
    "host-header-": ("A05:2025", "CWE-644", "backend"),
    "path-traversal-": ("A01:2025", "CWE-22", "backend"),
    "open-redirect-": ("A01:2025", "CWE-601", "backend"),
    "bola-": ("A01:2025", "CWE-639", "api"),
    "bfla-": ("A01:2025", "CWE-285", "api"),
    "ldap-injection-": ("A05:2025", "CWE-90", "backend"),
    "xpath-injection-": ("A05:2025", "CWE-643", "backend"),
    "js-secret-": ("A05:2025", "CWE-798", "frontend"),
    "business-logic-": ("A04:2025", "CWE-840", "backend"),
    "redos-": ("A06:2025", "CWE-1333", "backend"),
    "exposed-dashboard-": ("A02:2025", "CWE-668", "infra"),
    "outdated-js-": ("A03:2025", "CWE-1104", "frontend"),
    "mobile-secret-": ("M1:2024", "CWE-798", "mobile"),
    "sca-dependency-confusion": ("A03:2025", "CWE-427", "backend"),
    "sca-": ("A03:2025", "CWE-1104", "backend"),
    "ios-secret-": ("M1:2024", "CWE-798", "mobile"),
    # IaC misconfigurations (specific prefixes before the generic "iac-" catch-all).
    "iac-secret-": ("A05:2025", "CWE-798", "infra"),
    "iac-hardcoded-": ("A05:2025", "CWE-798", "infra"),
    "iac-iam-": ("A01:2025", "CWE-269", "infra"),
    "iac-tf-public-": ("A05:2025", "CWE-668", "infra"),
    "iac-cfn-public-": ("A05:2025", "CWE-668", "infra"),
    "iac-tf-unencrypted-": ("A02:2025", "CWE-311", "infra"),
    "iac-cfn-unencrypted": ("A02:2025", "CWE-311", "infra"),
    "iac-tf-open-": ("A05:2025", "CWE-284", "infra"),
    "iac-cfn-open-": ("A05:2025", "CWE-284", "infra"),
    "iac-k8s-": ("A05:2025", "CWE-250", "infra"),
    "iac-docker-": ("A05:2025", "CWE-250", "infra"),
    "iac-compose-": ("A05:2025", "CWE-250", "infra"),
    "iac-": ("A05:2025", "CWE-16", "infra"),
    "secrets-": ("A05:2025", "CWE-798", "backend"),
    "secret-": ("A05:2025", "CWE-798", "backend"),
    # CI/CD pipeline security (supply-chain integrity).
    "cicd-gha-script-injection": ("A05:2025", "CWE-94", "infra"),
    "cicd-gha-pr-target-checkout": ("A08:2025", "CWE-94", "infra"),
    "cicd-gha-unpinned-action": ("A08:2025", "CWE-829", "infra"),
    "cicd-gitlab-unpinned-image": ("A08:2025", "CWE-829", "infra"),
    "cicd-": ("A08:2025", "CWE-829", "infra"),
    # CSPM — cloud posture (AWS). Specific prefixes before the generic catch-all.
    "cspm-s3-unencrypted": ("A02:2025", "CWE-311", "infra"),
    "cspm-s3-": ("A05:2025", "CWE-668", "infra"),
    "cspm-sg-": ("A05:2025", "CWE-284", "infra"),
    "cspm-ebs-": ("A02:2025", "CWE-311", "infra"),
    "cspm-rds-unencrypted": ("A02:2025", "CWE-311", "infra"),
    "cspm-rds-": ("A05:2025", "CWE-668", "infra"),
    "cspm-iam-no-mfa": ("A07:2025", "CWE-308", "infra"),
    "cspm-iam-": ("A07:2025", "CWE-521", "infra"),
    "cspm-cloudtrail-": ("A09:2025", "CWE-778", "infra"),
    "cspm-": ("A05:2025", "CWE-16", "infra"),
    "jwt-": ("A07:2025", "CWE-347", "backend"),
    "csv-formula-injection": ("A05:2025", "CWE-1236", "backend"),
    "web-cache-poisoning": ("A05:2025", "CWE-524", "backend"),
    "http-parameter-pollution": ("A05:2025", "CWE-235", "backend"),
    "graphql-batching-abuse": ("A04:2025", "CWE-770", "api"),
    "graphql-field-suggestions": ("A02:2025", "CWE-200", "api"),
    "graphql-introspection": ("A02:2025", "CWE-200", "api"),
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


# SAST check_ids are "sast-<lang>-<class>"; the security class (the suffix) drives
# the OWASP/CWE mapping regardless of language.
_SAST_SUFFIX = {
    "command-injection": ("A05:2025", "CWE-78", "backend"),
    "code-injection": ("A05:2025", "CWE-94", "backend"),
    "nosql-injection": ("A05:2025", "CWE-943", "database"),
    "sql-injection": ("A05:2025", "CWE-89", "database"),
    "insecure-deserialization": ("A08:2025", "CWE-502", "backend"),
    "object-injection": ("A08:2025", "CWE-502", "backend"),
    "unsafe-yaml": ("A08:2025", "CWE-502", "backend"),
    "ssti": ("A05:2025", "CWE-1336", "backend"),
    "dom-xss": ("A05:2025", "CWE-79", "frontend"),
    "xss": ("A05:2025", "CWE-79", "frontend"),
    "file-inclusion": ("A05:2025", "CWE-98", "backend"),
    "xxe": ("A05:2025", "CWE-611", "backend"),
    "xpath-injection": ("A05:2025", "CWE-643", "backend"),
    "ldap-injection": ("A05:2025", "CWE-90", "backend"),
    "header-injection": ("A05:2025", "CWE-113", "backend"),
    "mass-assignment": ("A08:2025", "CWE-915", "backend"),
    "timing-attack": ("A02:2025", "CWE-208", "backend"),
    "zip-slip": ("A01:2025", "CWE-22", "backend"),
    "reflected-xss": ("A05:2025", "CWE-79", "frontend"),
    "postmessage-origin": ("A05:2025", "CWE-346", "frontend"),
    "css-injection": ("A05:2025", "CWE-79", "frontend"),
    "path-traversal": ("A01:2025", "CWE-22", "backend"),
    "ssrf": ("A01:2025", "CWE-918", "backend"),
    "open-redirect": ("A01:2025", "CWE-601", "backend"),
    "prototype-pollution": ("A08:2025", "CWE-1321", "backend"),
    "weak-jwt": ("A07:2025", "CWE-347", "backend"),
    "cors-misconfig": ("A02:2025", "CWE-942", "backend"),
    "insecure-cookie": ("A02:2025", "CWE-614", "backend"),
    "redos": ("A06:2025", "CWE-1333", "backend"),
    "sensitive-logging": ("A09:2025", "CWE-532", "backend"),
    "weak-hash": ("A02:2025", "CWE-327", "backend"),
    "weak-crypto": ("A02:2025", "CWE-327", "backend"),
    "weak-random": ("A02:2025", "CWE-330", "backend"),
    "tls-verify-disabled": ("A02:2025", "CWE-295", "backend"),
    "tls-skip-verify": ("A02:2025", "CWE-295", "backend"),
    "trust-all-certs": ("A02:2025", "CWE-295", "backend"),
    "debug-enabled": ("A05:2025", "CWE-489", "backend"),
    "insecure-tempfile": ("A01:2025", "CWE-377", "backend"),
}


def classify(check_id: str) -> tuple[str, str, str]:
    if check_id in _EXACT:
        return _EXACT[check_id]
    if check_id.startswith("sast-"):
        # Longest suffix first so e.g. "nosql-injection" wins over "sql-injection".
        for suffix in sorted(_SAST_SUFFIX, key=len, reverse=True):
            if check_id.endswith(suffix):
                return _SAST_SUFFIX[suffix]
        return ("A05:2025", "CWE-94", "backend")  # generic SAST fallback
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
