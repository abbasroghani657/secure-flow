"""Built-in web security checks.

Each check inspects a real HTTP response from the target and returns a list of
``dict`` findings. A finding with ``passed=True`` is a control the site got
right (drives the "Passed" tab); otherwise it is a vulnerability/misconfig.

These are all passive, unauthenticated checks against the target the user has
verified they own — no exploitation, no fuzzing, no denial of service.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import parse_qs, urljoin, urlparse

import httpx


@dataclass
class Finding:
    check_id: str
    title: str
    severity: str  # critical|high|medium|low|info
    url: str
    description: str = ""
    impact: str = ""
    evidence: str = ""
    remediation: str = ""
    compliance_ref: str = ""
    passed: bool = False
    # Standards mapping (filled centrally by taxonomy.enrich); see app/taxonomy.py
    owasp: str = ""   # e.g. "A05:2025"
    cwe: str = ""     # e.g. "CWE-89"
    layer: str = ""   # frontend | api | backend | database | infra

    def as_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity,
            "url": self.url,
            "description": self.description,
            "impact": self.impact,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "compliance_ref": self.compliance_ref,
            "passed": self.passed,
            "owasp": self.owasp,
            "cwe": self.cwe,
            "layer": self.layer,
        }


@dataclass
class Probe:
    """Everything the checks need from a single fetch of the base URL."""

    url: str
    final_url: str
    status_code: int
    headers: dict  # lower-cased keys
    raw_headers: dict  # original casing
    set_cookies: list[str] = field(default_factory=list)
    is_https: bool = False
    http_redirects_to_https: Optional[bool] = None
    body_snippet: str = ""


# ---- Header presence / value checks ---------------------------------------

def _header(probe: Probe, name: str) -> Optional[str]:
    return probe.headers.get(name.lower())


def check_https(probe: Probe) -> list[Finding]:
    if probe.is_https:
        f = [Finding(
            "uses-https", "Site is served over HTTPS", "info", probe.final_url,
            description="The target responds over TLS/HTTPS.",
            remediation="No action needed.",
            compliance_ref="OWASP A02:2021", passed=True,
        )]
        if probe.http_redirects_to_https:
            f.append(Finding(
                "http-to-https-redirect", "HTTP redirects to HTTPS", "info", probe.final_url,
                description="Plain HTTP requests are redirected to HTTPS.",
                remediation="No action needed.",
                compliance_ref="OWASP A02:2021", passed=True,
            ))
        elif probe.http_redirects_to_https is False:
            f.append(Finding(
                "no-http-redirect", "HTTP is not redirected to HTTPS", "medium", probe.url,
                description="The site is reachable over plain HTTP and does not force a redirect to HTTPS.",
                impact="Traffic can be intercepted or downgraded by a man-in-the-middle before TLS is negotiated.",
                remediation="Configure the server to 301-redirect all HTTP traffic to HTTPS.",
                compliance_ref="OWASP A02:2021",
            ))
        return f
    return [Finding(
        "no-https", "Site is not served over HTTPS", "high", probe.url,
        description="The target does not serve content over TLS/HTTPS.",
        impact="All data, including credentials and session cookies, is transmitted in clear text.",
        evidence=f"Base URL resolved to {probe.final_url}",
        remediation="Obtain a TLS certificate (e.g. Let's Encrypt) and serve all traffic over HTTPS.",
        compliance_ref="PCI DSS 4.1",
    )]


def check_hsts(probe: Probe) -> list[Finding]:
    if not probe.is_https:
        return []
    val = _header(probe, "strict-transport-security")
    if val:
        weak = "max-age=0" in val.replace(" ", "") or (
            "max-age=" in val and _max_age(val) is not None and _max_age(val) < 15552000
        )
        if weak:
            return [Finding(
                "weak-hsts", "Weak HSTS max-age", "low", probe.final_url,
                description="Strict-Transport-Security is set but with a short max-age.",
                impact="A short HSTS window leaves a gap where downgrade attacks are possible.",
                evidence=f"Strict-Transport-Security: {val}",
                remediation="Use at least max-age=15768000 (6 months); add includeSubDomains and preload.",
                compliance_ref="OWASP A05:2021",
            )]
        return [Finding(
            "hsts-present", "HSTS is enabled", "info", probe.final_url,
            description="Strict-Transport-Security header is present.",
            evidence=f"Strict-Transport-Security: {val}",
            remediation="No action needed.",
            compliance_ref="OWASP A05:2021", passed=True,
        )]
    return [Finding(
        "missing-hsts", "Missing HSTS header", "medium", probe.final_url,
        description="The Strict-Transport-Security header is not set.",
        impact="Browsers may connect over HTTP first, exposing users to SSL-stripping attacks.",
        remediation="Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        compliance_ref="OWASP A05:2021",
    )]


def _max_age(val: str) -> Optional[int]:
    for part in val.split(";"):
        part = part.strip()
        if part.lower().startswith("max-age="):
            try:
                return int(part.split("=", 1)[1])
            except ValueError:
                return None
    return None


def check_csp(probe: Probe) -> list[Finding]:
    val = _header(probe, "content-security-policy")
    if val:
        if "unsafe-inline" in val or "unsafe-eval" in val:
            return [Finding(
                "weak-csp", "Content-Security-Policy allows unsafe directives", "low", probe.final_url,
                description="A CSP is present but permits 'unsafe-inline' or 'unsafe-eval'.",
                impact="Weakens the CSP's protection against cross-site scripting (XSS).",
                evidence=f"Content-Security-Policy: {val[:180]}",
                remediation="Remove 'unsafe-inline'/'unsafe-eval'; use nonces or hashes for inline scripts.",
                compliance_ref="OWASP A03:2021",
            )]
        return [Finding(
            "csp-present", "Content-Security-Policy is set", "info", probe.final_url,
            description="A Content-Security-Policy header is present.",
            evidence=f"Content-Security-Policy: {val[:180]}",
            remediation="No action needed.",
            compliance_ref="OWASP A03:2021", passed=True,
        )]
    return [Finding(
        "missing-csp", "Missing Content-Security-Policy", "medium", probe.final_url,
        description="No Content-Security-Policy header was returned.",
        impact="Without a CSP the site has no defence-in-depth against XSS and data injection.",
        remediation="Define a restrictive CSP, e.g. default-src 'self'; object-src 'none'; frame-ancestors 'none'.",
        compliance_ref="OWASP A03:2021",
    )]


def check_x_frame(probe: Probe) -> list[Finding]:
    xfo = _header(probe, "x-frame-options")
    csp = _header(probe, "content-security-policy") or ""
    if xfo or "frame-ancestors" in csp:
        return [Finding(
            "clickjacking-protected", "Clickjacking protection present", "info", probe.final_url,
            description="X-Frame-Options or CSP frame-ancestors restricts framing.",
            evidence=f"X-Frame-Options: {xfo}" if xfo else "CSP frame-ancestors set",
            remediation="No action needed.",
            compliance_ref="OWASP A05:2021", passed=True,
        )]
    return [Finding(
        "missing-x-frame-options", "Missing clickjacking protection", "medium", probe.final_url,
        description="Neither X-Frame-Options nor CSP frame-ancestors is set.",
        impact="The page can be embedded in an attacker's iframe for clickjacking.",
        remediation="Add 'X-Frame-Options: DENY' or CSP 'frame-ancestors \\'none\\''.",
        compliance_ref="OWASP A05:2021",
    )]


def check_x_content_type(probe: Probe) -> list[Finding]:
    val = _header(probe, "x-content-type-options")
    if val and val.lower() == "nosniff":
        return [Finding(
            "nosniff-present", "MIME-sniffing protection present", "info", probe.final_url,
            description="X-Content-Type-Options: nosniff is set.",
            remediation="No action needed.", compliance_ref="OWASP A05:2021", passed=True,
        )]
    return [Finding(
        "missing-x-content-type-options", "Missing X-Content-Type-Options", "low", probe.final_url,
        description="X-Content-Type-Options: nosniff is not set.",
        impact="Browsers may MIME-sniff responses, enabling certain XSS vectors.",
        remediation="Add: X-Content-Type-Options: nosniff", compliance_ref="OWASP A05:2021",
    )]


def check_referrer_policy(probe: Probe) -> list[Finding]:
    val = _header(probe, "referrer-policy")
    if val:
        return [Finding(
            "referrer-policy-present", "Referrer-Policy is set", "info", probe.final_url,
            evidence=f"Referrer-Policy: {val}", remediation="No action needed.",
            compliance_ref="OWASP A05:2021", passed=True,
        )]
    return [Finding(
        "missing-referrer-policy", "Missing Referrer-Policy", "low", probe.final_url,
        description="No Referrer-Policy header is set.",
        impact="Full URLs (which may contain sensitive tokens) can leak to third-party sites.",
        remediation="Add: Referrer-Policy: strict-origin-when-cross-origin", compliance_ref="OWASP A05:2021",
    )]


def check_permissions_policy(probe: Probe) -> list[Finding]:
    if _header(probe, "permissions-policy"):
        return [Finding(
            "permissions-policy-present", "Permissions-Policy is set", "info", probe.final_url,
            remediation="No action needed.", compliance_ref="OWASP A05:2021", passed=True,
        )]
    return [Finding(
        "missing-permissions-policy", "Missing Permissions-Policy", "low", probe.final_url,
        description="No Permissions-Policy header restricts powerful browser features.",
        impact="Embedded content can request camera, microphone, geolocation, etc.",
        remediation="Add a Permissions-Policy limiting features, e.g. geolocation=(), camera=(), microphone=().",
        compliance_ref="OWASP A05:2021",
    )]


def check_server_banner(probe: Probe) -> list[Finding]:
    findings: list[Finding] = []
    for hdr, label in (("server", "Server"), ("x-powered-by", "X-Powered-By")):
        val = _header(probe, hdr)
        # Flag only when a version number is disclosed.
        if val and any(c.isdigit() for c in val):
            findings.append(Finding(
                f"banner-{hdr}", f"Version disclosure in {label} header", "low", probe.final_url,
                description=f"The {label} header reveals software and version details.",
                impact="Attackers can fingerprint the stack and target known CVEs for that version.",
                evidence=f"{label}: {val}",
                remediation=f"Suppress or generalise the {label} header at the web server/proxy.",
                compliance_ref="OWASP A05:2021",
            ))
    return findings


def check_cors(probe: Probe) -> list[Finding]:
    acao = _header(probe, "access-control-allow-origin")
    acac = _header(probe, "access-control-allow-credentials")
    if acao == "*" and acac and acac.lower() == "true":
        return [Finding(
            "cors-wildcard-credentials", "Insecure CORS configuration", "high", probe.final_url,
            description="Access-Control-Allow-Origin is '*' together with Allow-Credentials: true.",
            impact="Any origin can read authenticated responses — a serious data-exposure risk.",
            evidence="Access-Control-Allow-Origin: *; Access-Control-Allow-Credentials: true",
            remediation="Never combine a wildcard origin with credentials; echo a validated allow-list origin.",
            compliance_ref="OWASP A05:2021",
        )]
    return []


def check_cookies(probe: Probe) -> list[Finding]:
    findings: list[Finding] = []
    for raw in probe.set_cookies:
        name = raw.split("=", 1)[0].strip()
        low = raw.lower()
        problems = []
        if "httponly" not in low:
            problems.append("HttpOnly")
        if probe.is_https and "secure" not in low:
            problems.append("Secure")
        if "samesite" not in low:
            problems.append("SameSite")
        if problems:
            findings.append(Finding(
                f"cookie-flags-{name}", f"Cookie '{name}' missing {', '.join(problems)}", "medium",
                probe.final_url,
                description=f"The cookie '{name}' is set without the {', '.join(problems)} attribute(s).",
                impact="Cookies without HttpOnly/Secure/SameSite are exposed to XSS theft and CSRF.",
                evidence=raw[:160],
                remediation="Set Secure, HttpOnly and SameSite=Lax (or Strict) on session cookies.",
                compliance_ref="OWASP A05:2021",
            ))
        else:
            findings.append(Finding(
                f"cookie-secure-{name}", f"Cookie '{name}' is hardened", "info", probe.final_url,
                description=f"Cookie '{name}' carries the recommended security attributes.",
                remediation="No action needed.", compliance_ref="OWASP A05:2021", passed=True,
            ))
    return findings


def check_mixed_content(probe: Probe) -> list[Finding]:
    if not probe.is_https or not probe.body_snippet:
        return []
    # http:// resources loaded on an https page (script/src/href/link).
    refs = re.findall(r'(?:src|href)\s*=\s*["\'](http://[^"\']+)["\']', probe.body_snippet, re.IGNORECASE)
    refs = [r for r in refs if not r.startswith("http://www.w3.org")]  # ignore XML namespaces
    if refs:
        return [Finding(
            "mixed-content", "Mixed content on HTTPS page", "low", probe.final_url,
            description="The HTTPS page references resources over plain HTTP.",
            impact="Mixed content can be tampered with in transit and browsers may block it.",
            evidence="; ".join(refs[:3])[:200],
            remediation="Load all resources over HTTPS (or protocol-relative URLs).",
            compliance_ref="OWASP A02:2021",
        )]
    return []


BASE_CHECKS = [
    check_https, check_hsts, check_csp, check_x_frame, check_x_content_type,
    check_referrer_policy, check_permissions_policy, check_server_banner,
    check_cors, check_cookies, check_mixed_content,
]

DANGEROUS_METHODS = {"PUT", "DELETE", "TRACE", "TRACK", "CONNECT"}


def check_http_methods(base_url: str, allow_header: str) -> list[Finding]:
    """Analyse an OPTIONS Allow header for dangerous enabled methods."""
    if not allow_header:
        return []
    methods = {m.strip().upper() for m in allow_header.split(",") if m.strip()}
    risky = sorted(methods & DANGEROUS_METHODS)
    if risky:
        return [Finding(
            "dangerous-http-methods", f"Dangerous HTTP methods enabled: {', '.join(risky)}",
            "medium", base_url,
            description=f"The server advertises support for {', '.join(risky)}.",
            impact="Methods like PUT/DELETE/TRACE can enable file upload, deletion or cross-site tracing.",
            evidence=f"Allow: {allow_header}",
            remediation="Disable unused HTTP methods at the server/proxy; allow only GET, POST, HEAD.",
            compliance_ref="OWASP A05:2021",
        )]
    return []


def directory_listing_finding(url: str, body: str) -> Optional[Finding]:
    if re.search(r"<title>\s*Index of /", body, re.IGNORECASE) or "Directory listing for" in body:
        return Finding(
            "directory-listing", "Directory listing enabled", "medium", url,
            description="The server returns an auto-generated directory index.",
            impact="Attackers can enumerate files not meant to be discoverable.",
            evidence=f"Directory index returned at {url}",
            remediation="Disable directory autoindex (e.g. 'Options -Indexes' / autoindex off).",
            compliance_ref="OWASP A05:2021",
        )
    return None


COMMON_DIRS = ["/uploads/", "/images/", "/files/", "/backup/", "/assets/", "/static/"]

_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)
_SECRET_HINTS = re.compile(
    r"\b(password|passwd|secret|api[_-]?key|todo|fixme|hack|bug|username|"
    r"internal|http://(?:localhost|127\.0\.0\.1|10\.|192\.168\.)|aws_|token)\b",
    re.IGNORECASE,
)
_SESSION_PARAMS = {"sessionid", "session", "phpsessid", "jsessionid", "sid",
                   "sessid", "auth", "token", "access_token", "api_key", "apikey"}


def check_sensitive_comments(probe: Probe) -> list[Finding]:
    if not probe.body_snippet:
        return []
    for c in _COMMENT_RE.findall(probe.body_snippet):
        m = _SECRET_HINTS.search(c)
        if m:
            snippet = c.strip().replace("\n", " ")[:120]
            return [Finding(
                "sensitive-comment", "Sensitive information in HTML comment", "low", probe.final_url,
                description="An HTML comment contains potentially sensitive keywords.",
                impact="Comments can leak credentials, internal hosts, or hints about hidden functionality.",
                evidence=f"<!-- …{snippet}… -->",
                remediation="Strip developer comments from production HTML.",
                compliance_ref="OWASP A02:2025",
            )]
    return []


# (library, regex capturing version, minimum safe version, note)
JS_LIBRARIES = [
    ("jQuery", re.compile(r"jquery[.-]?(\d+\.\d+\.\d+)", re.I), (3, 5, 0), "XSS in older jQuery (CVE-2020-11022/23)"),
    ("AngularJS", re.compile(r"angular(?:\.min)?[.-]?(1\.\d+\.\d+)", re.I), (1, 8, 3), "AngularJS 1.x is end-of-life"),
    ("Bootstrap", re.compile(r"bootstrap[.-]?(\d+\.\d+\.\d+)", re.I), (4, 3, 1), "XSS in older Bootstrap"),
    ("Lodash", re.compile(r"lodash[.-]?(\d+\.\d+\.\d+)", re.I), (4, 17, 21), "Prototype pollution (CVE-2019-10744)"),
    ("Moment.js", re.compile(r"moment[.-]?(\d+\.\d+\.\d+)", re.I), (2, 29, 4), "ReDoS in older Moment.js"),
    ("Handlebars", re.compile(r"handlebars[.-]?(\d+\.\d+\.\d+)", re.I), (4, 7, 7), "Prototype pollution / RCE"),
]


def _ver(s: str) -> tuple:
    return tuple(int(x) for x in s.split("."))


def check_js_libraries(probe: Probe) -> list[Finding]:
    if not probe.body_snippet:
        return []
    out: list[Finding] = []
    seen: set[str] = set()
    for name, rx, min_safe, note in JS_LIBRARIES:
        m = rx.search(probe.body_snippet)
        if not m or name in seen:
            continue
        try:
            found = _ver(m.group(1))
        except ValueError:
            continue
        if found < min_safe:
            seen.add(name)
            out.append(Finding(
                f"outdated-js-{name.lower().replace('.', '')}", f"Outdated JavaScript library: {name} {m.group(1)}",
                "medium", probe.final_url,
                description=f"The page loads {name} {m.group(1)}, which is below the recommended {'.'.join(map(str, min_safe))}.",
                impact=note,
                evidence=f"Detected {name} {m.group(1)} in a script reference.",
                remediation=f"Upgrade {name} to {'.'.join(map(str, min_safe))} or later.",
                compliance_ref="OWASP A03:2025",
            ))
    return out


def check_sri(probe: Probe) -> list[Finding]:
    if not probe.body_snippet:
        return []
    host = urlparse(probe.final_url).hostname or ""
    # cross-origin <script src> / <link href> tags without an integrity= attribute
    tags = re.findall(r"<(?:script|link)\b[^>]*>", probe.body_snippet, re.IGNORECASE)
    bad: list[str] = []
    for tag in tags:
        src = re.search(r'(?:src|href)\s*=\s*["\']([^"\']+)["\']', tag, re.I)
        if not src:
            continue
        u = src.group(1)
        if not (u.startswith("http://") or u.startswith("https://") or u.startswith("//")):
            continue  # same-origin relative — SRI not required
        h = urlparse(u if "//" in u[:8] else "https:" + u).hostname or ""
        if h and h != host and "integrity=" not in tag.lower():
            bad.append(u)
    if bad:
        return [Finding(
            "missing-sri", "Missing Subresource Integrity (SRI)", "low", probe.final_url,
            description="External scripts/styles are loaded without an integrity hash.",
            impact="If the third-party host or CDN is compromised, malicious code runs on your site.",
            evidence="; ".join(bad[:3])[:200],
            remediation='Add integrity="sha384-…" and crossorigin to third-party <script>/<link> tags.',
            compliance_ref="OWASP A08:2025",
        )]
    return []


def check_tabnabbing(probe: Probe) -> list[Finding]:
    if not probe.body_snippet:
        return []
    for tag in re.findall(r"<a\b[^>]*target\s*=\s*[\"']_blank[\"'][^>]*>", probe.body_snippet, re.IGNORECASE):
        rel = re.search(r'rel\s*=\s*["\']([^"\']*)["\']', tag, re.I)
        if not rel or "noopener" not in rel.group(1).lower():
            return [Finding(
                "reverse-tabnabbing", "Reverse tabnabbing (target=_blank without rel=noopener)",
                "low", probe.final_url,
                description="Links open in a new tab without rel=\"noopener\".",
                impact="The opened page can rewrite the opener tab's location for phishing.",
                evidence=tag[:120],
                remediation='Add rel="noopener noreferrer" to every target="_blank" link.',
                compliance_ref="OWASP A01:2025",
            )]
    return []


def check_csrf_forms(forms) -> list[Finding]:
    """POST forms without a CSRF token field (operates on crawler-discovered forms)."""
    token_names = ("csrf", "token", "authenticity", "_token", "requestverification", "xsrf", "nonce")
    for form in forms:
        if form.method != "post":
            continue
        if any(any(t in (name or "").lower() for t in token_names) for name in form.inputs):
            continue
        return [Finding(
            "missing-csrf-token", "Form without CSRF protection", "medium", form.action,
            description="A state-changing POST form has no anti-CSRF token field.",
            impact="Attackers can forge requests from a victim's authenticated session (CSRF).",
            evidence=f"POST form at {form.action} with fields: {', '.join(form.inputs)[:120]}",
            remediation="Add a per-session anti-CSRF token to every state-changing form; use SameSite cookies.",
            compliance_ref="OWASP A01:2025",
        )]
    return []


def check_session_in_url(param_urls: list[str]) -> list[Finding]:
    for u in param_urls:
        qs = parse_qs(urlparse(u).query)
        hit = _SESSION_PARAMS & {k.lower() for k in qs}
        if hit:
            return [Finding(
                "session-in-url", "Session token exposed in URL", "medium", u,
                description=f"A session/authentication token ({', '.join(sorted(hit))}) is passed in the URL.",
                impact="Tokens in URLs leak via logs, Referer headers, and browser history — enabling session hijacking.",
                evidence=f"Parameter(s) {', '.join(sorted(hit))} in query string.",
                remediation="Carry session tokens in cookies (HttpOnly, Secure) or Authorization headers, never the URL.",
                compliance_ref="OWASP A07:2025",
            )]
    return []


# ---- Sensitive path exposure ----------------------------------------------

SENSITIVE_PATHS = [
    ("/.git/config", "Exposed Git repository", "high",
     "The .git directory is publicly reachable — source code and secrets may be downloadable.",
     "Block access to .git/ at the web server, or remove it from the web root.", "OWASP A05:2021"),
    ("/.env", "Exposed environment file", "critical",
     "A .env file is publicly reachable and typically contains credentials and API keys.",
     "Remove .env from the web root and block access to dotfiles.", "OWASP A05:2021"),
    ("/.env.local", "Exposed local environment file", "critical",
     "A .env.local file is publicly reachable and typically contains secrets.",
     "Remove environment files from the web root.", "OWASP A05:2021"),
    ("/.git/HEAD", "Exposed Git HEAD", "high",
     "The .git/HEAD file is reachable, confirming an exposed repository.",
     "Block access to the .git/ directory.", "OWASP A05:2021"),
    ("/.svn/entries", "Exposed Subversion metadata", "high",
     "An .svn directory is reachable, exposing source and history.",
     "Remove .svn/ from the web root.", "OWASP A05:2021"),
    ("/.hg/requires", "Exposed Mercurial repository", "high",
     "A Mercurial (.hg) repository is reachable.",
     "Remove .hg/ from the web root.", "OWASP A05:2021"),
    ("/backup.zip", "Exposed backup archive", "high",
     "A backup archive is publicly downloadable.",
     "Remove backups from the web root.", "OWASP A05:2021"),
    ("/backup.sql", "Exposed SQL dump", "critical",
     "A database dump is publicly downloadable.",
     "Remove database dumps from the web root.", "OWASP A05:2021"),
    ("/db.sql", "Exposed SQL dump", "critical",
     "A database dump is publicly downloadable.",
     "Remove database dumps from the web root.", "OWASP A05:2021"),
    ("/.DS_Store", "Exposed .DS_Store file", "low",
     "A macOS .DS_Store file leaks directory structure.",
     "Remove .DS_Store files and block dotfiles.", "OWASP A05:2021"),
    ("/phpinfo.php", "Exposed phpinfo()", "medium",
     "A phpinfo() page discloses server configuration and paths.",
     "Delete phpinfo test files from production.", "OWASP A05:2021"),
    ("/server-status", "Exposed Apache server-status", "medium",
     "The Apache server-status page is publicly reachable.",
     "Restrict mod_status to localhost.", "OWASP A05:2021"),
    ("/.aws/credentials", "Exposed AWS credentials file", "critical",
     "An AWS credentials file is publicly reachable.",
     "Remove cloud credential files from the web root immediately and rotate keys.", "OWASP A05:2021"),
    ("/.htpasswd", "Exposed .htpasswd file", "high",
     "An .htpasswd file with password hashes is reachable.",
     "Block access to .htpasswd.", "OWASP A05:2021"),
    ("/config.php.bak", "Exposed config backup", "high",
     "A backup of a config file is downloadable as source.",
     "Remove editor/backup files (.bak, ~) from the web root.", "OWASP A05:2021"),
    ("/wp-config.php.bak", "Exposed WordPress config backup", "critical",
     "A WordPress config backup with DB credentials is downloadable.",
     "Remove backup files from the web root.", "OWASP A05:2021"),
    ("/.vscode/sftp.json", "Exposed SFTP deployment config", "high",
     "An editor deployment config may contain server credentials.",
     "Remove .vscode/ deployment configs from the web root.", "OWASP A05:2021"),
    ("/docker-compose.yml", "Exposed docker-compose file", "medium",
     "A docker-compose file may reveal services, ports and secrets.",
     "Do not serve infrastructure files from the web root.", "OWASP A05:2021"),
    ("/.npmrc", "Exposed .npmrc", "high",
     "An .npmrc file may contain registry auth tokens.",
     "Remove .npmrc from the web root and rotate tokens.", "OWASP A05:2021"),
    ("/swagger.json", "Exposed API schema (Swagger)", "low",
     "An API schema is publicly reachable, mapping the API surface.",
     "Restrict API docs/schemas to authenticated users in production.", "OWASP A05:2021"),
    ("/.well-known/openid-configuration", "OIDC configuration exposed", "info",
     "OpenID configuration is published (usually expected).",
     "No action if intended.", "OWASP A05:2021"),
]


# Paths that legitimately return HTML/JSON; everything else that returns an HTML
# shell is treated as a soft-404 (SPA fallback) and ignored.
HTML_OK_PATHS = {"/phpinfo.php", "/server-status"}

# Positive content signatures — a match is strong evidence the real file is served.
PATH_SIGNATURES = {
    "/.env": re.compile(r"^[A-Z][A-Z0-9_]*\s*=", re.MULTILINE),
    "/.env.local": re.compile(r"^[A-Z][A-Z0-9_]*\s*=", re.MULTILINE),
    "/.git/config": re.compile(r"\[core\]|repositoryformatversion", re.IGNORECASE),
    "/.git/HEAD": re.compile(r"ref:\s*refs/", re.IGNORECASE),
    "/.hg/requires": re.compile(r"revlog|dotencode|store", re.IGNORECASE),
    "/backup.sql": re.compile(r"(INSERT INTO|CREATE TABLE|DROP TABLE|-- MySQL dump)", re.IGNORECASE),
    "/db.sql": re.compile(r"(INSERT INTO|CREATE TABLE|DROP TABLE)", re.IGNORECASE),
    "/.htpasswd": re.compile(r"^[^:\s]+:[^:\s]+$", re.MULTILINE),
    "/.aws/credentials": re.compile(r"aws_access_key_id|\[default\]", re.IGNORECASE),
    "/.npmrc": re.compile(r"_authToken|registry=", re.IGNORECASE),
    "/phpinfo.php": re.compile(r"phpinfo\(\)|PHP Version", re.IGNORECASE),
    "/server-status": re.compile(r"Apache Server Status", re.IGNORECASE),
    "/docker-compose.yml": re.compile(r"services:|image:", re.IGNORECASE),
    "/swagger.json": re.compile(r'"swagger"|"openapi"', re.IGNORECASE),
    "/config.php.bak": re.compile(r"<\?php|define\(", re.IGNORECASE),
    "/wp-config.php.bak": re.compile(r"DB_PASSWORD|DB_NAME|<\?php", re.IGNORECASE),
}


def looks_present(status_code: int, body: str, path: str, baseline_body: str | None = None) -> bool:
    if status_code != 200:
        return False
    stripped = body.strip()
    if not stripped:
        return False

    # Soft-404: response is (nearly) identical to a known-nonexistent URL's page.
    if baseline_body is not None:
        b = baseline_body.strip()
        if stripped == b or (len(b) > 40 and abs(len(stripped) - len(b)) < 0.05 * len(b) and stripped[:200] == b[:200]):
            return False

    low = stripped.lower()
    is_html = low.startswith("<!doctype html") or low.startswith("<html") or "<html" in low[:300]
    if is_html and path not in HTML_OK_PATHS:
        return False  # an HTML shell for a non-HTML file is a soft-404

    sig = PATH_SIGNATURES.get(path)
    if sig is not None:
        return bool(sig.search(body))
    # No signature defined (e.g. binary archives, .DS_Store): the non-HTML 200 stands.
    return True


def build_path_finding(base_url: str, path: str, resp_status: int, resp_body: str) -> Optional[Finding]:
    for p, title, sev, desc, fix, ref in SENSITIVE_PATHS:
        if p == path:
            return Finding(
                f"exposed-{path.strip('/').replace('/', '-')}", title, sev, urljoin(base_url, path),
                description=desc,
                impact="Sensitive files exposed to the public internet can lead to full compromise.",
                evidence=f"HTTP {resp_status} at {path} ({len(resp_body)} bytes)",
                remediation=fix, compliance_ref=ref,
            )
    return None


def check_security_txt(base_url: str, present: bool) -> Finding:
    if present:
        return Finding(
            "security-txt-present", "security.txt is published", "info",
            urljoin(base_url, "/.well-known/security.txt"),
            description="A /.well-known/security.txt file is published for vulnerability reporting.",
            remediation="No action needed.", compliance_ref="ISO 27001 A.16", passed=True,
        )
    return Finding(
        "missing-security-txt", "No security.txt published", "info",
        urljoin(base_url, "/.well-known/security.txt"),
        description="No /.well-known/security.txt file was found.",
        impact="Researchers have no standard channel to report vulnerabilities.",
        remediation="Publish /.well-known/security.txt with a contact and policy URL.",
        compliance_ref="ISO 27001 A.16",
    )


def normalize_url(raw: str) -> str:
    raw = raw.strip()
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    parsed = urlparse(raw)
    if not parsed.netloc:
        raise ValueError("Invalid URL")
    return raw
