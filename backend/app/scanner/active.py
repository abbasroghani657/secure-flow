"""Active vulnerability tests.

These send crafted (but non-destructive) inputs to parameters and forms on a
target the user has *verified they own*, then analyse the response. No data is
modified, no brute force, no DoS — the payloads only read/reflect.

Covered: reflected XSS (HTML injection), error-based SQL injection, open redirect,
and path traversal / local file inclusion.
"""

from __future__ import annotations

import re
import secrets
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from .checks import Finding
from .crawler import Form

# ---- signatures ----------------------------------------------------------

SQL_ERRORS = [
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"mysql_fetch",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"pg_query\(\)|postgresql.*error|pg::syntaxerror",
    r"ora-\d{5}",
    r"sqlite3?::|sqlite_error|near \".*\": syntax error",
    r"microsoft ole db provider for sql server",
    r"odbc sql server driver",
    r"sqlstate\[",
]
SQL_RE = re.compile("|".join(SQL_ERRORS), re.IGNORECASE)

PASSWD_RE = re.compile(r"root:.*:0:0:")
WIN_INI_RE = re.compile(r"\[(fonts|extensions|mci extensions)\]", re.IGNORECASE)

REDIRECT_HINT_PARAMS = {"url", "redirect", "redirect_url", "next", "return", "returnurl",
                        "return_url", "dest", "destination", "continue", "goto", "r", "u"}

TRAVERSAL_PAYLOADS = ["../../../../../../../../etc/passwd", "....//....//....//etc/passwd",
                      "..\\..\\..\\..\\..\\..\\windows\\win.ini"]

# Command injection: arithmetic output (191*7=1337) proves execution, not mere
# reflection (the literal payload never contains "1337").
CMDI_PAYLOADS = [
    ";echo sfci$((191*7))", "|echo sfci$((191*7))", "&&echo sfci$((191*7))",
    "`echo sfci$((191*7))`", "$(echo sfci$((191*7)))", "& set /a 191*7",
]
NOSQL_ERRORS = re.compile(
    r"(mongoerror|mongodb|bson|casterror|couchdberror|\$where|unexpected token '\$'|"
    r"e11000|failed to parse)", re.IGNORECASE)

# SSRF probes: (payload URL, signature that proves the server fetched it)
SSRF_PROBES = [
    ("http://169.254.169.254/latest/meta-data/", re.compile(r"ami-id|instance-id|iam/|placement/|hostname", re.I)),
    ("http://metadata.google.internal/computeMetadata/v1/", re.compile(r"computeMetadata|project-id|instance/", re.I)),
    ("file:///etc/passwd", re.compile(r"root:.*:0:0:")),
]

# Stack-trace / verbose-error signatures (A10 Mishandling of Exceptional Conditions).
STACKTRACE_RE = re.compile(
    r"(traceback \(most recent call last\)|exception in thread|"
    r"at [\w.$]+\([\w.]+\.java:\d+\)|php (fatal|warning|parse) error|"
    r"system\.\w+exception|org\.springframework|werkzeug\.exceptions|"
    r"stack trace:|<b>fatal error</b>)",
    re.IGNORECASE,
)


def _with_param(url: str, name: str, value: str) -> str:
    parts = urlparse(url)
    qs = parse_qs(parts.query, keep_blank_values=True)
    qs[name] = [value]
    new_q = urlencode({k: v[0] for k, v in qs.items()})
    return urlunparse(parts._replace(query=new_q))


def _get(client: httpx.Client, url: str, allow_redirects: bool = True):
    try:
        return client.get(url, follow_redirects=allow_redirects)
    except httpx.HTTPError:
        return None


# ---- individual tests ----------------------------------------------------

def _xss(client: httpx.Client, url: str, param: str) -> Finding | None:
    token = secrets.token_hex(4)
    marker = f"sfx{token}"
    payload = f'"><{marker}>'
    r = _get(client, _with_param(url, param, payload))
    if r is None:
        return None
    # The raw, un-encoded marker tag appearing in the body means HTML injection.
    if f"<{marker}>" in r.text:
        return Finding(
            check_id=f"xss-reflected-{param}", title="Reflected Cross-Site Scripting (XSS)",
            severity="high", url=_with_param(url, param, payload),
            description=f"Input in the '{param}' parameter is reflected into the HTML response without encoding.",
            impact="An attacker can inject scripts that run in victims' browsers to steal sessions or data.",
            evidence=f"Injected '{payload}' and the raw tag <{marker}> was reflected unescaped.",
            remediation="Context-aware output encoding for all user input; add a strict Content-Security-Policy.",
            compliance_ref="OWASP A03:2021",
        )
    return None


def _sqli(client: httpx.Client, url: str, param: str, baseline: str | None) -> Finding | None:
    r = _get(client, _with_param(url, param, "'"))
    if r is None:
        return None
    if SQL_RE.search(r.text) and (baseline is None or not SQL_RE.search(baseline)):
        m = SQL_RE.search(r.text)
        return Finding(
            check_id=f"sqli-{param}", title="SQL Injection", severity="critical",
            url=_with_param(url, param, "'"),
            description=f"A database error is triggered by injecting a quote into the '{param}' parameter.",
            impact="SQL injection can expose or modify the entire database, including credentials.",
            evidence=f"Error signature returned: '{m.group(0)[:80]}'",
            remediation="Use parameterised queries / prepared statements; never concatenate user input into SQL.",
            compliance_ref="OWASP A03:2021",
        )
    return None


def _open_redirect(client: httpx.Client, url: str, param: str) -> Finding | None:
    evil = "https://evil.example.com/"
    r = _get(client, _with_param(url, param, evil), allow_redirects=False)
    if r is None:
        return None
    loc = r.headers.get("location", "")
    if r.status_code in (301, 302, 303, 307, 308) and loc.startswith("https://evil.example.com"):
        return Finding(
            check_id=f"open-redirect-{param}", title="Open Redirect", severity="medium",
            url=_with_param(url, param, evil),
            description=f"The '{param}' parameter redirects to an arbitrary external URL.",
            impact="Attackers use open redirects for convincing phishing links that appear to originate from your domain.",
            evidence=f"Set {param}={evil} → HTTP {r.status_code}, Location: {loc[:80]}",
            remediation="Allow-list permitted redirect destinations; reject absolute external URLs.",
            compliance_ref="OWASP A01:2021",
        )
    return None


def _ssti(client: httpx.Client, url: str, param: str) -> Finding | None:
    # Unique arithmetic (7*191=1337) is unlikely to appear by coincidence.
    for payload, expect in (("{{7*191}}", "1337"), ("${7*191}", "1337"), ("#{7*191}", "1337")):
        r = _get(client, _with_param(url, param, payload))
        if r is None:
            continue
        if expect in r.text and payload not in r.text:
            return Finding(
                check_id=f"ssti-{param}", title="Server-Side Template Injection (SSTI)",
                severity="critical", url=_with_param(url, param, payload),
                description=f"The '{param}' parameter is evaluated by a server-side template engine.",
                impact="SSTI often leads to remote code execution on the server.",
                evidence=f"Injected '{payload}' and the server returned the evaluated result '{expect}'.",
                remediation="Never render user input as a template; use a sandboxed engine and static templates.",
                compliance_ref="OWASP A05:2025",
            )
    return None


def _crlf(client: httpx.Client, url: str, param: str) -> Finding | None:
    payload = "sf%0d%0aX-SF-Injected:%20sfcrlf"
    # Some stacks decode the value into a header — check the RESPONSE headers.
    r = _get(client, _with_param(url, param, payload), allow_redirects=False)
    if r is None:
        return None
    if r.headers.get("x-sf-injected", "").strip() == "sfcrlf":
        return Finding(
            check_id=f"crlf-{param}", title="HTTP Response Splitting (CRLF Injection)",
            severity="high", url=_with_param(url, param, payload),
            description=f"CRLF characters in the '{param}' parameter inject new response headers.",
            impact="Attackers can set cookies, poison caches, or split responses.",
            evidence="Injected CRLF produced header 'X-SF-Injected: sfcrlf' in the response.",
            remediation="Strip CR/LF from any user input placed into response headers.",
            compliance_ref="OWASP A05:2025",
        )
    return None


def _traversal(client: httpx.Client, url: str, param: str) -> Finding | None:
    for payload in TRAVERSAL_PAYLOADS:
        r = _get(client, _with_param(url, param, payload))
        if r is None:
            continue
        if PASSWD_RE.search(r.text) or WIN_INI_RE.search(r.text):
            return Finding(
                check_id=f"path-traversal-{param}", title="Path Traversal / Local File Inclusion",
                severity="high", url=_with_param(url, param, payload),
                description=f"The '{param}' parameter can read files outside the web root.",
                impact="Attackers can read sensitive files (config, credentials, source) from the server.",
                evidence=f"Payload '{payload}' returned OS file contents.",
                remediation="Never pass user input to file paths; canonicalise and allow-list, or use opaque IDs.",
                compliance_ref="OWASP A01:2021",
            )
    return None


def _cmdi(client: httpx.Client, url: str, param: str) -> Finding | None:
    # "1337" only appears if the shell evaluated 191*7 — not from reflecting the payload.
    for payload in CMDI_PAYLOADS:
        r = _get(client, _with_param(url, param, payload))
        if r is None:
            continue
        if "sfci1337" in r.text or ("1337" in r.text and "191" not in r.text and payload not in r.text):
            return Finding(
                check_id=f"cmdi-{param}", title="OS Command Injection", severity="critical",
                url=_with_param(url, param, payload),
                description=f"The '{param}' parameter is passed to a system shell.",
                impact="Command injection gives an attacker arbitrary command execution on the server.",
                evidence=f"Injected '{payload}' and the shell evaluated 191*7 → 1337 in the response.",
                remediation="Never pass user input to a shell; use parameterised APIs and strict allow-lists.",
                compliance_ref="OWASP A05:2025",
            )
    return None


def _ssrf(client: httpx.Client, url: str, param: str) -> Finding | None:
    for payload, sig in SSRF_PROBES:
        r = _get(client, _with_param(url, param, payload))
        if r is None:
            continue
        if sig.search(r.text):
            return Finding(
                check_id=f"ssrf-{param}", title="Server-Side Request Forgery (SSRF)",
                severity="high", url=_with_param(url, param, payload),
                description=f"The '{param}' parameter makes the server fetch an attacker-controlled URL.",
                impact="SSRF can reach internal services and cloud metadata to steal credentials.",
                evidence=f"Injected '{payload}' and the response contained internal/metadata content.",
                remediation="Allow-list outbound hosts; block internal ranges and cloud metadata IPs.",
                compliance_ref="OWASP A01:2025",
            )
    return None


def _nosql(client: httpx.Client, url: str, param: str, baseline: str | None) -> Finding | None:
    for payload in ('"', "'\"", "[$ne]", "';return true;var x='"):
        r = _get(client, _with_param(url, param, payload))
        if r is None:
            continue
        if NOSQL_ERRORS.search(r.text) and (baseline is None or not NOSQL_ERRORS.search(baseline)):
            m = NOSQL_ERRORS.search(r.text)
            return Finding(
                check_id=f"nosqli-{param}", title="NoSQL Injection", severity="high",
                url=_with_param(url, param, payload),
                description=f"A NoSQL database error is triggered via the '{param}' parameter.",
                impact="NoSQL injection can bypass authentication or expose/modify database records.",
                evidence=f"Error signature: '{m.group(0)[:80]}'",
                remediation="Validate and type-cast input; use safe query builders, never raw operators from input.",
                compliance_ref="OWASP A05:2025",
            )
    return None


# ---- orchestration -------------------------------------------------------

def test_param_url(client: httpx.Client, url: str) -> list[Finding]:
    params = list(parse_qs(urlparse(url).query, keep_blank_values=True).keys())
    if not params:
        return []
    baseline_resp = _get(client, url)
    baseline = baseline_resp.text if baseline_resp is not None else None

    findings: list[Finding] = []
    saw_stacktrace = False
    baseline_tests = (_sqli, _nosql)  # these compare against the baseline response
    for p in params:
        for test in (_xss, _sqli, _open_redirect, _traversal, _ssti, _crlf, _cmdi, _ssrf, _nosql):
            try:
                f = test(client, url, p, baseline) if test in baseline_tests else test(client, url, p)
            except httpx.HTTPError:
                continue
            if f:
                findings.append(f)
        # Verbose-error / stack-trace disclosure (A10) — probe with a malformed value.
        if not saw_stacktrace:
            r = _get(client, _with_param(url, p, "sf'\"<>{{"))
            if r is not None and STACKTRACE_RE.search(r.text) and (baseline is None or not STACKTRACE_RE.search(baseline)):
                saw_stacktrace = True
                findings.append(Finding(
                    check_id="verbose-error", title="Verbose error / stack trace disclosure",
                    severity="low", url=url,
                    description="The application returns internal stack traces on malformed input.",
                    impact="Stack traces reveal frameworks, file paths and logic that aid further attacks.",
                    evidence="A server stack trace was returned in the response body.",
                    remediation="Return generic error pages; log details server-side only.",
                    compliance_ref="OWASP A10:2025",
                ))
    return findings


_XXE_PAYLOAD = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<!DOCTYPE sf [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>\n'
    "<sf>&xxe;</sf>"
)
_XXE_HINT = re.compile(r"/(api|xml|soap|rpc|service|feed|upload|import|ws)\b", re.I)


def test_xxe(client: httpx.Client, base_url: str, param_urls: list[str], max_urls: int = 6) -> list[Finding]:
    """Send an in-band XXE payload to XML-ish endpoints; flag if a local file leaks."""
    targets = [base_url] + [u for u in param_urls if _XXE_HINT.search(urlparse(u).path)]
    seen: set[str] = set()
    findings: list[Finding] = []
    for url in targets[:max_urls]:
        base = url.split("?")[0]
        if base in seen:
            continue
        seen.add(base)
        try:
            r = client.post(base, content=_XXE_PAYLOAD.encode(),
                            headers={"Content-Type": "application/xml"})
        except httpx.HTTPError:
            continue
        if r is not None and PASSWD_RE.search(r.text):
            findings.append(Finding(
                check_id="xxe", title="XML External Entity (XXE) Injection", severity="high", url=base,
                description="The endpoint parses XML with external entities enabled and returns local file contents.",
                impact="Attackers can read server files, and XXE can escalate to SSRF or denial of service.",
                evidence="An XXE payload referencing file:///etc/passwd returned OS file contents.",
                remediation="Disable external entities and DTD processing in the XML parser.",
                compliance_ref="OWASP A05:2025",
            ))
            break
    return findings


def test_host_header(client: httpx.Client, base_url: str) -> list[Finding]:
    """Detect Host header injection — a poisoned Host reflected into the page."""
    try:
        r = client.get(base_url, headers={"Host": "evil.sf-test.example"}, follow_redirects=False)
    except httpx.HTTPError:
        return []
    loc = r.headers.get("location", "")
    if "evil.sf-test.example" in loc or "evil.sf-test.example" in r.text:
        return [Finding(
            check_id="host-header-injection", title="Host Header Injection",
            severity="medium", url=base_url,
            description="A user-supplied Host header is reflected into responses or redirects.",
            impact="Enables password-reset poisoning, cache poisoning and phishing.",
            evidence="Injected Host 'evil.sf-test.example' was reflected back.",
            remediation="Validate the Host header against an allow-list of expected hostnames.",
            compliance_ref="OWASP A05:2025",
        )]
    return []


def test_form(client: httpx.Client, form: Form) -> list[Finding]:
    """Probe a form by injecting into each field (GET forms only for safety)."""
    if form.method != "get" or not form.inputs:
        return []
    # Represent the form as a param URL and reuse the URL tester.
    from urllib.parse import urlencode as _ue
    base = form.action + ("&" if urlparse(form.action).query else "?") + _ue({n: "test" for n in form.inputs})
    return test_param_url(client, base)


def run_active_tests(client: httpx.Client, param_urls: list[str], forms: list[Form],
                     max_urls: int = 15, max_forms: int = 10) -> list[Finding]:
    findings: list[Finding] = []
    for url in param_urls[:max_urls]:
        findings.extend(test_param_url(client, url))
    for form in forms[:max_forms]:
        findings.extend(test_form(client, form))
    # De-dupe by (check_id, url)
    seen = set()
    unique = []
    for f in findings:
        key = (f.check_id, f.url)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique
