"""Static detection of DOM-based XSS.

httpx does not execute JavaScript, so we can't taint-trace at runtime. Instead we
statically scan the page's inline and same-origin scripts for a **source** that
flows into a dangerous **sink** in the same statement — e.g. ``el.innerHTML =
location.hash`` or ``document.write(location.search)``. This is a heuristic
("potential DOM XSS"), so findings are medium severity and worth manual review.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

import httpx

from .checks import Finding

# A user-controlled source appearing right inside a dangerous sink on one statement.
_SINK_SOURCE_RE = re.compile(
    r"(?P<sink>\.innerHTML|\.outerHTML|document\.write(?:ln)?|\.insertAdjacentHTML|"
    r"\beval|\bnew\s+Function|\.html\s*\()\s*[=(]?[^;\n{}]{0,160}?"
    r"(?P<source>location\s*\.\s*(?:hash|search|href|pathname)|"
    r"document\s*\.\s*(?:URL|documentURI|referrer|cookie)|window\s*\.\s*name|\blocation\b)",
    re.IGNORECASE,
)

_INLINE_SCRIPT_RE = re.compile(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", re.IGNORECASE | re.DOTALL)
_SCRIPT_SRC_RE = re.compile(r"<script[^>]*\bsrc=[\"']([^\"']+)[\"']", re.IGNORECASE)


def scan_js_for_dom_xss(code: str, url: str) -> Finding | None:
    m = _SINK_SOURCE_RE.search(code or "")
    if not m:
        return None
    snippet = re.sub(r"\s+", " ", m.group(0)).strip()[:140]
    return Finding(
        check_id="dom-xss", title="Potential DOM-based XSS", severity="medium", url=url,
        description="A user-controllable source (URL/location/referrer) flows into a dangerous DOM sink in client-side JavaScript.",
        impact="If the source reaches the sink unsanitised, an attacker can run script in the victim's browser.",
        evidence=f"{m.group('source')} → {m.group('sink')}: …{snippet}…",
        remediation="Never pass URL/location data to innerHTML/eval/document.write; use textContent or a sanitiser (DOMPurify).",
        compliance_ref="OWASP A03:2021",
    )


def check_dom_xss(client: httpx.Client, probe) -> list[Finding]:
    html = getattr(probe, "body_snippet", "") or ""
    base = probe.final_url
    host = urlparse(base).hostname

    # 1. Inline scripts
    for code in _INLINE_SCRIPT_RE.findall(html):
        f = scan_js_for_dom_xss(code, base)
        if f:
            return [f]  # one representative finding is enough

    # 2. A few same-origin external scripts
    checked = 0
    for src in _SCRIPT_SRC_RE.findall(html):
        if checked >= 5:
            break
        js_url = urljoin(base, src)
        if urlparse(js_url).hostname != host:
            continue  # only analyse first-party JS
        checked += 1
        try:
            r = client.get(js_url)
        except httpx.HTTPError:
            continue
        if "javascript" in r.headers.get("content-type", "") or js_url.endswith(".js"):
            f = scan_js_for_dom_xss(r.text, js_url)
            if f:
                return [f]
    return []
