"""Safe (non-destructive) denial-of-service detection.

DoS bugs are about resource exhaustion, so the naive test *is* the attack. Instead
we send bounded canaries that reveal the vulnerability's presence without exhausting
anything:

- **ReDoS**: send short → longer inputs (bounded) and watch for *exponential* timing
  growth. A vulnerable regex reveals its catastrophic backtracking well before the
  input is big enough to actually hang the server, and every request has a timeout.
- **XML entity expansion (billion laughs)**: send a tiny "small laughs" payload that
  expands to ~1000 chars (not billions). If the parser expands it at all, it is
  vulnerable to the full attack — detected without the damage.
"""

from __future__ import annotations

import time
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from .checks import Finding

# Bounded input lengths — 2^28 backtracks is a brief, recoverable CPU blip, not a crash.
_REDOS_LENGTHS = (14, 21, 28)
_REQ_TIMEOUT = 8.0

# "small laughs": 10^3 = 1000 chars of expansion — enough to prove entity expansion is on.
_SMALL_LAUGHS = (
    '<?xml version="1.0"?>\n'
    '<!DOCTYPE sf [\n'
    '  <!ENTITY a "aaaaaaaaaa">\n'
    '  <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">\n'
    '  <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">\n'
    ']>\n<sf>&c;</sf>'
)
_CONTROL_XML = '<?xml version="1.0"?><sf>ok</sf>'


def _with_param(url: str, name: str, value: str) -> str:
    parts = urlparse(url)
    qs = parse_qs(parts.query, keep_blank_values=True)
    qs[name] = [value]
    return urlunparse(parts._replace(query=urlencode({k: v[0] for k, v in qs.items()})))


def _timed_get(client: httpx.Client, url: str) -> float | None:
    start = time.time()
    try:
        client.get(url, timeout=_REQ_TIMEOUT)
    except httpx.TimeoutException:
        return _REQ_TIMEOUT  # treated as "hung" (bounded by the timeout)
    except httpx.HTTPError:
        return None
    return time.time() - start


def test_redos(client: httpx.Client, param_urls: list[str], max_urls: int = 6) -> list[Finding]:
    for url in param_urls[:max_urls]:
        for pname in parse_qs(urlparse(url).query):
            times: dict[int, float] = {}
            for n in _REDOS_LENGTHS:
                t = _timed_get(client, _with_param(url, pname, "a" * n + "!"))
                if t is None:
                    break
                times[n] = t
            if len(times) != len(_REDOS_LENGTHS):
                continue
            lo, mid, hi = (times[k] for k in _REDOS_LENGTHS)
            # Exponential (not linear) growth + a clear absolute delay at the top.
            if hi >= 2.0 and hi > 3 * mid + 0.3 and mid >= lo:
                return [Finding(
                    check_id=f"redos-{pname}", title="Regular Expression Denial of Service (ReDoS)",
                    severity="medium", url=_with_param(url, pname, "a" * 28 + "!"),
                    description=f"Response time for the '{pname}' parameter grows exponentially with input length.",
                    impact="A short crafted string can pin a CPU for minutes, taking the service down (DoS).",
                    evidence=f"Timing grew {lo:.2f}s -> {mid:.2f}s -> {hi:.2f}s for inputs of {_REDOS_LENGTHS} chars.",
                    remediation="Fix the vulnerable regex (avoid nested quantifiers) or use a linear-time engine (RE2).",
                    compliance_ref="OWASP A06:2025",
                )]
    return []


def test_xml_expansion(client: httpx.Client, base_url: str, param_urls: list[str]) -> list[Finding]:
    from .active import _XXE_HINT  # reuse the XML-ish endpoint hint

    targets = [base_url] + [u for u in param_urls if _XXE_HINT.search(urlparse(u).path)]
    seen: set[str] = set()
    for url in targets[:5]:
        base = url.split("?")[0]
        if base in seen:
            continue
        seen.add(base)
        hdr = {"Content-Type": "application/xml"}
        try:
            start = time.time()
            r = client.post(base, content=_SMALL_LAUGHS.encode(), headers=hdr, timeout=_REQ_TIMEOUT)
            elapsed = time.time() - start
            ctrl = client.post(base, content=_CONTROL_XML.encode(), headers=hdr, timeout=_REQ_TIMEOUT)
        except httpx.HTTPError:
            continue
        expanded = "aaaaaaaaaa" * 3 in r.text  # the 1000-char expansion was reflected
        much_slower = elapsed > 1.0 and (ctrl is None or elapsed > 4 * ((time.time() - start) or 0.01))
        if r.status_code < 500 and (expanded or much_slower):
            return [Finding(
                "xml-entity-expansion", "XML entity expansion (billion-laughs) enabled", "medium", base,
                description="The XML parser expands internal entities, so it is vulnerable to entity-expansion DoS.",
                impact="A tiny 'billion laughs' document can exhaust server memory/CPU and crash the service.",
                evidence="A bounded 'small laughs' payload was expanded by the parser.",
                remediation="Disable DTD/entity expansion in the XML parser (secure-processing feature).",
                compliance_ref="OWASP A05:2025",
            )]
    return []
