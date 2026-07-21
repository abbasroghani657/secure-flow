"""Automating parts of "manual" testing with clever logic.

These are heuristic, black-box automations of classes usually left to a human
pentester. They are honest about confidence — findings are "potential" and worth
manual confirmation, because a scanner can't know the application's *intended*
business rules the way a person can.

- Parameter tampering: feed numeric fields negative / zero / huge values and see
  if the server accepts them without validation (price/quantity abuse).
- Race conditions: fire many identical requests at an "action" endpoint at once
  and see if a single-use action succeeds repeatedly.
"""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from .checks import Finding

# Params that carry an amount/quantity where business rules usually apply.
_NUMERIC_PARAM = re.compile(
    r"^(price|amount|qty|quantity|total|cost|balance|discount|credit|points|sum|"
    r"fee|value|salary|limit|budget|stock|count)s?$", re.I)
# Endpoints whose action is typically meant to happen once per user.
_ACTION_HINT = re.compile(
    r"(redeem|claim|apply|coupon|promo|voucher|transfer|withdraw|vote|like|follow|"
    r"purchase|checkout|order|book|reserve|register|signup|invite|gift|reward)", re.I)
_VALIDATION_ERROR = re.compile(
    r"(invalid|not allowed|must be|too (large|small|high|low)|out of range|"
    r"negative|error|reject|forbidden|cannot be)", re.I)


def _with_param(url: str, name: str, value: str) -> str:
    parts = urlparse(url)
    qs = parse_qs(parts.query, keep_blank_values=True)
    qs[name] = [value]
    return urlunparse(parts._replace(query=urlencode({k: v[0] for k, v in qs.items()})))


def test_parameter_tampering(client: httpx.Client, param_urls: list[str], max_urls: int = 12) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()
    for url in param_urls[:max_urls]:
        for pname in parse_qs(urlparse(url).query):
            if not _NUMERIC_PARAM.match(pname) or pname in seen:
                continue
            seen.add(pname)
            try:
                r = client.get(_with_param(url, pname, "-1"))
            except httpx.HTTPError:
                continue
            # Accepted if it returns 200, echoes the negative value, and shows no validation error.
            if r.status_code == 200 and "-1" in r.text and not _VALIDATION_ERROR.search(r.text):
                findings.append(Finding(
                    check_id=f"business-logic-{pname}", title="Potential business-logic flaw (parameter tampering)",
                    severity="medium", url=_with_param(url, pname, "-1"),
                    description=f"A negative value in the '{pname}' parameter was accepted without a validation error.",
                    impact="Negative prices/quantities can let attackers pay less, refund themselves, or abuse limits.",
                    evidence=f"Set {pname}=-1 → HTTP 200 with the value reflected and no validation error.",
                    remediation="Enforce server-side business rules (non-negative, min/max, ownership) on every value.",
                    compliance_ref="OWASP A04:2025",
                ))
                break  # one per URL is enough
    return findings


def test_race_condition(client: httpx.Client, action_urls: list[str], parallel: int = 15,
                        max_urls: int = 4) -> list[Finding]:
    findings: list[Finding] = []
    candidates = [u for u in action_urls if _ACTION_HINT.search(u)][:max_urls]
    for url in candidates:
        def _fire(_):
            try:
                r = client.get(url)
                return r.status_code
            except httpx.HTTPError:
                return None
        with ThreadPoolExecutor(max_workers=parallel) as ex:
            codes = list(ex.map(_fire, range(parallel)))
        ok = sum(1 for c in codes if c == 200)
        # A single-use action that succeeds on (almost) every concurrent hit hints at
        # missing locking / idempotency — a race-condition candidate.
        if ok >= parallel - 1 and any(c in (409, 429) for c in codes) is False:
            findings.append(Finding(
                check_id="race-condition", title="Potential race condition (no request throttling/locking)",
                severity="low", url=url,
                description="An action-style endpoint accepted many simultaneous identical requests, all succeeding.",
                impact="Without locking/idempotency, attackers can double-spend, redeem coupons repeatedly, or over-book.",
                evidence=f"{ok}/{parallel} concurrent requests to {urlparse(url).path} returned 200.",
                remediation="Add idempotency keys, row locks or rate limits to single-use actions.",
                compliance_ref="OWASP A04:2025",
            ))
    return findings


def run_logic_tests(client: httpx.Client, param_urls: list[str], pages: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(test_parameter_tampering(client, param_urls))
    findings.extend(test_race_condition(client, param_urls + pages))
    return findings
