"""Login-endpoint checks: missing brute-force protection and user enumeration.

Both need a login form, which we detect by field names. Requests are bounded
(a handful of failed logins) and only run against the user's own verified target.
"""

from __future__ import annotations

import difflib

import httpx

from .checks import Finding
from .crawler import Form

_USER_FIELDS = {"username", "user", "email", "login", "user_login", "userid", "user_name", "j_username"}
_PASS_FIELDS = {"password", "passwd", "pass", "pwd", "j_password"}
_LOCK_HINT = ("captcha", "too many", "locked", "rate limit", "try again later", "blocked")


def _login_form(forms: list[Form]) -> Form | None:
    for f in forms:
        names = {n.lower() for n in f.inputs}
        if names & _PASS_FIELDS and names & _USER_FIELDS:
            return f
    return None


def _submit(client: httpx.Client, form: Form, user: str, pw: str):
    data = {n: "x" for n in form.inputs}
    for n in form.inputs:
        ln = n.lower()
        if ln in _USER_FIELDS:
            data[n] = user
        elif ln in _PASS_FIELDS:
            data[n] = pw
    try:
        if form.method == "post":
            return client.post(form.action, data=data)
        return client.get(form.action, params=data)
    except httpx.HTTPError:
        return None


def run_auth_tests(client: httpx.Client, forms: list[Form], host: str) -> list[Finding]:
    form = _login_form(forms)
    if form is None:
        return []
    findings: list[Finding] = []

    # 1. Brute-force protection: several rapid failed logins.
    codes, bodies = [], []
    for i in range(7):
        r = _submit(client, form, f"sfuser{i}@{host}", "wrongpass123")
        if r is None:
            break
        codes.append(r.status_code)
        bodies.append(r.text.lower())
    blocked = any(c == 429 for c in codes) or any(any(h in b for h in _LOCK_HINT) for b in bodies[2:])
    if codes and not blocked:
        findings.append(Finding(
            "no-brute-force-protection", "No brute-force protection on login", "medium", form.action,
            description="Multiple rapid failed logins were accepted with no rate limiting, lockout or CAPTCHA.",
            impact="Attackers can brute-force or credential-stuff accounts without being slowed down.",
            evidence=f"{len(codes)} rapid failed logins, none rate-limited (no 429/lockout/CAPTCHA).",
            remediation="Add rate limiting, account lockout/backoff, and CAPTCHA after repeated failures.",
            compliance_ref="OWASP A07:2025",
        ))

    # 2. User enumeration: compare a likely-valid vs a clearly-invalid username.
    r_valid = _submit(client, form, f"admin@{host}", "wrongpass123")
    r_bogus = _submit(client, form, "sf-nonexistent-9zx@invalid.example", "wrongpass123")
    if r_valid is not None and r_bogus is not None and r_valid.status_code == r_bogus.status_code:
        ratio = difflib.SequenceMatcher(None, r_valid.text[:3000], r_bogus.text[:3000]).ratio()
        if ratio < 0.92:
            findings.append(Finding(
                "user-enumeration", "Username enumeration on login", "medium", form.action,
                description="The login response differs for existing vs non-existing usernames.",
                impact="Attackers can discover valid accounts to target with password attacks.",
                evidence=f"Responses for a valid-looking vs bogus username differ (similarity {ratio:.0%}).",
                remediation="Return an identical, generic error for any failed login.",
                compliance_ref="OWASP A07:2025",
            ))
    return findings
