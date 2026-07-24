"""Guided manual-test playbooks.

The highest-paying bug-bounty classes — business logic, race conditions,
account-takeover chains, OAuth/SSO abuse — cannot be reliably auto-confirmed by
any scanner. Rather than pretend (false confidence) or stay silent, SecureFlow
ships each as an info-severity advisory with a concrete, hands-on test recipe.
This is what turns the report from a scan into a teaching tool.
"""

from __future__ import annotations

from .checks import Finding

# (check_id, title, owasp, cwe, why-it-matters, hands-on test recipe)
_PLAYBOOKS = [
    ("playbook-business-logic", "Payment & business-logic manipulation", "A04:2025", "CWE-840",
     "Tampering with price/quantity/currency, negative values, coupon/gift-card stacking, refund abuse, and "
     "workflow-step bypass are among the highest-paying findings and are invisible to automated scanners.",
     "1) In checkout, intercept and set amount/currency/quantity to a negative, zero, or smaller value. "
     "2) Re-apply or stack the same coupon/gift-card several times. 3) Jump straight to the confirmation URL "
     "without paying. 4) Request a refund twice. 5) Reorder multi-step approval flows."),
    ("playbook-race-condition", "Race conditions (single-packet / TOCTOU)", "A04:2025", "CWE-362",
     "Modern race attacks (single-packet, HTTP/2) fire 20-30 requests at once to beat a check — re-redeeming "
     "gift-cards, withdrawing twice, overrunning OTP/MFA attempt limits, bypassing invite caps.",
     "Send the same state-changing request (redeem / withdraw / vote / apply-coupon) many times in parallel "
     "(Burp Turbo Intruder single-packet, or 20+ concurrent requests). If the limit is exceeded, it's a race. "
     "Target balances, quotas, one-time tokens, and MFA attempt counters."),
    ("playbook-account-takeover-chain", "Account-takeover chains", "A07:2025", "CWE-287",
     "The biggest payouts are chains: host-header password-reset poisoning, IDOR on the email/phone-change "
     "endpoint (no re-auth/OTP), reset-token leak via Referer, or CSRF on email change without confirmation.",
     "1) On password reset, set Host / X-Forwarded-Host to your domain and check the reset link. 2) Change "
     "another user's email/phone by ID without re-auth. 3) Check whether reset tokens leak in the Referer to "
     "third-party scripts. 4) Chain an open redirect with the OAuth redirect_uri to steal the code."),
    ("playbook-oauth-sso", "OAuth / OIDC / SSO takeover", "A07:2025", "CWE-287",
     "OAuth chains (authorization-code injection/theft, redirect_uri bypass, 'login with X' pre-account-"
     "takeover, IdP mix-up, PKCE downgrade) are a top-earning, nearly-invisible category.",
     "1) Tamper redirect_uri with path/param tricks (//evil.com, ?next=, #, @). 2) Register the victim's email "
     "before they sign up via social login. 3) Replay/inject an auth code across sessions. 4) Drop the PKCE "
     "code_challenge and see if it still works. 5) Swap the issuer / mix up the IdP."),
    ("playbook-web-cache", "Web cache poisoning & deception", "A05:2025", "CWE-524",
     "Cache poisoning (unkeyed headers/params) serves stored XSS/redirects to every user; cache deception "
     "stores a victim's authenticated page at a public URL — both are mass-impact.",
     "1) Add unkeyed headers (X-Forwarded-Host/Scheme, X-Original-URL) and check if a poisoned response is "
     "cached and served to others. 2) Append /nonexistent.css or ;.css to an authenticated page and see if "
     "the cache stores the personalised response at a public URL."),
    ("playbook-sspp", "Server-side prototype pollution (Node.js)", "A08:2025", "CWE-1321",
     "SSPP can lead to RCE, auth bypass, or DoS in Node.js and is far less known than the client-side variant. "
     "A scanner can hint at the surface; confirmation is manual.",
     "Send JSON with __proto__ / constructor.prototype keys (e.g. {\"__proto__\":{\"isAdmin\":true}}) or a "
     "polluting query string, then look for changed behaviour — new properties on unrelated objects, reflected "
     "gadget values, or altered authorization checks."),
    ("playbook-deserialization-gadgets", "Deserialization gadget chains", "A08:2025", "CWE-502",
     "The scanner flags deserialization signatures; the high-value part is confirming a gadget chain to RCE "
     "(Java ysoserial, .NET TypeNameHandling/ViewState, PHP POP/phar://, Python pickle, Ruby Marshal).",
     "Identify the format from the flagged blob, then attempt a benign gadget (e.g. ysoserial URLDNS for Java) "
     "that triggers a DNS/HTTP callback — proving code execution without causing damage."),
    ("playbook-ssrf-metadata", "SSRF → cloud metadata / internal RCE", "A01:2025", "CWE-918",
     "Blind SSRF to 169.254.169.254 (IMDSv1) yields temporary cloud credentials → account takeover (the "
     "Capital One breach). Also test alternate protocols and DNS-rebinding to bypass allow-lists.",
     "Point any URL / webhook / PDF-render / SVG / URL-preview parameter at http://169.254.169.254/latest/"
     "meta-data/ (and gopher://, dict://, file://). Use an OAST / DNS-rebinding host to bypass IP allow-lists "
     "and catch blind SSRF via out-of-band callbacks."),
    ("playbook-graphql-authz", "GraphQL authorization & batching abuse", "A01:2025", "CWE-285",
     "GraphQL is barely defended: resolver-level authorization bypass, alias/batching brute force (defeats "
     "rate limits on OTP/login), and field-suggestion schema harvesting.",
     "1) Send 100 aliased login/OTP mutations in one request to bypass rate limiting. 2) Query objects you "
     "shouldn't own to test resolver-level authz. 3) Use field suggestions + introspection to map the schema."),
]


def playbook_findings(url: str) -> list[Finding]:
    """Return the guided manual-test advisories for a web/deep scan."""
    out: list[Finding] = []
    for cid, title, owasp, cwe, why, recipe in _PLAYBOOKS:
        out.append(Finding(
            check_id=cid, title=f"Manual test recommended: {title}", severity="info", url=url,
            description=why,
            impact="High bug-bounty value; not reliably detectable by automated scanning — verify by hand.",
            evidence="Guided manual-review playbook — see remediation for the step-by-step test recipe.",
            remediation="How to test — " + recipe,
            compliance_ref=f"OWASP {owasp}",
            owasp=owasp, cwe=cwe, layer="backend",   # set directly so taxonomy keeps per-playbook mapping
        ))
    return out
