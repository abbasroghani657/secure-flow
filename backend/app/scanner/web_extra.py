"""Additional black-box web checks: secrets in JS, JWT weaknesses, open Firebase,
and client-side (postMessage / storage / JSONP / prototype-pollution) heuristics."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from urllib.parse import urljoin, urlparse

import httpx

from .checks import Finding

_SCRIPT_SRC_RE = re.compile(r"<script[^>]*\bsrc=[\"']([^\"']+)[\"']", re.I)
_INLINE_RE = re.compile(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", re.I | re.S)

# (label, regex, severity). Secret keys that must never ship in front-end code are
# HIGH; Google API keys are often legitimately public (Maps/Firebase) so LOW.
_SECRET_PATTERNS = [
    ("AWS access key", re.compile(r"AKIA[0-9A-Z]{16}"), "critical"),
    ("Stripe secret key", re.compile(r"sk_live_[0-9A-Za-z]{20,}"), "critical"),
    ("Private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), "critical"),
    ("Slack token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}"), "high"),
    ("Generic hardcoded secret", re.compile(r"(?i)(?:api[_-]?key|secret|access[_-]?token|auth[_-]?token|password)['\"]?\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]"), "high"),
    ("Google API key (verify it is restricted)", re.compile(r"AIza[0-9A-Za-z_\-]{35}"), "low"),
]

# Third segment may be empty (alg=none tokens are header.payload.)
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]{5,}\.eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]*")
_WEAK_JWT_SECRETS = ["secret", "password", "123456", "changeme", "jwt", "jwtsecret",
                     "jwt_secret", "key", "secretkey", "admin", "test", "your-256-bit-secret"]

_STORAGE_SECRET_RE = re.compile(
    r"(?:local|session)Storage\.setItem\(\s*['\"][^'\"]*(?:token|password|secret|jwt|api[_-]?key|auth)[^'\"]*['\"]",
    re.I)
_POSTMSG_RE = re.compile(r"addEventListener\(\s*['\"]message['\"]", re.I)
_ORIGIN_CHECK_RE = re.compile(r"\.origin\s*[=!]==?|\borigin\s*===", re.I)
_JSONP_RE = re.compile(r"[?&](callback|jsonp|cb)=", re.I)
_PROTO_RE = re.compile(r"\[\s*['\"]__proto__['\"]\s*\]|\.__proto__\s*=|constructor\s*\[\s*['\"]prototype['\"]")


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _gather_js(client: httpx.Client, probe) -> list[tuple[str, str]]:
    """Return (label, code) for inline scripts and a few first-party external scripts."""
    html = getattr(probe, "body_snippet", "") or ""
    base, host = probe.final_url, urlparse(probe.final_url).hostname
    blobs: list[tuple[str, str]] = [("inline script", c) for c in _INLINE_RE.findall(html)]
    fetched = 0
    for src in _SCRIPT_SRC_RE.findall(html):
        if fetched >= 6:
            break
        u = urljoin(base, src)
        if urlparse(u).hostname != host:
            continue
        fetched += 1
        try:
            r = client.get(u)
            blobs.append((u, r.text))
        except httpx.HTTPError:
            continue
    return blobs


def check_js_secrets(blobs: list[tuple[str, str]], base_url: str) -> list[Finding]:
    out: list[Finding] = []
    seen: set[str] = set()
    for label, code in blobs:
        for name, rx, sev in _SECRET_PATTERNS:
            m = rx.search(code)
            if m and name not in seen:
                seen.add(name)
                out.append(Finding(
                    f"js-secret-{name.lower().split(' ')[0]}", f"Secret in JavaScript: {name}", sev, base_url,
                    description=f"A {name} appears in front-end JavaScript ({label}).",
                    impact="Anything in client-side JS is public; embedded secrets can be extracted and abused.",
                    evidence=f"Matched: {m.group(0)[:32]}…",
                    remediation="Move secrets server-side; for public keys, restrict them by referrer/API/scope.",
                    compliance_ref="OWASP A05:2021",
                ))
    return out


def check_jwt(probe) -> list[Finding]:
    blob = (getattr(probe, "body_snippet", "") or "")
    for v in (getattr(probe, "set_cookies", []) or []):
        blob += " " + v
    for raw in dict.fromkeys(_JWT_RE.findall(blob)):
        parts = raw.split(".")
        try:
            header = json.loads(_b64url_decode(parts[0]))
        except Exception:  # noqa: BLE001
            continue
        alg = str(header.get("alg", "")).lower()
        if alg == "none":
            return [Finding("jwt-alg-none", "JWT accepts 'none' algorithm", "high", probe.final_url,
                            description="A JWT uses alg=none, meaning it is unsigned.",
                            impact="Anyone can forge tokens and impersonate any user.",
                            evidence="JWT header alg=none", remediation="Reject 'none'; require a strong signature (RS256/HS256).",
                            compliance_ref="OWASP A07:2025")]
        if alg == "hs256":
            signing_input = f"{parts[0]}.{parts[1]}".encode()
            try:
                expected = parts[2]
                for secret in _WEAK_JWT_SECRETS:
                    sig = base64.urlsafe_b64encode(hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()).rstrip(b"=").decode()
                    if hmac.compare_digest(sig, expected):
                        return [Finding("jwt-weak-secret", "JWT signed with a weak secret", "critical", probe.final_url,
                                        description=f"The JWT's HMAC secret is a common weak value ('{secret}').",
                                        impact="A guessable secret lets an attacker forge valid tokens for any user.",
                                        evidence=f"Signature verified with secret '{secret}'",
                                        remediation="Use a long, random, secret (32+ bytes) stored securely.",
                                        compliance_ref="OWASP A07:2025")]
            except Exception:  # noqa: BLE001
                pass
    return []


def check_open_firebase(client: httpx.Client, probe) -> list[Finding]:
    html = getattr(probe, "body_snippet", "") or ""
    for db in dict.fromkeys(re.findall(r"https://([a-z0-9.\-]+\.firebaseio\.com)", html, re.I)):
        try:
            r = client.get(f"https://{db}/.json", timeout=8)
        except httpx.HTTPError:
            continue
        if r.status_code == 200 and "permission denied" not in r.text.lower() and r.text.strip() not in ("", "null"):
            return [Finding("open-firebase-db", "Publicly readable Firebase database", "high", f"https://{db}/.json",
                            description="The Firebase Realtime Database allows unauthenticated reads.",
                            impact="Anyone can read (often write) the entire database — a data breach.",
                            evidence=f"GET https://{db}/.json returned data without auth.",
                            remediation="Set Firebase security rules to require authentication.",
                            compliance_ref="OWASP A05:2021")]
    return []


def check_client_side(blobs: list[tuple[str, str]], base_url: str) -> list[Finding]:
    out: list[Finding] = []
    joined = "\n".join(code for _, code in blobs)
    if _POSTMSG_RE.search(joined) and not _ORIGIN_CHECK_RE.search(joined):
        out.append(Finding("postmessage-no-origin", "postMessage handler without origin check", "medium", base_url,
                           description="A window 'message' listener does not validate event.origin.",
                           impact="Any site can post messages the handler trusts, enabling data theft or DOM XSS.",
                           evidence="addEventListener('message', …) with no origin comparison.",
                           remediation="Always check event.origin against an allow-list in message handlers.",
                           compliance_ref="OWASP A08:2025"))
    if _STORAGE_SECRET_RE.search(joined):
        out.append(Finding("sensitive-web-storage", "Sensitive data in localStorage/sessionStorage", "low", base_url,
                           description="Tokens/passwords appear to be stored in web storage.",
                           impact="Web storage is readable by any script (and XSS), so tokens there are exposed.",
                           evidence="localStorage/sessionStorage.setItem with a token/secret-like key.",
                           remediation="Keep session tokens in HttpOnly cookies, not web storage.",
                           compliance_ref="OWASP A07:2025"))
    if _PROTO_RE.search(joined):
        out.append(Finding("prototype-pollution", "Potential prototype pollution", "low", base_url,
                           description="Client-side code manipulates __proto__/constructor.prototype.",
                           impact="Unsafe recursive merges with user input can pollute Object.prototype and lead to XSS/RCE.",
                           evidence="__proto__ / constructor.prototype assignment in JS.",
                           remediation="Avoid unsafe deep-merge on untrusted input; freeze prototypes / use Map.",
                           compliance_ref="OWASP A08:2025"))
    if _JSONP_RE.search(joined) or _JSONP_RE.search(base_url):
        out.append(Finding("insecure-jsonp", "Potential insecure JSONP endpoint", "low", base_url,
                           description="A JSONP-style callback parameter is used.",
                           impact="JSONP can leak data cross-origin and run attacker-controlled callbacks.",
                           evidence="callback/jsonp parameter detected.",
                           remediation="Replace JSONP with CORS; validate/whitelist callback names.",
                           compliance_ref="OWASP A05:2021"))
    return out


def run_web_extra(client: httpx.Client, probe) -> list[Finding]:
    findings: list[Finding] = []
    blobs = _gather_js(client, probe)
    findings.extend(check_js_secrets(blobs, probe.final_url))
    findings.extend(check_client_side(blobs, probe.final_url))
    findings.extend(check_jwt(probe))
    try:
        findings.extend(check_open_firebase(client, probe))
    except Exception:  # noqa: BLE001
        pass
    return findings
