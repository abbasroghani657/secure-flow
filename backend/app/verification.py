"""Domain ownership verification.

Before a target can be scanned, the user must prove they control it via one of:

- **DNS**  — a TXT record on the host:  ``secureflow-verify=<token>``
- **meta** — a tag on the homepage:    ``<meta name="secureflow-verify" content="<token>">``
- **file** — a file at:                 ``/.well-known/secureflow-verify.txt`` containing the token

This is the same model reputable scanners (Search Console, Detectify) use, and it
is what makes running a scan legally defensible.
"""

from __future__ import annotations

import re
import secrets

import httpx

try:
    import dns.resolver

    _HAS_DNS = True
except ImportError:  # pragma: no cover
    _HAS_DNS = False

TOKEN_PREFIX = "secureflow-verify"
_META_RE = re.compile(
    r"""<meta[^>]+name=["']secureflow-verify["'][^>]+content=["']([^"']+)["']""",
    re.IGNORECASE,
)
_META_RE_REV = re.compile(
    r"""<meta[^>]+content=["']([^"']+)["'][^>]+name=["']secureflow-verify["']""",
    re.IGNORECASE,
)


def new_token() -> str:
    return secrets.token_hex(16)


def instructions(host: str, token: str) -> list[dict]:
    return [
        {
            "method": "dns",
            "title": "DNS TXT record",
            "detail": f"Add a TXT record to {host} with this value:",
            "value": f"{TOKEN_PREFIX}={token}",
        },
        {
            "method": "meta",
            "title": "HTML meta tag",
            "detail": "Add this tag inside the <head> of your homepage:",
            "value": f'<meta name="secureflow-verify" content="{token}">',
        },
        {
            "method": "file",
            "title": "Verification file",
            "detail": f"Upload a file at https://{host}/.well-known/secureflow-verify.txt containing:",
            "value": token,
        },
    ]


def _check_dns(host: str, token: str) -> bool:
    if not _HAS_DNS:
        return False
    target = f"{TOKEN_PREFIX}={token}"
    try:
        answers = dns.resolver.resolve(host, "TXT", lifetime=8)
    except Exception:
        return False
    for rdata in answers:
        txt = b"".join(rdata.strings).decode(errors="ignore") if hasattr(rdata, "strings") else str(rdata)
        if target in txt.strip().strip('"'):
            return True
    return False


def _check_meta(host: str, token: str) -> bool:
    for scheme in ("https", "http"):
        try:
            r = httpx.get(f"{scheme}://{host}/", timeout=10, follow_redirects=True,
                          headers={"User-Agent": "SecureFlow-Verifier/1.0"})
        except httpx.HTTPError:
            continue
        html = r.text
        for rx in (_META_RE, _META_RE_REV):
            m = rx.search(html)
            if m and m.group(1).strip() == token:
                return True
        return False  # reached the site but tag absent
    return False


def _check_file(host: str, token: str) -> bool:
    for scheme in ("https", "http"):
        try:
            r = httpx.get(f"{scheme}://{host}/.well-known/secureflow-verify.txt",
                          timeout=10, follow_redirects=True,
                          headers={"User-Agent": "SecureFlow-Verifier/1.0"})
        except httpx.HTTPError:
            continue
        if r.status_code == 200 and token in r.text.strip():
            return True
        return False
    return False


def verify(host: str, token: str) -> str | None:
    """Return the method that succeeded, or None if verification failed."""
    if _check_dns(host, token):
        return "dns"
    if _check_meta(host, token):
        return "meta"
    if _check_file(host, token):
        return "file"
    return None
