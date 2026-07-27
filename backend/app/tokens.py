"""Machine API tokens for the CLI and CI pipelines.

A token looks like ``ptx_<prefix>_<secret>``. The user sees the full value once at
creation; we persist only ``prefix`` (to display and look up) and a hash of the
whole token (to verify). Tokens carry the owner's plan, so a CI scan is gated
exactly like a scan started in the browser.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

API_TOKEN_PREFIX = "ptx_"
_PREFIX_LEN = len(API_TOKEN_PREFIX) + 8  # "ptx_" + 8 lookup chars


def generate_api_token() -> tuple[str, str, str]:
    """Return (full_token, prefix, hashed_token). Show full_token to the user once."""
    body = secrets.token_urlsafe(24)
    lookup = secrets.token_hex(4)  # 8 hex chars, non-secret, for O(1) lookup
    full = f"{API_TOKEN_PREFIX}{lookup}_{body}"
    return full, token_prefix(full), _hash(full)


def token_prefix(token: str) -> str:
    """The stored, non-secret lookup key: the first ``ptx_`` + 8 chars."""
    return token[:_PREFIX_LEN]


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def verify_api_token(token: str, hashed: str) -> bool:
    return hmac.compare_digest(_hash(token), hashed)
