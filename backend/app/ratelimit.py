"""Shared rate limiter (slowapi) — protects auth endpoints from brute force."""

from slowapi import Limiter
from slowapi.util import get_remote_address

# Keyed by client IP. In production behind a proxy, ensure the real IP is passed
# through (e.g. X-Forwarded-For handling at the proxy / trusted-hosts config).
limiter = Limiter(key_func=get_remote_address, default_limits=[])
