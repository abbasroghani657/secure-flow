"""Security headers on every response.

A security product should pass its own scan. This applies the same hardening our
scanner looks for: no MIME sniffing, no framing, a strict referrer policy, a
locked-down Permissions-Policy, and HSTS when served over HTTPS.
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from .config import settings


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        h = response.headers
        h.setdefault("X-Content-Type-Options", "nosniff")
        h.setdefault("X-Frame-Options", "DENY")
        h.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        h.setdefault("Permissions-Policy", "geolocation=(), camera=(), microphone=()")
        # The API serves JSON only — forbid any active content outright.
        h.setdefault("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
        h.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        if settings.environment == "production":
            h.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
        # Don't advertise the server stack.
        if "server" in h:
            del h["server"]
        return response
