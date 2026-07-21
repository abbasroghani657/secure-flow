"""API-oriented checks: CORS origin reflection, excessive data exposure,
mass assignment, and WebSocket origin validation."""

from __future__ import annotations

import json
import re
import socket
import ssl
from urllib.parse import urljoin, urlparse

import httpx

from .checks import Finding
from .crawler import Form

_EVIL_ORIGIN = "https://evil.sf-test.example"

# Field names that should almost never appear in an API response body.
_SENSITIVE_FIELDS = {
    "password", "passwd", "pwd", "pass", "hash", "password_hash", "salt",
    "ssn", "secret", "token", "access_token", "refresh_token", "api_key", "apikey",
    "private_key", "privatekey", "credit_card", "card_number", "cardnumber", "cvv",
    "security_code", "pin", "session_id",
}
# Privileged fields an attacker adds to try to escalate via mass assignment.
_MASS_ASSIGN_FIELDS = {"isAdmin": "true", "is_admin": "true", "admin": "true",
                       "role": "admin", "is_verified": "true", "verified": "true",
                       "account_type": "admin"}


def check_cors_reflection(client: httpx.Client, base_url: str) -> list[Finding]:
    try:
        r = client.get(base_url, headers={"Origin": _EVIL_ORIGIN})
    except httpx.HTTPError:
        return []
    acao = r.headers.get("access-control-allow-origin", "")
    acac = r.headers.get("access-control-allow-credentials", "").lower()
    if acao == _EVIL_ORIGIN or acao == "null":
        sev = "high" if acac == "true" else "medium"
        return [Finding(
            "cors-origin-reflection", "CORS reflects arbitrary origin", sev, base_url,
            description="The server reflects any supplied Origin in Access-Control-Allow-Origin.",
            impact=("With credentials allowed, any website can read this site's authenticated responses."
                    if acac == "true" else "Any origin can read cross-origin responses from this endpoint."),
            evidence=f"Sent Origin: {_EVIL_ORIGIN} → Access-Control-Allow-Origin: {acao}"
                     f"{'; Allow-Credentials: true' if acac == 'true' else ''}",
            remediation="Allow-list specific trusted origins; never reflect the Origin with credentials.",
            compliance_ref="OWASP A01:2025",
        )]
    return []


def _find_sensitive_keys(obj, found: set) -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k.lower() in _SENSITIVE_FIELDS:
                found.add(k)
            _find_sensitive_keys(v, found)
    elif isinstance(obj, list):
        for it in obj[:50]:
            _find_sensitive_keys(it, found)


def check_excessive_data(client: httpx.Client, base_url: str, endpoints: list[str], max_urls: int = 12) -> list[Finding]:
    seen: set[str] = set()
    for url in ([base_url] + endpoints)[:max_urls]:
        try:
            r = client.get(url)
        except httpx.HTTPError:
            continue
        ctype = r.headers.get("content-type", "")
        if "json" not in ctype:
            continue
        try:
            data = r.json()
        except (json.JSONDecodeError, ValueError):
            continue
        found: set = set()
        _find_sensitive_keys(data, found)
        if found and url not in seen:
            seen.add(url)
            return [Finding(
                "excessive-data-exposure", "Excessive data exposure in API response", "high", url,
                description="A JSON API response includes sensitive fields that should not leave the server.",
                impact="Leaking password hashes, tokens or PII lets attackers escalate or breach accounts.",
                evidence=f"Response at {urlparse(url).path} exposes: {', '.join(sorted(found))}",
                remediation="Return only the fields the client needs; strip secrets/PII server-side (DTOs).",
                compliance_ref="OWASP API3:2023",
            )]
    return []


def test_mass_assignment(client: httpx.Client, forms: list[Form], max_forms: int = 8) -> list[Finding]:
    for form in forms:
        if form.method != "post":
            continue
        data = {n: "test" for n in form.inputs}
        data.update(_MASS_ASSIGN_FIELDS)
        try:
            r = client.post(form.action, data=data)
        except httpx.HTTPError:
            continue
        body = r.text.lower()
        # If the response echoes a privileged value back as set, the extra field was bound.
        if r.status_code < 500 and ('"role":"admin"' in body.replace(" ", "") or
                                    '"isadmin":true' in body.replace(" ", "") or
                                    '"is_admin":true' in body.replace(" ", "") or
                                    '"verified":true' in body.replace(" ", "")):
            return [Finding(
                "mass-assignment", "Potential mass assignment", "high", form.action,
                description="A POST form accepted extra privileged fields (e.g. role/isAdmin) that were reflected as set.",
                impact="Attackers can set fields they shouldn't control — e.g. make themselves an admin.",
                evidence="Injected isAdmin/role=admin into the request and the privileged value was reflected.",
                remediation="Bind only explicitly-allowed fields (allow-list); never mass-assign request bodies to models.",
                compliance_ref="OWASP API6:2023",
            )]
    return []


def check_websocket(probe, timeout: float = 8.0) -> list[Finding]:
    html = getattr(probe, "body_snippet", "") or ""
    for m in dict.fromkeys(re.findall(r"wss?://[a-zA-Z0-9.\-:/]+", html)):
        p = urlparse(m)
        host, port = p.hostname, p.port or (443 if p.scheme == "wss" else 80)
        if not host:
            continue
        req = (f"GET {p.path or '/'} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\n"
               f"Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\n"
               f"Sec-WebSocket-Key: c2VjdXJlZmxvdw==\r\nOrigin: {_EVIL_ORIGIN}\r\n\r\n")
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            if p.scheme == "wss":
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)
            sock.sendall(req.encode())
            resp = sock.recv(256).decode("latin-1", "replace")
            sock.close()
        except Exception:  # noqa: BLE001
            continue
        if "101" in resp.split("\r\n")[0] and "switching protocols" in resp.lower():
            return [Finding(
                "websocket-no-origin-check", "WebSocket accepts cross-origin connections", "medium", m,
                description="The WebSocket endpoint completed a handshake from a foreign Origin.",
                impact="Cross-site WebSocket hijacking can let malicious sites act over the user's authenticated socket.",
                evidence=f"Handshake to {m} with Origin {_EVIL_ORIGIN} returned 101 Switching Protocols.",
                remediation="Validate the Origin header on the WebSocket handshake and require authentication.",
                compliance_ref="OWASP A01:2025",
            )]
    return []
