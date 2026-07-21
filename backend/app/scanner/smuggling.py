"""HTTP Request Smuggling detection (timing-based).

Front-end and back-end servers can disagree about where one request ends when both
``Content-Length`` and ``Transfer-Encoding`` are present. This module uses the
industry-standard **timing** technique (the safe variant used by mainstream
scanners): it sends a single ambiguous request that, if the desync exists, makes
one server wait for data that never arrives — producing a large, measurable delay.

It does NOT inject a second (malicious) request, so it does not attempt to poison
other users' traffic. Still, malformed requests carry some residual risk, so this
runs only on the "deep" scan and only against the user's own verified target.
"""

from __future__ import annotations

import socket
import ssl
import time
from urllib.parse import urlparse

from .checks import Finding

_TIMEOUT = 10.0          # socket timeout for the probe
_DELAY_THRESHOLD = 5.0   # seconds over baseline that signals a likely desync


def _raw_request(host: str, port: int, use_tls: bool, payload: bytes) -> float | None:
    """Send raw bytes; return seconds until first response byte, or None on error.
    A clean timeout returns _TIMEOUT (i.e. it hung)."""
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=_TIMEOUT)
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        start = time.time()
        sock.sendall(payload)
        sock.settimeout(_TIMEOUT)
        try:
            data = sock.recv(64)
            if not data:
                return time.time() - start
            return time.time() - start
        except socket.timeout:
            return _TIMEOUT  # hung waiting for a body that never completes
    except Exception:  # noqa: BLE001
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _build(host: str, path: str, headers: list[str], body: str) -> bytes:
    lines = [f"POST {path} HTTP/1.1", f"Host: {host}", "Connection: close", *headers]
    return ("\r\n".join(lines) + "\r\n\r\n" + body).encode()


def check_smuggling(base_url: str) -> list[Finding]:
    p = urlparse(base_url)
    host = p.hostname
    if not host:
        return []
    use_tls = p.scheme == "https"
    port = p.port or (443 if use_tls else 80)
    path = p.path or "/"

    # Baseline: a well-formed request should return quickly.
    baseline = _raw_request(host, port, use_tls, _build(host, path, ["Content-Length: 0"], ""))
    if baseline is None:
        return []

    probes = {
        "CL.TE": _build(host, path, ["Content-Length: 4", "Transfer-Encoding: chunked"], "1\r\nA\r\nX"),
        "TE.CL": _build(host, path, ["Content-Length: 6", "Transfer-Encoding: chunked"], "0\r\n\r\nX"),
    }
    for name, payload in probes.items():
        t = _raw_request(host, port, use_tls, payload)
        if t is None:
            continue
        # A large delay only on the ambiguous request indicates a parsing desync.
        if t >= baseline + _DELAY_THRESHOLD and t >= _DELAY_THRESHOLD:
            return [Finding(
                "http-request-smuggling", f"Possible HTTP request smuggling ({name})", "high", base_url,
                description=f"An ambiguous Content-Length/Transfer-Encoding request ({name}) caused a large delay, "
                            "suggesting the front-end and back-end disagree on request boundaries.",
                impact="Request smuggling can bypass security controls, poison caches and hijack other users' requests.",
                evidence=f"{name} probe responded in {t:.1f}s vs a {baseline:.1f}s baseline.",
                remediation="Use HTTP/2 end-to-end, reject requests with both CL and TE, and normalise ambiguous framing.",
                compliance_ref="OWASP A05:2025",
            )]
    return []
