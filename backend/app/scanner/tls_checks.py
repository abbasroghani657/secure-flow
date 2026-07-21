"""Deep TLS / certificate analysis.

Uses Python's ``ssl`` for protocol/cipher probing and ``cryptography`` to parse the
certificate. Detects deprecated TLS versions, weak ciphers, weak certificate
signatures/keys, self-signed / hostname-mismatch certs. Runs only for HTTPS.
"""

from __future__ import annotations

import re
import socket
import ssl
from datetime import datetime, timezone

# Names of genuinely weak ciphers (used to confirm a "weak cipher accepted" result).
_WEAK_CIPHER_RE = re.compile(r"RC4|3DES|(?<!TLS_)\bDES\b|NULL|EXP|MD5|ADH|AECDH|_CBC_.*_SHA$", re.I)

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa

from .checks import Finding


def _peer_cert_der(host: str, port: int) -> bytes | None:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=8) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                return ss.getpeercert(binary_form=True)
    except (ssl.SSLError, OSError):
        return None


def _tls_version_enabled(host: str, port: int, version: ssl.TLSVersion) -> bool:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = version
        ctx.maximum_version = version
    except (ValueError, OSError):
        return False  # this client build can't negotiate that old version — can't test
    try:
        with socket.create_connection((host, port), timeout=8) as s:
            with ctx.wrap_socket(s, server_hostname=host):
                return True
    except (ssl.SSLError, OSError):
        return False


def _weak_cipher_accepted(host: str, port: int) -> str | None:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # TLS 1.3 cipher suites can't be disabled via set_ciphers(), so cap at TLS 1.2 —
    # otherwise a strong TLS 1.3 cipher would be mis-reported as "weak".
    try:
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    except (ValueError, OSError):
        pass
    try:
        ctx.set_ciphers("RC4:3DES:DES:NULL:EXPORT:MD5:aNULL:eNULL:LOW")
    except ssl.SSLError:
        return None  # client won't even offer weak ciphers — can't test
    try:
        with socket.create_connection((host, port), timeout=8) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                name = ss.cipher()[0]
    except (ssl.SSLError, OSError):
        return None
    # Only report if the negotiated cipher is genuinely weak.
    return name if _WEAK_CIPHER_RE.search(name) else None


def check_tls(host: str, port: int = 443) -> list[Finding]:
    findings: list[Finding] = []
    url = f"https://{host}"

    # --- certificate analysis (reliable via cryptography) ---
    der = _peer_cert_der(host, port)
    if der is not None:
        try:
            cert = x509.load_der_x509_certificate(der)
            sig = (cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "").lower()
            if sig in ("md5", "sha1"):
                findings.append(Finding(
                    "weak-cert-signature", f"Weak certificate signature ({sig.upper()})", "medium", url,
                    description=f"The TLS certificate is signed with {sig.upper()}, which is broken/deprecated.",
                    impact="Weak signatures can be forged, undermining certificate trust.",
                    evidence=f"Signature algorithm: {sig}",
                    remediation="Re-issue the certificate with SHA-256 or stronger.",
                    compliance_ref="OWASP A02:2021"))
            pub = cert.public_key()
            size = getattr(pub, "key_size", None)
            if isinstance(pub, (rsa.RSAPublicKey, dsa.DSAPublicKey)) and size and size < 2048:
                findings.append(Finding(
                    "weak-cert-key", f"Weak certificate key size ({size}-bit)", "medium", url,
                    description=f"The certificate uses a {size}-bit key, below the 2048-bit minimum.",
                    impact="Small keys are increasingly factorable, allowing decryption/impersonation.",
                    evidence=f"Public key size: {size} bits",
                    remediation="Use a 2048-bit+ RSA or a 256-bit+ ECC key.",
                    compliance_ref="OWASP A02:2021"))
            if cert.issuer == cert.subject:
                findings.append(Finding(
                    "self-signed-cert", "Self-signed TLS certificate", "medium", url,
                    description="The certificate is self-signed (issuer == subject).",
                    impact="Self-signed certs aren't trusted and enable man-in-the-middle attacks.",
                    evidence="Certificate issuer equals its subject.",
                    remediation="Use a certificate from a trusted CA (e.g. Let's Encrypt).",
                    compliance_ref="OWASP A02:2021"))
        except Exception:  # noqa: BLE001
            pass

    # --- hostname validation ---
    vctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=8) as s:
            with vctx.wrap_socket(s, server_hostname=host):
                pass
    except ssl.SSLCertVerificationError as e:
        if "hostname mismatch" in str(e).lower() or "doesn't match" in str(e).lower():
            findings.append(Finding(
                "cert-hostname-mismatch", "Certificate hostname mismatch", "medium", url,
                description="The certificate is not valid for this hostname.",
                impact="Browsers warn users, and it can indicate misconfiguration or MITM.",
                evidence=str(e)[:120], remediation="Issue a certificate covering this hostname (SAN).",
                compliance_ref="OWASP A02:2021"))
    except (ssl.SSLError, OSError):
        pass

    # --- deprecated protocol versions ---
    for name, ver in (("TLS 1.0", ssl.TLSVersion.TLSv1), ("TLS 1.1", ssl.TLSVersion.TLSv1_1)):
        if _tls_version_enabled(host, port, ver):
            findings.append(Finding(
                f"deprecated-tls-{name.split()[1].replace('.', '')}", f"Deprecated {name} enabled", "medium", url,
                description=f"The server still accepts {name}, which is deprecated and insecure.",
                impact="Old TLS versions have known weaknesses (BEAST/POODLE-era) and fail compliance (PCI).",
                evidence=f"{name} handshake succeeded.",
                remediation="Disable TLS 1.0/1.1; require TLS 1.2+.",
                compliance_ref="OWASP A02:2021"))

    # --- weak ciphers ---
    weak = _weak_cipher_accepted(host, port)
    if weak:
        findings.append(Finding(
            "weak-tls-cipher", f"Weak TLS cipher accepted ({weak})", "medium", url,
            description=f"The server negotiated a weak cipher: {weak}.",
            impact="Weak ciphers (RC4/3DES/NULL/EXPORT) can be broken, exposing traffic.",
            evidence=f"Negotiated cipher: {weak}",
            remediation="Restrict to strong AEAD ciphers (e.g. ECDHE-…-GCM); drop RC4/3DES/NULL/EXPORT.",
            compliance_ref="OWASP A02:2021"))

    return findings
