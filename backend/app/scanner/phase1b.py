"""API inventory (shadow endpoints + exposed docs), OAuth misconfig, file-upload
surface, and JWKS exposure."""

from __future__ import annotations

import re
from urllib.parse import parse_qs, urljoin, urlparse, urlunparse

import httpx

from .checks import Finding

_API_DOCS = ["/openapi.json", "/swagger/v1/swagger.json", "/api-docs", "/v2/api-docs",
             "/swagger-ui.html", "/swagger-ui/", "/api/swagger.json", "/redoc"]
_DOC_FP = re.compile(r'"openapi"|"swagger"|swagger-ui|redoc|"paths"\s*:', re.I)
_VER_RE = re.compile(r"/v(\d+)(/|$)")
_FILE_INPUT_RE = re.compile(r'type\s*=\s*["\']file["\']|enctype\s*=\s*["\']multipart/form-data', re.I)
_OAUTH_AUTHORIZE_RE = re.compile(
    r'https?://[^\s"\'<>]+/(?:oauth2?/)?authorize\?[^\s"\'<>]*client_id=[^\s"\'<>]+', re.I)
_EVIL = "https://evil.sf-test.example/cb"


def check_api_inventory(client: httpx.Client, base_url: str, endpoints: list[str]) -> list[Finding]:
    findings: list[Finding] = []

    # 1. Exposed API documentation (maps the whole API surface).
    for path in _API_DOCS:
        try:
            r = client.get(urljoin(base_url, path))
        except httpx.HTTPError:
            continue
        if r.status_code == 200 and _DOC_FP.search(r.text[:4000]):
            findings.append(Finding(
                "exposed-api-docs", "Exposed API documentation", "low", urljoin(base_url, path),
                description="Machine-readable API docs (OpenAPI/Swagger) are publicly reachable.",
                impact="Full API schemas hand attackers every endpoint, parameter and method.",
                evidence=f"API documentation served at {path}",
                remediation="Restrict API docs to authenticated internal users in production.",
                compliance_ref="OWASP API9:2023"))
            break

    # 2. Shadow / old API versions: if the app uses /vN, probe older versions.
    versions_seen = set()
    for u in endpoints:
        m = _VER_RE.search(urlparse(u).path)
        if m:
            versions_seen.add((u, int(m.group(1))))
    for url, ver in list(versions_seen)[:4]:
        for older in range(max(0, ver - 2), ver):
            probe = _VER_RE.sub(f"/v{older}\\2", urlparse(url).path, count=1)
            try:
                r = client.get(urljoin(base_url, probe))
            except httpx.HTTPError:
                continue
            if r.status_code < 400:
                findings.append(Finding(
                    "shadow-api-version", f"Deprecated API version still live (v{older})", "medium",
                    urljoin(base_url, probe),
                    description=f"An older API version (v{older}) responds while the app uses v{ver}.",
                    impact="Old API versions often miss newer security fixes and are forgotten (shadow APIs).",
                    evidence=f"/v{older} responded HTTP {r.status_code} while v{ver} is in use.",
                    remediation="Retire and block deprecated API versions.",
                    compliance_ref="OWASP API9:2023"))
                return findings
    return findings


def check_file_upload(probe) -> list[Finding]:
    if _FILE_INPUT_RE.search(getattr(probe, "body_snippet", "") or ""):
        return [Finding(
            "file-upload-surface", "File upload functionality present", "info", probe.final_url,
            description="The page contains a file-upload input / multipart form.",
            impact="Unrestricted uploads can lead to webshells, stored XSS (SVG) or path traversal.",
            evidence="Detected <input type=file> / multipart form.",
            remediation="Validate type/extension/size server-side, store outside the web root, and scan uploads.",
            compliance_ref="OWASP A04:2025")]
    return []


def check_jwks_exposure(client: httpx.Client, base_url: str, probe) -> list[Finding]:
    for path in ("/.well-known/jwks.json", "/jwks.json", "/.well-known/openid-configuration"):
        try:
            r = client.get(urljoin(base_url, path))
        except httpx.HTTPError:
            continue
        if r.status_code == 200 and ('"keys"' in r.text or '"jwks_uri"' in r.text):
            # A public key + an RS256 JWT elsewhere is the classic algorithm-confusion setup.
            body = (getattr(probe, "body_snippet", "") or "")
            for v in (getattr(probe, "set_cookies", []) or []):
                body += " " + v
            rs256 = "rs256" in body.lower() or bool(re.search(r"eyJ[\w-]*rs256", body, re.I))
            sev = "medium" if rs256 else "info"
            return [Finding(
                "jwks-exposed", "JWKS / signing keys published", sev, urljoin(base_url, path),
                description="A JWKS endpoint exposes the token-signing public key(s).",
                impact="With an RS256 token, a published public key enables JWT algorithm-confusion (RS256→HS256) forgery.",
                evidence=f"Public keys served at {path}" + (" and an RS256 token was seen." if rs256 else "."),
                remediation="Reject 'alg' downgrades server-side; pin the expected algorithm; rotate keys.",
                compliance_ref="OWASP A07:2025")]
    return []


def check_oauth(client: httpx.Client, probe) -> list[Finding]:
    body = getattr(probe, "body_snippet", "") or ""
    m = _OAUTH_AUTHORIZE_RE.search(body)
    if not m:
        return []
    auth_url = m.group(0)
    qs = parse_qs(urlparse(auth_url).query)
    findings: list[Finding] = []

    if "state" not in qs:
        findings.append(Finding(
            "oauth-missing-state", "OAuth flow without 'state' parameter", "medium", auth_url,
            description="An OAuth authorization request omits the anti-CSRF 'state' parameter.",
            impact="Without 'state', the OAuth flow is vulnerable to CSRF / login-CSRF.",
            evidence="Authorize URL has no state parameter.",
            remediation="Include an unguessable 'state' value and verify it on callback; use PKCE.",
            compliance_ref="OWASP A01:2025"))

    # redirect_uri manipulation: does the endpoint accept an external callback?
    if "redirect_uri" in qs:
        parts = urlparse(auth_url)
        new_qs = {k: v[0] for k, v in qs.items()}
        new_qs["redirect_uri"] = _EVIL
        from urllib.parse import urlencode
        tampered = urlunparse(parts._replace(query=urlencode(new_qs)))
        try:
            r = client.get(tampered, follow_redirects=False)
            loc = r.headers.get("location", "")
            if r.status_code in (301, 302, 303, 307, 308) and _EVIL.split("//")[1].split("/")[0] in loc:
                findings.append(Finding(
                    "oauth-open-redirect-uri", "OAuth redirect_uri not validated", "high", auth_url,
                    description="The authorization endpoint redirected to an attacker-controlled redirect_uri.",
                    impact="An open redirect_uri lets attackers steal authorization codes/tokens.",
                    evidence=f"Set redirect_uri={_EVIL} → redirect to {loc[:80]}",
                    remediation="Strictly allow-list exact redirect_uris server-side.",
                    compliance_ref="OWASP A01:2025"))
        except httpx.HTTPError:
            pass
    return findings
