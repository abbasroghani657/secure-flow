"""Dedicated API security scanner — OpenAPI / Swagger spec analysis.

Upload an OpenAPI 3 or Swagger 2 specification (JSON or YAML) and it is statically
analysed against the OWASP API Security Top 10: missing authentication, BOLA
surface, credentials in the URL, cleartext servers, excessive data exposure, and
improper inventory (deprecated / multiple versions). No live traffic — pure spec
review, so it is safe to run against any documented API.
"""

from __future__ import annotations

import json
import re

import yaml

from .checks import Finding

_SENSITIVE_FIELD = re.compile(
    r"^(password|passwd|pwd|secret|token|ssn|social_?security|credit_?card|card_?number|"
    r"cvv|api_?key|private_?key|auth|session)$", re.I)


def _load(content: str):
    try:
        return json.loads(content)
    except (json.JSONDecodeError, ValueError):
        pass
    try:
        return yaml.safe_load(content)
    except yaml.YAMLError:
        return None


def _f(check_id, title, severity, where, description, remediation, impact="", evidence="") -> Finding:
    return Finding(check_id=check_id, title=title, severity=severity, url=where,
                   description=description, impact=impact, evidence=evidence or where,
                   remediation=remediation, compliance_ref="OWASP API Security Top 10")


_METHODS = ("get", "post", "put", "patch", "delete", "options", "head")


def run_api_scan(filename: str, content: str) -> list[Finding]:
    spec = _load(content)
    if not isinstance(spec, dict) or not (spec.get("openapi") or spec.get("swagger") or spec.get("paths")):
        return [Finding("api-unparsed", "Could not parse the API specification", "info", filename,
                        description="The file is not a recognisable OpenAPI 3 / Swagger 2 document.",
                        remediation="Upload a valid openapi.json / openapi.yaml / swagger spec.",
                        compliance_ref="OWASP API Security Top 10", passed=True)]

    findings: list[Finding] = []
    is_v2 = bool(spec.get("swagger"))

    # ---- Cleartext servers (API8: security misconfiguration) ----
    server_urls: list[str] = []
    if is_v2:
        schemes = spec.get("schemes") or []
        host = spec.get("host", "")
        server_urls = [f"{s}://{host}" for s in schemes]
    else:
        server_urls = [s.get("url", "") for s in (spec.get("servers") or [])]
    for u in server_urls:
        if u.startswith("http://"):
            findings.append(_f("api-cleartext-server", "API served over cleartext HTTP", "high", u,
                               description=f"A server URL uses http:// ({u}).",
                               impact="API traffic (including tokens) can be intercepted on the wire.",
                               remediation="Serve the API only over HTTPS/TLS.", evidence=u))
            break

    # ---- Security schemes ----
    schemes = (spec.get("securityDefinitions") if is_v2
               else (spec.get("components", {}) or {}).get("securitySchemes", {})) or {}
    for name, sc in schemes.items():
        if not isinstance(sc, dict):
            continue
        stype = (sc.get("type") or "").lower()
        loc = (sc.get("in") or "").lower()
        sname = (sc.get("name") or "").lower()
        if stype == "apikey" and loc == "query":
            findings.append(_f("api-apikey-in-query", "API key passed in the URL query string", "high",
                               f"securityScheme:{name}",
                               description=f"Security scheme '{name}' sends the API key as a query parameter.",
                               impact="Keys in URLs leak via logs, browser history, Referer headers and proxies.",
                               remediation="Send credentials in a header (Authorization) instead of the query string.",
                               evidence=f"apiKey in query ({sname})"))
        if (stype == "basic") or (stype == "http" and (sc.get("scheme", "").lower() == "basic")):
            findings.append(_f("api-weak-basic-auth", "HTTP Basic authentication", "low", f"securityScheme:{name}",
                               description=f"Security scheme '{name}' uses HTTP Basic auth.",
                               impact="Basic auth sends reusable credentials on every request and is easily replayed.",
                               remediation="Prefer OAuth2 / short-lived bearer tokens over Basic auth.",
                               evidence="type: basic"))

    global_security = bool(spec.get("security"))

    # ---- Per-operation analysis ----
    paths = spec.get("paths") or {}
    total_ops = 0
    unauth_ops = 0
    versions: set[str] = set()
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        mv = re.search(r"/v(\d+)\b", path)
        if mv:
            versions.add(mv.group(1))
        has_path_param = "{" in path
        for method, op in item.items():
            if method.lower() not in _METHODS or not isinstance(op, dict):
                continue
            total_ops += 1
            op_secured = ("security" in op) or global_security
            if not op_secured:
                unauth_ops += 1
                if has_path_param:
                    findings.append(_f("api-bola-surface", "Object endpoint without authentication (BOLA surface)",
                                       "high", f"{method.upper()} {path}",
                                       description=f"{method.upper()} {path} takes an object id but declares no security.",
                                       impact="Object-level endpoints without auth are the #1 API risk (BOLA/IDOR).",
                                       remediation="Require authentication and enforce per-object ownership checks.",
                                       evidence=f"{method.upper()} {path} — no security"))
            if op.get("deprecated") is True:
                findings.append(_f("api-deprecated-endpoint", "Deprecated endpoint still documented", "low",
                                   f"{method.upper()} {path}",
                                   description=f"{method.upper()} {path} is marked deprecated.",
                                   impact="Deprecated/zombie endpoints are often unpatched — improper inventory (API9).",
                                   remediation="Retire deprecated endpoints and remove them from the live API.",
                                   evidence="deprecated: true"))

    # ---- Missing authentication overall ----
    if total_ops and not global_security and not schemes:
        findings.append(_f("api-missing-authentication", "API defines no authentication at all", "high", filename,
                           description="The spec declares no security schemes and no global security.",
                           impact="Every documented endpoint is effectively unauthenticated (API2: broken auth).",
                           remediation="Define a security scheme and apply it globally or per operation.",
                           evidence=f"{total_ops} operations, 0 security schemes"))

    if len(versions) > 1:
        findings.append(_f("api-multiple-versions", f"Multiple API versions exposed (v{', v'.join(sorted(versions))})",
                           "low", filename,
                           description="The spec exposes more than one API version.",
                           impact="Old versions are often unpatched and forgotten — improper inventory (API9).",
                           remediation="Retire old versions; keep an accurate inventory of live endpoints.",
                           evidence=f"versions: {sorted(versions)}"))

    # ---- Excessive data exposure (sensitive fields in schemas) ----
    schemas = (spec.get("definitions") if is_v2 else (spec.get("components", {}) or {}).get("schemas", {})) or {}
    exposed: list[str] = []
    for sname, sch in schemas.items():
        props = (sch or {}).get("properties", {}) if isinstance(sch, dict) else {}
        for prop in props:
            if _SENSITIVE_FIELD.match(str(prop)):
                exposed.append(f"{sname}.{prop}")
    if exposed:
        findings.append(_f("api-excessive-data-exposure", "Sensitive fields exposed in API responses", "medium",
                           filename,
                           description="Response schemas include sensitive fields: " + ", ".join(exposed[:6]) + ".",
                           impact="Returning secrets/PII to clients leaks data even if the UI hides it (API3).",
                           remediation="Never serialise passwords/tokens/PII in responses; use response DTOs.",
                           evidence=", ".join(exposed[:6])))

    if not findings:
        findings.append(_f("api-clean", f"No API spec issues found ({total_ops} operations)", "info", filename,
                           description="The API specification passed all static checks.",
                           remediation="Keep the spec in sync with the live API and re-scan on change."))
        findings[-1].passed = True
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: (f.passed, order.get(f.severity, 5)))
    return findings
