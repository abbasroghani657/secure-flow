"""Scan orchestration: fetch the target, run checks, persist findings, score."""

from __future__ import annotations

import ipaddress
import json
import socket
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import httpx
from sqlmodel import Session

from ..config import settings
from ..database import engine as db_engine
from ..models import Finding as FindingModel
from ..models import Scan, ScanStatus, Severity
from ..taxonomy import enrich as enrich_taxonomy
from .active import run_active_tests, test_file_upload, test_host_header, test_stored_xss, test_xxe
from .api_checks import check_cors_reflection, check_excessive_data, check_websocket, test_mass_assignment
from .auth_tests import check_logout_invalidation, run_auth_tests
from .cloud import check_cloud_buckets
from .dom_xss import check_dom_xss
from .dos_checks import test_redos, test_xml_expansion
from .logic import run_logic_tests
from .web_extra import run_web_extra
from .checks import (
    BASE_CHECKS,
    COMMON_DIRS,
    SENSITIVE_PATHS,
    Finding,
    Probe,
    build_path_finding,
    check_csrf_forms,
    check_http_methods,
    check_js_libraries,
    check_coep_corp,
    check_internal_ip,
    check_security_txt,
    check_sensitive_comments,
    check_session_in_url,
    check_source_disclosure,
    check_sri,
    check_tabnabbing,
    directory_listing_finding,
    looks_present,
)
from .crawler import crawl
from .dns_checks import run_dns_checks
from .phase1b import check_api_inventory, check_file_upload, check_jwks_exposure, check_oauth
from .services import check_exposed_dashboards, check_exposed_services
from .tls_checks import check_tls

# Severity weights used to turn findings into a 0-100 security score.
SEVERITY_WEIGHT = {"critical": 40, "high": 20, "medium": 8, "low": 3, "info": 0}

USER_AGENT = "SecureFlow-Scanner/1.0 (+https://secureflow.app/scanner)"


def _is_private_host(host: str) -> bool:
    """Block scanning of localhost / private / link-local addresses (SSRF guard)."""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False  # can't resolve — let the HTTP request fail naturally
    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            return True
    return False


def _probe_base(client: httpx.Client, url: str) -> Probe:
    resp = client.get(url)
    final = str(resp.url)
    is_https = final.startswith("https://")
    headers = {k.lower(): v for k, v in resp.headers.items()}

    # Detect http->https redirect behaviour with a separate plain-http probe.
    http_redirects = None
    parsed = urlparse(final)
    http_url = f"http://{parsed.netloc}{parsed.path or '/'}"
    try:
        r2 = client.get(http_url)
        http_redirects = str(r2.url).startswith("https://")
    except httpx.HTTPError:
        http_redirects = None

    set_cookies = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
    if not set_cookies and "set-cookie" in resp.headers:
        set_cookies = [resp.headers["set-cookie"]]

    return Probe(
        url=url,
        final_url=final,
        status_code=resp.status_code,
        headers=headers,
        raw_headers=dict(resp.headers),
        set_cookies=set_cookies,
        is_https=is_https,
        http_redirects_to_https=http_redirects,
        body_snippet=resp.text[:400000],  # enough to scan for mixed content / inline refs
    )


def _access_control_check(client: httpx.Client, pages: list[str]) -> list[Finding]:
    """Authenticated scan only: re-fetch discovered pages WITHOUT the session and
    flag any that return the same content — a forced-browsing / broken-access-control
    candidate (the page may not actually require authentication)."""
    findings: list[Finding] = []
    # A fresh client with no auth headers.
    with httpx.Client(timeout=settings.scan_http_timeout, follow_redirects=False,
                      headers={"User-Agent": USER_AGENT}) as anon:
        checked = 0
        for url in pages:
            if checked >= 8 or not urlparse(url).query and url.rstrip("/").count("/") <= 2:
                continue  # focus on deeper/app-like pages
            try:
                authed = client.get(url)
                plain = anon.get(url)
            except httpx.HTTPError:
                continue
            checked += 1
            # Authed must succeed; unauth returning the same 200 body == not protected.
            if authed.status_code != 200 or plain.status_code != 200:
                continue
            a, p = authed.text, plain.text
            if len(a) > 200 and abs(len(a) - len(p)) < 0.05 * len(a) and a[:400] == p[:400]:
                findings.append(Finding(
                    "broken-access-control", "Page reachable without authentication", "medium", url,
                    description="A page found during the authenticated crawl returns identical content without the session.",
                    impact="If this page is meant to be private, it exposes data/functions to unauthenticated users (broken access control).",
                    evidence=f"Authenticated and anonymous requests to {url} returned the same 200 response.",
                    remediation="Enforce server-side authorization on every protected route, not just in the UI.",
                    compliance_ref="OWASP A01:2025",
                ))
                if len(findings) >= 3:
                    break
    return findings


def _manual_review_advisory(url: str) -> Finding:
    """Honest disclosure: classes no automated scanner can reliably verify."""
    return Finding(
        "manual-review-advisory", "Manual review recommended (out of automated scope)", "info", url,
        description="Some vulnerability classes cannot be reliably detected by any automated scanner "
                    "and require a human penetration tester or source-code review.",
        impact="These remain untested by automated scanning and could still be exploitable.",
        evidence="Out of automated scope: business-logic flaws (price/coupon abuse, race conditions), "
                 "complex privilege-escalation and multi-step workflows, and insecure design.",
        remediation="Commission a manual penetration test / secure code review for these categories.",
        compliance_ref="OWASP A06:2025",
    )


def _collect_findings(client: httpx.Client, base_url: str, scan_type: str = "web",
                      authenticated: bool = False) -> list[Finding]:
    findings: list[Finding] = []
    probe = _probe_base(client, base_url)
    host = urlparse(probe.final_url).hostname or ""
    findings.append(_manual_review_advisory(probe.final_url))

    # 1. Header / TLS / cookie / CORS / mixed-content checks
    for check in BASE_CHECKS:
        try:
            findings.extend(check(probe))
        except Exception as exc:  # a single bad check shouldn't kill the scan
            findings.append(Finding(
                f"check-error-{check.__name__}", f"Check {check.__name__} errored", "info",
                probe.final_url, description=str(exc), passed=False,
            ))

    # 2. DNS / email-security (SPF, DMARC, CAA, zone transfer) + deep TLS/crypto + exposed services
    try:
        findings.extend(run_dns_checks(host))
    except Exception:
        pass
    if probe.is_https and host:
        try:
            findings.extend(check_tls(host))
        except Exception:
            pass
    try:
        findings.extend(check_exposed_dashboards(client, probe.final_url))
        findings.extend(check_exposed_services(host, client))
    except Exception:
        pass

    # 3. Dangerous HTTP methods (OPTIONS) + Host header injection + sensitive comments
    try:
        opt = client.request("OPTIONS", probe.final_url)
        findings.extend(check_http_methods(probe.final_url, opt.headers.get("allow", "")))
    except httpx.HTTPError:
        pass
    try:
        findings.extend(test_host_header(client, probe.final_url))
    except httpx.HTTPError:
        pass
    findings.extend(check_sensitive_comments(probe))
    findings.extend(check_internal_ip(probe))    # internal IP disclosure
    findings.extend(check_coep_corp(probe))      # missing cross-origin isolation headers
    findings.extend(check_file_upload(probe))    # file-upload surface
    try:
        findings.extend(check_jwks_exposure(client, probe.final_url, probe))  # JWKS / alg-confusion surface
        findings.extend(check_oauth(client, probe))                          # OAuth misconfig
    except Exception:
        pass
    findings.extend(check_js_libraries(probe))   # outdated JS libraries (A03)
    findings.extend(check_sri(probe))            # missing Subresource Integrity (A08)
    findings.extend(check_tabnabbing(probe))     # reverse tabnabbing
    findings.extend(check_dom_xss(client, probe))          # potential DOM-based XSS
    try:
        findings.extend(check_cloud_buckets(client, probe))  # open cloud storage buckets
    except Exception:
        pass
    try:
        findings.extend(run_web_extra(client, probe))       # JS secrets, JWT, Firebase, client-side
    except Exception:
        pass
    try:
        findings.extend(check_cors_reflection(client, probe.final_url))  # CORS origin reflection
    except Exception:
        pass
    try:
        findings.extend(check_websocket(probe))              # WebSocket origin validation
    except Exception:
        pass

    # 3b. GraphQL introspection exposed
    for gp in ("/graphql", "/api/graphql", "/v1/graphql"):
        try:
            gr = client.post(urljoin(probe.final_url, gp),
                             json={"query": "{__schema{queryType{name}}}"})
            if gr.status_code == 200 and "__schema" in gr.text and "queryType" in gr.text:
                findings.append(Finding(
                    "graphql-introspection", "GraphQL introspection enabled", "low",
                    urljoin(probe.final_url, gp),
                    description="The GraphQL endpoint answers introspection queries.",
                    impact="Introspection exposes the full API schema, easing targeted attacks.",
                    evidence=f"__schema returned at {gp}",
                    remediation="Disable introspection in production.",
                    compliance_ref="OWASP A02:2025",
                ))
                break
        except httpx.HTTPError:
            continue

    # 4. Exposed sensitive files. First fetch a random path to learn what a
    #    "not found" looks like — servers that soft-404 (return 200 for anything)
    #    would otherwise produce false positives.
    baseline_body = None
    try:
        rb = client.get(urljoin(probe.final_url, "/sf-nonexistent-a7f3c9e1b2"))
        if rb.status_code == 200:
            baseline_body = rb.text
    except httpx.HTTPError:
        pass

    for path, *_ in SENSITIVE_PATHS:
        target = urljoin(probe.final_url, path)
        try:
            r = client.get(target)
            if looks_present(r.status_code, r.text, path, baseline_body):
                f = build_path_finding(probe.final_url, path, r.status_code, r.text)
                if f:
                    findings.append(f)
        except httpx.HTTPError:
            continue

    # 5. Directory listing on common directories
    for d in COMMON_DIRS:
        try:
            r = client.get(urljoin(probe.final_url, d))
            f = directory_listing_finding(urljoin(probe.final_url, d), r.text)
            if f:
                findings.append(f)
        except httpx.HTTPError:
            continue

    # 6. security.txt
    try:
        st = client.get(urljoin(probe.final_url, "/.well-known/security.txt"))
        findings.append(check_security_txt(probe.final_url, st.status_code == 200 and "contact" in st.text.lower()))
    except httpx.HTTPError:
        findings.append(check_security_txt(probe.final_url, False))

    # 7. Crawl the site and actively test discovered parameters/forms
    if scan_type in ("web", "deep") and settings.crawl_enabled:
        try:
            result = crawl(client, probe.final_url, settings.max_crawl_pages, settings.max_crawl_depth)
            findings.extend(check_session_in_url(result.param_urls))
            findings.extend(check_csrf_forms(result.forms))
            if settings.active_tests_enabled:
                findings.extend(run_active_tests(client, result.param_urls, result.forms,
                                                 max_urls=settings.max_active_urls))
                findings.extend(test_xxe(client, probe.final_url, result.param_urls))
                # Safe (bounded) DoS canaries — ReDoS timing + XML small-laughs
                findings.extend(test_redos(client, result.param_urls))
                findings.extend(test_xml_expansion(client, probe.final_url, result.param_urls))
                # Automated business-logic heuristics (parameter tampering, race conditions)
                findings.extend(run_logic_tests(client, result.param_urls, result.pages))
                # API / auth checks
                findings.extend(check_excessive_data(client, probe.final_url, result.param_urls + result.pages))
                findings.extend(test_mass_assignment(client, result.forms))
                findings.extend(test_stored_xss(client, result.forms, result.pages))
                findings.extend(run_auth_tests(client, result.forms, host))
                findings.extend(check_source_disclosure(client, result.pages))
                findings.extend(check_api_inventory(client, probe.final_url, result.param_urls + result.pages))
                findings.extend(test_file_upload(client, result.forms, probe.final_url))
                # Session lifecycle (logout invalidation) needs an authenticated session.
                if authenticated:
                    findings.extend(check_logout_invalidation(client, probe.final_url, result.pages))
            # Authenticated scan: test discovered pages for missing access control.
            if authenticated:
                findings.extend(_access_control_check(client, result.pages + result.param_urls))
        except Exception:
            pass

    # 8. Tag every finding with OWASP 2025 category, CWE and affected layer.
    for f in findings:
        enrich_taxonomy(f)

    return findings


def compute_score(findings: list[Finding]) -> int:
    penalty = sum(SEVERITY_WEIGHT.get(f.severity, 0) for f in findings if not f.passed)
    return max(0, min(100, 100 - penalty))


def _tally_and_complete(session: Session, scan: Scan, findings: list[Finding]) -> None:
    """Persist findings, tally severity counts, score, and mark the scan completed."""
    # Triage: confidence + risk-based priority (KEV/EPSS) for every scan type.
    try:
        from .prioritize import prioritize_findings
        prioritize_findings(findings)
    except Exception:  # noqa: BLE001 - triage must never fail the scan
        pass

    counts = {s.value: 0 for s in Severity}
    passed = 0
    for f in findings:
        if f.passed:
            passed += 1
        else:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        session.add(FindingModel(scan_id=scan.id, **f.as_dict()))
    scan.critical_count = counts["critical"]
    scan.high_count = counts["high"]
    scan.medium_count = counts["medium"]
    scan.low_count = counts["low"]
    scan.info_count = counts["info"]
    scan.passed_count = passed
    scan.security_score = compute_score(findings)
    scan.status = ScanStatus.completed
    scan.progress = 100
    scan.finished_at = datetime.now(timezone.utc)
    session.add(scan)
    session.commit()


def _run_mobile_scan(session: Session, scan: Scan) -> None:
    """Analyse the uploaded APK for this scan, then delete the file."""
    import os

    from .mobile_scanner import MobileTarget, run_mobile_scan

    apk_path = os.path.join(settings.upload_dir, f"{scan.id}.apk")
    try:
        findings = run_mobile_scan(MobileTarget(apk_path=apk_path))
        for f in findings:
            enrich_taxonomy(f)
        _tally_and_complete(session, scan, findings)
    except Exception as exc:  # noqa: BLE001
        scan.status = ScanStatus.failed
        scan.error = f"Scan error: {exc}"
        scan.finished_at = datetime.now(timezone.utc)
        session.add(scan)
        session.commit()
    finally:
        try:
            if os.path.exists(apk_path):
                os.remove(apk_path)  # never keep the uploaded binary
        except OSError:
            pass


def _run_sca_scan(session: Session, scan: Scan) -> None:
    """Scan the uploaded dependency manifest for known-vulnerable packages."""
    import os

    from .sca_scanner import run_sca_scan

    path = os.path.join(settings.upload_dir, f"{scan.id}.dep")
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            content = fh.read()
        findings, _sbom, _n = run_sca_scan(scan.target_url, content)
        for f in findings:
            enrich_taxonomy(f)
        _tally_and_complete(session, scan, findings)
    except Exception as exc:  # noqa: BLE001
        scan.status = ScanStatus.failed
        scan.error = f"Scan error: {exc}"
        scan.finished_at = datetime.now(timezone.utc)
        session.add(scan)
        session.commit()
    finally:
        try:
            if os.path.exists(path):
                os.remove(path)
        except OSError:
            pass


def _run_ios_scan(session: Session, scan: Scan) -> None:
    """Static analysis of an uploaded iOS IPA, then delete the file."""
    import os

    from .ios_scanner import IOSTarget, run_ios_scan

    ipa_path = os.path.join(settings.upload_dir, f"{scan.id}.ipa")
    try:
        findings = run_ios_scan(IOSTarget(ipa_path=ipa_path))
        for f in findings:
            enrich_taxonomy(f)
        _tally_and_complete(session, scan, findings)
    except Exception as exc:  # noqa: BLE001
        scan.status = ScanStatus.failed
        scan.error = f"Scan error: {exc}"
        scan.finished_at = datetime.now(timezone.utc)
        session.add(scan)
        session.commit()
    finally:
        try:
            if os.path.exists(ipa_path):
                os.remove(ipa_path)
        except OSError:
            pass


def _run_iac_scan(session: Session, scan: Scan) -> None:
    """Scan an uploaded Infrastructure-as-Code file for misconfigurations."""
    import os

    from .iac_scanner import run_iac_scan

    path = os.path.join(settings.upload_dir, f"{scan.id}.iac")
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            content = fh.read()
        findings = run_iac_scan(scan.target_url, content)
        for f in findings:
            enrich_taxonomy(f)
        _tally_and_complete(session, scan, findings)
    except Exception as exc:  # noqa: BLE001
        scan.status = ScanStatus.failed
        scan.error = f"Scan error: {exc}"
        scan.finished_at = datetime.now(timezone.utc)
        session.add(scan)
        session.commit()
    finally:
        try:
            if os.path.exists(path):
                os.remove(path)
        except OSError:
            pass


def _run_secrets_scan(session: Session, scan: Scan) -> None:
    """Scan an uploaded source archive (ZIP) or file for leaked secrets."""
    import os

    from .secrets_scanner import run_secrets_scan

    path = os.path.join(settings.upload_dir, f"{scan.id}.src")
    try:
        with open(path, "rb") as fh:
            data = fh.read()
        findings = run_secrets_scan(scan.target_url, data)
        for f in findings:
            enrich_taxonomy(f)
        _tally_and_complete(session, scan, findings)
    except Exception as exc:  # noqa: BLE001
        scan.status = ScanStatus.failed
        scan.error = f"Scan error: {exc}"
        scan.finished_at = datetime.now(timezone.utc)
        session.add(scan)
        session.commit()
    finally:
        try:
            if os.path.exists(path):
                os.remove(path)
        except OSError:
            pass


def _run_cicd_scan(session: Session, scan: Scan) -> None:
    """Scan an uploaded CI/CD workflow (or ZIP of workflows) for pipeline misconfigs."""
    import os

    from .cicd_scanner import run_cicd_scan

    path = os.path.join(settings.upload_dir, f"{scan.id}.ci")
    try:
        with open(path, "rb") as fh:
            data = fh.read()
        findings = run_cicd_scan(scan.target_url, data)
        for f in findings:
            enrich_taxonomy(f)
        _tally_and_complete(session, scan, findings)
    except Exception as exc:  # noqa: BLE001
        scan.status = ScanStatus.failed
        scan.error = f"Scan error: {exc}"
        scan.finished_at = datetime.now(timezone.utc)
        session.add(scan)
        session.commit()
    finally:
        try:
            if os.path.exists(path):
                os.remove(path)
        except OSError:
            pass


def _run_sast_scan(session: Session, scan: Scan) -> None:
    """Static analysis of an uploaded source archive for dangerous code patterns."""
    import os

    from .sast_scanner import run_sast_scan

    path = os.path.join(settings.upload_dir, f"{scan.id}.sast")
    try:
        with open(path, "rb") as fh:
            data = fh.read()
        findings = run_sast_scan(scan.target_url, data)
        for f in findings:
            enrich_taxonomy(f)
        _tally_and_complete(session, scan, findings)
    except Exception as exc:  # noqa: BLE001
        scan.status = ScanStatus.failed
        scan.error = f"Scan error: {exc}"
        scan.finished_at = datetime.now(timezone.utc)
        session.add(scan)
        session.commit()
    finally:
        try:
            if os.path.exists(path):
                os.remove(path)
        except OSError:
            pass


def _run_cspm_scan(session: Session, scan: Scan) -> None:
    """Cloud posture scan of the owner's AWS account; credentials are wiped after."""
    import json

    from .cspm_scanner import CSPMTarget, run_cspm_scan

    try:
        creds = json.loads(scan.auth_headers or "{}")
        target = CSPMTarget(
            access_key=creds.get("aws_access_key", ""),
            secret_key=creds.get("aws_secret_key", ""),
            region=creds.get("aws_region", "us-east-1"),
            session_token=creds.get("aws_session_token"),
        )
        findings = run_cspm_scan(target)
        for f in findings:
            enrich_taxonomy(f)
        _tally_and_complete(session, scan, findings)
    except Exception as exc:  # noqa: BLE001
        scan.status = ScanStatus.failed
        scan.error = f"Scan error: {exc}"
        scan.finished_at = datetime.now(timezone.utc)
        session.add(scan)
        session.commit()
    finally:
        # Never keep cloud credentials after the scan.
        scan.auth_headers = None
        session.add(scan)
        session.commit()


def run_scan(scan_id: int) -> None:
    """Entry point for the background task. Owns its own DB session."""
    with Session(db_engine) as session:
        scan = session.get(Scan, scan_id)
        if scan is None:
            return
        scan.status = ScanStatus.running
        scan.started_at = datetime.now(timezone.utc)
        scan.progress = 5
        session.add(scan)
        session.commit()

        # Mobile APK scan: static analysis of an uploaded file — no network target.
        if scan.scan_type == "mobile":
            _run_mobile_scan(session, scan)
            return
        # SCA scan: analyse an uploaded dependency manifest — no network target.
        if scan.scan_type == "sca":
            _run_sca_scan(session, scan)
            return
        # iOS scan: static analysis of an uploaded IPA — no network target.
        if scan.scan_type == "ios":
            _run_ios_scan(session, scan)
            return
        # IaC scan: static analysis of an uploaded config file — no network target.
        if scan.scan_type == "iac":
            _run_iac_scan(session, scan)
            return
        # Secrets scan: analyse an uploaded source archive — no network target.
        if scan.scan_type == "secrets":
            _run_secrets_scan(session, scan)
            return
        # CI/CD scan: analyse an uploaded workflow file — no network target.
        if scan.scan_type == "cicd":
            _run_cicd_scan(session, scan)
            return
        # SAST scan: static analysis of an uploaded source archive — no network target.
        if scan.scan_type == "sast":
            _run_sast_scan(session, scan)
            return
        # CSPM scan: query the owner's AWS account with their read-only credentials.
        if scan.scan_type == "cspm":
            _run_cspm_scan(session, scan)
            return

        base_url = scan.target_url
        host = urlparse(base_url).hostname or ""

        if _is_private_host(host):
            scan.status = ScanStatus.failed
            scan.error = "Refusing to scan a private/loopback address."
            scan.finished_at = datetime.now(timezone.utc)
            session.add(scan)
            session.commit()
            return

        # Optional credentials for an authenticated scan (scan behind the login).
        auth_headers: dict = {}
        if scan.auth_headers:
            try:
                auth_headers = json.loads(scan.auth_headers)
            except (json.JSONDecodeError, TypeError):
                auth_headers = {}

        try:
            if scan.scan_type == "bola":
                # BOLA/IDOR: two-session object-authorization test.
                from .access_control import TwoSessionTarget, run_bola_scan

                headers_b: dict = {}
                if scan.auth_headers_b:
                    try:
                        headers_b = json.loads(scan.auth_headers_b)
                    except (json.JSONDecodeError, TypeError):
                        headers_b = {}
                scan.progress = 30
                session.add(scan)
                session.commit()
                findings = run_bola_scan(TwoSessionTarget(
                    base_url=base_url, headers_a=auth_headers, headers_b=headers_b,
                ))
                for f in findings:
                    enrich_taxonomy(f)
            elif scan.scan_type == "llm":
                # LLM app scan: probe the endpoint for OWASP LLM Top 10 issues.
                from .llm_scanner import LLMTarget, run_llm_scan

                scan.progress = 30
                session.add(scan)
                session.commit()
                llm_target = LLMTarget(
                    endpoint=scan.llm_endpoint or base_url,
                    body_template=scan.llm_body_template or '{"prompt": "{{PROMPT}}"}',
                    response_path=scan.llm_response_path or "",
                    headers=auth_headers,
                )
                findings = run_llm_scan(llm_target)
                for f in findings:
                    enrich_taxonomy(f)
            else:
                with httpx.Client(
                    timeout=settings.scan_http_timeout,
                    follow_redirects=True,
                    headers={"User-Agent": USER_AGENT, **auth_headers},
                    verify=True,
                ) as client:
                    scan.progress = 20
                    session.add(scan)
                    session.commit()

                    findings = _collect_findings(client, base_url, scan.scan_type, authenticated=bool(auth_headers))

                # Deep scan: also run the Nuclei template engine (active, but gated on
                # verified ownership and with intrusive/DoS templates excluded).
                if scan.scan_type == "deep":
                    scan.progress = 45
                    session.add(scan)
                    session.commit()
                    from .nuclei_runner import run_nuclei
                    from .smuggling import check_smuggling

                    findings.extend(run_nuclei(base_url))
                    try:
                        findings.extend(check_smuggling(base_url))  # timing-based, deep scan only
                    except Exception:  # noqa: BLE001
                        pass

            scan.progress = 85
            session.add(scan)
            session.commit()

            _tally_and_complete(session, scan, findings)
        except httpx.HTTPError as exc:
            scan.status = ScanStatus.failed
            scan.error = f"Could not reach target: {exc}"
            scan.finished_at = datetime.now(timezone.utc)
            session.add(scan)
            session.commit()
        except Exception as exc:  # noqa: BLE001
            scan.status = ScanStatus.failed
            scan.error = f"Scan error: {exc}"
            scan.finished_at = datetime.now(timezone.utc)
            session.add(scan)
            session.commit()
        finally:
            # Never keep the user's session credentials after the scan runs.
            if scan.auth_headers is not None or scan.auth_headers_b is not None:
                scan.auth_headers = None
                scan.auth_headers_b = None
                session.add(scan)
                session.commit()
