"""DNS / email-security and TLS certificate checks."""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone

from .checks import Finding

try:
    import dns.resolver
    _HAS_DNS = True
except ImportError:  # pragma: no cover
    _HAS_DNS = False


def _txt_records(name: str) -> list[str]:
    if not _HAS_DNS:
        return []
    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=8)
    except Exception:
        return []
    out = []
    for r in answers:
        try:
            out.append(b"".join(r.strings).decode(errors="ignore"))
        except Exception:
            out.append(str(r).strip('"'))
    return out


def check_spf(host: str) -> list[Finding]:
    domain = host[4:] if host.startswith("www.") else host
    records = _txt_records(domain)
    spf = [r for r in records if r.lower().startswith("v=spf1")]
    if spf:
        return [Finding("spf-present", "SPF record present", "info", f"dns://{domain}",
                        description="An SPF record is published.", evidence=spf[0][:120],
                        remediation="No action needed.", compliance_ref="Email security", passed=True)]
    return [Finding(
        "missing-spf", "No SPF record", "low", f"dns://{domain}",
        description="No SPF (Sender Policy Framework) TXT record was found for the domain.",
        impact="Without SPF, attackers can more easily spoof email from your domain.",
        remediation="Publish an SPF record, e.g. 'v=spf1 include:_spf.yourprovider.com -all'.",
        compliance_ref="Email security",
    )]


def check_dmarc(host: str) -> list[Finding]:
    domain = host[4:] if host.startswith("www.") else host
    records = _txt_records(f"_dmarc.{domain}")
    dmarc = [r for r in records if r.lower().startswith("v=dmarc1")]
    if dmarc:
        policy = "none"
        for part in dmarc[0].split(";"):
            if part.strip().lower().startswith("p="):
                policy = part.strip()[2:]
        if policy.lower() == "none":
            return [Finding(
                "weak-dmarc", "DMARC policy is 'none'", "low", f"dns://_dmarc.{domain}",
                description="A DMARC record exists but its policy is p=none (monitor only).",
                impact="Spoofed mail is not rejected or quarantined.",
                evidence=dmarc[0][:120],
                remediation="Move to p=quarantine then p=reject once monitoring looks clean.",
                compliance_ref="Email security",
            )]
        return [Finding("dmarc-present", "DMARC enforced", "info", f"dns://_dmarc.{domain}",
                        description="A DMARC record with an enforcing policy is published.",
                        evidence=dmarc[0][:120], remediation="No action needed.",
                        compliance_ref="Email security", passed=True)]
    return [Finding(
        "missing-dmarc", "No DMARC record", "low", f"dns://_dmarc.{domain}",
        description="No DMARC TXT record was found at _dmarc." + domain + ".",
        impact="Without DMARC, receivers have no policy for handling spoofed mail from your domain.",
        remediation="Publish a DMARC record, starting with 'v=DMARC1; p=none; rua=mailto:you@domain'.",
        compliance_ref="Email security",
    )]


def _has_a(name: str) -> bool:
    if not _HAS_DNS:
        return False
    try:
        dns.resolver.resolve(name, "A", lifetime=6)
        return True
    except Exception:
        return False


def check_email_hardening(host: str) -> list[Finding]:
    """MTA-STS, TLS-RPT and BIMI — the modern email-security layer beyond SPF/DMARC.
    Only advises when the domain actually sends/receives mail (has an MX record)."""
    domain = host[4:] if host.startswith("www.") else host
    if not _HAS_DNS:
        return []
    try:
        dns.resolver.resolve(domain, "MX", lifetime=6)
    except Exception:
        return []   # not a mail domain — these records are not expected

    findings: list[Finding] = []
    if not any("v=STSv1" in r for r in _txt_records(f"_mta-sts.{domain}")):
        findings.append(Finding(
            "missing-mta-sts", "No MTA-STS policy", "low", f"dns://_mta-sts.{domain}",
            description="No MTA-STS (SMTP MTA Strict Transport Security) policy is published.",
            impact="Without MTA-STS, inbound mail can be downgraded to cleartext via an active attacker.",
            remediation="Publish a _mta-sts TXT record and an mta-sts.txt policy enforcing TLS.",
            compliance_ref="Email security"))
    if not any("v=TLSRPTv1" in r for r in _txt_records(f"_smtp._tls.{domain}")):
        findings.append(Finding(
            "missing-tls-rpt", "No TLS-RPT (SMTP TLS reporting)", "info", f"dns://_smtp._tls.{domain}",
            description="No SMTP TLS-RPT record is published, so TLS delivery failures go unreported.",
            impact="You get no visibility into downgrade/interception attempts against your mail.",
            remediation="Publish a _smtp._tls TXT record with 'v=TLSRPTv1; rua=mailto:you@domain'.",
            compliance_ref="Email security"))
    if not any("v=BIMI1" in r for r in _txt_records(f"default._bimi.{domain}")):
        findings.append(Finding(
            "missing-bimi", "No BIMI record", "info", f"dns://default._bimi.{domain}",
            description="No BIMI record is published (brand logo in supporting mail clients).",
            impact="Minor: no brand indicator; BIMI also signals strong DMARC enforcement.",
            remediation="Publish a BIMI record once DMARC is at enforcement (p=quarantine/reject).",
            compliance_ref="Email security"))
    return findings


def check_dnssec(host: str) -> list[Finding]:
    """DNSSEC — is the zone signed? An unsigned zone is open to DNS spoofing."""
    domain = host[4:] if host.startswith("www.") else host
    if not _HAS_DNS:
        return []
    try:
        dns.resolver.resolve(domain, "DNSKEY", lifetime=6)
        return []   # signed
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        pass
    except Exception:
        return []
    return [Finding(
        "missing-dnssec", "DNSSEC not enabled", "low", f"dns://{domain}",
        description="The domain has no DNSKEY record — the DNS zone is not signed with DNSSEC.",
        impact="Unsigned DNS can be spoofed/poisoned, redirecting users or enabling domain takeover.",
        evidence="No DNSKEY record found.",
        remediation="Enable DNSSEC at your DNS provider and add the DS record at the registrar.",
        compliance_ref="OWASP A02:2025")]


def check_tls_certificate(host: str, port: int = 443) -> list[Finding]:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
    except Exception:
        return []  # non-HTTPS or unreachable — HTTPS presence is covered elsewhere

    not_after = cert.get("notAfter")
    if not not_after:
        return []
    try:
        expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except ValueError:
        return []
    days = (expires - datetime.now(timezone.utc)).days

    url = f"https://{host}"
    if days < 0:
        return [Finding("cert-expired", "TLS certificate has expired", "high", url,
                        description="The server's TLS certificate is expired.",
                        evidence=f"Expired on {not_after}",
                        remediation="Renew the certificate immediately and automate renewal.",
                        compliance_ref="OWASP A02:2021")]
    if days < 21:
        return [Finding("cert-expiring", "TLS certificate expiring soon", "medium", url,
                        description=f"The TLS certificate expires in {days} day(s).",
                        impact="An expired certificate breaks HTTPS for all users.",
                        evidence=f"Expires {not_after}",
                        remediation="Renew now and set up automated renewal (e.g. ACME/Let's Encrypt).",
                        compliance_ref="OWASP A02:2021")]
    return [Finding("cert-valid", "TLS certificate valid", "info", url,
                    description=f"The TLS certificate is valid for {days} more day(s).",
                    remediation="No action needed.", compliance_ref="OWASP A02:2021", passed=True)]


# CNAME service fragment -> fingerprint proving the target is unclaimed (dangling).
_TAKEOVER = {
    "github.io": "There isn't a GitHub Pages site here",
    "herokudns.com": "No such app",
    "herokuapp.com": "No such app",
    "s3.amazonaws.com": "NoSuchBucket",
    "amazonaws.com": "NoSuchBucket",
    "cloudfront.net": "Bad request",
    "fastly.net": "Fastly error: unknown domain",
    "surge.sh": "project not found",
    "bitbucket.io": "Repository not found",
    "ghost.io": "Domain error",
    "readthedocs.io": "unknown to Read the Docs",
    "wordpress.com": "Do you want to register",
    "pantheonsite.io": "The gods are wise",
    "netlify.app": "Not Found",
}
_SUBDOMAINS = ["www", "blog", "dev", "staging", "api", "mail", "cdn", "assets", "test", "app", "shop", "portal"]


def _cname(name: str) -> str | None:
    if not _HAS_DNS:
        return None
    try:
        answers = dns.resolver.resolve(name, "CNAME", lifetime=6)
        return str(answers[0].target).rstrip(".").lower()
    except Exception:
        return None


def check_subdomain_takeover(host: str) -> list[Finding]:
    base = host[4:] if host.startswith("www.") else host
    findings: list[Finding] = []
    checked = 0
    for sub in ["@"] + _SUBDOMAINS:
        if checked >= 8:
            break
        fqdn = base if sub == "@" else f"{sub}.{base}"
        cname = _cname(fqdn)
        if not cname:
            continue
        service = next((svc for svc in _TAKEOVER if svc in cname), None)
        if not service:
            continue
        checked += 1
        # Confirm the pointed-to resource is unclaimed by looking for its fingerprint.
        for scheme in ("https", "http"):
            try:
                r = httpx.get(f"{scheme}://{fqdn}/", timeout=8, follow_redirects=True,
                              headers={"User-Agent": "SecureFlow-Scanner/1.0"})
            except httpx.HTTPError:
                continue
            if _TAKEOVER[service].lower() in r.text.lower():
                findings.append(Finding(
                    "subdomain-takeover", f"Possible subdomain takeover: {fqdn}", "high",
                    f"https://{fqdn}",
                    description=f"{fqdn} has a dangling CNAME to {cname} ({service}) that appears unclaimed.",
                    impact="An attacker can claim the service and host content on your subdomain.",
                    evidence=f"CNAME {fqdn} → {cname}; unclaimed-service fingerprint returned.",
                    remediation="Remove the dangling DNS record or re-claim the service.",
                    compliance_ref="OWASP A01:2025",
                ))
            break
    return findings


def check_caa(host: str) -> list[Finding]:
    domain = host[4:] if host.startswith("www.") else host
    if not _HAS_DNS:
        return []
    try:
        dns.resolver.resolve(domain, "CAA", lifetime=8)
        return []  # CAA present
    except dns.resolver.NoAnswer:
        pass
    except Exception:
        return []
    return [Finding(
        "missing-caa", "No CAA DNS record", "low", f"dns://{domain}",
        description="No Certification Authority Authorization (CAA) record is set.",
        impact="Any CA may issue certificates for the domain, widening mis-issuance risk.",
        remediation="Publish a CAA record naming your allowed CA(s).",
        compliance_ref="OWASP A02:2021")]


def check_zone_transfer(host: str) -> list[Finding]:
    domain = host[4:] if host.startswith("www.") else host
    if not _HAS_DNS:
        return []
    try:
        import dns.query
        import dns.zone
        ns_records = dns.resolver.resolve(domain, "NS", lifetime=8)
    except Exception:
        return []
    for ns in ns_records:
        ns_host = str(ns.target).rstrip(".")
        try:
            ns_ip = str(dns.resolver.resolve(ns_host, "A", lifetime=6)[0])
            xfr = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, lifetime=8))
            if xfr:
                return [Finding(
                    "dns-zone-transfer", "DNS zone transfer (AXFR) allowed", "high", f"dns://{domain}",
                    description=f"The nameserver {ns_host} allowed a full DNS zone transfer.",
                    impact="AXFR exposes every DNS record — subdomains, internal hosts and infrastructure.",
                    evidence=f"AXFR from {ns_host} ({ns_ip}) returned the zone.",
                    remediation="Restrict AXFR to authorised secondary nameservers only.",
                    compliance_ref="OWASP A05:2021")]
        except Exception:
            continue
    return []


def run_dns_checks(host: str) -> list[Finding]:
    findings: list[Finding] = []
    for fn in (check_spf, check_dmarc, check_caa, check_zone_transfer,
               check_email_hardening, check_dnssec):
        try:
            findings.extend(fn(host))
        except Exception:
            continue
    try:
        findings.extend(check_tls_certificate(host))
    except Exception:
        pass
    try:
        findings.extend(check_subdomain_takeover(host))
    except Exception:
        pass
    return findings
