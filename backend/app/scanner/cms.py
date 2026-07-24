"""CMS-specific checks (WordPress / Drupal / Joomla).

WordPress alone powers ~40% of the web and is a huge, under-served target. When a
web scan lands on a CMS we fingerprint it and run the checks that matter: version
disclosure, user enumeration, XML-RPC abuse surface, and exposed config backups.

All black-box and non-destructive — only reads.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin

import httpx

from .checks import Finding


def _get(client: httpx.Client, url: str):
    try:
        return client.get(url, timeout=8, follow_redirects=True)
    except httpx.HTTPError:
        return None


def _is_wordpress(client: httpx.Client, base: str, home_html: str) -> bool:
    if re.search(r'/wp-content/|/wp-includes/|wp-json|name="generator"[^>]*WordPress', home_html, re.I):
        return True
    r = _get(client, urljoin(base, "/wp-login.php"))
    return bool(r and r.status_code == 200 and "user_login" in r.text)


def check_cms(client: httpx.Client, base_url: str, home_html: str) -> list[Finding]:
    findings: list[Finding] = []

    # ---- Drupal / Joomla version disclosure (light) ----
    gen = re.search(r'name="generator"\s+content="([^"]+)"', home_html, re.I)
    if gen and re.search(r"Drupal|Joomla", gen.group(1), re.I):
        findings.append(Finding(
            "cms-version-disclosure", f"CMS version disclosed ({gen.group(1)})", "low", base_url,
            description=f"The page's generator tag reveals '{gen.group(1)}'.",
            impact="Knowing the exact CMS/version lets an attacker pick matching public exploits.",
            evidence=f"generator = {gen.group(1)}",
            remediation="Remove the generator meta tag and version strings.",
            compliance_ref="OWASP A02:2025"))

    if not _is_wordpress(client, base_url, home_html):
        return findings

    findings.append(Finding(
        "wordpress-detected", "WordPress detected", "info", base_url,
        description="The target is running WordPress.",
        impact="WordPress is the most-attacked CMS; keep core, plugins and themes patched.",
        evidence="WordPress fingerprints (wp-content / wp-json / wp-login) present.",
        remediation="Harden WordPress: latest core, minimal plugins, a WAF, and 2FA on admin.",
        compliance_ref="OWASP A06:2025", passed=True))

    # ---- Version disclosure via readme.html / generator ----
    ver = None
    if gen and "wordpress" in gen.group(1).lower():
        ver = gen.group(1)
    rm = _get(client, urljoin(base_url, "/readme.html"))
    if rm and rm.status_code == 200 and "wordpress" in rm.text.lower():
        m = re.search(r"Version\s+([0-9.]+)", rm.text)
        ver = f"WordPress {m.group(1)}" if m else (ver or "WordPress (readme.html exposed)")
        findings.append(Finding(
            "wordpress-version-disclosure", "WordPress version disclosed", "low", urljoin(base_url, "/readme.html"),
            description=f"readme.html is public and reveals {ver}.",
            impact="The exact version enables targeted exploitation of known core CVEs.",
            evidence=f"{ver} via /readme.html",
            remediation="Delete or block readme.html; strip version strings.",
            compliance_ref="OWASP A02:2025"))

    # ---- User enumeration via the REST API ----
    users = _get(client, urljoin(base_url, "/wp-json/wp/v2/users"))
    if users and users.status_code == 200 and re.search(r'"slug"\s*:\s*"[^"]+"', users.text):
        names = re.findall(r'"slug"\s*:\s*"([^"]+)"', users.text)[:5]
        findings.append(Finding(
            "wordpress-user-enumeration", "WordPress user enumeration (REST API)", "medium", base_url,
            description="The /wp-json/wp/v2/users endpoint lists valid usernames.",
            impact="Valid usernames make password brute-force and credential-stuffing far easier.",
            evidence=f"Usernames leaked: {', '.join(names)}",
            remediation="Restrict the users REST endpoint (a security plugin or must-use plugin) or require auth.",
            compliance_ref="OWASP A07:2025"))

    # ---- XML-RPC enabled (brute-force + pingback DDoS amplification) ----
    xr = None
    try:
        xr = client.post(urljoin(base_url, "/xmlrpc.php"),
                         content="<?xml version='1.0'?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>",
                         headers={"Content-Type": "text/xml"}, timeout=8)
    except httpx.HTTPError:
        pass
    if xr is not None and xr.status_code == 200 and "methodResponse" in xr.text:
        pingback = "pingback.ping" in xr.text
        findings.append(Finding(
            "wordpress-xmlrpc-enabled", "WordPress XML-RPC enabled", "medium", urljoin(base_url, "/xmlrpc.php"),
            description="xmlrpc.php is enabled and answers method calls.",
            impact="XML-RPC allows login brute-force amplification (system.multicall)"
                   + (" and pingback-based SSRF/DDoS" if pingback else "") + ".",
            evidence="system.listMethods returned a methodResponse" + (" including pingback.ping" if pingback else ""),
            remediation="Disable XML-RPC if unused, or block pingback and rate-limit xmlrpc.php.",
            compliance_ref="OWASP A05:2025"))

    # ---- Exposed wp-config backups (would leak DB credentials) ----
    for path in ("/wp-config.php.bak", "/wp-config.php~", "/wp-config.php.save",
                 "/wp-config.php.old", "/.wp-config.php.swp", "/wp-config.php.txt"):
        r = _get(client, urljoin(base_url, path))
        if r and r.status_code == 200 and ("DB_PASSWORD" in r.text or "DB_NAME" in r.text):
            findings.append(Finding(
                "wordpress-config-backup-exposed", "Exposed wp-config backup (DB credentials)", "critical",
                urljoin(base_url, path),
                description=f"A backup of wp-config.php is publicly readable at {path}.",
                impact="The backup exposes the database credentials and secret keys — full site compromise.",
                evidence=f"{path} returned wp-config content (DB_PASSWORD/DB_NAME).",
                remediation="Delete backup files from the web root and store backups outside it.",
                compliance_ref="OWASP A02:2025"))
            break

    # ---- Exposed debug log ----
    dl = _get(client, urljoin(base_url, "/wp-content/debug.log"))
    if dl and dl.status_code == 200 and re.search(r"PHP (Notice|Warning|Fatal)|\[.*UTC\]", dl.text):
        findings.append(Finding(
            "wordpress-debug-log-exposed", "Exposed WordPress debug.log", "medium",
            urljoin(base_url, "/wp-content/debug.log"),
            description="/wp-content/debug.log is publicly readable.",
            impact="Debug logs leak paths, queries, and sometimes tokens that aid further attacks.",
            evidence="debug.log returned PHP error entries.",
            remediation="Disable WP_DEBUG_LOG in production and block the file.",
            compliance_ref="OWASP A09:2025"))

    return findings
