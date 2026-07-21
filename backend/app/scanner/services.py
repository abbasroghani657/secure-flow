"""Exposed admin dashboards and unauthenticated data services."""

from __future__ import annotations

import socket
from urllib.parse import urljoin

import httpx

from .checks import Finding

# (path, product, fingerprint substring, severity)
_DASHBOARDS = [
    ("/phpmyadmin/", "phpMyAdmin", "phpmyadmin", "high"),
    ("/adminer.php", "Adminer", "adminer", "high"),
    ("/jenkins/", "Jenkins", "jenkins", "high"),
    ("/grafana/login", "Grafana", "grafana", "medium"),
    ("/kibana/", "Kibana", "kibana", "medium"),
    ("/solr/", "Apache Solr admin", "solr", "high"),
    ("/manager/html", "Tomcat Manager", "tomcat", "high"),
    ("/.env", "", "", ""),  # placeholder skipped below
]


def check_exposed_dashboards(client: httpx.Client, base_url: str) -> list[Finding]:
    findings: list[Finding] = []
    for path, product, fp, sev in _DASHBOARDS:
        if not product:
            continue
        try:
            r = client.get(urljoin(base_url, path))
        except httpx.HTTPError:
            continue
        if r.status_code == 200 and fp in r.text.lower():
            findings.append(Finding(
                f"exposed-dashboard-{product.split()[0].lower()}", f"Exposed {product} interface", sev,
                urljoin(base_url, path),
                description=f"A {product} admin/management interface is reachable.",
                impact="Admin dashboards are prime targets for brute-force and known-exploit attacks.",
                evidence=f"{product} fingerprint at {path}",
                remediation="Restrict the interface to a VPN/allow-list and require strong authentication.",
                compliance_ref="OWASP A05:2021"))
    return findings


def _probe_tcp(host: str, port: int, send: bytes, expect: bytes, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            if send:
                s.sendall(send)
            data = s.recv(128)
            return expect in data
    except OSError:
        return False


def check_exposed_services(host: str, client: httpx.Client) -> list[Finding]:
    """Check the target host for unauthenticated data services on well-known ports."""
    findings: list[Finding] = []

    if _probe_tcp(host, 6379, b"PING\r\n", b"+PONG"):
        findings.append(Finding(
            "exposed-redis", "Unauthenticated Redis exposed", "critical", f"{host}:6379",
            description="A Redis server on port 6379 responded to PING without authentication.",
            impact="Anyone can read/write the cache/DB and often achieve code execution.",
            evidence="Redis replied +PONG to an unauthenticated PING.",
            remediation="Bind Redis to localhost, require a password, and firewall the port.",
            compliance_ref="OWASP A05:2021"))

    if _probe_tcp(host, 11211, b"version\r\n", b"VERSION"):
        findings.append(Finding(
            "exposed-memcached", "Unauthenticated Memcached exposed", "high", f"{host}:11211",
            description="A Memcached server on port 11211 is reachable without authentication.",
            impact="Cached data can be read/altered and the service abused for DDoS amplification.",
            evidence="Memcached replied to an unauthenticated 'version' command.",
            remediation="Bind to localhost, disable UDP, and firewall the port.",
            compliance_ref="OWASP A05:2021"))

    for scheme in ("http", "https"):
        try:
            r = client.get(f"{scheme}://{host}:9200/", timeout=6)
        except httpx.HTTPError:
            continue
        if r.status_code == 200 and ("cluster_name" in r.text or "lucene_version" in r.text):
            findings.append(Finding(
                "exposed-elasticsearch", "Unauthenticated Elasticsearch exposed", "critical", f"{host}:9200",
                description="An Elasticsearch node on port 9200 is reachable without authentication.",
                impact="Attackers can read, modify or delete all indexed data.",
                evidence="GET :9200/ returned cluster info without auth.",
                remediation="Enable Elasticsearch security/auth and firewall the port.",
                compliance_ref="OWASP A05:2021"))
        break
    return findings
