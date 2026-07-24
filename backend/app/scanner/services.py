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


# MongoDB legacy OP_QUERY {isMaster:1} on admin.$cmd — replies with server topology.
_MONGO_ISMASTER = (
    b"\x3a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00"
    b"\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\x01\x00\x00\x00"
    b"\x13\x00\x00\x00\x10ismaster\x00\x01\x00\x00\x00\x00"
)
_MONGO_SIGS = (b"ismaster", b"isWritablePrimary", b"maxBsonObjectSize", b"maxWireVersion")


def _mongo_exposed(host: str, port: int = 27017, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(_MONGO_ISMASTER)
            data = s.recv(512)
        return any(sig in data for sig in _MONGO_SIGS)
    except OSError:
        return False


def _mysql_exposed(host: str, port: int = 3306, timeout: float = 3.0) -> bool:
    # MySQL/MariaDB send a handshake greeting immediately on connect.
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            data = s.recv(256)
        return b"mysql_native_password" in data or b"caching_sha2_password" in data or b"mariadb" in data.lower()
    except OSError:
        return False


def _postgres_exposed(host: str, port: int = 5432, timeout: float = 3.0) -> bool:
    # A protocol-3 StartupMessage draws an auth-request ('R') or error ('E') reply.
    body = b"\x00\x03\x00\x00user\x00scan\x00database\x00scan\x00\x00"
    msg = (len(body) + 4).to_bytes(4, "big") + body
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(msg)
            data = s.recv(64)
        return len(data) > 0 and data[:1] in (b"R", b"E")
    except OSError:
        return False


def _http_service(client: httpx.Client, host: str, port: int, path: str, sig: str,
                  scheme: str = "http", timeout: float = 5.0) -> bool:
    try:
        r = client.get(f"{scheme}://{host}:{port}{path}", timeout=timeout)
    except httpx.HTTPError:
        return False
    return r.status_code in (200, 401) and sig.lower() in r.text.lower()


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

    if _mongo_exposed(host):
        findings.append(Finding(
            "exposed-mongodb", "Unauthenticated MongoDB exposed", "critical", f"{host}:27017",
            description="A MongoDB server on port 27017 answered isMaster without authentication.",
            impact="Anyone can read, modify or drop every database on the server.",
            evidence="MongoDB returned server topology to an unauthenticated isMaster query.",
            remediation="Enable authorization, bind to localhost, and firewall port 27017.",
            compliance_ref="OWASP A05:2021"))

    if _http_service(client, host, 2375, "/version", "ApiVersion"):
        findings.append(Finding(
            "exposed-docker-api", "Unauthenticated Docker Engine API exposed", "critical", f"{host}:2375",
            description="The Docker Engine API on port 2375 is reachable without TLS/authentication.",
            impact="An attacker can start containers and mount the host filesystem — full host takeover (RCE).",
            evidence="GET :2375/version returned the Docker API version.",
            remediation="Never expose the Docker socket/API; require mTLS and firewall the port.",
            compliance_ref="OWASP A05:2021"))

    if _http_service(client, host, 2379, "/version", "etcdserver"):
        findings.append(Finding(
            "exposed-etcd", "Unauthenticated etcd exposed", "high", f"{host}:2379",
            description="An etcd key-value store on port 2379 is reachable without authentication.",
            impact="etcd holds Kubernetes cluster state and secrets — full cluster compromise.",
            evidence="GET :2379/version returned etcd server info.",
            remediation="Enable client cert auth and firewall etcd to the control plane only.",
            compliance_ref="OWASP A05:2021"))

    if _http_service(client, host, 15672, "/", "RabbitMQ"):
        findings.append(Finding(
            "exposed-rabbitmq", "RabbitMQ management interface exposed", "medium", f"{host}:15672",
            description="The RabbitMQ management console on port 15672 is reachable.",
            impact="Default/weak credentials give access to all queues and message contents.",
            evidence="RabbitMQ management interface responded on :15672.",
            remediation="Restrict the management interface to a VPN/allow-list and use strong credentials.",
            compliance_ref="OWASP A05:2021"))

    if _mysql_exposed(host):
        findings.append(Finding(
            "exposed-mysql", "Database port reachable from the internet (MySQL)", "medium", f"{host}:3306",
            description="A MySQL/MariaDB server on port 3306 is reachable from outside.",
            impact="An internet-exposed database port is continuously brute-forced and attacked.",
            evidence="MySQL sent its handshake greeting on port 3306.",
            remediation="Bind the database to the app's private network and firewall port 3306.",
            compliance_ref="OWASP A05:2021"))

    if _postgres_exposed(host):
        findings.append(Finding(
            "exposed-postgres", "Database port reachable from the internet (PostgreSQL)", "medium", f"{host}:5432",
            description="A PostgreSQL server on port 5432 is reachable from outside.",
            impact="An internet-exposed database port is continuously brute-forced and attacked.",
            evidence="PostgreSQL replied to a startup message on port 5432.",
            remediation="Bind the database to the app's private network and firewall port 5432.",
            compliance_ref="OWASP A05:2021"))
    return findings
