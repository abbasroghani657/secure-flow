"""BOLA / IDOR detection via two authenticated sessions.

Broken Object Level Authorization (OWASP API #1) is only reliably detectable with
two identities. We crawl as user A to find object-reference URLs (paths/params
carrying an id or uuid), then for each one compare three responses:

    A    (the owner)      -> 200 with A's private object
    anon (no session)     -> should be blocked; if it returns the same object the
                             resource is simply public, so we skip it
    B    (a *different* user) -> if B receives A's object, authorization is broken

The three-way comparison (B must look like A, and look *less* like the blocked
response) keeps false positives low: login redirects, 403s and error pages don't
resemble A's object, so they never trigger a finding.

Run only against a target the user owns, with two accounts they control.
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx

from .checks import Finding
from .crawler import crawl

USER_AGENT = "SecureFlow-Scanner/1.0"

_UUID_RE = re.compile(r"/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_NUM_PATH_RE = re.compile(r"/\d+(?:/|$)")
_ID_PARAM_RE = re.compile(r"(?:^|&)(id|[a-z_]*_id|uid|uuid|order|account|user|invoice|doc|file|num|key)=[\w-]+", re.I)


@dataclass
class TwoSessionTarget:
    base_url: str
    headers_a: dict = field(default_factory=dict)
    headers_b: dict = field(default_factory=dict)


_PRIVILEGED_RE = re.compile(
    r"/(admin|administrator|manage(?:ment)?|internal|config(?:uration)?|dashboard|"
    r"users?|accounts?|roles?|permissions?|delete|ban|promote|grant|approve|"
    r"moderat|superuser|backend|staff|console)(/|$|\?|-)", re.I)


def has_object_ref(url: str) -> bool:
    """True if the URL addresses a specific object by id/uuid (path or query)."""
    p = urlparse(url)
    return bool(_NUM_PATH_RE.search(p.path) or _UUID_RE.search(p.path) or _ID_PARAM_RE.search(p.query))


def has_privileged_ref(url: str) -> bool:
    """True if the URL looks like a privileged/admin function endpoint."""
    return bool(_PRIVILEGED_RE.search(urlparse(url).path))


def _similarity(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    return difflib.SequenceMatcher(None, a[:3000], b[:3000]).ratio()


def _get(client: httpx.Client, url: str):
    try:
        return client.get(url)
    except httpx.HTTPError:
        return None


def _same_identity(ca: httpx.Client, cb: httpx.Client, base_url: str) -> bool:
    """Heuristic: if A and B see a byte-identical authenticated home page, they are
    probably the same account — which would make every check a false positive."""
    ra, rb = _get(ca, base_url), _get(cb, base_url)
    if ra is None or rb is None or ra.status_code != 200 or rb.status_code != 200:
        return False
    return ra.text == rb.text and len(ra.text) > 200


def run_bola_scan(target: TwoSessionTarget, max_candidates: int = 20, timeout: float = 12.0) -> list[Finding]:
    findings: list[Finding] = []
    ua = {"User-Agent": USER_AGENT}
    with httpx.Client(timeout=timeout, follow_redirects=True, headers={**ua, **target.headers_a}) as ca, \
         httpx.Client(timeout=timeout, follow_redirects=True, headers=ua) as canon, \
         httpx.Client(timeout=timeout, follow_redirects=True, headers={**ua, **target.headers_b}) as cb:

        if _same_identity(ca, cb, target.base_url):
            return [Finding(
                "bola-same-account", "The two accounts appear identical", "info", target.base_url,
                description="Sessions A and B returned the same authenticated page — they look like the same user.",
                remediation="Provide credentials for two DIFFERENT accounts to test object-level authorization.",
                compliance_ref="OWASP API1:2023", passed=True,
            )]

        # Discover object-reference URLs while authenticated as A.
        try:
            result = crawl(ca, target.base_url, max_pages=25, max_depth=2)
        except Exception:  # noqa: BLE001
            result = None
        candidates: list[str] = []
        seen: set[str] = set()
        for u in ((result.param_urls + result.pages) if result else []):
            if u not in seen and has_object_ref(u):
                seen.add(u)
                candidates.append(u)

        for url in candidates[:max_candidates]:
            ra = _get(ca, url)
            if ra is None or ra.status_code != 200 or len(ra.text) < 50:
                continue
            ranon = _get(canon, url)
            # Publicly reachable object → not an authorization flaw.
            if ranon is not None and ranon.status_code == 200 and _similarity(ranon.text, ra.text) > 0.9:
                continue
            rb = _get(cb, url)
            if rb is None or rb.status_code != 200:
                continue  # B was denied (403/redirect/etc.) — authorization works here
            sim_ba = _similarity(rb.text, ra.text)
            sim_banon = _similarity(rb.text, ranon.text) if ranon is not None else 0.0
            if sim_ba > 0.85 and sim_ba >= sim_banon:
                findings.append(Finding(
                    check_id=f"bola-{urlparse(url).path.strip('/').replace('/', '-')[:40] or 'root'}",
                    title="Broken Object Level Authorization (IDOR/BOLA)", severity="high", url=url,
                    description="A second user (B) can retrieve an object that belongs to user A by requesting A's URL.",
                    impact="Any user can read (and often modify) other users' records — a direct data breach.",
                    evidence=f"User B received the same object as user A at {url} (response similarity {sim_ba:.0%}).",
                    remediation="Enforce per-object ownership checks on the server for every request, not just the UI.",
                    compliance_ref="OWASP API1:2023",
                ))
                if len(findings) >= 10:
                    break

        # --- BFLA / vertical privilege escalation ---
        # Privileged/admin function endpoints A can reach: can the (lower-priv) B reach them too?
        priv_seen: set[str] = set()
        priv = []
        for u in ((result.pages + result.param_urls) if result else []):
            if u not in priv_seen and has_privileged_ref(u):
                priv_seen.add(u)
                priv.append(u)
        for url in priv[:max_candidates]:
            ra = _get(ca, url)
            if ra is None or ra.status_code != 200 or len(ra.text) < 80:
                continue
            ranon = _get(canon, url)
            # Must actually be privileged: anonymous access should be denied.
            if ranon is not None and ranon.status_code == 200 and _similarity(ranon.text, ra.text) > 0.9:
                continue
            rb = _get(cb, url)
            if rb is None or rb.status_code != 200:
                continue  # B denied — function-level authorization works here
            sim_ba = _similarity(rb.text, ra.text)
            sim_banon = _similarity(rb.text, ranon.text) if ranon is not None else 0.0
            if sim_ba > 0.85 and sim_ba >= sim_banon:
                findings.append(Finding(
                    check_id=f"bfla-{urlparse(url).path.strip('/').replace('/', '-')[:40] or 'root'}",
                    title="Broken Function-Level Authorization / Privilege Escalation", severity="high", url=url,
                    description="A second (lower-privileged) account can access a privileged/admin function endpoint.",
                    impact="A normal user can invoke admin-only functionality — full privilege escalation.",
                    evidence=f"Account B reached the privileged endpoint {url} (response similarity {sim_ba:.0%}). "
                             "Verify B is less privileged than A.",
                    remediation="Enforce role/function checks server-side on every privileged endpoint.",
                    compliance_ref="OWASP API5:2023",
                ))
                if len([f for f in findings if f.check_id.startswith("bfla-")]) >= 5:
                    break
    return findings
