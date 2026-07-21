"""Open (publicly listable) cloud storage bucket detection.

Finds S3 / Google Cloud Storage / Azure Blob URLs referenced by the page, then
checks whether each bucket lets anyone list its contents — a common cause of data
leaks. Only the buckets the target itself references are probed.
"""

from __future__ import annotations

import re

import httpx

from .checks import Finding

# (provider, regex capturing the bucket root URL)
_BUCKET_PATTERNS = [
    ("Amazon S3", re.compile(r"https?://[a-z0-9.\-]+\.s3[.\-][a-z0-9.\-]*amazonaws\.com", re.I)),
    ("Amazon S3", re.compile(r"https?://s3[.\-][a-z0-9.\-]*amazonaws\.com/[a-z0-9.\-_]+", re.I)),
    ("Google Cloud Storage", re.compile(r"https?://storage\.googleapis\.com/[a-z0-9.\-_]+", re.I)),
    ("Google Cloud Storage", re.compile(r"https?://[a-z0-9.\-_]+\.storage\.googleapis\.com", re.I)),
    ("Azure Blob Storage", re.compile(r"https?://[a-z0-9]+\.blob\.core\.windows\.net/[a-z0-9.\-]+", re.I)),
]

# Signatures of a public listing response.
_LISTING_RE = re.compile(r"<ListBucketResult|<EnumerationResults|<Contents>|<Blob>", re.I)


def _bucket_root(url: str) -> str:
    """Trim to the bucket root: scheme://host plus one path segment for path-style
    URLs (…amazonaws.com/bucket), or just the host for virtual-host style
    (bucket.s3.amazonaws.com)."""
    m = re.match(r"(https?://[^/]+)(/[^/?#]+)?", url)
    if not m:
        return url
    return m.group(1) + (m.group(2) or "")


def extract_bucket_urls(html: str) -> list[tuple[str, str]]:
    found: dict[str, str] = {}
    for provider, rx in _BUCKET_PATTERNS:
        for m in rx.finditer(html or ""):
            root = _bucket_root(m.group(0))
            found.setdefault(root, provider)
    return [(provider, url) for url, provider in found.items()]


def _is_publicly_listable(client: httpx.Client, url: str) -> bool:
    try:
        r = client.get(url + ("&" if "?" in url else "?") + "list-type=2", timeout=8)
    except httpx.HTTPError:
        return False
    return r.status_code == 200 and bool(_LISTING_RE.search(r.text))


def check_cloud_buckets(client: httpx.Client, probe) -> list[Finding]:
    findings: list[Finding] = []
    for provider, url in extract_bucket_urls(getattr(probe, "body_snippet", ""))[:5]:
        try:
            if _is_publicly_listable(client, url):
                findings.append(Finding(
                    check_id="open-cloud-bucket", title=f"Publicly listable {provider} bucket",
                    severity="high", url=url,
                    description=f"A {provider} bucket referenced by the site lets anyone list its contents.",
                    impact="Attackers can enumerate and download every object in the bucket — a data breach.",
                    evidence=f"Listing response returned from {url}",
                    remediation="Disable public list permissions; restrict the bucket policy/ACL to least privilege.",
                    compliance_ref="OWASP A05:2021",
                ))
        except Exception:  # noqa: BLE001
            continue
    return findings
