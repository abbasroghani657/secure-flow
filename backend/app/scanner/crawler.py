"""A small, polite same-origin crawler.

Discovers pages, forms and parameterised URLs so the scanner can look beyond the
homepage. Bounded by page count and depth, same-origin only, and it never submits
anything — it only follows links and records where user input flows.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urljoin, urlparse, urldefrag

import httpx
from bs4 import BeautifulSoup

SKIP_EXT = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".css", ".js",
    ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".zip", ".gz", ".mp4", ".mp3",
    ".avi", ".mov", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
)


@dataclass
class Form:
    action: str
    method: str  # get | post
    inputs: list[str]  # field names


@dataclass
class CrawlResult:
    pages: list[str] = field(default_factory=list)          # discovered page URLs
    param_urls: list[str] = field(default_factory=list)     # URLs carrying query params
    forms: list[Form] = field(default_factory=list)         # discovered forms


def _same_origin(a: str, b: str) -> bool:
    pa, pb = urlparse(a), urlparse(b)
    return (pa.scheme, pa.netloc) == (pb.scheme, pb.netloc)


def crawl(client: httpx.Client, base_url: str, max_pages: int = 20, max_depth: int = 2) -> CrawlResult:
    result = CrawlResult()
    seen: set[str] = set()
    q: deque[tuple[str, int]] = deque([(base_url, 0)])

    while q and len(result.pages) < max_pages:
        url, depth = q.popleft()
        url, _ = urldefrag(url)
        if url in seen:
            continue
        seen.add(url)

        try:
            r = client.get(url)
        except httpx.HTTPError:
            continue
        ctype = r.headers.get("content-type", "")
        if "text/html" not in ctype:
            continue

        result.pages.append(url)
        if urlparse(url).query:
            result.param_urls.append(url)

        try:
            soup = BeautifulSoup(r.text, "html.parser")
        except Exception:
            continue

        # forms
        for form in soup.find_all("form"):
            action = urljoin(url, form.get("action") or url)
            if not _same_origin(base_url, action):
                continue
            method = (form.get("method") or "get").strip().lower()
            names = [i.get("name") for i in form.find_all(["input", "textarea", "select"]) if i.get("name")]
            if names:
                result.forms.append(Form(action=action, method="post" if method == "post" else "get", inputs=names))

        if depth >= max_depth:
            continue

        # links
        for a in soup.find_all("a", href=True):
            nxt = urljoin(url, a["href"])
            nxt, _ = urldefrag(nxt)
            if not _same_origin(base_url, nxt):
                continue
            if any(urlparse(nxt).path.lower().endswith(ext) for ext in SKIP_EXT):
                continue
            if urlparse(nxt).query and nxt not in result.param_urls:
                result.param_urls.append(nxt)
            if nxt not in seen:
                q.append((nxt, depth + 1))

    # de-dupe param urls by path+param-set to avoid testing the same shape repeatedly
    result.param_urls = _dedupe_param_urls(result.param_urls)
    return result


def _dedupe_param_urls(urls: list[str]) -> list[str]:
    seen_shapes: set[tuple] = set()
    out: list[str] = []
    for u in urls:
        p = urlparse(u)
        shape = (p.path, tuple(sorted(parse_qs(p.query).keys())))
        if shape in seen_shapes:
            continue
        seen_shapes.add(shape)
        out.append(u)
    return out
