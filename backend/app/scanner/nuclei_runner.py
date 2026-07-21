"""Nuclei deep-scan integration.

Shells out to the Nuclei binary (ProjectDiscovery), runs its template engine
against a verified target, and parses the JSONL output into our Finding shape.

Intrusive / DoS / fuzzing templates are excluded — this stays a safe, mostly
passive assessment even though Nuclei sends active probes. Only ever run against
a target whose ownership the user has verified.
"""

from __future__ import annotations

import json
import os
import subprocess
import threading
import time
from pathlib import Path

from ..config import settings
from .checks import Finding

# nuclei severity -> our severity (both use the same words; map "unknown" to info)
_SEV_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "unknown": "info",
}

# Tags we refuse to run — anything that could damage or overload a target.
_EXCLUDE_TAGS = "dos,intrusive,fuzz,brute-force"

# High-signal template set for a bounded deep scan. The full CVE corpus is too
# large to sweep synchronously; a job queue (roadmap) will lift this restriction.
_DEFAULT_TAGS = "ssl,tech,misconfiguration,exposure,exposed-panels,default-login,cve"


def nuclei_binary() -> str | None:
    """Locate the nuclei binary: explicit config, then bundled bin/, then PATH."""
    if settings.nuclei_path and Path(settings.nuclei_path).exists():
        return settings.nuclei_path
    bundled = Path(__file__).resolve().parents[2] / "bin" / ("nuclei.exe" if os.name == "nt" else "nuclei")
    if bundled.exists():
        return str(bundled)
    from shutil import which

    return which("nuclei")


def _compliance_ref(info: dict) -> str:
    cls = info.get("classification") or {}
    for key, prefix in (("cve-id", ""), ("cwe-id", "")):
        val = cls.get(key)
        if val:
            first = val[0] if isinstance(val, list) else val
            if first:
                return str(first).upper()
    tags = info.get("tags")
    if tags:
        return (tags[0] if isinstance(tags, list) else str(tags)).upper()
    return "Nuclei"


def _to_finding(rec: dict) -> Finding:
    info = rec.get("info") or {}
    severity = _SEV_MAP.get((info.get("severity") or "info").lower(), "info")
    matched = rec.get("matched-at") or rec.get("host") or ""
    desc = (info.get("description") or "").strip()
    remediation = (info.get("remediation") or "").strip() or "Review the referenced template and vendor guidance."
    name = info.get("name") or rec.get("template-id") or "Nuclei finding"

    evidence_bits = []
    if rec.get("template-id"):
        evidence_bits.append(f"template: {rec['template-id']}")
    if rec.get("matcher-name"):
        evidence_bits.append(f"matcher: {rec['matcher-name']}")
    extracted = rec.get("extracted-results")
    if extracted:
        evidence_bits.append("extracted: " + ", ".join(map(str, extracted))[:160])

    return Finding(
        check_id=f"nuclei-{rec.get('template-id', 'unknown')}",
        title=name,
        severity=severity,
        url=matched,
        description=desc,
        impact=(info.get("impact") or "").strip(),
        evidence=" | ".join(evidence_bits),
        remediation=remediation,
        compliance_ref=_compliance_ref(info),
        passed=False,
    )


def run_nuclei(url: str, timeout: int = 180) -> list[Finding]:
    """Run nuclei against ``url``, returning findings.

    Output is read incrementally, so if the ``timeout`` deadline is reached the
    process is stopped but every finding collected up to that point is kept
    (nothing is discarded). Returns an empty list only if nuclei is unavailable.
    """
    binary = nuclei_binary()
    if not binary:
        return []

    cmd = [
        binary,
        "-u", url,
        "-jsonl",              # machine-readable JSONL on stdout
        "-silent",             # suppress banner/logs so stdout is clean
        "-no-color",
        "-disable-update-check",
        "-tags", _DEFAULT_TAGS,
        "-exclude-tags", _EXCLUDE_TAGS,
        "-timeout", "8",       # per-request timeout (seconds)
        "-rate-limit", "50",   # be gentle with the target
        "-concurrency", "40",
    ]

    lines: list[str] = []

    def _read(stream):
        for line in stream:
            lines.append(line)

    creationflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        encoding="utf-8",
        errors="replace",
        creationflags=creationflags,
    )
    reader = threading.Thread(target=_read, args=(proc.stdout,), daemon=True)
    reader.start()

    deadline = time.time() + timeout
    while proc.poll() is None and time.time() < deadline:
        time.sleep(0.5)
    if proc.poll() is None:  # deadline hit — stop but keep what we have
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
    reader.join(timeout=5)

    findings: list[Finding] = []
    for line in lines:
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        findings.append(_to_finding(rec))
    return findings
