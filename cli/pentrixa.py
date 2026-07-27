#!/usr/bin/env python3
"""Pentrixa CLI — run a security scan from your terminal or CI pipeline.

Zero dependencies (Python 3.8+ standard library only), so it drops straight into
any CI runner. Authenticates with a Pentrixa API token.

Usage:
    export PENTRIXA_TOKEN=ptx_xxx
    pentrixa.py scan https://app.example.com --type web --fail-on high

Env:
    PENTRIXA_TOKEN   API token (create one in Settings -> API tokens). Required.
    PENTRIXA_API     API base URL (default: https://api.pentrixa.app).

Exit codes:
    0  scan finished and nothing at/above --fail-on
    1  findings at/above --fail-on severity (fails the build)
    2  usage / auth / target error
    3  scan failed or timed out
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
DEFAULT_API = "https://api.pentrixa.app"

# CI runners (especially Windows) may use a non-UTF-8 console. Never let an
# unusual character in a finding title crash the run.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def _api_base() -> str:
    return os.environ.get("PENTRIXA_API", DEFAULT_API).rstrip("/")


def _token() -> str:
    tok = os.environ.get("PENTRIXA_TOKEN", "").strip()
    if not tok:
        _die(2, "PENTRIXA_TOKEN is not set. Create a token in Settings -> API tokens.")
    return tok


def _die(code: int, msg: str) -> "None":
    print(f"pentrixa: {msg}", file=sys.stderr)
    sys.exit(code)


def _request(method: str, path: str, body: dict | None = None) -> dict:
    url = _api_base() + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {_token()}")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")
        try:
            detail = json.loads(detail).get("detail", detail)
        except Exception:
            pass
        if e.code == 401:
            _die(2, "authentication failed. Check PENTRIXA_TOKEN.")
        if e.code == 402:
            _die(2, f"upgrade required: {detail}")
        if e.code == 403:
            _die(2, f"target not authorized: {detail}. Verify the target in the dashboard first.")
        _die(2, f"API error {e.code}: {detail}")
    except urllib.error.URLError as e:
        _die(2, f"cannot reach {url}: {e.reason}")
    return {}


def _bar(counts: dict) -> str:
    return (f"{counts.get('critical_count', 0)} critical, "
            f"{counts.get('high_count', 0)} high, "
            f"{counts.get('medium_count', 0)} medium, "
            f"{counts.get('low_count', 0)} low")


def cmd_scan(args: argparse.Namespace) -> int:
    _token()  # fail fast with a clean message if the token is missing
    threshold = SEVERITY_ORDER.index(args.fail_on)
    print(f"pentrixa: starting {args.type} scan of {args.url}")
    scan = _request("POST", "/api/scans", {"target_url": args.url, "scan_type": args.type})
    scan_id = scan.get("id")
    if not scan_id:
        _die(3, "scan was not created")
    print(f"pentrixa: scan #{scan_id} queued")

    deadline = time.time() + args.timeout
    detail = scan
    while True:
        detail = _request("GET", f"/api/scans/{scan_id}")
        status = detail.get("status")
        if status in ("completed", "failed"):
            break
        if time.time() > deadline:
            _die(3, f"timed out after {args.timeout}s (scan still {status})")
        print(f"pentrixa: {status}... {detail.get('progress', 0)}%")
        time.sleep(args.poll)

    if detail.get("status") == "failed":
        _die(3, f"scan failed: {detail.get('error', 'unknown error')}")

    score = detail.get("security_score")
    print(f"\npentrixa: scan complete - score {score}/100")
    print(f"pentrixa: {_bar(detail)}")

    findings = [f for f in detail.get("findings", []) if not f.get("passed")]
    blocking = [f for f in findings
                if SEVERITY_ORDER.index(f.get("severity", "info")) >= threshold]

    if args.json:
        print(json.dumps(detail, indent=2))
    else:
        for f in sorted(findings, key=lambda x: -SEVERITY_ORDER.index(x.get("severity", "info")))[:50]:
            mark = "x" if f in blocking else "-"
            print(f"  [{mark}] {f.get('severity', '').upper():8} {f.get('title', '')}  ({f.get('url', '')})")

    report = f"{_api_base().replace('api.', 'app.')}/scans/{scan_id}"
    print(f"\npentrixa: full report -> {report}")

    if blocking:
        print(f"\npentrixa: FAIL — {len(blocking)} finding(s) at or above '{args.fail_on}'.",
              file=sys.stderr)
        return 1
    print(f"\npentrixa: PASS — nothing at or above '{args.fail_on}'.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pentrixa", description="Pentrixa security scanner CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="Run a scan and (optionally) fail the build on findings")
    s.add_argument("url", help="Target URL (must be a verified target on your account)")
    s.add_argument("--type", default="web", help="Scan type (default: web)")
    s.add_argument("--fail-on", default="high", choices=SEVERITY_ORDER,
                   help="Minimum severity that fails the build (default: high)")
    s.add_argument("--timeout", type=int, default=900, help="Max seconds to wait (default: 900)")
    s.add_argument("--poll", type=int, default=5, help="Seconds between status checks (default: 5)")
    s.add_argument("--json", action="store_true", help="Print the full result as JSON")
    s.set_defaults(func=cmd_scan)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
