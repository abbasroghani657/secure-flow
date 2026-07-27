# Pentrixa CLI + GitHub Action

Run Pentrixa security scans from your terminal or CI pipeline and **fail the build
when new vulnerabilities appear** — shift security left, catch issues before they
ship.

The CLI is a single Python file with **zero dependencies** (standard library only),
so it runs on any CI runner that has Python 3.8+.

## 1. Get an API token

In the dashboard: **Settings → API tokens → New token**. Copy it once (it is shown
only at creation) and store it somewhere safe. In CI, add it as a secret named
`PENTRIXA_TOKEN`.

> API tokens and CI scanning are a **Pro** feature.

## 2. Verify your target

You can only scan a domain you have proven you control. Add and verify the target
in the dashboard first (DNS TXT record, HTML meta tag, or `.well-known` file).

## 3. Run a scan locally

```bash
export PENTRIXA_TOKEN=ptx_xxx
python3 pentrixa.py scan https://staging.example.com --type web --fail-on high
```

Exit codes:

| Code | Meaning |
|------|---------|
| `0`  | Scan finished, nothing at or above `--fail-on` |
| `1`  | Findings at or above `--fail-on` — **build fails** |
| `2`  | Usage / auth / unverified-target error |
| `3`  | Scan failed or timed out |

Options: `--type` (web, headers, api, …), `--fail-on` (info/low/medium/high/critical),
`--timeout`, `--poll`, `--json`.

## 4. Add it to GitHub Actions

```yaml
- name: Pentrixa scan
  uses: pentrixa/scan-action@v1
  with:
    target: https://staging.example.com
    token: ${{ secrets.PENTRIXA_TOKEN }}
    fail-on: high
```

A complete workflow is in [`examples/github-workflow.yml`](examples/github-workflow.yml).

## Self-hosted / other CI

Point the CLI at any Pentrixa API with `PENTRIXA_API`:

```bash
PENTRIXA_API=https://pentrixa.internal.mycorp.com python3 pentrixa.py scan https://app --fail-on medium
```

Works the same in GitLab CI, CircleCI, Jenkins — anywhere you can run Python and set
two environment variables.
