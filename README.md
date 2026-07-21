# SecureFlow

A full-stack web application security scanning platform (DAST). Users register,
add a target they own, and run a security scan that checks real HTTP responses for
vulnerabilities, misconfigurations and exposures — then get prioritised, fixable
findings mapped to OWASP Top 10:2025 / CWE / PCI DSS / ISO 27001.

> **Authorised use only.** SecureFlow performs passive, unauthenticated GET
> requests. A target can only be scanned after the user has **proven ownership**
> of the domain (DNS TXT, HTML meta tag, or a `.well-known` file). Scanning of
> private/loopback addresses is blocked.

## Getting started (local dev)

```bash
# 1. Backend
cd backend
python -m venv .venv
.venv/Scripts/activate          # Windows  (macOS/Linux: source .venv/bin/activate)
pip install -r requirements.txt
cp .env.example .env            # then set a strong JWT_SECRET
alembic upgrade head            # create the database schema
python scripts/install_nuclei.py   # optional: download the Nuclei binary for deep scans
uvicorn app.main:app --reload --port 8077

# 2. Frontend (new terminal)
cd frontend
npm install
cp .env.example .env
npm run dev                     # http://localhost:5173
```

Or run the whole stack (Postgres + backend + worker + nginx) with **Docker Compose**:

```bash
cp .env.docker.example .env     # set POSTGRES_PASSWORD and JWT_SECRET
docker compose up --build
```

> The Nuclei binary (`backend/bin/`), the dev database, and every `.env` are
> git-ignored — never committed. Run `scripts/install_nuclei.py` after cloning
> if you want deep scans.

## Domain ownership verification

Before any scan, the user adds a target and proves control of it via **any one** of:

- **DNS TXT record** — `secureflow-verify=<token>` on the host
- **HTML meta tag** — `<meta name="secureflow-verify" content="<token>">` on the homepage
- **Verification file** — the token at `/.well-known/secureflow-verify.txt`

The backend re-checks the live domain on demand; only verified targets can be
scanned. This is what makes running a scan legally defensible.

## Stack

| Layer | Tech |
| --- | --- |
| Frontend | React 18 + Vite + React Router |
| Backend | FastAPI (Python 3.11) |
| Database | SQLite (dev) / Postgres (prod) via SQLModel; **Alembic** migrations |
| Auth | JWT (bearer tokens), pbkdf2 hashing, **rate-limited** endpoints |
| Hardening | Security headers on every response, brute-force rate limiting, prod secret guard |
| Deploy | **Docker Compose** — Postgres + backend + worker + nginx frontend |
| Scanner | Built-in Python engine (httpx) **+ Nuclei** deep-scan engine (ProjectDiscovery). |

## What the scanner checks (built-in engine)

**Passive (headers / TLS / config):**
- HTTPS / TLS presence, HTTP→HTTPS redirect, and **TLS certificate expiry**
- HSTS, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options,
  Referrer-Policy, Permissions-Policy
- Cookie flags (Secure, HttpOnly, SameSite)
- Server / X-Powered-By version disclosure
- Insecure CORS (wildcard origin + credentials)
- **Mixed content** on HTTPS pages
- **Dangerous HTTP methods** (PUT/DELETE/TRACE via OPTIONS)
- **Directory listing** on common directories
- **Email security**: missing/weak **SPF** and **DMARC** DNS records
- **~20 exposed sensitive paths** — `.git/`, `.svn/`, `.hg/`, `.env`(.local),
  SQL dumps, `.aws/credentials`, `.htpasswd`, `.npmrc`, config/WP backups,
  `docker-compose.yml`, Swagger, `phpinfo.php`, `server-status`, … — validated
  with per-file content signatures and a **soft-404 baseline** to avoid false positives
- `security.txt` presence

**Active (crawl + injection tests — verified targets only):**
- A same-origin **crawler** discovers pages, forms and parameterised URLs
- **SQL Injection**, **NoSQL Injection**, **OS Command Injection**, **Reflected
  XSS**, **Server-Side Template Injection (SSTI)**, **Server-Side Request Forgery
  (SSRF)**, **XML External Entity (XXE)**, **CRLF / HTTP response splitting**,
  **Host header injection**, **Open Redirect**, and **Path Traversal / LFI** are
  probed with non-destructive payloads on discovered parameters and GET forms
- **Potential DOM-based XSS** — static source→sink analysis of first-party JavaScript
- **Open (publicly listable) cloud storage buckets** referenced by the site (S3/GCS/Azure)
- **GraphQL introspection**, **verbose error / stack-trace disclosure**,
  **sensitive data in HTML comments**, and **session tokens in URLs**

**Client-side & supply chain (passive):**
- **Outdated / vulnerable JS libraries** (jQuery, AngularJS, Bootstrap, Lodash, …)
- **Missing Subresource Integrity (SRI)** on third-party scripts/styles
- **Missing CSRF token** on state-changing forms
- **Reverse tabnabbing** (`target=_blank` without `rel=noopener`)
- **Subdomain takeover** (dangling CNAMEs to unclaimed services)

> Active tests send crafted-but-harmless inputs (no data change, no brute force,
> no DoS) and only run because the target's ownership was verified first.

## AI/LLM and Mobile scanning (modules)

Beyond the web scanner, two standalone engines cover other OWASP families:

- **OWASP LLM Top 10** (`app/scanner/llm_scanner.py`) — probes a live LLM app
  endpoint (you supply the URL, a JSON body template with `{{PROMPT}}`, headers,
  and the response field path) for **prompt injection**, **jailbreak / guardrail
  bypass**, **system-prompt leakage**, **improper output handling** (HTML/XSS
  echo), and **sensitive information disclosure**. Detection is canary-based to
  keep false positives near zero.
- **OWASP Mobile Top 10** (`app/scanner/mobile_scanner.py`) — static analysis of
  an Android **APK** (a ZIP): scans for **hardcoded secrets** (Google/AWS/Stripe/
  Firebase/private keys) and reads the manifest for **debuggable** builds,
  **allowBackup**, **cleartext traffic**, **exported components**, and a low
  **minSdkVersion**.

> These run against apps/endpoints you own or are authorised to test. They are
> wired as engines today; the API/UI scan types for them are the next step.

## Authenticated scanning

A scan can optionally carry a **session cookie or bearer token** from a logged-in
session on the verified target (New Scan → "Authenticated scan"). The scanner then
crawls and tests pages **behind the login**, multiplying coverage, and runs a
**broken-access-control** check: pages found while authenticated are re-fetched
without the session — any that return identical content are flagged (forced
browsing / missing authorization, A01). Credentials are used for that scan only
and **cleared from the database the moment it finishes** (never exposed via the API).

> Production hardening TODO: encrypt the in-flight `auth_headers` at rest.

### IDOR / BOLA (two-account) testing

The "IDOR / BOLA" scan type (`app/scanner/access_control.py`) takes credentials
for **two** accounts. It crawls as user A to find object-reference URLs (paths or
params carrying an id/uuid), then for each one compares three responses — A
(owner), anonymous (must be blocked), and B (a different user). If **B receives
A's object**, object-level authorization is broken (OWASP API #1, CWE-639). The
three-way comparison keeps false positives low, and a same-account guard warns if
the two sessions look identical. Both credential sets are cleared after the scan.

## Standards mapping (OWASP 2025 + CWE)

Every finding is tagged (centrally, in `app/taxonomy.py`) with its **OWASP Top
10:2025** category (A01–A10), a **CWE ID**, and the **affected layer**
(frontend / api / backend / database / infra). The results page groups findings
by OWASP category in an "OWASP Top 10" view and shows the CWE on each finding.

**Honest coverage.** SecureFlow is a black-box, unauthenticated scanner. It
detects issues visible from the outside: injection (SQLi/NoSQLi/command/SSTI/
XSS/SSRF/CRLF/host-header), misconfiguration, exposed files, weak crypto/TLS,
missing headers, email-spoofing gaps, outdated JS libraries, SRI/CSRF/tabnabbing,
subdomain takeover, and information disclosure.

It does **not** detect classes that genuinely need authentication, source code,
or human judgement — these require the authenticated-scanning project or code
review and are called out rather than silently missed:
IDOR/BOLA & access-control logic, privilege escalation, mass assignment,
insecure deserialization, business logic (price/coupon/race conditions), file
upload abuse, MFA/session-fixation, weak password policy, and A09 logging/alerting
gaps (which need internal/infra visibility). Some black-box classes remain on the
roadmap too: DOM-based XSS (needs JS analysis), XXE, HTTP request smuggling,
web cache poisoning, and open cloud-bucket enumeration.

**Deep scan (Nuclei):** the "Deep scan" type additionally runs the bundled Nuclei
engine against the verified target with a curated, high-signal template set
(`ssl,tech,misconfiguration,exposure,exposed-panels,default-login,cve`), with
`dos/intrusive/fuzz/brute-force` templates excluded and a time-bounded run that
keeps partial results. The Nuclei binary lives in `backend/bin/` (git-ignored);
override with `NUCLEI_PATH`.

Each result is a finding (with severity, impact, evidence, remediation and a
compliance reference) or a passed control. The scan produces a 0–100 security
score weighted by exploitability.

## Continuous monitoring

A background worker (`app/worker.py`) drains a DB-backed scan queue with bounded
concurrency, recovers scans orphaned by a restart, and enqueues due **schedules**.
Schedules run a verified target daily or weekly; each completed scan is diffed
against the target's previous scan to flag **new** findings, and an email alert
(logged if SMTP is unconfigured) fires on new or high-severity issues. Run the
worker in-process (`WORKER_IN_PROCESS=true`, default) or standalone with
`python -m app.worker`.

## Reports

Every completed scan has an **Export report** button that opens a print-optimised
Security Assessment Report (`/scans/:id/report`) — logo header, executive summary
with risk rating, severity breakdown, per-finding remediation, a compliance
summary table and passed controls. "Print / Save as PDF" turns it into a
shareable client/auditor deliverable.

## Running locally

Two terminals.

### 1. Backend (port 8077)

```bash
cd backend
py -m venv .venv
# Windows:
.venv/Scripts/python -m pip install -r requirements.txt
.venv/Scripts/python -m uvicorn app.main:app --reload --port 8077
```

Copy `.env.example` to `.env` and set a strong `JWT_SECRET` before production.
API docs: http://127.0.0.1:8077/docs

### 2. Frontend (port 5173)

```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:5173

The frontend reads the API base URL from `frontend/.env` (`VITE_API_URL`).

## Deploy with Docker

The whole stack — Postgres, the API, a standalone scan worker, and the nginx-served
frontend — comes up with one command:

```bash
cp .env.docker.example .env   # then set strong POSTGRES_PASSWORD and JWT_SECRET
docker compose up --build
```

Then open http://localhost:8080. nginx serves the SPA and proxies `/api` to the
backend; the backend runs `alembic upgrade head` on start; the worker runs as its
own process (`python -m app.worker`). To enable Nuclei "Deep scan" in the
container, uncomment the Nuclei install lines in `backend/Dockerfile`.

## Database migrations (Alembic)

The schema is versioned with Alembic, so model changes no longer require wiping
the database.

```bash
cd backend
# after editing app/models.py:
.venv/Scripts/python -m alembic revision --autogenerate -m "describe change"
.venv/Scripts/python -m alembic upgrade head
```

In dev, `AUTO_CREATE_TABLES=true` also creates any missing tables on startup for
convenience. In production set it to `false` and let `alembic upgrade head`
(run by the Docker entrypoint) own the schema.

## Security hardening

SecureFlow is built to pass its own scan: every API response carries
`X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`,
`Permissions-Policy`, a locked-down CSP and (in production) HSTS; auth endpoints
are rate-limited (login 10/min, register 5/min) to blunt brute force; and the app
refuses to start in production while `JWT_SECRET` is still the default.

## Project layout

```
secure flow/
├── backend/
│   └── app/
│       ├── main.py            # FastAPI app + CORS + routers
│       ├── config.py          # settings (.env)
│       ├── database.py        # engine + session
│       ├── models.py          # User, Target, Scan, Finding
│       ├── security.py        # hashing + JWT
│       ├── schemas.py         # request/response models
│       ├── deps.py            # auth dependency
│       ├── routers/           # auth.py, scans.py
│       └── scanner/           # checks.py, engine.py  ← the scan logic
├── frontend/
│   └── src/
│       ├── api.js             # fetch client
│       ├── auth.jsx           # auth context
│       ├── theme.js           # design tokens
│       ├── components/ui.jsx
│       └── pages/             # Landing, Auth, Dashboard, NewScan, ScanResults
└── docker-compose.yml        # full stack: Postgres + backend + worker + nginx
```

## Roadmap (next steps toward production)

- [x] **Target ownership verification** — DNS TXT / meta-tag / file challenge; scans gated on verified targets.
- [x] **Nuclei integration** — "Deep scan" type runs the bundled Nuclei binary (bounded, high-signal templates, intrusive/DoS excluded) and merges JSONL results into findings.
- [x] **Background worker / queue** — DB-backed queue with a bounded worker, claim-by-status, and crash recovery. Deployable in-process (dev) or standalone (`python -m app.worker`).
- [x] **Scheduled scans & notifications** — daily/weekly recurring scans per verified target; new-finding detection vs the previous scan; email (or logged) alerts on new/high-severity issues.
- [x] **Postgres + Alembic migrations** — schema is versioned; `create_all` only for dev convenience.
- [x] **Security hardening** — security headers on every response, auth rate limiting, prod secret guard.
- [x] **Docker deployment** — `docker compose up` brings up Postgres + backend + worker + nginx frontend.
- [ ] **Billing/subscriptions (Stripe)** — plans, scan quotas, checkout (needs a Stripe account/keys).
- [ ] **Multiple worker processes** — needs row-level locking (`SELECT ... FOR UPDATE`) on the claim; full-CVE deep sweeps once unbounded.
- [ ] **Team/org accounts, multi-page crawling, server-side PDF.**
- [ ] **Email verification, password reset, audit log, CAPTCHA** on auth.
- [ ] **Automated test suite** and CI/CD.
```
