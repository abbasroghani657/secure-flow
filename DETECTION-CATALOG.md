# SecureFlow — Detection Catalog

The complete list of vulnerabilities SecureFlow detects (~172 distinct checks across
web, API, authentication, AI/LLM and mobile), plus thousands of CVE templates via
the Nuclei deep-scan engine. Every finding is tagged with severity, its **OWASP
Top 10:2025** category, a **CWE ID**, the affected layer, evidence, and a fix.

---

## 🌐 Web Application

### Injection (OWASP A05)
| # | Vulnerability | CWE |
|---|---|---|
| 1 | SQL Injection (error-based) | CWE-89 |
| 1b | Blind SQL Injection — boolean-based | CWE-89 |
| 1c | Blind SQL Injection — time-based | CWE-89 |
| 2 | NoSQL Injection | CWE-943 |
| 3 | OS Command Injection | CWE-78 |
| 4 | LDAP Injection | CWE-90 |
| 5 | XPath Injection | CWE-643 |
| 6 | XML External Entity (XXE) | CWE-611 |
| 7 | Server-Side Template Injection (SSTI) | CWE-1336 |
| 8 | Client-Side Template Injection (Angular/Vue) | CWE-1336 |
| 9 | Server-Side Includes (SSI) Injection | CWE-97 |
| 10 | Reflected XSS | CWE-79 |
| 11 | DOM-based XSS | CWE-79 |
| 12 | Stored / Second-order XSS | CWE-79 |
| 13 | CRLF / HTTP Response Splitting | CWE-113 |
| 14 | Host Header Injection | CWE-644 |
| 14a | CSV / Formula Injection (spreadsheet export) | CWE-1236 |

### Broken Access Control (OWASP A01)
| # | Vulnerability | CWE |
|---|---|---|
| 15 | IDOR / BOLA (object-level authorization) | CWE-639 |
| 16 | BFLA / Vertical Privilege Escalation | CWE-285 |
| 17 | Forced browsing (page reachable without auth) | CWE-284 |
| 18 | Server-Side Request Forgery (SSRF) | CWE-918 |
| 19 | Path Traversal / LFI | CWE-22 |
| 20 | Open Redirect | CWE-601 |
| 21 | Insecure CORS (wildcard + credentials) | CWE-942 |
| 22 | CORS origin reflection | CWE-942 |
| 23 | CSRF token missing on forms | CWE-352 |
| 24 | Subdomain takeover | CWE-350 |
| 25 | Reverse tabnabbing | CWE-1022 |
| 26 | Excessive data exposure (API) | CWE-213 |
| 27 | WebSocket cross-origin handshake | CWE-1385 |
| 28 | Internal IP / hostname disclosure | CWE-200 |

### Security Misconfiguration (OWASP A02)
| # | Vulnerability | CWE |
|---|---|---|
| 29 | Missing Content-Security-Policy | CWE-1021 |
| 30 | Weak CSP directives (unsafe-eval/wildcard/…) | CWE-1021 |
| 31 | Missing clickjacking protection (X-Frame-Options) | CWE-1021 |
| 32 | Missing X-Content-Type-Options | CWE-693 |
| 33 | Missing Referrer-Policy | CWE-200 |
| 34 | Missing Permissions-Policy | — |
| 35 | Missing COOP | CWE-693 |
| 36 | Missing COEP/CORP | CWE-693 |
| 37 | Server / X-Powered-By version disclosure | CWE-200 |
| 38 | Dangerous HTTP methods (PUT/DELETE/TRACE) | CWE-650 |
| 39 | Directory listing enabled | CWE-548 |
| 40 | GraphQL introspection exposed | CWE-200 |
| 41 | Sensitive data in HTML comments | CWE-615 |
| 42 | Exposed API documentation (Swagger/OpenAPI) | CWE-668 |
| 43 | Deprecated "shadow" API versions | CWE-1059 |
| 44 | Source-code disclosure (backup/swap files) | CWE-540 |
| 45 | Open (publicly listable) cloud bucket (S3/GCS/Azure) | CWE-668 |
| 46 | Publicly readable Firebase database | CWE-668 |
| 47 | Exposed admin dashboards (phpMyAdmin/Adminer/Jenkins/Kibana/Solr/Tomcat) | CWE-668 |
| 48 | Unauthenticated Redis exposed | CWE-668 |
| 49 | Unauthenticated Memcached exposed | CWE-668 |
| 50 | Unauthenticated Elasticsearch exposed | CWE-668 |
| 50a | Unauthenticated MongoDB exposed | CWE-668 |
| 50b | Unauthenticated Docker Engine API exposed (RCE) | CWE-668 |
| 50c | Unauthenticated etcd exposed | CWE-668 |
| 50d | RabbitMQ management interface exposed | CWE-668 |
| 50e | Database port reachable — MySQL/MariaDB | CWE-668 |
| 50f | Database port reachable — PostgreSQL | CWE-668 |
| 51–70 | **~20 exposed sensitive files** — `.git`, `.env`(.local), `.svn`, `.hg`, SQL dumps, `.aws/credentials`, `.htpasswd`, config/WP backups, `docker-compose.yml`, `.npmrc`, `actuator`(+`/env`), `web.config`, `id_rsa`, `xmlrpc.php`, `wp-json` users, `elmah.axd`, `crossdomain.xml`, `.idea`, `phpinfo.php`, `server-status`, `.DS_Store` | CWE-538 |

### Cryptographic Failures (OWASP A04)
| # | Vulnerability | CWE |
|---|---|---|
| 71 | No HTTPS | CWE-319 |
| 72 | No HTTP→HTTPS redirect | CWE-319 |
| 73 | Missing / weak HSTS | CWE-319 |
| 74 | Mixed content | CWE-319 |
| 75 | TLS certificate expired | CWE-295 |
| 76 | TLS certificate expiring soon | CWE-295 |
| 77 | Deprecated TLS 1.0 enabled | CWE-327 |
| 78 | Deprecated TLS 1.1 enabled | CWE-327 |
| 79 | Weak TLS cipher (RC4/3DES/NULL/EXPORT) | CWE-327 |
| 80 | Weak certificate signature (SHA-1) | CWE-327 |
| 81 | Weak certificate key size (<2048) | CWE-326 |
| 82 | Self-signed certificate | CWE-295 |
| 83 | Certificate hostname mismatch | CWE-295 |

### Authentication Failures (OWASP A07)
| # | Vulnerability | CWE |
|---|---|---|
| 84 | JWT accepts `alg=none` | CWE-347 |
| 85 | JWT weak / guessable secret | CWE-347 |
| 85a | JWT algorithm-confusion surface (RS256/ES256 asymmetric) | CWE-347 |
| 85b | JWT `jku` / `x5u` external-key-URL header | CWE-347 |
| 85c | JWT embedded `jwk` (self-provided key) | CWE-347 |
| 85d | JWT `kid` header injection surface (path/SQL) | CWE-347 |
| 86 | JWKS exposure / algorithm-confusion surface | CWE-347 |
| 87 | No brute-force protection on login | CWE-307 |
| 88 | Username enumeration | CWE-203 |
| 89 | Session not invalidated on logout | CWE-613 |
| 90 | Session token exposed in URL | CWE-598 |
| 91 | Weak session cookie flags (Secure/HttpOnly/SameSite) | CWE-614 |

### Insecure Design / Business Logic (OWASP A04/A06)
| # | Vulnerability | CWE |
|---|---|---|
| 92 | Business-logic flaw (parameter tampering) | CWE-840 |
| 93 | Race condition (no locking/idempotency) | CWE-362 |
| 94 | Unrestricted file upload | CWE-434 |
| 95 | Webshell upload → code execution | CWE-434 |
| 96 | File-upload surface (needs validation) | CWE-434 |

### Supply Chain / Data Integrity (OWASP A03/A08)
| # | Vulnerability | CWE |
|---|---|---|
| 97 | Outdated JS libraries (jQuery/Angular/Bootstrap/Lodash/Moment/Handlebars) | CWE-1104 |
| 98 | Secrets in front-end JavaScript | CWE-798 |
| 99 | Missing Subresource Integrity (SRI) | CWE-353 |
| 100 | Insecure deserialization surface (Java/PHP) | CWE-502 |
| 101 | ASP.NET ViewState exposure | CWE-502 |
| 102 | Mass assignment | CWE-915 |

### Client-Side (OWASP A05/A08)
| # | Vulnerability | CWE |
|---|---|---|
| 103 | postMessage handler without origin check | CWE-346 |
| 104 | Sensitive data in local/session storage | CWE-922 |
| 105 | Prototype pollution | CWE-1321 |
| 106 | Insecure JSONP | CWE-79 |

### OAuth (OWASP A01)
| # | Vulnerability | CWE |
|---|---|---|
| 107 | OAuth flow without `state` (CSRF) | CWE-352 |
| 108 | OAuth `redirect_uri` not validated | CWE-601 |

### Denial of Service — *safely detected* (OWASP A06)
| # | Vulnerability | CWE |
|---|---|---|
| 109 | ReDoS (Regular Expression DoS) — bounded timing probe | CWE-1333 |
| 110 | XML entity expansion / billion-laughs — "small laughs" probe | CWE-776 |

### Infrastructure / Errors (OWASP A05/A10/A09)
| # | Vulnerability | CWE |
|---|---|---|
| 111 | HTTP Request Smuggling (timing-based, deep scan) | CWE-444 |
| 112 | Verbose error / stack-trace disclosure | CWE-209 |
| 113 | Missing `security.txt` | CWE-778 |
| 114 | Email: missing SPF | — |
| 115 | Email: missing DMARC | — |
| 116 | Email: weak DMARC policy | — |
| 117 | DNS: zone transfer (AXFR) allowed | CWE-200 |
| 118 | DNS: missing CAA record | CWE-16 |

---

## 🤖 AI / LLM Application (OWASP LLM Top 10:2025)
| # | Vulnerability | OWASP |
|---|---|---|
| 119 | Prompt Injection | LLM01 |
| 120 | Jailbreak / guardrail bypass | LLM01 |
| 121 | Indirect Prompt Injection (via retrieved content) | LLM08 |
| 122 | Sensitive Information Disclosure | LLM02 |
| 123 | Improper Output Handling | LLM05 |
| 124 | Excessive Agency | LLM06 |
| 125 | System Prompt Leakage | LLM07 |
| 126 | Misinformation / hallucination | LLM09 |
| 127 | Unbounded Consumption | LLM10 |

*(LLM03 Supply Chain and LLM04 Model Poisoning are flagged as manual-review items —
they require model/dataset provenance review and are not black-box testable.)*

---

## 📱 Mobile — Android APK (OWASP Mobile Top 10:2024)
| # | Vulnerability | OWASP | CWE |
|---|---|---|---|
| 128–134 | Hardcoded secrets (Google/AWS/Stripe/Firebase/private key/Slack/generic) | M1 | CWE-798 |
| 135 | Weak cryptography (ECB/DES/RC4) | M10 | CWE-327 |
| 136 | Insecure WebView (JS + file access / addJavascriptInterface) | M4 | CWE-749 |
| 137 | Missing certificate pinning | M5 | CWE-295 |
| 138 | Insecure data storage — external storage | M9 | CWE-312 |
| 139 | Insecure data storage — unencrypted SQLite | M9 | CWE-312 |
| 140 | No root / tamper detection | M7 | CWE-919 |
| 141 | Excessive dangerous permissions | M6 | CWE-250 |
| 142 | Publicly readable Firebase (from app) | M9 | CWE-668 |
| 143 | Debuggable release build | M8 | CWE-489 |
| 144 | Backup allowed (allowBackup) | M9 | CWE-530 |
| 145 | Cleartext traffic permitted | M5 | CWE-319 |
| 146 | Exported component without permission | M8 | CWE-926 |
| 147 | Low minimum SDK version | M8 | — |

---

## 🍎 Mobile — iOS IPA (OWASP Mobile Top 10:2024)
| # | Vulnerability | OWASP | CWE |
|---|---|---|---|
| 148 | Hardcoded secrets in app bundle | M1 | CWE-798 |
| 149 | App Transport Security disabled (arbitrary loads) | M5 | CWE-319 |
| 150 | ATS per-domain insecure exception | M5 | CWE-319 |
| 151 | Custom URL scheme(s) registered | M4 | CWE-939 |
| 152 | Binary not compiled as PIE (ASLR) | M7 | CWE-121 |
| 153 | No stack-smashing protection (canaries) | M7 | CWE-121 |
| 154 | No jailbreak detection | M7 | CWE-919 |

---

## 📦 Dependencies — SCA + SBOM (OSV.dev)
| # | Vulnerability | OWASP | CWE |
|---|---|---|---|
| 155 | Known-vulnerable dependency (CVE) — npm / PyPI / Go / RubyGems / Packagist / crates | A03 | CWE-1104 |
| — | Emits a **CycloneDX SBOM** of every parsed component | — | — |

---

## ☁️ Infrastructure-as-Code (Terraform / CloudFormation / Kubernetes / Docker)
| # | Vulnerability | OWASP | CWE |
|---|---|---|---|
| 156 | Public storage bucket (S3 ACL / AccessControl) | A05 | CWE-668 |
| 157 | Security group open to 0.0.0.0/0 on a sensitive port | A05 | CWE-284 |
| 158 | Publicly accessible database (RDS) | A05 | CWE-668 |
| 159 | Storage without encryption at rest (EBS / RDS) | A02 | CWE-311 |
| 160 | IAM policy grants `*` on `*` (full admin) | A01 | CWE-269 |
| 161 | Hardcoded secret / credential in IaC | A05 | CWE-798 |
| 162 | Privileged container (K8s / compose) | A05 | CWE-250 |
| 163 | Container shares host namespace (hostNetwork/PID/IPC) | A05 | CWE-250 |
| 164 | hostPath / Docker-socket volume mount | A05 | CWE-250 |
| 165 | Container allows privilege escalation | A05 | CWE-250 |
| 166 | Container runs as root (UID 0 / no USER) | A05 | CWE-250 |
| 167 | Dangerous Linux capability (SYS_ADMIN/NET_ADMIN/ALL) | A05 | CWE-250 |
| 168 | Unpinned image tag (`:latest` / no tag) | A05 | CWE-16 |
| 169 | Dockerfile: remote script piped to shell / ADD from URL | A05 | CWE-16 |

---

## 🔑 Secrets — source-code archive (GitGuardian/TruffleHog style)
Upload a `.zip` of a repository; every text file is scanned (vendored dirs, lockfiles
and binaries skipped). Matches are **redacted** in the report.
| # | Vulnerability | OWASP | CWE |
|---|---|---|---|
| 170 | AWS access key ID / secret access key | A05 | CWE-798 |
| 171 | GitHub token (classic / fine-grained / OAuth) | A05 | CWE-798 |
| 172 | GitLab / npm / PyPI / Square token | A05 | CWE-798 |
| 173 | Google API key / OAuth client secret | A05 | CWE-798 |
| 174 | Slack token & webhook URL | A05 | CWE-798 |
| 175 | Stripe / Twilio / SendGrid / Mailgun key | A05 | CWE-798 |
| 176 | Private key block (RSA/EC/OpenSSH/PGP) | A05 | CWE-798 |
| 177 | JSON Web Token (JWT) | A05 | CWE-798 |
| 178 | Basic-auth credentials embedded in a URL | A05 | CWE-798 |
| 179 | Hardcoded secret via high-entropy assignment | A05 | CWE-798 |
| 179a | Azure Storage key · DigitalOcean · GCP service-account · kubeconfig | A05 | CWE-798 |
| 179b | OpenAI · Anthropic · Shopify · Discord · Telegram · New Relic tokens | A05 | CWE-798 |
| 179c | Atlassian · HashiCorp Vault · Mailchimp · PayPal · Sentry · Cloudflare · Datadog | A05 | CWE-798 |
| 179d | Database connection string with embedded password | A05 | CWE-798 |

---

## 🔁 CI/CD Pipeline Security (GitHub Actions / GitLab CI)
Upload a workflow file or a `.zip` — supply-chain and pipeline misconfigurations.
| # | Vulnerability | OWASP | CWE |
|---|---|---|---|
| 180 | `pull_request_target` checks out untrusted PR code | A08 | CWE-94 |
| 181 | Script injection from untrusted event data (`${{ github.event.* }}`) | A05 | CWE-94 |
| 182 | Third-party action not pinned to a commit SHA | A08 | CWE-829 |
| 183 | GITHUB_TOKEN granted `write-all` / no explicit permissions | A08 | CWE-829 |
| 184 | Remote script piped into a shell (`curl \| bash`) in CI | A08 | CWE-829 |
| 185 | Secret printed to build logs | A08 | CWE-532 |
| 186 | Self-hosted runner used (fork-PR risk) | A08 | CWE-829 |
| 187 | Deprecated unsecure workflow commands enabled | A08 | CWE-829 |
| 188 | GitLab CI image not pinned to a digest/tag | A08 | CWE-829 |

---

## 🧬 SAST — source code (Python AST + JS/TS/PHP/Java/Go/Ruby rules)
Upload a source `.zip`; Python is analysed with the real `ast` module, other
languages with a curated dangerous-sink ruleset.
| # | Vulnerability | OWASP | CWE |
|---|---|---|---|
| 189 | Code injection — `eval`/`exec`/`Function`/`vm`/timer-string | A05 | CWE-94 |
| 190 | OS command injection — `system`/`exec`/`shell=True`/`child_process` | A05 | CWE-78 |
| 191 | SQL injection — query built by f-string / concat / format | A05 | CWE-89 |
| 192 | Insecure deserialization — `pickle`/`ObjectInputStream`/`unserialize` | A08 | CWE-502 |
| 193 | Unsafe `yaml.load()` without SafeLoader | A08 | CWE-502 |
| 194 | Server-side template injection (`render_template_string`) | A05 | CWE-1336 |
| 195 | DOM XSS / reflected XSS sink (`innerHTML`, `dangerouslySetInnerHTML`, `echo $_GET`) | A05 | CWE-79 |
| 196 | Remote/local file inclusion (`include $_GET`) | A05 | CWE-98 |
| 197 | Weak hash (MD5/SHA-1) / weak cipher (DES/ECB/createCipher) | A02 | CWE-327 |
| 198 | Insecure randomness for security tokens | A02 | CWE-330 |
| 199 | TLS verification disabled (`verify=False`, `rejectUnauthorized:false`, trust-all) | A02 | CWE-295 |
| 200 | Flask `debug=True` / insecure temp file | A05 | CWE-489 |

### 🟦 JavaScript / TypeScript — deep coverage (Node · Express · React · Angular · Vue · NestJS)
Applies to `.js` `.jsx` `.ts` `.tsx` `.mjs` — the **same 29-class ruleset runs on TypeScript**.
| # | Vulnerability | OWASP | CWE |
|---|---|---|---|
| 201 | **NoSQL injection** — request input in a Mongo query / `$where` | A05 | CWE-943 |
| 202 | **SSRF** — `axios`/`fetch`/`http.get` with a request-derived URL | A01 | CWE-918 |
| 203 | **Path traversal** — `fs.readFile`/`sendFile` with request input | A01 | CWE-22 |
| 204 | **Open redirect** — `res.redirect(req.*)` | A01 | CWE-601 |
| 205 | **Prototype pollution** — `__proto__` / user-keyed assignment | A08 | CWE-1321 |
| 206 | **Angular** `bypassSecurityTrust*` / **Vue** `v-html` XSS | A05 | CWE-79 |
| 207 | **Insecure JWT** — `algorithms:['none']` / hardcoded signing secret | A07 | CWE-347 |
| 208 | **Permissive CORS** — `origin: '*'` | A02 | CWE-942 |
| 209 | Cookie flag disabled (`httpOnly:false`/`secure:false`) | A02 | CWE-614 |
| 210 | Dynamic `RegExp` from input (ReDoS) | A06 | CWE-1333 |
| 211 | Secret written to logs (`console.log(password)`) | A09 | CWE-532 |
| 212 | **Server-side template injection** — `handlebars/ejs/pug.compile(req.*)` | A05 | CWE-1336 |
| 213 | **XXE** — XML parser with entity expansion (`noent:true`) | A05 | CWE-611 |
| 214 | **CRLF / header injection** — `res.setHeader(_, req.*)` | A05 | CWE-113 |
| 215 | **Unsafe YAML** — `yaml.load()` without a safe schema | A08 | CWE-502 |
| 216 | **Mass assignment** — `Object.assign(model, req.body)` / `new Model(req.body)` | A08 | CWE-915 |
| 217 | **XPath / LDAP injection** — filter built with request input | A05 | CWE-643 / CWE-90 |
| 218 | **Reflected XSS** — `res.send(req.*)` | A05 | CWE-79 |
| 219 | **Timing-unsafe secret comparison** — `token === userToken` | A02 | CWE-208 |
| 220 | **Zip Slip** — archive entry path used as a write path | A01 | CWE-22 |

---

## ☁️ CSPM — Cloud Security Posture (AWS)
Scan an AWS account with **read-only** credentials (used only for the scan, then
wiped). Prowler / ScoutSuite category.
| # | Vulnerability | OWASP | CWE |
|---|---|---|---|
| 201 | S3 bucket publicly accessible | A05 | CWE-668 |
| 202 | S3 bucket without Block Public Access | A05 | CWE-668 |
| 203 | S3 bucket without default encryption | A02 | CWE-311 |
| 204 | Security group open to 0.0.0.0/0 on a sensitive port | A05 | CWE-284 |
| 205 | EBS volume not encrypted | A02 | CWE-311 |
| 206 | IAM user without MFA | A07 | CWE-308 |
| 207 | IAM access key not rotated (>90 days) | A07 | CWE-521 |
| 208 | Weak / missing IAM password policy | A07 | CWE-521 |
| 209 | RDS instance publicly accessible | A05 | CWE-668 |
| 210 | RDS storage not encrypted | A02 | CWE-311 |
| 211 | CloudTrail audit logging not enabled | A09 | CWE-778 |

---

## 🔬 Deep Scan — Nuclei engine
Thousands of community templates: known **CVEs**, exposed panels, default credentials,
technology/version fingerprinting, and misconfigurations — merged into the findings
with the same severity/OWASP/CWE tagging.

---

## 🧭 Honest scope (what still needs a human)
Every scan surfaces a **"manual review recommended"** advisory for classes no automated
scanner can reliably verify: complex business-logic flaws, deep authorization logic,
insecure design, and (for LLMs) supply-chain / model-poisoning risks. These are called
out explicitly rather than silently missed — honest scope beats false confidence.
