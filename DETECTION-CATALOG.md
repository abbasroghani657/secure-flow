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
| 1 | SQL Injection | CWE-89 |
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
