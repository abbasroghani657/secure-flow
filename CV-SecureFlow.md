# SecureFlow — CV / Résumé entry

Repository: https://github.com/abbasroghani657/secure-flow

---

## One-liner (for a CV project line)

**SecureFlow — Full-stack web application security scanner (DAST)** · React, FastAPI, Python
Built a production-style vulnerability scanning platform that detects 50+ classes of web
vulnerabilities mapped to OWASP Top 10:2025 and CWE, with authenticated scanning, an
LLM/Mobile security module, and a background scan engine.

---

## Résumé bullet points (copy-paste)

**SecureFlow — Web Application Security Scanning Platform**
*Personal project · React, FastAPI (Python), SQLModel, Docker*

- Built a full-stack **DAST platform** that crawls a target and actively tests for **50+ vulnerability
  types** across the **OWASP Top 10:2025** — SQL/NoSQL injection, XSS, SSRF, SSTI, OS command
  injection, CSRF, path traversal, security misconfigurations and more — each finding tagged with its
  **OWASP category, CWE ID, severity and remediation**.
- Engineered a **domain-ownership verification** gate (DNS/HTML/file) and **authenticated scanning**
  (session-based) so scans are legally defensible and can test behind a login.
- Integrated the **Nuclei** engine (thousands of CVE templates) and added dedicated **OWASP LLM Top 10**
  (prompt injection, jailbreak, system-prompt leakage) and **OWASP Mobile Top 10** (Android APK static
  analysis) modules.
- Implemented a **background job queue + scheduler** for recurring scans, **email alerts** on new
  findings, and exportable **PDF security reports**.
- Designed the backend with **JWT auth, rate limiting, Alembic migrations, a soft-404/false-positive
  engine**, and a **Docker Compose** deployment (Postgres + API + worker + nginx).

---

## Skills demonstrated (keywords for ATS / recruiters)

Application Security · DAST · OWASP Top 10 · CWE · Penetration Testing Concepts ·
SQL Injection · XSS · SSRF · SSTI · CSRF · Python · FastAPI · REST APIs · React ·
SQLModel/SQLAlchemy · Alembic · JWT Authentication · Background Workers / Job Queues ·
Docker · Nuclei · LLM Security · Mobile (Android) Security · Git/GitHub

---

## 2–3 sentence portfolio / LinkedIn description

SecureFlow is a full-stack web security scanner I built end-to-end. It verifies domain
ownership, then crawls and actively (but safely) tests the target for 50+ vulnerability
classes across the OWASP Top 10:2025 — from SQL injection and XSS to SSRF and SSTI — and
presents prioritised, CWE-tagged findings with fixes and exportable PDF reports. It also
includes authenticated scanning, a Nuclei-powered deep scan, and dedicated modules for
LLM and Android mobile app security.

---

> Honest scope note (useful in interviews): SecureFlow is a **black-box + authenticated
> DAST** tool. It does not claim to cover classes that require source code or manual
> review (e.g. business-logic flaws). Being explicit about detection limits is itself a
> security-engineering best practice.
