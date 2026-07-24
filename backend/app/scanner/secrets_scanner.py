"""Secrets scanning for a source-code archive.

Upload a ZIP of a repository (or a single text file); every text file is scanned
for leaked credentials — provider-specific API keys/tokens, private keys, and
high-entropy strings assigned to secret-looking variables. This is the
GitGuardian / TruffleHog / gitleaks category, built in-house.

Purely static and offline — nothing is sent anywhere. Matches are redacted in
the evidence so the report never re-leaks the secret.
"""

from __future__ import annotations

import io
import math
import re
import zipfile

from .checks import Finding

# --------------------------------------------------------------------------- #
# Provider detectors: (name, compiled regex, severity, high_confidence)
# High-confidence = a structurally unique token (few false positives).
# --------------------------------------------------------------------------- #
_DETECTORS: list[tuple[str, re.Pattern, str, bool]] = [
    ("AWS access key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "critical", True),
    ("AWS secret access key",
     re.compile(r"(?i)aws.{0,20}?(secret|private).{0,20}?['\"]([0-9a-zA-Z/+]{40})['\"]"), "critical", True),
    ("GitHub personal access token", re.compile(r"\bghp_[0-9A-Za-z]{36}\b"), "critical", True),
    ("GitHub OAuth/app token", re.compile(r"\bgh[ousr]_[0-9A-Za-z]{36}\b"), "critical", True),
    ("GitHub fine-grained token", re.compile(r"\bgithub_pat_[0-9A-Za-z_]{82}\b"), "critical", True),
    ("GitLab personal access token", re.compile(r"\bglpat-[0-9A-Za-z_\-]{20}\b"), "critical", True),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "high", True),
    ("Google OAuth client secret", re.compile(r"\bGOCSPX-[0-9A-Za-z_\-]{28}\b"), "high", True),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,48}\b"), "high", True),
    ("Slack webhook URL", re.compile(r"https://hooks\.slack\.com/services/T[0-9A-Za-z_/]{20,}"), "high", True),
    ("Stripe secret key", re.compile(r"\b[rs]k_live_[0-9A-Za-z]{20,}\b"), "critical", True),
    ("Twilio account SID", re.compile(r"\bAC[0-9a-fA-F]{32}\b"), "high", True),
    ("Twilio API key", re.compile(r"\bSK[0-9a-fA-F]{32}\b"), "high", True),
    ("SendGrid API key", re.compile(r"\bSG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}\b"), "critical", True),
    ("Mailgun API key", re.compile(r"\bkey-[0-9a-zA-Z]{32}\b"), "high", True),
    ("npm access token", re.compile(r"\bnpm_[0-9A-Za-z]{36}\b"), "high", True),
    ("PyPI upload token", re.compile(r"\bpypi-AgEIcHlwaS5vcmc[0-9A-Za-z_\-]{50,}"), "critical", True),
    ("Square access token", re.compile(r"\b(sq0atp|sq0csp)-[0-9A-Za-z_\-]{22,43}\b"), "high", True),
    ("Private key block",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----"), "critical", True),
    ("JSON Web Token (JWT)",
     re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"), "medium", True),
    ("Basic-auth credentials in URL",
     re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.\-]*://[^/\s:@]+:([^/\s:@${}<>%]{3,})@[^/\s:@]+"), "high", True),
    ("Google service-account private key id",
     re.compile(r'"private_key_id"\s*:\s*"[0-9a-f]{40}"'), "high", True),
    # --- Cloud providers ---
    ("Azure Storage account key", re.compile(r"AccountKey=[A-Za-z0-9+/]{86}=="), "critical", True),
    ("DigitalOcean access token", re.compile(r"\bdo[oprt]_v1_[a-f0-9]{64}\b"), "critical", True),
    ("GCP service-account credentials", re.compile(r'"type"\s*:\s*"service_account"'), "high", True),
    ("Kubernetes kubeconfig", re.compile(r"(?m)^\s*kind:\s*Config\b"), "high", True),
    # --- SaaS / API providers ---
    ("OpenAI API key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}T3BlbkFJ[A-Za-z0-9_\-]{20,}\b"), "critical", True),
    ("Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{24,}\b"), "critical", True),
    ("Shopify access token", re.compile(r"\bshp(at|ss|ca|pa)_[a-fA-F0-9]{32}\b"), "critical", True),
    ("Discord bot token", re.compile(r"\b[MNO][A-Za-z0-9_\-]{23}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,}\b"), "high", True),
    ("Discord webhook URL", re.compile(r"https://(?:canary\.|ptb\.)?discord(?:app)?\.com/api/webhooks/\d+/[\w\-]+"), "medium", True),
    ("Telegram bot token", re.compile(r"\b\d{8,10}:[A-Za-z0-9_\-]{35,}\b"), "high", True),
    ("New Relic user key", re.compile(r"\bNRAK-[A-Z0-9]{27}\b"), "high", True),
    ("Sentry DSN", re.compile(r"https://[0-9a-f]{32}@[\w.\-]+/\d+"), "medium", True),
    ("Atlassian API token", re.compile(r"\bATATT3[A-Za-z0-9_\-=]{20,}\b"), "high", True),
    ("HashiCorp Vault token", re.compile(r"\bhvs\.[A-Za-z0-9_\-]{20,}\b"), "critical", True),
    ("Mailchimp API key", re.compile(r"\b[0-9a-f]{32}-us\d{1,2}\b"), "high", True),
    ("PayPal/Braintree access token", re.compile(r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}"), "critical", True),
    ("Cloudflare API token", re.compile(r"(?i)cloudflare.{0,20}['\"][A-Za-z0-9_\-]{40}['\"]"), "high", True),
    ("Datadog API key", re.compile(r"(?i)datadog.{0,20}['\"][0-9a-f]{32}['\"]"), "high", True),
    # --- Data stores ---
    ("Database connection string with password",
     re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?|mssql|mariadb)://[^/\s:@]+:([^/\s:@${}<>%]{3,})@[^/\s:@]+"), "high", True),
]

# Generic "assignment" secrets — a secret-looking name set to a literal.
# The name may carry a prefix (GITHUB_TOKEN, dbPassword), so allow leading
# identifier chars before the keyword; the value-side entropy check is the
# real false-positive guard.
_ASSIGN_RE = re.compile(
    r"""(?ix)
    \b(
        [a-z0-9]* [_-]?
        (?:
            password | passwd | pwd | secret(?:[_-]?key)? | api[_-]?key | apikey |
            access[_-]?key | auth[_-]?token | client[_-]?secret | private[_-]?key |
            encryption[_-]?key | db[_-]?pass(?:word)? | token
        )
    )
    \s* [:=] \s*
    ['"]([^'"\s${}<>]{8,120})['"]
    """,
)

# Values that look like a secret assignment but are clearly not real.
_PLACEHOLDER_RE = re.compile(
    r"(?i)^(?:changeme|change_me|example|examplepassword|your[_-]?|xxx+|placeholder|redacted|"
    r"none|null|true|false|test|testing|password|secret|123456|abcdef|dummy|sample|"
    r"\{\{.*\}\}|<.*>|\$\{.*\}|%\(.*\)s|process\.env|os\.environ).*"
)

# Directories/files that are noise (vendored deps, build output, lockfiles, VCS).
_SKIP_DIR = re.compile(r"(^|/)(node_modules|vendor|\.git|dist|build|out|target|"
                       r"__pycache__|\.venv|venv|site-packages|bower_components|\.next|\.nuxt)(/|$)")
_SKIP_FILE = re.compile(r"(?i)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock|"
                        r"composer\.lock|Cargo\.lock|go\.sum|\.min\.(js|css)|\.map)$")
_BINARY_EXT = re.compile(r"(?i)\.(png|jpe?g|gif|ico|webp|bmp|pdf|zip|gz|tar|7z|rar|jar|war|"
                         r"class|exe|dll|so|dylib|o|a|bin|wasm|woff2?|ttf|eot|mp[34]|mov|"
                         r"avi|mkv|pyc|pdb|db|sqlite3?)$")

_MAX_FILE_BYTES = 1_000_000       # skip files bigger than 1 MB
_MAX_FILES = 4000                 # bound total files scanned
_MAX_FINDINGS = 400               # bound findings


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _redact(token: str) -> str:
    token = token.strip()
    if len(token) <= 8:
        return token[0] + "…"
    return f"{token[:4]}…{token[-2:]} ({len(token)} chars)"


def _line_no(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _looks_like_secret_value(val: str) -> bool:
    """Entropy + charset heuristics for a generic assignment value."""
    if _PLACEHOLDER_RE.match(val):
        return False
    if len(val) < 8:
        return False
    # Mostly a single repeated char, or a plain English-ish word → not a secret.
    if re.fullmatch(r"[a-zA-Z]{1,20}", val):
        return False
    ent = _shannon_entropy(val)
    has_mixed = bool(re.search(r"[0-9]", val)) and bool(re.search(r"[a-zA-Z]", val))
    # Base64/hex-looking high-entropy blob, or a decent-entropy mixed string.
    if re.fullmatch(r"[A-Za-z0-9+/=_\-]{16,}", val) and ent >= 3.5:
        return True
    if has_mixed and ent >= 3.0 and len(val) >= 12:
        return True
    return False


def scan_text(path: str, text: str) -> list[Finding]:
    """Scan a single file's text and return findings, each anchored to a line."""
    findings: list[Finding] = []
    seen: set[str] = set()
    # Values already reported by a specific detector, keyed by line+value, so the
    # generic assignment heuristic below doesn't re-report the same secret.
    reported_values: set[str] = set()

    for name, rx, sev, _hc in _DETECTORS:
        for m in rx.finditer(text):
            token = m.group(0)
            # For URL basic-auth / secret-in-quotes, the sensitive part is a group.
            secret = m.group(m.lastindex) if m.lastindex else token
            line = _line_no(text, m.start())
            key = f"{name}:{path}:{line}:{secret[:10]}"
            if key in seen:
                continue
            seen.add(key)
            reported_values.add(f"{line}:{secret[:16]}")
            findings.append(Finding(
                check_id=f"secret-{name}".lower().replace(" ", "-").replace("/", "-").replace("(", "").replace(")", ""),
                title=f"Exposed secret: {name}", severity=sev,
                url=f"{path}:{line}",
                description=f"A {name} was found committed in `{path}` (line {line}).",
                impact="A leaked credential lets an attacker use the associated service/account directly — a top breach vector.",
                evidence=f"{path}:{line} → {_redact(secret)}",
                remediation="Revoke/rotate this credential immediately, then remove it from the code and load it from a secret store or environment variable. Rotating is essential — git history keeps the old value.",
                compliance_ref="OWASP A05:2021",
            ))
            if len(findings) >= _MAX_FINDINGS:
                return findings

    for m in _ASSIGN_RE.finditer(text):
        var, val = m.group(1), m.group(2)
        if not _looks_like_secret_value(val):
            continue
        line = _line_no(text, m.start())
        if f"{line}:{val[:16]}" in reported_values:  # already flagged by a specific detector
            continue
        key = f"assign:{path}:{line}:{val[:10]}"
        if key in seen:
            continue
        seen.add(key)
        findings.append(Finding(
            check_id="secret-hardcoded-assignment",
            title=f"Hardcoded secret in variable ('{var}')", severity="high",
            url=f"{path}:{line}",
            description=f"A high-entropy value is assigned to `{var}` in `{path}` (line {line}), which looks like a hardcoded secret.",
            impact="Hardcoded credentials in source leak to everyone with repo access and persist in git history.",
            evidence=f"{path}:{line} → {var} = {_redact(val)}",
            remediation="Move the value to an environment variable or secret manager and rotate it if it was ever real.",
            compliance_ref="OWASP A05:2021",
        ))
        if len(findings) >= _MAX_FINDINGS:
            break
    return findings


def _iter_zip_files(data: bytes):
    """Yield (path, text) for scannable text files inside a ZIP."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return
    count = 0
    for info in zf.infolist():
        if info.is_dir():
            continue
        name = info.filename
        if _SKIP_DIR.search(name) or _SKIP_FILE.search(name) or _BINARY_EXT.search(name):
            continue
        if info.file_size > _MAX_FILE_BYTES or info.file_size == 0:
            continue
        count += 1
        if count > _MAX_FILES:
            break
        try:
            raw = zf.read(info)
        except (zipfile.BadZipFile, RuntimeError, OSError):
            continue
        # Heuristic binary check: NUL byte in the first chunk.
        if b"\x00" in raw[:1024]:
            continue
        yield name, raw.decode("utf-8", "replace")


def run_secrets_scan(filename: str, data: bytes) -> list[Finding]:
    """Scan an uploaded archive (ZIP) or a single text file for secrets."""
    findings: list[Finding] = []
    files_scanned = 0

    if data[:2] == b"PK":  # ZIP archive
        for path, text in _iter_zip_files(data):
            files_scanned += 1
            findings.extend(scan_text(path, text))
            if len(findings) >= _MAX_FINDINGS:
                break
    else:  # single text file
        try:
            text = data.decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            text = ""
        files_scanned = 1
        findings.extend(scan_text(filename, text))

    # De-duplicate identical secrets seen across multiple files (same token+type).
    unique: dict[str, Finding] = {}
    for f in findings:
        k = f"{f.check_id}:{f.evidence.split(chr(10))[0]}"
        unique.setdefault(k, f)
    findings = list(unique.values())

    if not findings:
        findings.append(Finding(
            "secrets-clean", f"No exposed secrets found ({files_scanned} file(s) scanned)", "info",
            filename, description="No leaked credentials were detected in the scanned files.",
            remediation="Keep secret scanning in CI to catch newly-committed credentials.",
            compliance_ref="OWASP A05:2021", passed=True,
        ))
    # Sort: real findings by severity, passed last.
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: (f.passed, order.get(f.severity, 5)))
    return findings
