"""Static Application Security Testing (SAST) for a source archive.

Upload a ZIP of source code; each file is analysed for dangerous constructs.
Python is analysed with the real `ast` module (structural, low false-positive);
other languages use a curated ruleset of dangerous sinks. This is the
Snyk Code / SonarQube / Semgrep category, built in-house with no external
scanner dependency.

Findings are anchored to file:line and mapped to CWE / OWASP by the taxonomy.
"""

from __future__ import annotations

import ast
import io
import re
import zipfile

from .checks import Finding

# Reuse the archive-walking hygiene from the secrets scanner.
from .secrets_scanner import _SKIP_DIR, _SKIP_FILE, _BINARY_EXT

_MAX_FILES = 3000
_MAX_FINDINGS = 500
_MAX_FILE_BYTES = 1_000_000


def _f(check_id, title, severity, path, line, description, remediation, impact="", evidence="") -> Finding:
    return Finding(
        check_id=check_id, title=title, severity=severity, url=f"{path}:{line}",
        description=description, impact=impact,
        evidence=evidence or f"{path}:{line}", remediation=remediation,
        compliance_ref="OWASP A03:2021",
    )


# --------------------------------------------------------------------------- #
# Python — AST-based analysis
# --------------------------------------------------------------------------- #
def _dotted_name(node: ast.AST) -> str:
    """Resolve a call target like os.system / subprocess.run / hashlib.md5."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _is_dynamic(node: ast.AST) -> bool:
    """True if the expression is not a plain string/number literal."""
    if isinstance(node, ast.Constant):
        return False
    # Tuple/list of constants (e.g. subprocess.run(["ls", "-la"])) is static.
    if isinstance(node, (ast.List, ast.Tuple)):
        return any(_is_dynamic(e) for e in node.elts)
    return True


def _is_tainted_sql(node: ast.AST) -> bool:
    """A SQL string built by f-string / % / + concatenation → likely injectable."""
    if isinstance(node, ast.JoinedStr):  # f"... {x} ..."
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mod, ast.Add)):
        # "... %s ..." % x   or   "..." + x
        return True
    if isinstance(node, ast.Call):
        fn = _dotted_name(node.func)
        if fn.endswith(".format"):  # "...".format(x)
            return True
    return False


class _PyVisitor(ast.NodeVisitor):
    def __init__(self, path: str):
        self.path = path
        self.findings: list[Finding] = []

    def _add(self, *a, **kw):
        self.findings.append(_f(*a, **kw))

    def visit_Call(self, node: ast.Call):
        name = _dotted_name(node.func)
        short = name.split(".")[-1]
        args = node.args
        kw = {k.arg: k.value for k in node.keywords}
        ln = node.lineno

        # eval / exec of dynamic input → code injection
        if name in ("eval", "exec") and args and _is_dynamic(args[0]):
            self._add("sast-py-code-injection", f"Dynamic {name}() — code injection risk", "high",
                      self.path, ln,
                      description=f"`{name}()` is called on a non-literal expression.",
                      impact="If any part of the expression is user-controlled, the attacker runs arbitrary Python.",
                      remediation=f"Avoid {name}() on dynamic input; use a safe parser (ast.literal_eval) or explicit dispatch.",
                      evidence=f"{name}(...) at line {ln}")

        # OS command execution
        if name in ("os.system", "os.popen", "os.spawnl", "os.spawnv") and args and _is_dynamic(args[0]):
            self._add("sast-py-command-injection", "OS command injection risk", "high",
                      self.path, ln,
                      description=f"`{name}()` runs a dynamically-built command string.",
                      impact="User-controlled input in a shell command allows arbitrary command execution.",
                      remediation="Use subprocess with an argument list and shell=False; never build shell strings from input.",
                      evidence=f"{name}(...) at line {ln}")
        if name.startswith("subprocess.") and kw.get("shell") is not None:
            v = kw["shell"]
            if isinstance(v, ast.Constant) and v.value is True:
                dyn = args and _is_dynamic(args[0])
                self._add("sast-py-command-injection", "subprocess called with shell=True", "high" if dyn else "medium",
                          self.path, ln,
                          description="A subprocess call uses shell=True.",
                          impact="shell=True with any dynamic argument enables command injection via shell metacharacters.",
                          remediation="Pass an argument list and use shell=False (the default).",
                          evidence=f"{name}(..., shell=True) at line {ln}")

        # Insecure deserialization
        if name in ("pickle.loads", "pickle.load", "cPickle.loads", "marshal.loads",
                    "dill.loads", "shelve.open"):
            self._add("sast-py-insecure-deserialization", f"Insecure deserialization ({short})", "high",
                      self.path, ln,
                      description=f"`{name}()` deserialises data that may be attacker-controlled.",
                      impact="Unpickling untrusted data executes arbitrary code (RCE).",
                      remediation="Never unpickle untrusted data; use JSON or a signed, schema-validated format.",
                      evidence=f"{name}(...) at line {ln}")
        if name in ("yaml.load",) and "Loader" not in kw:
            self._add("sast-py-unsafe-yaml", "Unsafe yaml.load() without SafeLoader", "high",
                      self.path, ln,
                      description="yaml.load() is called without a safe Loader.",
                      impact="Unsafe YAML loading can instantiate arbitrary Python objects (RCE).",
                      remediation="Use yaml.safe_load() or pass Loader=yaml.SafeLoader.",
                      evidence=f"yaml.load(...) at line {ln}")

        # SQL injection — tainted string into an execute()
        if short in ("execute", "executemany", "executescript", "raw", "extra") and args and _is_tainted_sql(args[0]):
            self._add("sast-py-sql-injection", "Possible SQL injection (string-built query)", "high",
                      self.path, ln,
                      description=f"A query passed to `{short}()` is built with f-string/%/+/.format().",
                      impact="Concatenating input into SQL allows an attacker to alter the query (data theft, auth bypass).",
                      remediation="Use parameterised queries (execute(sql, params)); never build SQL by string formatting.",
                      evidence=f"{short}(<f-string/concat>) at line {ln}")

        # SSTI via Flask render_template_string
        if short == "render_template_string" and args and _is_dynamic(args[0]):
            self._add("sast-py-ssti", "Server-side template injection (render_template_string)", "high",
                      self.path, ln,
                      description="render_template_string() renders a dynamically-built template.",
                      impact="User input in a Jinja2 template string leads to RCE via template injection.",
                      remediation="Render static template files with a context dict; never build templates from input.",
                      evidence=f"render_template_string(...) at line {ln}")

        # Weak hashing
        if name in ("hashlib.md5", "hashlib.sha1"):
            self._add("sast-py-weak-hash", f"Weak hash function ({short})", "low",
                      self.path, ln,
                      description=f"`{name}()` uses a cryptographically weak hash.",
                      impact="MD5/SHA-1 are broken for security use (collisions); unsafe for passwords/signatures.",
                      remediation="Use SHA-256+ for integrity, and a password hash (bcrypt/argon2/scrypt) for passwords.",
                      evidence=f"{name}() at line {ln}")

        # Disabled TLS verification
        if isinstance(kw.get("verify"), ast.Constant) and kw["verify"].value is False:
            self._add("sast-py-tls-verify-disabled", "TLS certificate verification disabled (verify=False)", "medium",
                      self.path, ln,
                      description="An HTTP request sets verify=False.",
                      impact="Disabling verification allows man-in-the-middle interception of the connection.",
                      remediation="Remove verify=False; trust the proper CA bundle or pin the certificate.",
                      evidence=f"{short}(..., verify=False) at line {ln}")

        # Flask debug mode
        if short == "run" and isinstance(kw.get("debug"), ast.Constant) and kw["debug"].value is True:
            self._add("sast-py-debug-enabled", "Flask app run with debug=True", "medium",
                      self.path, ln,
                      description="app.run(debug=True) enables the Werkzeug debugger.",
                      impact="The interactive debugger allows arbitrary code execution if reachable in production.",
                      remediation="Never run with debug=True in production; gate it behind an env var.",
                      evidence=f"run(debug=True) at line {ln}")

        # Insecure temp file
        if name == "tempfile.mktemp":
            self._add("sast-py-insecure-tempfile", "Insecure temporary file (tempfile.mktemp)", "low",
                      self.path, ln,
                      description="tempfile.mktemp() is subject to race conditions.",
                      impact="A predictable temp path can be hijacked (symlink/TOCTOU attacks).",
                      remediation="Use tempfile.mkstemp() or NamedTemporaryFile().",
                      evidence=f"tempfile.mktemp() at line {ln}")

        self.generic_visit(node)


def scan_python(path: str, text: str) -> list[Finding]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return []
    v = _PyVisitor(path)
    v.visit(tree)
    return v.findings


# --------------------------------------------------------------------------- #
# Other languages — curated dangerous-sink patterns
# Each rule: (check_id, title, severity, regex, description, remediation)
# --------------------------------------------------------------------------- #
def R(cid, title, sev, pattern, desc, rem):
    return (cid, title, sev, re.compile(pattern), desc, rem)


_JS_RULES = [
    # --- Code / command execution ---
    R("sast-js-code-injection", "Code injection via eval()/Function()/vm", "high",
      r"\b(eval|new\s+Function|vm\.runIn\w+)\s*\(",
      "eval()/new Function()/vm executes a string as code.",
      "Avoid eval/Function on any dynamic value; use JSON.parse or explicit logic."),
    R("sast-js-code-injection", "Timer called with a string (implicit eval)", "medium",
      r"\bset(Timeout|Interval)\s*\(\s*[`'\"]",
      "setTimeout/setInterval with a string argument runs it as code.",
      "Pass a function reference, never a string."),
    R("sast-js-command-injection", "OS command injection (child_process)", "high",
      r"child_process\.(exec|execSync)\s*\(\s*[`'\"]?[^)]*(\$\{|[`'\"]\s*\+)|\bexec(Sync)?\s*\(\s*[`'\"][^`'\"]*[`'\"]\s*\+",
      "child_process.exec runs a shell command built from a template/concatenation.",
      "Use execFile/spawn with an argument array; never interpolate input into a shell string."),
    # --- XSS ---
    R("sast-js-dom-xss", "DOM XSS sink (innerHTML/document.write/insertAdjacentHTML)", "medium",
      r"\.(innerHTML|outerHTML)\s*=|\bdocument\.write(ln)?\s*\(|\.insertAdjacentHTML\s*\(|dangerouslySetInnerHTML",
      "Assigning untrusted data to innerHTML/document.write/dangerouslySetInnerHTML causes XSS.",
      "Use textContent / safe DOM APIs, or sanitise with DOMPurify before rendering."),
    R("sast-js-dom-xss", "Angular XSS guard bypass (bypassSecurityTrust*)", "high",
      r"bypassSecurityTrust(Html|Script|Url|ResourceUrl|Style)\s*\(",
      "Angular's bypassSecurityTrust disables the built-in XSS sanitiser.",
      "Let Angular sanitise; if you must trust content, sanitise it explicitly first."),
    R("sast-js-xss", "Vue v-html renders raw HTML", "low",
      r"v-html\s*=",
      "v-html renders raw HTML and can introduce XSS with dynamic content.",
      "Avoid v-html for user content; render text or sanitise with DOMPurify."),
    # --- SQL / NoSQL ---
    R("sast-js-sql-injection", "Possible SQL injection (string-built query)", "high",
      r"\.(query|execute|raw)\s*\(\s*[`'\"][^`'\")]*(\$\{|[\"']\s*\+)",
      "A SQL query is built with template literals / string concatenation.",
      "Use parameterised queries / prepared statements, or a query builder with bindings."),
    R("sast-js-nosql-injection", "Possible NoSQL injection (request input in a query)", "high",
      r"\.(find|findOne|update\w*|delete\w*|remove|aggregate)\s*\(\s*\{[^}]*:\s*req\.(body|query|params)|\$where\s*:",
      "A MongoDB query uses request input directly as a value, or uses the $where operator.",
      "Cast/validate input types (e.g. String(x)); never pass raw req values into queries; avoid $where."),
    # --- Path traversal / SSRF / redirect ---
    R("sast-js-path-traversal", "Path traversal (fs/sendFile with request input)", "high",
      r"(fs\.(readFile|readFileSync|createReadStream|unlink)|res\.sendFile|res\.download)\s*\([^)]*req\.(query|params|body)",
      "A filesystem path is built from request input.",
      "Resolve the path and verify it stays inside an allowed base directory."),
    R("sast-js-ssrf", "Server-side request forgery (request URL from input)", "high",
      r"\b(axios|fetch|got|superagent|https?|request|node-fetch)(\.\w+)?\s*\(\s*[`'\"]?[^)]{0,50}req\.(query|params|body)",
      "An outbound HTTP request uses a URL taken from the incoming request.",
      "Allowlist destinations; block internal IPs and cloud metadata (169.254.169.254)."),
    R("sast-js-open-redirect", "Open redirect (res.redirect with request input)", "medium",
      r"res\.redirect\s*\(\s*[^)]{0,30}req\.(query|params|body)",
      "A redirect target is taken directly from request input.",
      "Redirect only to a validated allowlist of relative paths."),
    # --- Prototype pollution ---
    R("sast-js-prototype-pollution", "Prototype pollution sink", "medium",
      r"__proto__\s*\]|constructor\s*\[\s*[`'\"]prototype|\[\s*req\.(body|query|params)[\w.\[\]]*\]\s*=",
      "Assigning to a key taken from user input can pollute Object.prototype.",
      "Validate keys against an allowlist; use Map or Object.create(null)."),
    # --- Crypto / random ---
    R("sast-js-weak-hash", "Weak hash function (MD5/SHA-1)", "low",
      r"createHash\s*\(\s*[`'\"](md5|sha1)[`'\"]",
      "MD5/SHA-1 are cryptographically broken.",
      "Use SHA-256+; for passwords use bcrypt/argon2/scrypt."),
    R("sast-js-weak-crypto", "Deprecated createCipher (weak key, no IV)", "medium",
      r"crypto\.createCipher\s*\(",
      "createCipher derives a weak key and uses no IV.",
      "Use createCipheriv with a random IV and an AES-GCM cipher."),
    R("sast-js-weak-random", "Math.random() used for a security value", "low",
      r"(token|secret|key|password|nonce|otp|session|salt|iv)\w*\s*[=:]\s*[^;\n]*Math\.random\s*\(",
      "Math.random() is not cryptographically secure.",
      "Use crypto.randomBytes()/crypto.getRandomValues() for security values."),
    # --- TLS ---
    R("sast-js-tls-verify-disabled", "TLS verification disabled", "high",
      r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[`'\"]?0",
      "TLS certificate verification is turned off.",
      "Never disable verification; trust the proper CA store or pin the certificate."),
    # --- JWT ---
    R("sast-js-weak-jwt", "Insecure JWT — 'none' algorithm allowed", "high",
      r"jwt\.(verify|sign)\s*\([^)]*algorithms?\s*:\s*\[?[^\]]*[`'\"]none[`'\"]",
      "JWT is configured to allow the 'none' (unsigned) algorithm.",
      "Always specify an explicit algorithms allowlist that excludes 'none'."),
    R("sast-js-weak-jwt", "Hardcoded JWT signing secret", "medium",
      r"jwt\.sign\s*\([^,]+,\s*[`'\"][A-Za-z0-9_\-]{6,}[`'\"]",
      "The JWT signing secret is hardcoded in source.",
      "Load the signing secret from an environment variable or secret manager."),
    # --- Deserialization ---
    R("sast-js-insecure-deserialization", "Insecure deserialization (node-serialize)", "high",
      r"\bunserialize\s*\(",
      "node-serialize's unserialize() executes embedded functions — remote code execution.",
      "Use JSON.parse for untrusted data; never unserialize user input."),
    # --- CORS ---
    R("sast-js-cors-misconfig", "Permissive CORS (Allow-Origin: *)", "medium",
      r"cors\s*\(\s*\{[^}]*origin\s*:\s*[`'\"]\*[`'\"]|[`'\"]Access-Control-Allow-Origin[`'\"]\s*,\s*[`'\"]\*",
      "CORS allows any origin; with credentials this exposes user data cross-site.",
      "Reflect only an allowlist of trusted origins; never use '*' with credentials."),
    # --- Cookies ---
    R("sast-js-insecure-cookie", "Cookie security flag explicitly disabled", "low",
      r"(httpOnly|secure)\s*:\s*false",
      "A cookie disables httpOnly/secure, exposing it to theft.",
      "Set httpOnly, secure and sameSite on session cookies."),
    # --- ReDoS ---
    R("sast-js-redos", "Dynamic RegExp built from input (ReDoS)", "low",
      r"new\s+RegExp\s*\([^)]*\b(req\.(query|params|body)|userInput|\binput\b|\bparam\b)",
      "A RegExp is built from user input — vulnerable to ReDoS / regex injection.",
      "Avoid dynamic regexes from input; validate/escape or use a safe matcher."),
    # --- Sensitive logging ---
    R("sast-js-sensitive-logging", "Secret written to logs", "low",
      r"console\.(log|info|debug|error|warn)\s*\([^)]*\b(password|secret|api[_-]?key|access[_-]?token|private[_-]?key)\b",
      "A secret is written to the console/logs.",
      "Never log secrets; redact sensitive fields before logging."),
]

_PHP_RULES = [
    R("sast-php-command-injection", "OS command injection", "high",
      r"\b(system|exec|shell_exec|passthru|popen|proc_open)\s*\([^)]*\$",
      "A shell command is executed with a PHP variable.",
      "Use escapeshellarg()/escapeshellcmd(), or avoid shelling out with user input."),
    R("sast-php-code-injection", "Code injection via eval()", "high",
      r"\beval\s*\(\s*\$|\bassert\s*\(\s*\$",
      "eval()/assert() executes a variable as PHP code.",
      "Remove eval()/assert() on dynamic input; use explicit logic."),
    R("sast-php-file-inclusion", "Remote/Local file inclusion", "high",
      r"\b(include|include_once|require|require_once)\s*\(?\s*\$_(GET|POST|REQUEST|COOKIE)",
      "A file is included directly from request input.",
      "Whitelist allowed files; never include a path taken from the request."),
    R("sast-php-sql-injection", "Possible SQL injection", "high",
      r"->query\s*\(\s*[\"'][^\"')]*\$|mysql(i)?_query\s*\([^)]*\$_(GET|POST|REQUEST)",
      "A SQL query concatenates request input.",
      "Use prepared statements (PDO/mysqli) with bound parameters."),
    R("sast-php-object-injection", "PHP object injection (unserialize)", "high",
      r"\bunserialize\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)",
      "unserialize() is called on request input.",
      "Use json_decode() for untrusted data; never unserialize user input."),
    R("sast-php-xss", "Reflected XSS (echo of request input)", "medium",
      r"\becho\s+[^;]*\$_(GET|POST|REQUEST)",
      "Request input is echoed to the page without encoding.",
      "HTML-encode output with htmlspecialchars()."),
]

_JAVA_RULES = [
    R("sast-java-command-injection", "OS command injection (Runtime.exec)", "high",
      r"Runtime\.getRuntime\(\)\.exec\s*\([^)]*(\+|String\.format)",
      "Runtime.exec() runs a command built by concatenation/format.",
      "Use ProcessBuilder with an argument list and validated input."),
    R("sast-java-sql-injection", "Possible SQL injection (Statement + concat)", "high",
      r"(createStatement\(\)[\s\S]{0,80}?execute(Query|Update)?\s*\([^)]*\+)|executeQuery\s*\(\s*\"[^\"]*\"\s*\+",
      "A SQL statement is built by string concatenation.",
      "Use PreparedStatement with bound parameters."),
    R("sast-java-insecure-deserialization", "Insecure deserialization (ObjectInputStream)", "high",
      r"new\s+ObjectInputStream\s*\(",
      "Java native deserialization is used.",
      "Avoid Java serialization for untrusted data; use a safe format and validate types."),
    R("sast-java-weak-hash", "Weak hash algorithm (MD5/SHA-1)", "low",
      r"MessageDigest\.getInstance\s*\(\s*\"(MD5|SHA-1|SHA1)\"",
      "A weak hash algorithm is requested.",
      "Use SHA-256+, and bcrypt/argon2/PBKDF2 for passwords."),
    R("sast-java-weak-crypto", "Weak cipher (DES / ECB mode)", "medium",
      r"Cipher\.getInstance\s*\(\s*\"(DES|DESede|.*ECB.*)\"",
      "A weak cipher or ECB mode is used.",
      "Use AES in GCM (or CBC with random IV) mode."),
    R("sast-java-trust-all-certs", "TLS verification disabled (trust-all TrustManager)", "high",
      r"(checkServerTrusted\s*\([^)]*\)\s*\{\s*\}|TrustAllCerts|X509TrustManager\s*\(\s*\)\s*\{)",
      "A TrustManager that accepts all certificates is defined.",
      "Never disable certificate validation; trust the platform CA store."),
]

_GO_RULES = [
    R("sast-go-command-injection", "OS command injection (exec.Command)", "high",
      r"exec\.Command\s*\(\s*\"(sh|bash|/bin/sh|cmd)\"|exec\.Command\([^)]*fmt\.Sprintf",
      "exec.Command runs a shell or a formatted command string.",
      "Pass a fixed binary and an argument slice; avoid invoking a shell with dynamic input."),
    R("sast-go-sql-injection", "Possible SQL injection (fmt.Sprintf query)", "high",
      r"\.(Query|Exec|QueryRow)\s*\(\s*fmt\.Sprintf",
      "A SQL query is built with fmt.Sprintf.",
      "Use parameter placeholders ($1, ?) with query arguments."),
    R("sast-go-tls-skip-verify", "TLS verification disabled (InsecureSkipVerify)", "high",
      r"InsecureSkipVerify\s*:\s*true",
      "tls.Config sets InsecureSkipVerify: true.",
      "Remove InsecureSkipVerify; verify certificates against a CA pool."),
    R("sast-go-weak-hash", "Weak hash function (md5/sha1)", "low",
      r"\b(md5|sha1)\.(New|Sum)\b",
      "A weak hash function is used.",
      "Use crypto/sha256 or stronger; bcrypt/argon2 for passwords."),
]

_RUBY_RULES = [
    R("sast-rb-command-injection", "OS command injection (system/backticks/eval)", "high",
      r"\b(system|exec|`[^`]*#\{)|%x\{[^}]*#\{|\beval\s*\(",
      "A shell command or eval executes interpolated input.",
      "Use system with an argument array; never interpolate input into a command/eval."),
    R("sast-rb-sql-injection", "Possible SQL injection (interpolated query)", "high",
      r"\.(where|find_by_sql|execute)\s*\(\s*\"[^\"]*#\{",
      "A query interpolates a variable via #{...}.",
      "Use parameterised queries / ActiveRecord placeholders."),
]

_LANG_RULES = {
    ".js": _JS_RULES, ".jsx": _JS_RULES, ".ts": _JS_RULES, ".tsx": _JS_RULES, ".mjs": _JS_RULES,
    ".php": _PHP_RULES, ".php5": _PHP_RULES, ".phtml": _PHP_RULES,
    ".java": _JAVA_RULES,
    ".go": _GO_RULES,
    ".rb": _RUBY_RULES,
}


def scan_with_rules(path: str, text: str, rules) -> list[Finding]:
    out: list[Finding] = []
    for cid, title, sev, rx, desc, rem in rules:
        for m in rx.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            out.append(_f(cid, title, sev, path, line, description=desc, remediation=rem,
                          impact="Static analysis flagged a dangerous code pattern that commonly leads to this vulnerability class.",
                          evidence=f"{path}:{line}: {m.group(0)[:80].strip()}"))
    return out


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
def _ext(name: str) -> str:
    n = name.lower()
    dot = n.rfind(".")
    return n[dot:] if dot >= 0 else ""


def scan_file(path: str, text: str) -> list[Finding]:
    ext = _ext(path)
    if ext == ".py":
        return scan_python(path, text)
    rules = _LANG_RULES.get(ext)
    if rules:
        return scan_with_rules(path, text, rules)
    return []


_SUPPORTED = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".php", ".php5",
              ".phtml", ".java", ".go", ".rb"}


def run_sast_scan(filename: str, data: bytes) -> list[Finding]:
    """Analyse an uploaded source archive (ZIP) or a single file."""
    findings: list[Finding] = []
    files = 0

    if data[:2] == b"PK":
        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
        except zipfile.BadZipFile:
            zf = None
        if zf is not None:
            for info in zf.infolist():
                if info.is_dir() or info.file_size == 0 or info.file_size > _MAX_FILE_BYTES:
                    continue
                name = info.filename
                if _SKIP_DIR.search(name) or _SKIP_FILE.search(name) or _BINARY_EXT.search(name):
                    continue
                if _ext(name) not in _SUPPORTED:
                    continue
                files += 1
                if files > _MAX_FILES:
                    break
                try:
                    text = zf.read(info).decode("utf-8", "replace")
                except (zipfile.BadZipFile, RuntimeError, OSError):
                    continue
                findings.extend(scan_file(name, text))
                if len(findings) >= _MAX_FINDINGS:
                    break
    else:
        text = data.decode("utf-8", "replace")
        files = 1
        findings.extend(scan_file(filename, text))

    if files == 0 or (not findings and files):
        if not findings:
            findings.append(Finding(
                "sast-clean", f"No dangerous code patterns found ({files} file(s) scanned)", "info",
                filename, description="Static analysis found no dangerous sinks in the supported source files.",
                remediation="Keep running SAST in CI on every change.",
                compliance_ref="OWASP A03:2021", passed=True,
            ))
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: (f.passed, order.get(f.severity, 5)))
    return findings[:_MAX_FINDINGS]
