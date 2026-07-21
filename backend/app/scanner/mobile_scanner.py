"""OWASP Mobile Top 10 scanner (Android APK static analysis).

An APK is a ZIP archive. This module opens it, scans its contents for hardcoded
secrets, and reads the AndroidManifest for insecure security flags — no device
or emulator required. Only analyse apps you own or are authorised to test.

Covers: hardcoded credentials (M1), insecure data storage / backup (M9),
insecure communication / cleartext (M5), and security misconfiguration —
debuggable builds and exported components (M8).
"""

from __future__ import annotations

import re
import zipfile
from dataclasses import dataclass

from .checks import Finding

try:
    from pyaxmlparser import APK
    _HAS_AXML = True
except Exception:  # noqa: BLE001
    _HAS_AXML = False

# --- secret patterns (name, regex, severity) ---
SECRET_PATTERNS = [
    ("Google API key", re.compile(rb"AIza[0-9A-Za-z_\-]{35}"), "high"),
    ("AWS access key", re.compile(rb"AKIA[0-9A-Z]{16}"), "critical"),
    ("Private key", re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), "critical"),
    ("Slack token", re.compile(rb"xox[baprs]-[0-9A-Za-z\-]{10,}"), "high"),
    ("Stripe secret key", re.compile(rb"sk_live_[0-9A-Za-z]{20,}"), "critical"),
    ("Firebase database URL", re.compile(rb"[a-z0-9.\-]+\.firebaseio\.com"), "low"),
    ("Generic API key/secret", re.compile(rb"(?i)(?:api[_-]?key|secret|password|auth[_-]?token)['\"]?\s*[:=]\s*['\"][A-Za-z0-9_\-]{12,}['\"]"), "medium"),
]

SCAN_EXTENSIONS = (".xml", ".json", ".properties", ".txt", ".js", ".html", ".dex", ".kotlin_builtins", ".cfg", ".yml", ".yaml", ".env")
DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS", "android.permission.SEND_SMS",
    "android.permission.READ_CONTACTS", "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.RECORD_AUDIO", "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE", "android.permission.CAMERA",
    "android.permission.READ_CALL_LOG", "android.permission.REQUEST_INSTALL_PACKAGES",
}


@dataclass
class MobileTarget:
    apk_path: str
    app_label: str = ""


_WEAK_CRYPTO_RE = re.compile(rb"[A-Za-z0-9]+/ECB/|\bDESede?\b|\bDES/|\bRC4\b|\bARC4\b")


# Indicator byte-strings scanned across the app's dex files.
_NETWORK_IND = (b"okhttp", b"Retrofit", b"HttpsURLConnection", b"Ljava/net/URL", b"volley")
_PINNING_IND = (b"CertificatePinner", b"sha256/", b"X509TrustManager", b"network_security_config",
                b"pin-set", b"TrustKit")
_ROOT_IND = (b"test-keys", b"/system/xbin/su", b"/system/bin/su", b"RootBeer", b"isDeviceRooted",
             b"isRooted", b"Superuser", b"eu.chainfire", b"/system/app/Superuser", b"magisk")
_TAMPER_IND = (b"isDebuggerConnected", b"GET_SIGNATURES", b"signatureMatch", b"checkSignature")
_EXT_STORAGE_IND = (b"getExternalStorage", b"getExternalFilesDir", b"getExternalCacheDir",
                    b"EXTERNAL_STORAGE")


def _scan_code(zf: zipfile.ZipFile) -> list[Finding]:
    """Static analysis of classes*.dex: weak crypto, insecure WebView, and (absence-of)
    certificate pinning / root detection / secure storage — OWASP Mobile M4/M5/M7/M9/M10."""
    out: list[Finding] = []
    seen: dict[str, bool] = {}
    ind = {"network": False, "pinning": False, "root": False, "tamper": False,
           "ext_storage": False, "sqlite": False, "sqlcipher": False}

    for name in zf.namelist():
        if not name.endswith(".dex"):
            continue
        try:
            data = zf.read(name)
        except (KeyError, RuntimeError):
            continue

        if not seen.get("crypto") and _WEAK_CRYPTO_RE.search(data):
            seen["crypto"] = True
            m = _WEAK_CRYPTO_RE.search(data)
            out.append(Finding(
                "mobile-weak-crypto", "Weak cryptography in app", "medium", name,
                description="The app uses a weak cipher or mode (ECB / DES / RC4).",
                impact="Weak ciphers and ECB mode leak data patterns and are practically breakable.",
                evidence=f"Found cipher string: {m.group(0)[:24].decode('latin-1','replace')}",
                remediation="Use AES-GCM (authenticated) with a random IV; drop DES/RC4/ECB.",
                compliance_ref="OWASP Mobile M10:2024"))
        if not seen.get("webview") and (b"addJavascriptInterface" in data or
                                        (b"setJavaScriptEnabled" in data and b"setAllowFileAccess" in data)):
            seen["webview"] = True
            out.append(Finding(
                "mobile-insecure-webview", "Insecure WebView configuration", "medium", name,
                description="The app enables JavaScript with file access, or uses addJavascriptInterface.",
                impact="A malicious page in the WebView can read local files or call app code (RCE on old Android).",
                evidence="setJavaScriptEnabled+setAllowFileAccess or addJavascriptInterface present.",
                remediation="Disable file access, avoid addJavascriptInterface, and load only trusted content.",
                compliance_ref="OWASP Mobile M4:2024"))

        ind["network"] |= any(x in data for x in _NETWORK_IND)
        ind["pinning"] |= any(x in data for x in _PINNING_IND)
        ind["root"] |= any(x in data for x in _ROOT_IND)
        ind["tamper"] |= any(x in data for x in _TAMPER_IND)
        ind["ext_storage"] |= any(x in data for x in _EXT_STORAGE_IND)
        ind["sqlite"] |= b"SQLiteDatabase" in data
        ind["sqlcipher"] |= b"sqlcipher" in data.lower()

    # M5 — missing certificate pinning (only meaningful if the app does networking)
    if ind["network"] and not ind["pinning"]:
        out.append(Finding(
            "mobile-no-cert-pinning", "No TLS certificate pinning", "medium", "classes.dex",
            description="The app makes network calls but shows no certificate-pinning implementation.",
            impact="Without pinning, a rogue/compromised CA enables HTTPS man-in-the-middle interception.",
            evidence="Networking libraries present; no CertificatePinner / pin-set / TrustKit found.",
            remediation="Pin the server certificate/public key (OkHttp CertificatePinner or network-security-config).",
            compliance_ref="OWASP Mobile M5:2024"))

    # M7 — insufficient binary protection (no runtime self-defence)
    if not ind["root"] and not ind["tamper"]:
        out.append(Finding(
            "mobile-no-tamper-detection", "No root / tamper detection", "low", "classes.dex",
            description="No root-detection or anti-tampering / signature-verification logic was found.",
            impact="The app can be run on rooted/instrumented devices and repackaged without resistance.",
            evidence="No root-detection or signature-check indicators present.",
            remediation="Add root/emulator detection, signature verification and (optionally) code obfuscation.",
            compliance_ref="OWASP Mobile M7:2024"))

    # M9 — insecure data storage
    if ind["ext_storage"]:
        out.append(Finding(
            "mobile-external-storage", "Data written to external storage", "medium", "classes.dex",
            description="The app reads/writes external (shared) storage.",
            impact="Files on external storage are world-readable to other apps — sensitive data can leak.",
            evidence="getExternalStorage/getExternalFilesDir usage found.",
            remediation="Store sensitive data in internal storage (MODE_PRIVATE) or the EncryptedFile API.",
            compliance_ref="OWASP Mobile M9:2024"))
    if ind["sqlite"] and not ind["sqlcipher"]:
        out.append(Finding(
            "mobile-unencrypted-sqlite", "Unencrypted local database", "low", "classes.dex",
            description="The app uses SQLite without an encryption layer (e.g. SQLCipher).",
            impact="On a compromised device the local database is readable in plaintext.",
            evidence="SQLiteDatabase used; no SQLCipher found.",
            remediation="Encrypt local databases (SQLCipher / Jetpack Security).",
            compliance_ref="OWASP Mobile M9:2024"))
    return out


def _check_permissions(apk) -> list[Finding]:
    try:
        perms = set(apk.get_permissions())
    except Exception:  # noqa: BLE001
        return []
    dangerous = sorted(perms & DANGEROUS_PERMISSIONS)
    if len(dangerous) >= 4:
        return [Finding(
            "mobile-excessive-permissions", "Excessive dangerous permissions", "medium", "AndroidManifest.xml",
            description=f"The app requests {len(dangerous)} dangerous permissions.",
            impact="Broad permissions increase privacy risk and the blast radius if the app is compromised.",
            evidence="Dangerous permissions: " + ", ".join(p.split(".")[-1] for p in dangerous),
            remediation="Request only the permissions the app truly needs; drop the rest.",
            compliance_ref="OWASP Mobile M6:2024")]
    return []


def _check_firebase(zf: zipfile.ZipFile) -> list[Finding]:
    import re as _re

    import httpx
    dbs: set[str] = set()
    for name in zf.namelist():
        if not name.lower().endswith((".xml", ".json", ".dex", ".properties")):
            continue
        try:
            data = zf.read(name)
        except (KeyError, RuntimeError):
            continue
        for m in _re.findall(rb"https://([a-z0-9.\-]+\.firebaseio\.com)", data, _re.I):
            dbs.add(m.decode("latin-1", "replace"))
    for db in list(dbs)[:5]:
        try:
            r = httpx.get(f"https://{db}/.json", timeout=8)
        except httpx.HTTPError:
            continue
        if r.status_code == 200 and "permission denied" not in r.text.lower() and r.text.strip() not in ("", "null"):
            return [Finding(
                "mobile-open-firebase", "Publicly readable Firebase database (from app)", "high", f"https://{db}/.json",
                description="A Firebase database referenced by the app allows unauthenticated reads.",
                impact="Anyone can read (often write) the app's backend data — a data breach.",
                evidence=f"GET https://{db}/.json returned data without auth.",
                remediation="Set Firebase security rules to require authentication.",
                compliance_ref="OWASP Mobile M9:2024")]
    return []


def _scan_secrets(zf: zipfile.ZipFile) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()
    for name in zf.namelist():
        if not name.lower().endswith(SCAN_EXTENSIONS):
            continue
        try:
            data = zf.read(name)
        except (KeyError, RuntimeError):
            continue
        if len(data) > 8_000_000:  # skip very large blobs
            data = data[:8_000_000]
        for label, rx, sev in SECRET_PATTERNS:
            m = rx.search(data)
            if m and label not in seen:
                seen.add(label)
                sample = m.group(0)[:24].decode("latin-1", "replace")
                findings.append(Finding(
                    f"mobile-secret-{label.lower().replace(' ', '-')}",
                    f"Hardcoded secret in APK: {label}", sev, name,
                    description=f"A {label} is embedded in the app package ({name}).",
                    impact="Anyone can unzip the APK and extract the credential to abuse your backend.",
                    evidence=f"Pattern matched near: {sample}…",
                    remediation="Never ship secrets in the app; fetch short-lived tokens from a backend.",
                    compliance_ref="OWASP Mobile M1:2024",
                ))
    return findings


def _manifest_findings(apk) -> list[Finding]:
    out: list[Finding] = []

    def flag(attr: str) -> str:
        try:
            return (apk.get_element("application", attr) or "").lower()
        except Exception:  # noqa: BLE001
            return ""

    if flag("debuggable") == "true":
        out.append(Finding(
            "mobile-debuggable", "App is debuggable in release", "high", "AndroidManifest.xml",
            description="android:debuggable=\"true\" is set on the application.",
            impact="Attackers can attach a debugger, read memory and tamper with the running app.",
            evidence="application android:debuggable=true",
            remediation="Set android:debuggable=\"false\" (default) for release builds.",
            compliance_ref="OWASP Mobile M8:2024",
        ))
    if flag("allowBackup") == "true":
        out.append(Finding(
            "mobile-allow-backup", "App data backup allowed", "medium", "AndroidManifest.xml",
            description="android:allowBackup=\"true\" lets app data be extracted via adb backup.",
            impact="On a rooted or ADB-enabled device, private app data can be copied off-device.",
            evidence="application android:allowBackup=true",
            remediation="Set android:allowBackup=\"false\" unless you fully control backup contents.",
            compliance_ref="OWASP Mobile M9:2024",
        ))
    if flag("usesCleartextTraffic") == "true":
        out.append(Finding(
            "mobile-cleartext", "Cleartext (HTTP) traffic permitted", "high", "AndroidManifest.xml",
            description="android:usesCleartextTraffic=\"true\" allows unencrypted network traffic.",
            impact="Traffic can be intercepted or modified on the network (MITM).",
            evidence="application android:usesCleartextTraffic=true",
            remediation="Disable cleartext traffic and enforce HTTPS via a network-security-config.",
            compliance_ref="OWASP Mobile M5:2024",
        ))

    # Exported components without a permission (best effort across manifest tags)
    try:
        for tag in ("activity", "service", "receiver"):
            for el in apk.get_android_manifest_xml().findall(f".//{tag}"):
                exported = el.get("{http://schemas.android.com/apk/res/android}exported")
                perm = el.get("{http://schemas.android.com/apk/res/android}permission")
                name = el.get("{http://schemas.android.com/apk/res/android}name", "?")
                if exported == "true" and not perm:
                    out.append(Finding(
                        "mobile-exported-component", f"Exported {tag} without permission", "medium",
                        "AndroidManifest.xml",
                        description=f"The {tag} '{name}' is exported and callable by other apps without a permission.",
                        impact="Malicious apps on the device can invoke this component directly.",
                        evidence=f"{tag} {name} android:exported=true, no android:permission",
                        remediation="Set android:exported=\"false\" or guard it with a signature-level permission.",
                        compliance_ref="OWASP Mobile M8:2024",
                    ))
                    break  # one example per tag is enough
    except Exception:  # noqa: BLE001
        pass

    # Minimum SDK too low (old, unpatched Android)
    try:
        min_sdk = int(apk.get_min_sdk_version() or 0)
        if 0 < min_sdk < 24:  # < Android 7.0
            out.append(Finding(
                "mobile-low-min-sdk", f"Low minimum SDK (API {min_sdk})", "low", "AndroidManifest.xml",
                description=f"minSdkVersion is {min_sdk}; very old Android versions lack modern security controls.",
                impact="The app runs on unpatched OS versions with known vulnerabilities.",
                evidence=f"minSdkVersion={min_sdk}",
                remediation="Raise minSdkVersion to a currently-supported API level.",
                compliance_ref="OWASP Mobile M8:2024",
            ))
    except Exception:  # noqa: BLE001
        pass

    return out


def run_mobile_scan(target: MobileTarget) -> list[Finding]:
    findings: list[Finding] = []
    try:
        zf = zipfile.ZipFile(target.apk_path)
    except (zipfile.BadZipFile, FileNotFoundError):
        return [Finding("mobile-invalid-apk", "Not a valid APK", "info", target.apk_path,
                        description="The uploaded file is not a readable APK/ZIP archive.",
                        remediation="Upload a valid .apk file.", compliance_ref="OWASP Mobile M8:2024", passed=True)]

    with zf:
        findings.extend(_scan_secrets(zf))
        findings.extend(_scan_code(zf))
        try:
            findings.extend(_check_firebase(zf))
        except Exception:  # noqa: BLE001
            pass

    if _HAS_AXML:
        try:
            apk = APK(target.apk_path)
            findings.extend(_manifest_findings(apk))
            findings.extend(_check_permissions(apk))
        except Exception:  # noqa: BLE001
            pass

    if not findings:
        findings.append(Finding("mobile-clean", "No static issues detected", "info", target.apk_path,
                                description="No hardcoded secrets or insecure manifest flags were found.",
                                remediation="Static analysis is limited; consider dynamic testing too.",
                                compliance_ref="OWASP Mobile M8:2024", passed=True))
    return findings
