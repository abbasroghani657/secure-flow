"""OWASP Mobile Top 10 — iOS (IPA) static analysis.

An IPA is a ZIP containing Payload/<App>.app/. We read the app's Info.plist
(via plistlib — handles binary and XML plists), scan the bundle for hardcoded
secrets, and inspect the Mach-O executable for binary protections. No device or
Apple credentials required.
"""

from __future__ import annotations

import plistlib
import re
import struct
import zipfile
from dataclasses import dataclass

from .checks import Finding
from .mobile_scanner import SECRET_PATTERNS  # reuse the secret regexes

_JAILBREAK_IND = (b"cydia", b"/Applications/Cydia.app", b"/bin/bash", b"/usr/sbin/sshd",
                  b"jailbroken", b"jailbreak", b"/private/var/lib/apt", b"MobileSubstrate")


@dataclass
class IOSTarget:
    ipa_path: str


def _find_app_files(zf: zipfile.ZipFile):
    info, binary_name = None, None
    for name in zf.namelist():
        if re.match(r"Payload/[^/]+\.app/Info\.plist$", name):
            info = name
    if info:
        app_dir = info.rsplit("/", 1)[0]
        exe = app_dir.rsplit("/", 1)[-1].replace(".app", "")
        cand = f"{app_dir}/{exe}"
        if cand in zf.namelist():
            binary_name = cand
    return info, binary_name


def _scan_secrets(zf: zipfile.ZipFile) -> list[Finding]:
    out: list[Finding] = []
    seen: set[str] = set()
    for name in zf.namelist():
        if not name.lower().endswith((".plist", ".json", ".txt", ".strings", ".mobileprovision", ".xml")):
            continue
        try:
            data = zf.read(name)
        except (KeyError, RuntimeError):
            continue
        for label, rx, sev in SECRET_PATTERNS:
            m = rx.search(data)
            if m and label not in seen:
                seen.add(label)
                out.append(Finding(
                    f"ios-secret-{label.lower().split(' ')[0]}", f"Hardcoded secret in IPA: {label}", sev, name,
                    description=f"A {label} is embedded in the iOS app bundle ({name}).",
                    impact="Anyone can unzip the IPA and extract the credential to abuse your backend.",
                    evidence=f"Pattern matched near: {m.group(0)[:24].decode('latin-1','replace')}…",
                    remediation="Never ship secrets in the app; fetch short-lived tokens from a backend.",
                    compliance_ref="OWASP Mobile M1:2024"))
    return out


def _plist_findings(plist: dict) -> list[Finding]:
    out: list[Finding] = []
    ats = plist.get("NSAppTransportSecurity", {}) or {}
    if ats.get("NSAllowsArbitraryLoads") is True:
        out.append(Finding(
            "ios-ats-disabled", "App Transport Security disabled (arbitrary loads)", "high", "Info.plist",
            description="NSAllowsArbitraryLoads is true, so the app permits insecure HTTP connections.",
            impact="Traffic can be intercepted or modified (man-in-the-middle).",
            evidence="NSAppTransportSecurity.NSAllowsArbitraryLoads = true",
            remediation="Remove arbitrary loads; require HTTPS (and pin certificates).",
            compliance_ref="OWASP Mobile M5:2024"))
    for domain, cfg in (ats.get("NSExceptionDomains", {}) or {}).items():
        if isinstance(cfg, dict) and cfg.get("NSExceptionAllowsInsecureHTTPLoads") is True:
            out.append(Finding(
                "ios-ats-exception", "ATS insecure-HTTP exception", "medium", "Info.plist",
                description=f"An ATS exception permits insecure HTTP for {domain}.",
                impact="Cleartext traffic to that domain can be intercepted.",
                evidence=f"NSExceptionAllowsInsecureHTTPLoads for {domain}",
                remediation="Remove the insecure exception and use HTTPS.",
                compliance_ref="OWASP Mobile M5:2024"))
            break
    schemes = []
    for entry in plist.get("CFBundleURLTypes", []) or []:
        schemes += entry.get("CFBundleURLSchemes", []) or []
    if schemes:
        out.append(Finding(
            "ios-url-scheme", "Custom URL scheme(s) registered", "low", "Info.plist",
            description=f"The app registers custom URL scheme(s): {', '.join(schemes[:4])}.",
            impact="Unvalidated custom URL schemes can be hijacked or used to inject data.",
            evidence=f"CFBundleURLSchemes: {', '.join(schemes[:4])}",
            remediation="Validate all inbound URL-scheme data; prefer Universal Links.",
            compliance_ref="OWASP Mobile M4:2024"))
    return out


def _binary_findings(zf: zipfile.ZipFile, binary_name: str) -> list[Finding]:
    out: list[Finding] = []
    try:
        data = zf.read(binary_name)
    except (KeyError, RuntimeError):
        return out

    # Mach-O header flags (thin, little-endian arm64/x86_64).
    if data[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe") and len(data) >= 28:
        flags = struct.unpack("<I", data[24:28])[0]
        if not (flags & 0x200000):  # MH_PIE
            out.append(Finding(
                "ios-no-pie", "Binary not compiled as PIE (ASLR)", "medium", binary_name,
                description="The Mach-O executable lacks the PIE flag, weakening ASLR.",
                impact="Without ASLR, memory-corruption exploits are far easier.",
                evidence="Mach-O MH_PIE flag not set.",
                remediation="Build with position-independent executable (-fPIE) enabled.",
                compliance_ref="OWASP Mobile M7:2024"))
    if b"__stack_chk_fail" not in data and b"__stack_chk_guard" not in data:
        out.append(Finding(
            "ios-no-stack-canary", "No stack-smashing protection (canaries)", "low", binary_name,
            description="The binary shows no stack-canary symbols.",
            impact="Stack buffer overflows are easier to exploit without canaries.",
            evidence="No __stack_chk_* symbols found.",
            remediation="Compile with -fstack-protector-all.",
            compliance_ref="OWASP Mobile M7:2024"))
    if not any(x in data for x in _JAILBREAK_IND):
        out.append(Finding(
            "ios-no-jailbreak-detection", "No jailbreak detection", "low", binary_name,
            description="No jailbreak-detection indicators were found in the binary.",
            impact="The app runs unhindered on jailbroken devices where its data can be extracted.",
            evidence="No jailbreak-detection strings present.",
            remediation="Add jailbreak/root detection and respond appropriately.",
            compliance_ref="OWASP Mobile M7:2024"))
    return out


def run_ios_scan(target: IOSTarget) -> list[Finding]:
    try:
        zf = zipfile.ZipFile(target.ipa_path)
    except (zipfile.BadZipFile, FileNotFoundError):
        return [Finding("ios-invalid-ipa", "Not a valid IPA", "info", target.ipa_path,
                        description="The uploaded file is not a readable IPA/ZIP archive.",
                        remediation="Upload a valid .ipa file.", compliance_ref="OWASP Mobile M8:2024", passed=True)]
    findings: list[Finding] = []
    with zf:
        info_name, binary_name = _find_app_files(zf)
        findings.extend(_scan_secrets(zf))
        if info_name:
            try:
                findings.extend(_plist_findings(plistlib.loads(zf.read(info_name))))
            except Exception:  # noqa: BLE001
                pass
        if binary_name:
            findings.extend(_binary_findings(zf, binary_name))
    if not findings:
        findings.append(Finding("ios-clean", "No static iOS issues detected", "info", target.ipa_path,
                                description="No secrets, insecure ATS config or missing binary protections were found.",
                                remediation="Static analysis is limited; consider dynamic testing too.",
                                compliance_ref="OWASP Mobile M8:2024", passed=True))
    return findings
