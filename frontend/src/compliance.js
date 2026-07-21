// Maps a finding's OWASP Top 10:2025 category to the controls it touches in the
// major compliance frameworks. This turns raw findings into the compliance-gap
// reports enterprises actually buy.

// OWASP A-category -> { framework: control }
const CONTROLS = {
  A01: { "PCI DSS v4": "Req 7 — Restrict access", "SOC 2": "CC6.1 / CC6.3", "ISO 27001": "A.5.15 Access control", HIPAA: "§164.312(a) Access control", GDPR: "Art. 32 / Art. 25" },
  A02: { "PCI DSS v4": "Req 2 — Secure configuration", "SOC 2": "CC7.1", "ISO 27001": "A.8.9 Configuration mgmt", HIPAA: "§164.312(a)", GDPR: "Art. 32" },
  A03: { "PCI DSS v4": "Req 6.3 — Patch known vulns", "SOC 2": "CC7.1 / CC8.1", "ISO 27001": "A.8.30 / A.5.20 Supplier", HIPAA: "§164.308(a)(1)", GDPR: "Art. 32" },
  A04: { "PCI DSS v4": "Req 3 & 4 — Protect/encrypt data", "SOC 2": "CC6.7", "ISO 27001": "A.8.24 Cryptography", HIPAA: "§164.312(e) Transmission security", GDPR: "Art. 32(1)(a)" },
  A05: { "PCI DSS v4": "Req 6.2.4 — Injection defences", "SOC 2": "CC7.1", "ISO 27001": "A.8.28 Secure coding", HIPAA: "§164.312(c) Integrity", GDPR: "Art. 32" },
  A06: { "PCI DSS v4": "Req 6.2 — Secure SDLC", "SOC 2": "CC8.1", "ISO 27001": "A.8.25 Secure development", HIPAA: "§164.308(a)(1)", GDPR: "Art. 25 — By design" },
  A07: { "PCI DSS v4": "Req 8 — Authenticate access", "SOC 2": "CC6.1", "ISO 27001": "A.8.5 Secure authentication", HIPAA: "§164.312(d) Authentication", GDPR: "Art. 32" },
  A08: { "PCI DSS v4": "Req 6.3.3 / 11.5", "SOC 2": "CC7.1 / PI1.1", "ISO 27001": "A.8.28 / A.8.30", HIPAA: "§164.312(c) Integrity", GDPR: "Art. 32(1)(b)" },
  A09: { "PCI DSS v4": "Req 10 — Log & monitor", "SOC 2": "CC7.2 / CC7.3", "ISO 27001": "A.8.15 Logging", HIPAA: "§164.312(b) Audit controls", GDPR: "Art. 33 — Breach notification" },
  A10: { "PCI DSS v4": "Req 6.2 — Error handling", "SOC 2": "CC7.1", "ISO 27001": "A.8.26 App security requirements", HIPAA: "§164.312(c)", GDPR: "Art. 32" },
};

export const FRAMEWORKS = ["PCI DSS v4", "SOC 2", "ISO 27001", "HIPAA", "GDPR"];

// Normalise any finding OWASP tag (A01:2025, LLM01:2025, M5:2024) to an A-code.
function normalize(owasp) {
  if (!owasp) return null;
  if (owasp.startsWith("A")) return owasp.slice(0, 3);
  if (owasp.startsWith("LLM")) {
    const n = owasp.replace(/[^0-9]/g, "");
    if (["01", "08", "05", "1"].includes(n) || n === "1") return "A05"; // injection-like
    if (n === "02") return "A01"; // sensitive disclosure
    return "A06"; // design/agency/misinformation
  }
  if (owasp.startsWith("M")) {
    const n = parseInt(owasp.replace(/[^0-9]/g, ""), 10);
    if (n === 5) return "A04"; // pinning / cleartext
    if (n === 9 || n === 10) return "A04"; // storage / crypto
    if (n === 1) return "A02"; // hardcoded secrets
    return "A02";
  }
  return null;
}

// Given the scan's findings, return { framework: { gaps, controls:Set } }.
export function computeCompliance(findings) {
  const out = {};
  for (const fw of FRAMEWORKS) out[fw] = { gaps: 0, controls: new Set() };
  for (const f of findings) {
    if (f.passed) continue;
    const a = normalize(f.owasp);
    if (!a || !CONTROLS[a]) continue;
    for (const fw of FRAMEWORKS) {
      const ctrl = CONTROLS[a][fw];
      if (ctrl) {
        out[fw].gaps += 1;
        out[fw].controls.add(ctrl);
      }
    }
  }
  return out;
}
