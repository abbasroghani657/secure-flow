import { Link, useLocation } from "react-router-dom";
import { useState } from "react";
import { Logo, primaryBtn, ghostBtn } from "./ui";
import { useAuth } from "../auth";
import { T } from "../theme";

// ---- shared marketing data ------------------------------------------------
export const FEATURES = [
  { title: "Web & API scanning", tag: "DAST",
    desc: "Injection (SQLi/XSS/SSRF/SSTI…), broken access control, misconfiguration, TLS and exposed services — plus a dedicated OpenAPI/Swagger reviewer for the OWASP API Top 10.",
    points: ["Blind & time-based SQLi", "SSRF, XXE, SSTI, command injection", "Auth, JWT & CORS bypass analysis"] },
  { title: "Mobile — Android & iOS", tag: "SAST",
    desc: "Deep static analysis of an APK or IPA against the OWASP Mobile Top 10: hardcoded secrets, weak crypto, insecure storage, transport security and binary protections.",
    points: ["Secrets & weak crypto (ECB/DES)", "ATS, cert-pinning, WebView issues", "PIE/ASLR & jailbreak checks (iOS)"] },
  { title: "Cloud & containers", tag: "CSPM",
    desc: "AWS posture management, Infrastructure-as-Code (Terraform / CloudFormation / Kubernetes / Docker) and container-image CVE scanning from a docker save tar.",
    points: ["Public buckets, open SGs, IAM", "Root MFA, GuardDuty, KMS rotation", "OS-package CVEs per image layer"] },
  { title: "Source code (SAST)", tag: "10 languages",
    desc: "Python via the real AST plus curated rule engines for JS/TS, PHP, Java, Go, Ruby, C#, Kotlin and Swift — injection, deserialization, weak crypto and dangerous sinks.",
    points: ["29 JS/TS vulnerability classes", "Low false-positive AST analysis", "Enterprise + native mobile langs"] },
  { title: "Supply chain & secrets", tag: "SCA",
    desc: "Dependency CVEs across eight ecosystems via OSV, dependency-confusion detection, CI/CD pipeline risks, and 37 leaked-credential detectors across your source.",
    points: ["npm/PyPI/Go/Maven/NuGet + more", "GitHub Actions / GitLab CI risks", "AWS/GCP/Azure/Stripe/OpenAI keys"] },
  { title: "Fix-first prioritization", tag: "KEV + EPSS",
    desc: "Every finding carries a confidence level and a 0–100 priority blended from severity, CISA-KEV (is it exploited right now?) and EPSS (predicted probability).",
    points: ["“Patch these five” not “here are 400”", "Confidence: confirmed / firm / tentative", "Guided manual-test playbooks"] },
];

export const PRICING = [
  { name: "Free", price: "$0", period: "forever", blurb: "For a single site you own.", cta: "Start free", featured: false,
    features: ["1 verified target", "Web + headers scan", "OWASP Top 10 scorecard", "PDF report export"] },
  { name: "Pro", price: "$29", period: "/ month", blurb: "For teams that ship.", cta: "Start Pro", featured: true,
    features: ["10 targets", "All scanners — API, mobile, cloud, SAST, containers", "Daily scheduled scans", "KEV / EPSS prioritization", "Compliance mapping (PCI/SOC2/ISO)"] },
  { name: "Business", price: "$99", period: "/ month", blurb: "For agencies & security teams.", cta: "Contact us", featured: false,
    features: ["Unlimited targets", "Continuous monitoring + drift alerts", "Teams, roles & SSO", "Auditor-ready compliance reports", "API, CLI & integrations"] },
];

export const COMPARE = [
  ["Web app & API scanning", true, true, true],
  ["Mobile (Android + iOS)", true, false, false],
  ["Cloud posture (CSPM) + IaC", true, false, false],
  ["Container image CVEs", true, false, false],
  ["SAST — 10 languages", true, false, "Partial"],
  ["Secrets — 37 detectors", true, "Partial", false],
  ["KEV / EPSS fix-first priority", true, "Partial", false],
  ["Compliance mapping (PCI/SOC2/ISO)", true, true, false],
  ["Guided manual-test playbooks", true, false, "Partial"],
  ["Self-serve, from", "$0", "$$$", "$$"],
];

export const QUOTES = [
  { text: "One tool replaced our dependency scanner, our DAST and half our cloud-posture checklist. The KEV priority list is what we open first every morning.", initials: "RK", name: "R. Khan", role: "Head of Security, fintech" },
  { text: "We pointed it at a legacy WordPress site and it found an exposed wp-config backup in under a minute. That alone paid for the year.", initials: "AS", name: "A. Silva", role: "Founder, dev agency" },
  { text: "The OWASP scorecard makes client reports trivial — they see exactly where they stand across all ten categories, green and red.", initials: "MJ", name: "M. Johansson", role: "Independent pentester" },
];

export const NAV_LINKS = [
  ["/features", "Features"], ["/pricing", "Pricing"], ["/compare", "Compare"], ["/blog", "Blog"],
];

// ---- shared components ----------------------------------------------------
export function MarketingNav() {
  const { user } = useAuth();
  const loc = useLocation();
  const [open, setOpen] = useState(false);
  return (
    <nav style={{ position: "sticky", top: 0, zIndex: 60, background: "rgba(10,14,18,0.72)", backdropFilter: "blur(16px)", borderBottom: `1px solid ${T.border}` }}>
      <div style={{ maxWidth: 1200, margin: "0 auto", display: "flex", alignItems: "center", justifyContent: "space-between", gap: 24, padding: "14px 28px" }}>
        <Link to="/" style={{ display: "flex" }}><Logo /></Link>
        <div style={{ display: "flex", gap: 30, fontSize: 14 }} className="mkt-navlinks">
          {NAV_LINKS.map(([to, label]) => {
            const active = loc.pathname === to;
            return <Link key={to} to={to} style={{ color: active ? T.text : T.muted, fontWeight: active ? 600 : 400, position: "relative" }}>{label}</Link>;
          })}
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          {user ? (
            <Link to="/dashboard" style={{ ...primaryBtn, padding: "9px 18px", fontSize: 14 }}>Dashboard</Link>
          ) : (
            <>
              <Link to="/auth" style={{ ...ghostBtn, padding: "9px 16px", fontSize: 14 }} className="mkt-login">Log in</Link>
              <Link to="/auth" state={{ mode: "signup" }} style={{ ...primaryBtn, padding: "9px 18px", fontSize: 14 }}>Start free</Link>
            </>
          )}
        </div>
      </div>
    </nav>
  );
}

export function MarketingFooter() {
  const cols = [
    ["Product", [["Features", "/features"], ["Pricing", "/pricing"], ["Compare", "/compare"], ["Log in", "/auth"]]],
    ["Resources", [["Blog", "/blog"], ["Docs", "/blog"], ["OWASP 2025", "/blog"], ["Changelog", "/blog"]]],
    ["Company", [["About", "/blog"], ["Security", "/blog"], ["Privacy", "/blog"], ["Terms", "/blog"]]],
  ];
  return (
    <footer style={{ borderTop: `1px solid ${T.border}`, background: "rgba(255,255,255,0.015)", marginTop: 40 }}>
      <div style={{ maxWidth: 1120, margin: "0 auto", padding: "52px 28px 24px", display: "grid", gridTemplateColumns: "1.5fr 1fr 1fr 1fr", gap: 32 }} className="footer-grid">
        <div>
          <Logo size={18} />
          <p style={{ color: T.muted, fontSize: 13.5, lineHeight: 1.6, margin: "14px 0 0", maxWidth: 270 }}>Security scanning and penetration-testing intelligence for teams that ship fast. Scan only what you own.</p>
        </div>
        {cols.map(([h, items]) => (
          <div key={h}>
            <div style={{ fontSize: 13, fontWeight: 700, color: T.text, marginBottom: 14, letterSpacing: "0.03em" }}>{h}</div>
            <div style={{ display: "grid", gap: 10 }}>
              {items.map(([label, to]) => <Link key={label} to={to} style={{ fontSize: 13.5, color: T.muted }}>{label}</Link>)}
            </div>
          </div>
        ))}
      </div>
      <div style={{ maxWidth: 1120, margin: "0 auto", padding: "16px 28px 30px", borderTop: `1px solid ${T.border}`, display: "flex", justifyContent: "space-between", flexWrap: "wrap", gap: 12, color: T.faint, fontSize: 13 }}>
        <span>© {new Date().getFullYear()} Pentrixa. All rights reserved.</span>
        <span>Built on OWASP · CWE · OSV · CISA KEV · EPSS</span>
      </div>
    </footer>
  );
}

export function Check({ ok, size = 18 }) {
  if (ok === true) return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={T.accent} strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round"><path d="M20 6L9 17l-5-5" /></svg>;
  if (ok === false) return <svg width={size - 2} height={size - 2} viewBox="0 0 24 24" fill="none" stroke={T.faint} strokeWidth="2" strokeLinecap="round"><path d="M18 6L6 18M6 6l12 12" /></svg>;
  return <span style={{ fontSize: 13, fontWeight: 600, color: ok === "$0" ? T.accent : T.muted }}>{ok}</span>;
}

export const sectionTitle = { fontFamily: T.heading, fontSize: "clamp(28px, 4vw, 40px)", fontWeight: 700, letterSpacing: "-0.02em", margin: "0 0 14px" };
export const eyebrow = { display: "inline-block", fontFamily: T.mono, fontSize: 12, letterSpacing: "0.16em", textTransform: "uppercase", color: T.accent, marginBottom: 14 };
