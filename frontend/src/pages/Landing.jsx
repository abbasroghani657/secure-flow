import { Link, useNavigate } from "react-router-dom";
import { useState } from "react";
import { Logo, primaryBtn, ghostBtn } from "../components/ui";
import { useAuth } from "../auth";
import { T } from "../theme";

const FEATURES = [
  { title: "Web & API scanning", desc: "Injection (SQLi/XSS/SSRF/SSTI…), auth flaws, misconfig, TLS and exposed services — plus a dedicated OpenAPI/Swagger reviewer." },
  { title: "Mobile — Android & iOS", desc: "Static analysis of APK and IPA: hardcoded secrets, weak crypto, insecure storage, transport security and binary protections." },
  { title: "Cloud & containers", desc: "AWS posture (CSPM), Infrastructure-as-Code (Terraform/K8s/Docker) and container-image CVEs from a docker save tar." },
  { title: "Source code (SAST)", desc: "10 languages — Python (real AST), JS/TS, PHP, Java, Go, Ruby, C#, Kotlin, Swift — for injection, deserialization and weak crypto." },
  { title: "Supply chain & secrets", desc: "Dependency CVEs across 8 ecosystems (OSV), dependency confusion, CI/CD pipeline risks, and 37 leaked-credential detectors." },
  { title: "Fix-first prioritization", desc: "Every finding gets a confidence score and a priority blended from severity, CISA-KEV and EPSS — so you patch the five that matter." },
];

const PRICING = [
  { name: "Free", price: "$0", period: "forever", blurb: "For a single site you own.", cta: "Start free",
    features: ["1 verified target", "Web + headers scan", "OWASP Top 10 scorecard", "PDF report export"], featured: false },
  { name: "Pro", price: "$29", period: "/ month", blurb: "For teams that ship.", cta: "Start Pro",
    features: ["10 targets", "All scanners — API, mobile, cloud, SAST, containers", "Daily scheduled scans", "KEV/EPSS prioritization", "Compliance mapping"], featured: true },
  { name: "Business", price: "$99", period: "/ month", blurb: "For agencies & security teams.", cta: "Contact us",
    features: ["Unlimited targets", "Continuous monitoring + drift alerts", "Teams, roles & SSO", "Auditor-ready compliance reports", "API, CLI & integrations"], featured: false },
];

const COMPARE = [
  ["Web app & API scanning", true, true, true],
  ["Mobile (Android + iOS)", true, false, false],
  ["Cloud posture (CSPM) + IaC", true, false, false],
  ["Container image CVEs", true, false, false],
  ["SAST — 10 languages", true, false, "Partial"],
  ["KEV / EPSS fix-first priority", true, "Partial", false],
  ["Compliance mapping (PCI/SOC2/ISO)", true, true, false],
  ["Guided manual-test playbooks", true, false, "Partial"],
];

const QUOTES = [
  { text: "One tool replaced our dependency scanner, our DAST and half our cloud-posture checklist. The KEV priority list is what we open first every morning.", initials: "RK", name: "R. Khan", role: "Head of Security, fintech" },
  { text: "We pointed it at a legacy WordPress site and it found an exposed wp-config backup in under a minute. That alone paid for the year.", initials: "AS", name: "A. Silva", role: "Founder, dev agency" },
  { text: "The OWASP scorecard makes client reports trivial — they see exactly where they stand across all ten categories, green and red.", initials: "MJ", name: "M. Johansson", role: "Pentester" },
];

function Check({ ok }) {
  if (ok === true) return <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke={T.accent} strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round"><path d="M20 6L9 17l-5-5" /></svg>;
  if (ok === false) return <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke={T.faint} strokeWidth="2" strokeLinecap="round"><path d="M18 6L6 18M6 6l12 12" /></svg>;
  return <span style={{ fontSize: 12, color: T.muted }}>{ok}</span>;
}

export default function Landing() {
  const [url, setUrl] = useState("");
  const { user } = useAuth();
  const nav = useNavigate();

  function start(e) {
    e.preventDefault();
    nav("/auth", { state: { url } });
  }

  const sectionTitle = { fontFamily: T.heading, fontSize: 40, fontWeight: 700, letterSpacing: "-0.02em", margin: "0 0 14px" };

  return (
    <div>
      <nav style={{ position: "sticky", top: 0, zIndex: 50, display: "flex", alignItems: "center", justifyContent: "space-between", gap: 24, padding: "14px 40px", background: "rgba(10,14,18,0.82)", backdropFilter: "blur(14px)", borderBottom: `1px solid ${T.border}` }}>
        <Link to="/"><Logo /></Link>
        <div style={{ display: "flex", gap: 28, fontSize: 14, color: T.muted }}>
          <a href="#features" style={{ color: T.muted }}>Features</a>
          <a href="#pricing" style={{ color: T.muted }}>Pricing</a>
          <a href="#compare" style={{ color: T.muted }}>Compare</a>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          {user ? (
            <Link to="/dashboard" style={primaryBtn}>Dashboard</Link>
          ) : (
            <>
              <Link to="/auth" style={ghostBtn}>Log in</Link>
              <Link to="/auth" style={{ ...primaryBtn, padding: "10px 18px", fontSize: 14 }}>Start Free Scan</Link>
            </>
          )}
        </div>
      </nav>

      {/* Hero */}
      <header style={{ position: "relative", overflow: "hidden", padding: "96px 40px 64px", textAlign: "center" }}>
        <div style={{ position: "absolute", inset: 0, background: "radial-gradient(ellipse 60% 45% at 50% -5%, rgba(6,182,212,0.18), transparent 70%), radial-gradient(ellipse 40% 35% at 85% 20%, rgba(6,182,212,0.10), transparent 70%)", pointerEvents: "none" }} />
        <div style={{ position: "relative", maxWidth: 880, margin: "0 auto", animation: "fadeUp 0.7s ease both" }}>
          <div style={{ display: "inline-flex", alignItems: "center", gap: 8, padding: "6px 14px", borderRadius: 999, border: "1px solid rgba(6,182,212,0.35)", background: "rgba(6,182,212,0.08)", color: T.accentHi, fontSize: 13, fontWeight: 500, marginBottom: 28 }}>
            <span style={{ width: 7, height: 7, borderRadius: "50%", background: T.accent, animation: "blink 1.6s infinite" }} />
            310+ real checks across web, cloud, mobile & code
          </div>
          <h1 style={{ fontFamily: T.heading, fontSize: "clamp(40px, 6vw, 68px)", fontWeight: 800, letterSpacing: "-0.03em", lineHeight: 1.05, margin: "0 0 20px" }}>
            Find vulnerabilities<br />before <span style={{ color: T.accent, textShadow: "0 0 40px rgba(6,182,212,0.4)" }}>hackers do</span>
          </h1>
          <p style={{ fontSize: 18, lineHeight: 1.6, color: T.muted, maxWidth: 640, margin: "0 auto 36px" }}>
            Pentrixa scans your websites, APIs, mobile apps, cloud and source code for real, exploitable issues — then ranks them by what's actually being attacked in the wild, and tells you exactly how to fix each one.
          </p>
          <form onSubmit={start} style={{ display: "flex", gap: 10, maxWidth: 560, margin: "0 auto", flexWrap: "wrap", justifyContent: "center" }}>
            <input value={url} onChange={(e) => setUrl(e.target.value)} type="text" placeholder="https://your-website.com" aria-label="Website URL" style={{ flex: 1, minWidth: 260, padding: "15px 18px", borderRadius: 12, border: `1px solid ${T.borderStrong}`, background: "rgba(255,255,255,0.05)", color: T.text, fontSize: 15, fontFamily: T.body }} />
            <button type="submit" style={{ ...primaryBtn, padding: "15px 24px" }}>Scan Now — Free</button>
          </form>
          <div style={{ display: "flex", gap: 22, justifyContent: "center", marginTop: 26, color: T.faint, fontSize: 12.5, fontWeight: 500, flexWrap: "wrap" }}>
            {["OWASP Top 10:2025", "CISA KEV + EPSS", "No credit card", "Only scans sites you own"].map((t) => (
              <span key={t} style={{ display: "flex", alignItems: "center", gap: 6 }}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M20 6L9 17l-5-5" /></svg>{t}
              </span>
            ))}
          </div>
        </div>
      </header>

      {/* Trust / standards bar (honest — the real standards & data sources) */}
      <div style={{ borderTop: `1px solid ${T.border}`, borderBottom: `1px solid ${T.border}`, background: "rgba(255,255,255,0.015)" }}>
        <div style={{ maxWidth: 1000, margin: "0 auto", padding: "22px 40px", display: "flex", alignItems: "center", justifyContent: "center", gap: 34, flexWrap: "wrap" }}>
          <span style={{ fontSize: 12.5, color: T.faint, letterSpacing: "0.04em" }}>BUILT ON THE STANDARDS THAT MATTER</span>
          {["OWASP", "CWE", "OSV.dev", "CISA KEV", "FIRST EPSS", "Nuclei"].map((n) => (
            <span key={n} style={{ fontFamily: T.heading, fontWeight: 700, fontSize: 16, color: T.muted, opacity: 0.85 }}>{n}</span>
          ))}
        </div>
      </div>

      {/* Features */}
      <section id="features" style={{ padding: "88px 40px", maxWidth: 1180, margin: "0 auto" }}>
        <div style={{ textAlign: "center", maxWidth: 660, margin: "0 auto 56px" }}>
          <h2 style={sectionTitle}>Your entire attack surface, covered</h2>
          <p style={{ color: T.muted, fontSize: 16, lineHeight: 1.6, margin: 0 }}>One platform for scanning, prioritising and fixing — from web apps to cloud accounts to the code itself.</p>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(300px, 1fr))", gap: 18 }}>
          {FEATURES.map((f) => (
            <div key={f.title} style={{ padding: "26px 24px", borderRadius: 16, border: `1px solid ${T.border}`, background: "rgba(255,255,255,0.025)" }}>
              <div style={{ width: 42, height: 42, borderRadius: 11, background: "rgba(6,182,212,0.1)", border: "1px solid rgba(6,182,212,0.25)", display: "flex", alignItems: "center", justifyContent: "center", marginBottom: 16 }}>
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke={T.accent} strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /></svg>
              </div>
              <h3 style={{ fontFamily: T.heading, fontSize: 17, fontWeight: 600, margin: "0 0 8px" }}>{f.title}</h3>
              <p style={{ fontSize: 13.5, lineHeight: 1.55, color: T.muted, margin: 0 }}>{f.desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Score showcase */}
      <section style={{ padding: "40px 40px 88px", maxWidth: 1080, margin: "0 auto" }}>
        <div style={{ display: "grid", gridTemplateColumns: "1.1fr 0.9fr", gap: 48, alignItems: "center" }} className="score-grid">
          <div>
            <h2 style={sectionTitle}>One score. Total clarity.</h2>
            <p style={{ color: T.muted, fontSize: 16, lineHeight: 1.6, margin: "0 0 22px" }}>
              Every scan produces a Security Score from 0–100, weighted by real exploitability — not raw finding counts. Watch it climb as you ship fixes.
            </p>
            <div style={{ display: "grid", gap: 12 }}>
              {["Severity × confidence × CISA-KEV / EPSS", "Full OWASP Top 10 scorecard — every category", "Shareable PDF reports for clients and auditors"].map((t) => (
                <div key={t} style={{ display: "flex", gap: 10, alignItems: "center", fontSize: 14.5, color: T.text }}>
                  <span style={{ width: 22, height: 22, borderRadius: 7, background: "rgba(6,182,212,0.12)", display: "flex", alignItems: "center", justifyContent: "center", flex: "none" }}>
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke={T.accent} strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round"><path d="M20 6L9 17l-5-5" /></svg>
                  </span>{t}
                </div>
              ))}
            </div>
          </div>
          <div style={{ position: "relative", padding: "44px", borderRadius: 20, border: `1px solid ${T.border}`, background: "linear-gradient(180deg, rgba(6,182,212,0.06), rgba(255,255,255,0.02))", textAlign: "center" }}>
            <div style={{ fontFamily: T.heading, fontSize: 84, fontWeight: 800, letterSpacing: "-0.03em", color: T.accent, textShadow: "0 0 50px rgba(6,182,212,0.4)", lineHeight: 1 }}>92</div>
            <div style={{ fontSize: 13, color: T.muted, letterSpacing: "0.08em", textTransform: "uppercase", marginTop: 8 }}>Security Score</div>
            <div style={{ display: "inline-flex", alignItems: "center", gap: 6, marginTop: 16, padding: "5px 12px", borderRadius: 999, background: "rgba(6,182,212,0.1)", color: T.accentHi, fontSize: 13, fontWeight: 600 }}>▲ +14 this month</div>
          </div>
        </div>
      </section>

      {/* Pricing */}
      <section id="pricing" style={{ padding: "40px 40px 80px", maxWidth: 1080, margin: "0 auto" }}>
        <div style={{ textAlign: "center", maxWidth: 620, margin: "0 auto 48px" }}>
          <h2 style={sectionTitle}>Pricing that scales with you</h2>
          <p style={{ color: T.muted, fontSize: 16, margin: 0 }}>Start free. Upgrade when you need depth, scheduling or clients.</p>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: 18, alignItems: "start" }}>
          {PRICING.map((p) => (
            <div key={p.name} style={{ position: "relative", padding: "30px 26px", borderRadius: 18, border: `1.5px solid ${p.featured ? T.accent : T.border}`, background: p.featured ? "linear-gradient(180deg, rgba(6,182,212,0.08), rgba(255,255,255,0.02))" : "rgba(255,255,255,0.02)", boxShadow: p.featured ? "0 20px 60px rgba(6,182,212,0.12)" : "none" }}>
              {p.featured && <span style={{ position: "absolute", top: -12, left: "50%", transform: "translateX(-50%)", fontSize: 11, fontWeight: 700, letterSpacing: "0.06em", textTransform: "uppercase", color: T.accentInk, background: T.accent, padding: "4px 12px", borderRadius: 999 }}>Most popular</span>}
              <div style={{ fontFamily: T.heading, fontSize: 18, fontWeight: 600 }}>{p.name}</div>
              <div style={{ margin: "12px 0 4px", display: "flex", alignItems: "baseline", gap: 6 }}>
                <span style={{ fontFamily: T.heading, fontSize: 40, fontWeight: 800, letterSpacing: "-0.02em" }}>{p.price}</span>
                <span style={{ color: T.muted, fontSize: 14 }}>{p.period}</span>
              </div>
              <p style={{ color: T.muted, fontSize: 13.5, margin: "0 0 20px" }}>{p.blurb}</p>
              <Link to="/auth" style={{ ...(p.featured ? primaryBtn : ghostBtn), display: "block", textAlign: "center", marginBottom: 20 }}>{p.cta}</Link>
              <div style={{ display: "grid", gap: 10 }}>
                {p.features.map((ft) => (
                  <div key={ft} style={{ display: "flex", gap: 9, alignItems: "flex-start", fontSize: 13.5, color: T.text }}>
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke={T.accent} strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" style={{ flex: "none", marginTop: 2 }}><path d="M20 6L9 17l-5-5" /></svg>{ft}
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
        <p style={{ textAlign: "center", color: T.faint, fontSize: 13.5, marginTop: 26 }}>No subscription? Run a one-off deep scan and get the full report.</p>
      </section>

      {/* Comparison */}
      <section id="compare" style={{ padding: "40px 40px 88px", maxWidth: 900, margin: "0 auto" }}>
        <div style={{ textAlign: "center", marginBottom: 40 }}>
          <h2 style={sectionTitle}>How Pentrixa compares</h2>
        </div>
        <div style={{ overflowX: "auto", borderRadius: 16, border: `1px solid ${T.border}` }}>
          <table style={{ width: "100%", borderCollapse: "collapse", minWidth: 560 }}>
            <thead>
              <tr style={{ background: "rgba(255,255,255,0.03)" }}>
                <th style={{ textAlign: "left", padding: "16px 20px", fontSize: 13, color: T.muted, fontWeight: 600 }}>Capability</th>
                <th style={{ padding: "16px 12px", fontSize: 14, fontWeight: 700, color: T.accent }}>Pentrixa</th>
                <th style={{ padding: "16px 12px", fontSize: 13, color: T.muted, fontWeight: 600 }}>Detectify</th>
                <th style={{ padding: "16px 12px", fontSize: 13, color: T.muted, fontWeight: 600 }}>Burp Suite</th>
              </tr>
            </thead>
            <tbody>
              {COMPARE.map((r, i) => (
                <tr key={r[0]} style={{ borderTop: `1px solid ${T.border}`, background: i % 2 ? "transparent" : "rgba(255,255,255,0.012)" }}>
                  <td style={{ padding: "14px 20px", fontSize: 14, color: T.text }}>{r[0]}</td>
                  <td style={{ padding: "14px 12px", textAlign: "center" }}><span style={{ display: "inline-flex" }}><Check ok={r[1]} /></span></td>
                  <td style={{ padding: "14px 12px", textAlign: "center" }}><span style={{ display: "inline-flex" }}><Check ok={r[2]} /></span></td>
                  <td style={{ padding: "14px 12px", textAlign: "center" }}><span style={{ display: "inline-flex" }}><Check ok={r[3]} /></span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* Testimonials (placeholder — replace with real customer quotes) */}
      <section style={{ padding: "40px 40px 90px", maxWidth: 1120, margin: "0 auto" }}>
        <div style={{ textAlign: "center", marginBottom: 44 }}><h2 style={sectionTitle}>Loved by people who ship</h2></div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: 18 }}>
          {QUOTES.map((q) => (
            <div key={q.name} style={{ padding: "26px 24px", borderRadius: 16, border: `1px solid ${T.border}`, background: "rgba(255,255,255,0.025)", display: "flex", flexDirection: "column", gap: 18 }}>
              <p style={{ fontSize: 14.5, lineHeight: 1.6, color: T.text, margin: 0 }}>“{q.text}”</p>
              <div style={{ display: "flex", alignItems: "center", gap: 12, marginTop: "auto" }}>
                <span style={{ width: 38, height: 38, borderRadius: "50%", background: "rgba(6,182,212,0.12)", color: T.accentHi, display: "flex", alignItems: "center", justifyContent: "center", fontFamily: T.heading, fontWeight: 700, fontSize: 13 }}>{q.initials}</span>
                <div>
                  <div style={{ fontSize: 13.5, fontWeight: 600 }}>{q.name}</div>
                  <div style={{ fontSize: 12.5, color: T.muted }}>{q.role}</div>
                </div>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Final CTA */}
      <section id="how" style={{ padding: "20px 40px 100px", textAlign: "center" }}>
        <div style={{ maxWidth: 720, margin: "0 auto", padding: "52px 40px", borderRadius: 22, border: "1px solid rgba(6,182,212,0.28)", background: "linear-gradient(180deg, rgba(6,182,212,0.08), transparent)" }}>
          <h2 style={{ fontFamily: T.heading, fontSize: 34, fontWeight: 700, margin: "0 0 12px" }}>Run your first scan in 60 seconds</h2>
          <p style={{ color: T.muted, margin: "0 0 28px" }}>Free tier. No credit card. Findings you can act on today.</p>
          <Link to="/auth" style={{ ...primaryBtn, display: "inline-block", padding: "14px 28px" }}>Start Free Scan →</Link>
        </div>
      </section>

      {/* Footer */}
      <footer style={{ borderTop: `1px solid ${T.border}`, background: "rgba(255,255,255,0.015)" }}>
        <div style={{ maxWidth: 1120, margin: "0 auto", padding: "48px 40px 24px", display: "grid", gridTemplateColumns: "1.4fr 1fr 1fr 1fr", gap: 32 }} className="footer-grid">
          <div>
            <Logo size={18} />
            <p style={{ color: T.muted, fontSize: 13.5, lineHeight: 1.6, margin: "14px 0 0", maxWidth: 260 }}>Security scanning and penetration-testing intelligence for teams that ship fast.</p>
          </div>
          {[["Product", ["Features", "Pricing", "Compare", "Detection catalog"]], ["Resources", ["Docs", "OWASP 2025", "Changelog", "Status"]], ["Company", ["About", "Security", "Privacy", "Terms"]]].map(([h, items]) => (
            <div key={h}>
              <div style={{ fontSize: 13, fontWeight: 700, color: T.text, marginBottom: 14, letterSpacing: "0.03em" }}>{h}</div>
              <div style={{ display: "grid", gap: 10 }}>
                {items.map((it) => <a key={it} href="#" style={{ fontSize: 13.5, color: T.muted }}>{it}</a>)}
              </div>
            </div>
          ))}
        </div>
        <div style={{ maxWidth: 1120, margin: "0 auto", padding: "16px 40px 28px", borderTop: `1px solid ${T.border}`, display: "flex", justifyContent: "space-between", flexWrap: "wrap", gap: 12, color: T.faint, fontSize: 13 }}>
          <span>© {new Date().getFullYear()} Pentrixa. Scan only what you own.</span>
          <span>Built on OWASP · CWE · OSV · CISA KEV · EPSS</span>
        </div>
      </footer>
    </div>
  );
}
