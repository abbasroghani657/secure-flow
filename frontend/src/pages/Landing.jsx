import { Link, useNavigate } from "react-router-dom";
import { useState } from "react";
import { primaryBtn } from "../components/ui";
import { MarketingNav, MarketingFooter, FEATURES, QUOTES, sectionTitle, eyebrow } from "../components/marketing";
import ScanTerminal from "../components/ScanTerminal";
import { T } from "../theme";

const STATS = [
  ["310+", "detection checks"],
  ["15", "scan types"],
  ["10", "languages (SAST)"],
  ["8", "package ecosystems"],
];

export default function Landing() {
  const [url, setUrl] = useState("");
  const nav = useNavigate();
  const start = (e) => { e.preventDefault(); nav("/auth", { state: { url, mode: "signup" } }); };

  return (
    <div>
      <MarketingNav />

      {/* Hero — two column: pitch on the left, live scan on the right */}
      <header style={{ position: "relative", overflow: "hidden" }}>
        <div style={{ position: "absolute", inset: 0, background: "radial-gradient(ellipse 50% 40% at 20% -5%, rgba(6,182,212,0.16), transparent 65%), radial-gradient(ellipse 40% 50% at 90% 10%, rgba(6,182,212,0.10), transparent 65%)", pointerEvents: "none" }} />
        <div style={{ position: "relative", maxWidth: 1200, margin: "0 auto", padding: "72px 28px 64px", display: "grid", gridTemplateColumns: "1.05fr 0.95fr", gap: 56, alignItems: "center" }} className="hero-grid">
          <div style={{ animation: "fadeUp 0.7s ease both" }}>
            <div style={{ display: "inline-flex", alignItems: "center", gap: 8, padding: "6px 14px", borderRadius: 999, border: "1px solid rgba(6,182,212,0.35)", background: "rgba(6,182,212,0.08)", color: T.accentHi, fontSize: 12.5, fontWeight: 500, marginBottom: 26 }}>
              <span style={{ width: 7, height: 7, borderRadius: "50%", background: T.accent, animation: "blink 1.6s infinite" }} />
              310+ real checks across web, cloud, mobile & code
            </div>
            <h1 style={{ fontFamily: T.heading, fontSize: "clamp(38px, 5vw, 62px)", fontWeight: 800, letterSpacing: "-0.03em", lineHeight: 1.04, margin: "0 0 20px" }}>
              Find vulnerabilities before <span style={{ color: T.accent, textShadow: "0 0 40px rgba(6,182,212,0.4)" }}>hackers do</span>
            </h1>
            <p style={{ fontSize: 17.5, lineHeight: 1.6, color: T.muted, maxWidth: 520, margin: "0 0 32px" }}>
              Pentrixa scans your websites, APIs, mobile apps, cloud and source code for real, exploitable issues — then ranks them by what's being attacked in the wild and tells you exactly how to fix each one.
            </p>
            <form onSubmit={start} style={{ display: "flex", gap: 10, maxWidth: 500, flexWrap: "wrap" }}>
              <input value={url} onChange={(e) => setUrl(e.target.value)} type="text" placeholder="https://your-website.com" aria-label="Website URL" style={{ flex: 1, minWidth: 230, padding: "14px 16px", borderRadius: 12, border: `1px solid ${T.borderStrong}`, background: "rgba(255,255,255,0.05)", color: T.text, fontSize: 15, fontFamily: T.body }} />
              <button type="submit" style={{ ...primaryBtn, padding: "14px 22px" }}>Scan free →</button>
            </form>
            <div style={{ display: "flex", gap: 20, marginTop: 24, color: T.faint, fontSize: 12.5, fontWeight: 500, flexWrap: "wrap" }}>
              {["No credit card", "OWASP Top 10:2025", "Only scans sites you own"].map((t) => (
                <span key={t} style={{ display: "flex", alignItems: "center", gap: 6 }}>
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={T.accent} strokeWidth="2.4"><path d="M20 6L9 17l-5-5" /></svg>{t}
                </span>
              ))}
            </div>
          </div>
          <div style={{ animation: "fadeUp 0.9s ease both" }}><ScanTerminal /></div>
        </div>
      </header>

      {/* Standards bar */}
      <div style={{ borderTop: `1px solid ${T.border}`, borderBottom: `1px solid ${T.border}`, background: "rgba(255,255,255,0.015)" }}>
        <div style={{ maxWidth: 1040, margin: "0 auto", padding: "20px 28px", display: "flex", alignItems: "center", justifyContent: "center", gap: 30, flexWrap: "wrap" }}>
          <span style={{ fontSize: 12, color: T.faint, letterSpacing: "0.06em", fontFamily: T.mono }}>BUILT ON THE STANDARDS THAT MATTER</span>
          {["OWASP", "CWE", "OSV.dev", "CISA KEV", "FIRST EPSS", "Nuclei"].map((n) => (
            <span key={n} style={{ fontFamily: T.heading, fontWeight: 700, fontSize: 15.5, color: T.muted, opacity: 0.8 }}>{n}</span>
          ))}
        </div>
      </div>

      {/* Stats band */}
      <section style={{ maxWidth: 1000, margin: "0 auto", padding: "64px 28px 20px" }}>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 1, background: T.border, border: `1px solid ${T.border}`, borderRadius: 16, overflow: "hidden" }} className="stats-band">
          {STATS.map(([n, l]) => (
            <div key={l} style={{ background: "rgba(255,255,255,0.02)", padding: "26px 20px", textAlign: "center" }}>
              <div style={{ fontFamily: T.heading, fontSize: 38, fontWeight: 800, color: T.accent, letterSpacing: "-0.02em" }}>{n}</div>
              <div style={{ fontSize: 13, color: T.muted, marginTop: 4 }}>{l}</div>
            </div>
          ))}
        </div>
      </section>

      {/* Features preview */}
      <section style={{ maxWidth: 1160, margin: "0 auto", padding: "60px 28px" }}>
        <div style={{ textAlign: "center", maxWidth: 640, margin: "0 auto 48px" }}>
          <span style={eyebrow}>One platform</span>
          <h2 style={sectionTitle}>Your entire attack surface, covered</h2>
          <p style={{ color: T.muted, fontSize: 16, lineHeight: 1.6, margin: 0 }}>From a live web app to a cloud account to the source code itself — scanned, prioritised and fixable in one place.</p>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", gap: 18 }}>
          {FEATURES.slice(0, 3).map((f) => (
            <div key={f.title} style={{ padding: "28px 26px", borderRadius: 18, border: `1px solid ${T.border}`, background: "rgba(255,255,255,0.025)" }}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 16 }}>
                <div style={{ width: 42, height: 42, borderRadius: 11, background: "rgba(6,182,212,0.1)", border: "1px solid rgba(6,182,212,0.25)", display: "flex", alignItems: "center", justifyContent: "center" }}>
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke={T.accent} strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /></svg>
                </div>
                <span style={{ fontFamily: T.mono, fontSize: 11, color: T.accentHi, background: "rgba(6,182,212,0.1)", padding: "3px 9px", borderRadius: 6 }}>{f.tag}</span>
              </div>
              <h3 style={{ fontFamily: T.heading, fontSize: 18, fontWeight: 600, margin: "0 0 8px" }}>{f.title}</h3>
              <p style={{ fontSize: 13.5, lineHeight: 1.55, color: T.muted, margin: 0 }}>{f.desc}</p>
            </div>
          ))}
        </div>
        <div style={{ textAlign: "center", marginTop: 32 }}>
          <Link to="/features" style={{ color: T.accentHi, fontSize: 15, fontWeight: 600 }}>Explore all six scanning domains →</Link>
        </div>
      </section>

      {/* Score showcase */}
      <section style={{ maxWidth: 1040, margin: "0 auto", padding: "40px 28px 72px" }}>
        <div style={{ display: "grid", gridTemplateColumns: "1.1fr 0.9fr", gap: 48, alignItems: "center" }} className="score-grid">
          <div>
            <span style={eyebrow}>Fix-first, not noise-first</span>
            <h2 style={sectionTitle}>One score. Total clarity.</h2>
            <p style={{ color: T.muted, fontSize: 16, lineHeight: 1.6, margin: "0 0 22px" }}>Every scan produces a Security Score from 0–100, weighted by real exploitability — not raw finding counts. Watch it climb as you ship fixes.</p>
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
          <div style={{ padding: "44px", borderRadius: 20, border: `1px solid ${T.border}`, background: "linear-gradient(180deg, rgba(6,182,212,0.06), rgba(255,255,255,0.02))", textAlign: "center" }}>
            <div style={{ fontFamily: T.heading, fontSize: 84, fontWeight: 800, letterSpacing: "-0.03em", color: T.accent, textShadow: "0 0 50px rgba(6,182,212,0.4)", lineHeight: 1 }}>92</div>
            <div style={{ fontSize: 13, color: T.muted, letterSpacing: "0.08em", textTransform: "uppercase", marginTop: 8 }}>Security Score</div>
            <div style={{ display: "inline-flex", alignItems: "center", gap: 6, marginTop: 16, padding: "5px 12px", borderRadius: 999, background: "rgba(6,182,212,0.1)", color: T.accentHi, fontSize: 13, fontWeight: 600 }}>▲ +14 this month</div>
          </div>
        </div>
      </section>

      {/* Testimonials */}
      <section style={{ maxWidth: 1120, margin: "0 auto", padding: "20px 28px 80px" }}>
        <div style={{ textAlign: "center", marginBottom: 44 }}>
          <span style={eyebrow}>Trusted by builders</span>
          <h2 style={sectionTitle}>Loved by people who ship</h2>
        </div>
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
      <section style={{ padding: "10px 28px 96px", textAlign: "center" }}>
        <div style={{ maxWidth: 760, margin: "0 auto", padding: "56px 40px", borderRadius: 24, border: "1px solid rgba(6,182,212,0.28)", background: "linear-gradient(180deg, rgba(6,182,212,0.09), transparent)", position: "relative", overflow: "hidden" }}>
          <h2 style={{ fontFamily: T.heading, fontSize: "clamp(28px, 4vw, 38px)", fontWeight: 700, margin: "0 0 12px" }}>Run your first scan in 60 seconds</h2>
          <p style={{ color: T.muted, margin: "0 0 28px", fontSize: 16 }}>Free tier. No credit card. Findings you can act on today.</p>
          <Link to="/auth" state={{ mode: "signup" }} style={{ ...primaryBtn, display: "inline-block", padding: "15px 30px", fontSize: 15.5 }}>Start free scan →</Link>
        </div>
      </section>

      <MarketingFooter />
    </div>
  );
}
