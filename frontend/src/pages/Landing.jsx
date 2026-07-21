import { Link, useNavigate } from "react-router-dom";
import { useState } from "react";
import { Logo, primaryBtn, ghostBtn } from "../components/ui";
import { useAuth } from "../auth";
import { T } from "../theme";

const FEATURES = [
  { title: "Security header analysis", desc: "HSTS, CSP, X-Frame-Options, cookie flags and more — checked on every scan." },
  { title: "Exposed file detection", desc: "Finds public .git, .env, backups and config files before attackers do." },
  { title: "TLS & HTTPS checks", desc: "Verifies encryption, redirects and downgrade protection end to end." },
  { title: "Compliance mapping", desc: "Every finding maps to OWASP Top 10, PCI DSS and ISO 27001 controls." },
  { title: "Security score", desc: "A single 0–100 score weighted by real exploitability, not raw counts." },
  { title: "Actionable fixes", desc: "Each finding ships with the exact remediation and evidence." },
];

export default function Landing() {
  const [url, setUrl] = useState("");
  const { user } = useAuth();
  const nav = useNavigate();

  function start(e) {
    e.preventDefault();
    nav("/auth", { state: { url } });
  }

  return (
    <div>
      <nav style={{ position: "sticky", top: 0, zIndex: 50, display: "flex", alignItems: "center", justifyContent: "space-between", gap: 24, padding: "14px 40px", background: "rgba(13,15,13,0.82)", backdropFilter: "blur(14px)", borderBottom: `1px solid ${T.border}` }}>
        <Link to="/"><Logo /></Link>
        <div style={{ display: "flex", gap: 28, fontSize: 14, color: T.muted }}>
          <a href="#features" style={{ color: T.muted }}>Features</a>
          <a href="#how" style={{ color: T.muted }}>How it works</a>
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

      <header style={{ position: "relative", overflow: "hidden", padding: "96px 40px 72px", textAlign: "center" }}>
        <div style={{ position: "absolute", inset: 0, background: "radial-gradient(ellipse 60% 45% at 50% -5%, rgba(0,191,99,0.18), transparent 70%), radial-gradient(ellipse 40% 35% at 85% 20%, rgba(6,182,212,0.10), transparent 70%)", pointerEvents: "none" }} />
        <div style={{ position: "relative", maxWidth: 860, margin: "0 auto", animation: "fadeUp 0.7s ease both" }}>
          <div style={{ display: "inline-flex", alignItems: "center", gap: 8, padding: "6px 14px", borderRadius: 999, border: "1px solid rgba(0,191,99,0.35)", background: "rgba(0,191,99,0.08)", color: T.accentHi, fontSize: 13, fontWeight: 500, marginBottom: 28 }}>
            <span style={{ width: 7, height: 7, borderRadius: "50%", background: T.accent, animation: "blink 1.6s infinite" }} />
            Real scanning engine — no signup credit card required
          </div>
          <h1 style={{ fontFamily: T.heading, fontSize: "clamp(40px, 6vw, 68px)", fontWeight: 800, letterSpacing: "-0.03em", lineHeight: 1.05, margin: "0 0 20px" }}>
            Find vulnerabilities<br />before <span style={{ color: T.accent, textShadow: "0 0 40px rgba(0,191,99,0.4)" }}>hackers do</span>
          </h1>
          <p style={{ fontSize: 18, lineHeight: 1.6, color: T.muted, maxWidth: 620, margin: "0 auto 36px" }}>
            SecureFlow scans your websites for real misconfigurations and exposures — security headers, TLS, leaked files — then tells you exactly how to fix each one.
          </p>
          <form onSubmit={start} style={{ display: "flex", gap: 10, maxWidth: 560, margin: "0 auto", flexWrap: "wrap", justifyContent: "center" }}>
            <input value={url} onChange={(e) => setUrl(e.target.value)} type="text" placeholder="https://your-website.com" aria-label="Website URL" style={{ flex: 1, minWidth: 260, padding: "15px 18px", borderRadius: 12, border: `1px solid ${T.borderStrong}`, background: "rgba(255,255,255,0.05)", color: T.text, fontSize: 15, fontFamily: T.body }} />
            <button type="submit" style={{ ...primaryBtn, padding: "15px 24px" }}>Scan Now — Free</button>
          </form>
          <div style={{ display: "flex", gap: 22, justifyContent: "center", marginTop: 26, color: T.faint, fontSize: 12.5, fontWeight: 500, flexWrap: "wrap" }}>
            {["OWASP Top 10", "PCI DSS", "ISO 27001", "Only scans sites you own"].map((t) => (
              <span key={t} style={{ display: "flex", alignItems: "center", gap: 6 }}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M20 6L9 17l-5-5" /></svg>{t}
              </span>
            ))}
          </div>
        </div>
      </header>

      <section id="features" style={{ padding: "88px 40px", maxWidth: 1180, margin: "0 auto" }}>
        <div style={{ textAlign: "center", maxWidth: 640, margin: "0 auto 56px" }}>
          <h2 style={{ fontFamily: T.heading, fontSize: 40, fontWeight: 700, letterSpacing: "-0.02em", margin: "0 0 14px" }}>Your attack surface, covered</h2>
          <p style={{ color: T.muted, fontSize: 16, lineHeight: 1.6, margin: 0 }}>Every scan runs real checks against your live site and returns prioritised, fixable findings.</p>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(250px, 1fr))", gap: 18 }}>
          {FEATURES.map((f) => (
            <div key={f.title} style={{ padding: "26px 24px", borderRadius: 16, border: `1px solid ${T.border}`, background: "rgba(255,255,255,0.025)" }}>
              <div style={{ width: 42, height: 42, borderRadius: 11, background: "rgba(0,191,99,0.1)", border: "1px solid rgba(0,191,99,0.25)", display: "flex", alignItems: "center", justifyContent: "center", marginBottom: 16 }}>
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke={T.accent} strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /></svg>
              </div>
              <h3 style={{ fontFamily: T.heading, fontSize: 17, fontWeight: 600, margin: "0 0 8px" }}>{f.title}</h3>
              <p style={{ fontSize: 13.5, lineHeight: 1.55, color: T.muted, margin: 0 }}>{f.desc}</p>
            </div>
          ))}
        </div>
      </section>

      <section id="how" style={{ padding: "40px 40px 100px", textAlign: "center" }}>
        <div style={{ maxWidth: 720, margin: "0 auto", padding: "48px 40px", borderRadius: 20, border: "1px solid rgba(0,191,99,0.25)", background: "linear-gradient(180deg, rgba(0,191,99,0.06), transparent)" }}>
          <h2 style={{ fontFamily: T.heading, fontSize: 32, fontWeight: 700, margin: "0 0 12px" }}>Scan your first site in 30 seconds</h2>
          <p style={{ color: T.muted, margin: "0 0 28px" }}>Create an account, enter a URL you control, and get a full report.</p>
          <Link to="/auth" style={{ ...primaryBtn, display: "inline-block" }}>Get started free</Link>
        </div>
      </section>

      <footer style={{ padding: "28px 40px", borderTop: `1px solid ${T.border}`, display: "flex", justifyContent: "space-between", flexWrap: "wrap", gap: 12, color: T.faint, fontSize: 13 }}>
        <Logo size={16} />
        <span>© {new Date().getFullYear()} SecureFlow. Scan only what you own.</span>
      </footer>
    </div>
  );
}
