import { Link } from "react-router-dom";
import { primaryBtn } from "../components/ui";
import { MarketingNav, MarketingFooter, FEATURES, sectionTitle, eyebrow } from "../components/marketing";
import { T } from "../theme";

const SCAN_TYPES = [
  "Web app (DAST)", "Deep scan (Nuclei)", "API spec (OpenAPI)", "Android APK", "iOS IPA",
  "IDOR / BOLA", "Dependencies (SCA)", "Infrastructure (IaC)", "Container image", "Secrets",
  "CI/CD pipeline", "SAST (source)", "Cloud posture (AWS)", "AI / LLM", "WordPress / CMS",
];

export default function Features() {
  return (
    <div>
      <MarketingNav />
      <header style={{ maxWidth: 820, margin: "0 auto", padding: "72px 28px 20px", textAlign: "center" }}>
        <span style={eyebrow}>Features</span>
        <h1 style={{ fontFamily: T.heading, fontSize: "clamp(34px, 5vw, 52px)", fontWeight: 800, letterSpacing: "-0.03em", lineHeight: 1.06, margin: "0 0 18px" }}>
          Everything you need to find and fix real risk
        </h1>
        <p style={{ fontSize: 17, lineHeight: 1.6, color: T.muted, maxWidth: 620, margin: "0 auto" }}>
          Fifteen scan types, 310+ checks, one prioritised report. Here's the depth behind each domain.
        </p>
      </header>

      <section style={{ maxWidth: 1120, margin: "0 auto", padding: "44px 28px" }}>
        <div style={{ display: "grid", gap: 20 }}>
          {FEATURES.map((f, i) => (
            <div key={f.title} style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 40, alignItems: "center", padding: "34px 34px", borderRadius: 20, border: `1px solid ${T.border}`, background: "rgba(255,255,255,0.02)" }} className="feat-row">
              <div style={{ order: i % 2 ? 2 : 1 }}>
                <span style={{ fontFamily: T.mono, fontSize: 11, color: T.accentHi, background: "rgba(6,182,212,0.1)", padding: "4px 10px", borderRadius: 6 }}>{f.tag}</span>
                <h2 style={{ fontFamily: T.heading, fontSize: 26, fontWeight: 700, margin: "16px 0 12px", letterSpacing: "-0.02em" }}>{f.title}</h2>
                <p style={{ fontSize: 15, lineHeight: 1.6, color: T.muted, margin: 0 }}>{f.desc}</p>
              </div>
              <div style={{ order: i % 2 ? 1 : 2, display: "grid", gap: 12, padding: "26px 28px", borderRadius: 16, border: `1px solid ${T.border}`, background: "linear-gradient(180deg, rgba(6,182,212,0.05), transparent)" }}>
                {f.points.map((p) => (
                  <div key={p} style={{ display: "flex", gap: 11, alignItems: "center", fontSize: 14.5, color: T.text }}>
                    <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke={T.accent} strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" style={{ flex: "none" }}><path d="M20 6L9 17l-5-5" /></svg>{p}
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </section>

      <section style={{ maxWidth: 900, margin: "0 auto", padding: "40px 28px 20px", textAlign: "center" }}>
        <h2 style={sectionTitle}>Fifteen scan types under one roof</h2>
        <p style={{ color: T.muted, fontSize: 15.5, margin: "0 0 28px" }}>Point Pentrixa at a URL, upload a file, or connect a cloud account.</p>
        <div style={{ display: "flex", flexWrap: "wrap", gap: 10, justifyContent: "center" }}>
          {SCAN_TYPES.map((s) => (
            <span key={s} style={{ fontSize: 13.5, color: T.text, padding: "8px 15px", borderRadius: 999, border: `1px solid ${T.borderStrong}`, background: "rgba(255,255,255,0.025)" }}>{s}</span>
          ))}
        </div>
      </section>

      <section style={{ padding: "50px 28px 90px", textAlign: "center" }}>
        <Link to="/auth" state={{ mode: "signup" }} style={{ ...primaryBtn, display: "inline-block", padding: "14px 28px", fontSize: 15.5 }}>Start scanning free →</Link>
      </section>
      <MarketingFooter />
    </div>
  );
}
