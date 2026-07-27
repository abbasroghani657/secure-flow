import { Link } from "react-router-dom";
import { primaryBtn, ghostBtn } from "../components/ui";
import { MarketingNav, MarketingFooter, PRICING, sectionTitle, eyebrow } from "../components/marketing";
import { T } from "../theme";

const FAQ = [
  ["Is there really a free tier?", "Yes, one verified target, the web scan, the OWASP Top 10 scorecard and PDF export, free forever. No credit card."],
  ["What does “verified target” mean?", "You can only scan a domain after proving you control it (a DNS TXT record, an HTML meta tag, or a .well-known file). This keeps every scan authorised and legally defensible."],
  ["Do you store my source code or credentials?", "No. Uploaded files (APK/IPA, source archives, IaC, container images) are analysed and deleted immediately after the scan. Cloud keys are used only for that scan and wiped."],
  ["Can I cancel anytime?", "Yes. Plans are month-to-month; cancel whenever and keep access until the period ends."],
];

export default function Pricing() {
  return (
    <div>
      <MarketingNav />
      <header style={{ maxWidth: 760, margin: "0 auto", padding: "72px 28px 12px", textAlign: "center" }}>
        <span style={eyebrow}>Pricing</span>
        <h1 style={{ fontFamily: T.heading, fontSize: "clamp(34px, 5vw, 52px)", fontWeight: 800, letterSpacing: "-0.03em", margin: "0 0 16px" }}>Pricing that scales with you</h1>
        <p style={{ fontSize: 17, color: T.muted, margin: 0 }}>Start free. Upgrade when you need depth, scheduling or clients.</p>
      </header>

      <section style={{ maxWidth: 1040, margin: "0 auto", padding: "44px 28px 20px" }}>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: 18, alignItems: "start" }}>
          {PRICING.map((p) => (
            <div key={p.name} style={{ position: "relative", padding: "34px 30px", borderRadius: 20, border: `1.5px solid ${p.featured ? T.accent : T.border}`, background: p.featured ? "linear-gradient(180deg, rgba(6,182,212,0.09), rgba(255,255,255,0.02))" : "rgba(255,255,255,0.02)", boxShadow: p.featured ? "0 24px 70px rgba(6,182,212,0.14)" : "none" }}>
              {p.featured && <span style={{ position: "absolute", top: -13, left: "50%", transform: "translateX(-50%)", fontSize: 11, fontWeight: 700, letterSpacing: "0.06em", textTransform: "uppercase", color: T.accentInk, background: T.accent, padding: "5px 14px", borderRadius: 999 }}>Most popular</span>}
              <div style={{ fontFamily: T.heading, fontSize: 19, fontWeight: 600 }}>{p.name}</div>
              <div style={{ margin: "14px 0 4px", display: "flex", alignItems: "baseline", gap: 6 }}>
                <span style={{ fontFamily: T.heading, fontSize: 46, fontWeight: 800, letterSpacing: "-0.02em" }}>{p.price}</span>
                <span style={{ color: T.muted, fontSize: 14.5 }}>{p.period}</span>
              </div>
              <p style={{ color: T.muted, fontSize: 14, margin: "0 0 22px" }}>{p.blurb}</p>
              <Link to="/auth" state={{ mode: "signup" }} style={{ ...(p.featured ? primaryBtn : ghostBtn), display: "block", textAlign: "center", marginBottom: 22 }}>{p.cta}</Link>
              <div style={{ display: "grid", gap: 11 }}>
                {p.features.map((ft) => (
                  <div key={ft} style={{ display: "flex", gap: 10, alignItems: "flex-start", fontSize: 14, color: T.text }}>
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke={T.accent} strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" style={{ flex: "none", marginTop: 2 }}><path d="M20 6L9 17l-5-5" /></svg>{ft}
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </section>

      <section style={{ maxWidth: 760, margin: "0 auto", padding: "56px 28px 90px" }}>
        <h2 style={{ ...sectionTitle, textAlign: "center", marginBottom: 30 }}>Frequently asked</h2>
        <div style={{ display: "grid", gap: 12 }}>
          {FAQ.map(([q, a]) => (
            <div key={q} style={{ padding: "22px 24px", borderRadius: 14, border: `1px solid ${T.border}`, background: "rgba(255,255,255,0.02)" }}>
              <div style={{ fontSize: 15.5, fontWeight: 600, marginBottom: 8 }}>{q}</div>
              <p style={{ fontSize: 14, lineHeight: 1.6, color: T.muted, margin: 0 }}>{a}</p>
            </div>
          ))}
        </div>
      </section>
      <MarketingFooter />
    </div>
  );
}
