import { Link } from "react-router-dom";
import { primaryBtn, ghostBtn } from "../components/ui";
import { MarketingNav, MarketingFooter, sectionTitle, eyebrow } from "../components/marketing";
import { Icon, IconBadge } from "../components/icons";
import { T } from "../theme";

// The core loop, four honest steps from "I own this" to "it's fixed".
const STEPS = [
  { n: "01", icon: "shield", title: "Prove you own it",
    desc: "Add a target and verify control with a DNS TXT record, an HTML meta tag, or a .well-known file. Every scan is authorised, so results are legally defensible, not a stranger poking your site.",
    tag: "Authorised only" },
  { n: "02", icon: "search", title: "Scan the whole surface",
    desc: "Point Pentrixa at a URL, upload an APK / IPA / source archive / container, or connect a cloud account. Fifteen scan types and 310+ checks run across web, mobile, cloud, code and supply chain.",
    tag: "15 scan types" },
  { n: "03", icon: "target", title: "See what to fix first",
    desc: "Findings are enriched with OWASP, CWE, a confidence level and a 0-100 priority blended from severity, CISA-KEV (exploited right now?) and EPSS. You get ‘patch these five’, not ‘here are 400’.",
    tag: "KEV + EPSS" },
  { n: "04", icon: "plug", title: "Fix it inside your workflow",
    desc: "Read the remediation with evidence, get alerts in Slack / Teams, and wire the CLI or GitHub Action into CI so a new high or critical fails the build before it ships. Re-scan confirms the fix.",
    tag: "CI/CD + alerts" },
];

// Who uses it and why, the purposes, spelled out.
const AUDIENCES = [
  { icon: "code", title: "Engineering & DevSecOps",
    desc: "Catch vulnerabilities in the pull request, not in production. The GitHub Action blocks a merge on new high/critical findings, so security shifts left without a security engineer in every review.",
    points: ["Fail the build on new criticals", "Scan every PR automatically", "No bug reaches production unseen"] },
  { icon: "briefcase", title: "Agencies & consultants",
    desc: "Scan a client site in minutes and hand them a clean OWASP scorecard and PDF. One tool replaces a dependency scanner, a DAST and half a cloud checklist, so a full assessment fits in an afternoon.",
    points: ["Client-ready OWASP report", "Ten domains in one pass", "White-glove findings, not noise"] },
  { icon: "file", title: "Compliance & risk",
    desc: "Every finding maps to PCI DSS, SOC 2, ISO 27001, HIPAA and GDPR controls. Continuous monitoring plus drift alerts give auditors evidence that posture is watched, not checked once a year.",
    points: ["PCI / SOC2 / ISO mapping", "Continuous monitoring", "Auditor-ready exports"] },
  { icon: "bolt", title: "Founders & startups",
    desc: "You don't have a security team yet, so Pentrixa is one. Verify your app, run a scan, and get a prioritised list a developer can act on today, with the fixes explained in plain language.",
    points: ["Security team in a box", "Plain-language remediation", "Start free, upgrade when you grow"] },
];

// The three places Pentrixa shows up in your day.
const SURFACES = [
  { icon: "gauge", title: "The dashboard", desc: "A live security score, trend over time, and the OWASP Top 10 scorecard, green where you're clean, expandable where you're not." },
  { icon: "plug", title: "Your chat", desc: "Slack, Teams or Discord get a message the moment a scan finishes, filtered to critical/high, new-only, or every run." },
  { icon: "repeat", title: "Your pipeline", desc: "The CLI and GitHub Action run scans in CI and fail the build on new risk, so a regression never merges quietly." },
];

const num = { fontFamily: T.mono, fontSize: 13, color: T.accent, letterSpacing: "0.1em" };

export default function HowItWorks() {
  return (
    <div>
      <MarketingNav />

      {/* Hero */}
      <header style={{ maxWidth: 860, margin: "0 auto", padding: "72px 28px 24px", textAlign: "center" }}>
        <span style={eyebrow}>How it works</span>
        <h1 style={{ fontFamily: T.heading, fontSize: "clamp(34px, 5vw, 54px)", fontWeight: 800, letterSpacing: "-0.03em", lineHeight: 1.05, margin: "0 0 18px" }}>
          From “I own this site” to “it's fixed,” in one loop
        </h1>
        <p style={{ fontSize: 17.5, lineHeight: 1.6, color: T.muted, maxWidth: 640, margin: "0 auto" }}>
          Pentrixa is built around a simple, repeatable cycle: verify, scan, prioritise, and fix, wired into the tools your team already uses. Here's exactly how, and who it's for.
        </p>
      </header>

      {/* The 4-step loop */}
      <section style={{ maxWidth: 1120, margin: "0 auto", padding: "44px 28px 20px" }}>
        <div style={{ display: "grid", gap: 18 }}>
          {STEPS.map((s) => (
            <div key={s.n} style={{ display: "grid", gridTemplateColumns: "auto 1fr auto", gap: 26, alignItems: "center", padding: "28px 30px", borderRadius: 18, border: `1px solid ${T.border}`, background: "rgba(255,255,255,0.02)" }} className="how-step">
              <div style={{ display: "flex", alignItems: "center", gap: 20 }}>
                <span style={num}>{s.n}</span>
                <IconBadge name={s.icon} size={48} />
              </div>
              <div>
                <h2 style={{ fontFamily: T.heading, fontSize: 22, fontWeight: 700, margin: "0 0 7px", letterSpacing: "-0.02em" }}>{s.title}</h2>
                <p style={{ fontSize: 15, lineHeight: 1.6, color: T.muted, margin: 0, maxWidth: 640 }}>{s.desc}</p>
              </div>
              <span style={{ fontFamily: T.mono, fontSize: 11, color: T.accentHi, background: "rgba(6,182,212,0.1)", padding: "5px 12px", borderRadius: 6, whiteSpace: "nowrap" }} className="how-tag">{s.tag}</span>
            </div>
          ))}
        </div>
      </section>

      {/* Where it fits */}
      <section style={{ maxWidth: 1120, margin: "0 auto", padding: "56px 28px 20px", textAlign: "center" }}>
        <span style={eyebrow}>Where it fits</span>
        <h2 style={sectionTitle}>It meets your team where they already work</h2>
        <p style={{ color: T.muted, fontSize: 15.5, margin: "0 auto 34px", maxWidth: 620 }}>
          Security that lives in a separate tab gets ignored. Pentrixa shows up in three places instead.
        </p>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 18 }} className="how-surfaces">
          {SURFACES.map((s) => (
            <div key={s.title} style={{ padding: "30px 26px", borderRadius: 16, border: `1px solid ${T.border}`, background: "linear-gradient(180deg, rgba(6,182,212,0.05), transparent)", textAlign: "left" }}>
              <IconBadge name={s.icon} size={44} />
              <h3 style={{ fontFamily: T.heading, fontSize: 18, fontWeight: 700, margin: "16px 0 8px" }}>{s.title}</h3>
              <p style={{ fontSize: 14, lineHeight: 1.6, color: T.muted, margin: 0 }}>{s.desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Who it's for */}
      <section style={{ maxWidth: 1120, margin: "0 auto", padding: "56px 28px 20px", textAlign: "center" }}>
        <span style={eyebrow}>Who it's for</span>
        <h2 style={sectionTitle}>One platform, four kinds of team</h2>
        <p style={{ color: T.muted, fontSize: 15.5, margin: "0 auto 34px", maxWidth: 620 }}>
          The same engine, pointed at the problem you actually have.
        </p>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 18 }} className="how-audiences">
          {AUDIENCES.map((a) => (
            <div key={a.title} style={{ padding: "30px 30px", borderRadius: 18, border: `1px solid ${T.border}`, background: "rgba(255,255,255,0.02)", textAlign: "left" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 14, marginBottom: 14 }}>
                <IconBadge name={a.icon} size={44} />
                <h3 style={{ fontFamily: T.heading, fontSize: 20, fontWeight: 700, margin: 0, letterSpacing: "-0.02em" }}>{a.title}</h3>
              </div>
              <p style={{ fontSize: 14.5, lineHeight: 1.65, color: T.muted, margin: "0 0 16px" }}>{a.desc}</p>
              <div style={{ display: "grid", gap: 9 }}>
                {a.points.map((p) => (
                  <div key={p} style={{ display: "flex", gap: 10, alignItems: "center", fontSize: 14, color: T.text }}>
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke={T.accent} strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" style={{ flex: "none" }}><path d="M20 6L9 17l-5-5" /></svg>{p}
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Authorisation / trust band */}
      <section style={{ maxWidth: 1000, margin: "0 auto", padding: "56px 28px" }}>
        <div style={{ display: "flex", gap: 22, alignItems: "flex-start", padding: "32px 34px", borderRadius: 18, border: `1px solid ${T.borderStrong}`, background: "linear-gradient(120deg, rgba(6,182,212,0.07), transparent)" }} className="how-trust">
          <span style={{ flex: "none" }}><Icon name="lock" size={30} color={T.accent} /></span>
          <div>
            <h3 style={{ fontFamily: T.heading, fontSize: 20, fontWeight: 700, margin: "0 0 8px" }}>You can only scan what you own</h3>
            <p style={{ fontSize: 15, lineHeight: 1.65, color: T.muted, margin: 0 }}>
              Verification isn't a formality, it's the foundation. No target runs until you've proven control, uploaded files and cloud keys are analysed then deleted, and nothing is scanned without your say-so. That's how a security tool earns trust.
            </p>
          </div>
        </div>
      </section>

      {/* CTA */}
      <section style={{ padding: "20px 28px 90px", textAlign: "center" }}>
        <h2 style={{ fontFamily: T.heading, fontSize: "clamp(26px, 3.4vw, 36px)", fontWeight: 800, letterSpacing: "-0.02em", margin: "0 0 20px" }}>
          Run the loop on your own site
        </h2>
        <div style={{ display: "flex", gap: 14, justifyContent: "center", flexWrap: "wrap" }}>
          <Link to="/auth" state={{ mode: "signup" }} className="btn-primary" style={{ ...primaryBtn, display: "inline-block", padding: "14px 28px", fontSize: 15.5 }}>Start scanning free →</Link>
          <Link to="/features" className="btn-ghost" style={{ ...ghostBtn, display: "inline-block", padding: "14px 26px", fontSize: 15.5 }}>See every feature</Link>
        </div>
      </section>

      <MarketingFooter />
    </div>
  );
}
