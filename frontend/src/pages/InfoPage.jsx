import { useLocation, Link, Navigate } from "react-router-dom";
import { primaryBtn } from "../components/ui";
import { MarketingNav, MarketingFooter, eyebrow } from "../components/marketing";
import { PAGES } from "../data/pages";
import { T } from "../theme";

export default function InfoPage() {
  const loc = useLocation();
  const key = loc.pathname.replace("/", "");
  const page = PAGES[key];
  if (!page) return <Navigate to="/" replace />;

  return (
    <div>
      <MarketingNav />
      <header style={{ maxWidth: 760, margin: "0 auto", padding: "72px 28px 8px" }}>
        <span style={eyebrow}>{page.eyebrow}</span>
        <h1 style={{ fontFamily: T.heading, fontSize: "clamp(32px, 4.5vw, 48px)", fontWeight: 800, letterSpacing: "-0.03em", lineHeight: 1.08, margin: "0 0 18px" }}>{page.title}</h1>
        <p style={{ fontSize: 17.5, lineHeight: 1.6, color: T.muted, margin: 0 }}>{page.intro}</p>
      </header>

      <section style={{ maxWidth: 760, margin: "0 auto", padding: "36px 28px 20px", display: "grid", gap: 14 }}>
        {page.sections.map(([h, body], i) => (
          <div key={h} style={{ display: "grid", gridTemplateColumns: "auto 1fr", gap: "0 20px", alignItems: "start", padding: "24px 26px", borderRadius: 16, border: `1px solid ${T.border}`, background: "rgba(255,255,255,0.02)" }}>
            <span style={{ gridRow: "1 / span 2", fontFamily: T.mono, fontSize: 13, fontWeight: 700, color: T.accent, opacity: 0.7 }}>{String(i + 1).padStart(2, "0")}</span>
            <h2 style={{ fontFamily: T.heading, fontSize: 18.5, fontWeight: 600, margin: "0 0 8px" }}>{h}</h2>
            <p style={{ gridColumn: 2, fontSize: 14.5, lineHeight: 1.65, color: T.muted, margin: 0 }}>{body}</p>
          </div>
        ))}
      </section>

      <section style={{ maxWidth: 760, margin: "0 auto", padding: "26px 28px 90px" }}>
        <div style={{ padding: "32px 34px", borderRadius: 18, border: "1px solid rgba(6,182,212,0.28)", background: "linear-gradient(180deg, rgba(6,182,212,0.08), transparent)", display: "flex", alignItems: "center", justifyContent: "space-between", gap: 20, flexWrap: "wrap" }}>
          <div>
            <div style={{ fontFamily: T.heading, fontSize: 21, fontWeight: 700 }}>Ready to see your posture?</div>
            <div style={{ color: T.muted, fontSize: 14.5, marginTop: 4 }}>Free tier, no credit card.</div>
          </div>
          <Link to="/auth" state={{ mode: "signup" }} className="btn-primary" style={{ ...primaryBtn, display: "inline-block", padding: "13px 26px", whiteSpace: "nowrap" }}>Start free →</Link>
        </div>
      </section>
      <MarketingFooter />
    </div>
  );
}
