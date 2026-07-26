import { Link } from "react-router-dom";
import { primaryBtn } from "../components/ui";
import { MarketingNav, MarketingFooter, COMPARE, Check, eyebrow } from "../components/marketing";
import { T } from "../theme";

export default function Compare() {
  return (
    <div>
      <MarketingNav />
      <header style={{ maxWidth: 760, margin: "0 auto", padding: "72px 28px 12px", textAlign: "center" }}>
        <span style={eyebrow}>Compare</span>
        <h1 style={{ fontFamily: T.heading, fontSize: "clamp(34px, 5vw, 52px)", fontWeight: 800, letterSpacing: "-0.03em", margin: "0 0 16px" }}>How Pentrixa compares</h1>
        <p style={{ fontSize: 17, color: T.muted, margin: 0 }}>Most tools do one layer well. Pentrixa covers your whole attack surface — and tells you what to fix first.</p>
      </header>

      <section style={{ maxWidth: 940, margin: "0 auto", padding: "44px 28px 30px" }}>
        <div style={{ overflowX: "auto", borderRadius: 18, border: `1px solid ${T.border}` }}>
          <table style={{ width: "100%", borderCollapse: "collapse", minWidth: 620 }}>
            <thead>
              <tr style={{ background: "rgba(255,255,255,0.03)" }}>
                <th style={{ textAlign: "left", padding: "18px 22px", fontSize: 13, color: T.muted, fontWeight: 600 }}>Capability</th>
                <th style={{ padding: "18px 14px", fontSize: 15, fontWeight: 700, color: T.accent }}>Pentrixa</th>
                <th style={{ padding: "18px 14px", fontSize: 13.5, color: T.muted, fontWeight: 600 }}>Detectify</th>
                <th style={{ padding: "18px 14px", fontSize: 13.5, color: T.muted, fontWeight: 600 }}>Burp Suite</th>
              </tr>
            </thead>
            <tbody>
              {COMPARE.map((r, i) => (
                <tr key={r[0]} style={{ borderTop: `1px solid ${T.border}`, background: i % 2 ? "transparent" : "rgba(255,255,255,0.012)" }}>
                  <td style={{ padding: "15px 22px", fontSize: 14.5, color: T.text }}>{r[0]}</td>
                  {[1, 2, 3].map((c) => (
                    <td key={c} style={{ padding: "15px 14px", textAlign: "center" }}><span style={{ display: "inline-flex" }}><Check ok={r[c]} /></span></td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p style={{ textAlign: "center", color: T.faint, fontSize: 12.5, marginTop: 16 }}>Comparison reflects each product's core self-serve offering. Names are trademarks of their respective owners.</p>
      </section>

      <section style={{ padding: "40px 28px 90px", textAlign: "center" }}>
        <Link to="/auth" state={{ mode: "signup" }} className="btn-primary" style={{ ...primaryBtn, display: "inline-block", padding: "14px 28px", fontSize: 15.5 }}>See it on your site →</Link>
      </section>
      <MarketingFooter />
    </div>
  );
}
