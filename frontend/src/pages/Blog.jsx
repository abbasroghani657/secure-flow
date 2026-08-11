import { Link } from "react-router-dom";
import { MarketingNav, MarketingFooter, eyebrow } from "../components/marketing";
import { POSTS } from "../data/blog";
import { T } from "../theme";

const fmt = (d) => new Date(d).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });

export default function Blog() {
  const [lead, ...rest] = POSTS;
  return (
    <div>
      <style>{`
        @keyframes fadeUp {
          from { opacity: 0; transform: translateY(20px) scale(0.98); }
          to { opacity: 1; transform: translateY(0) scale(1); }
        }
        .blog-header { animation: fadeUp 0.6s cubic-bezier(0.16, 1, 0.3, 1) both; }
        .blog-lead { animation: fadeUp 0.6s cubic-bezier(0.16, 1, 0.3, 1) 0.15s both; transition: transform 0.2s, box-shadow 0.2s, border-color 0.2s; }
        .blog-lead:hover { transform: translateY(-3px); box-shadow: 0 12px 30px rgba(0,0,0,0.3); border-color: rgba(6,182,212,0.4) !important; }
        .blog-card { animation: fadeUp 0.6s cubic-bezier(0.16, 1, 0.3, 1) both; transition: transform 0.2s, background 0.2s, border-color 0.2s; }
        .blog-card:hover { transform: translateY(-3px); background: rgba(255,255,255,0.05) !important; border-color: rgba(255,255,255,0.15) !important; }
      `}</style>
      <MarketingNav />
      <header className="blog-header" style={{ maxWidth: 900, margin: "0 auto", padding: "72px 28px 20px", textAlign: "center" }}>
        <span style={eyebrow}>Blog</span>
        <h1 style={{ fontFamily: T.heading, fontSize: "clamp(34px, 5vw, 52px)", fontWeight: 800, letterSpacing: "-0.03em", margin: "0 0 16px" }}>Field notes on modern security</h1>
        <p style={{ fontSize: 17, color: T.muted, margin: 0 }}>Practical writing on scanning, prioritisation and the vulnerabilities that actually get people breached.</p>
      </header>

      <section style={{ maxWidth: 1120, margin: "0 auto", padding: "40px 28px 20px" }}>
        {/* Lead article */}
        <Link to={`/blog/${lead.slug}`} style={{ display: "block", borderRadius: 22, border: `1px solid ${T.border}`, overflow: "hidden", marginBottom: 26 }} className="blog-lead">
          <div style={{ display: "grid", gridTemplateColumns: "1.1fr 0.9fr", gap: 0 }} className="blog-lead-grid">
            <div style={{ padding: "44px 40px", display: "flex", flexDirection: "column", justifyContent: "center" }}>
              <span style={{ fontFamily: T.mono, fontSize: 11.5, color: T.accentHi, letterSpacing: "0.05em" }}>{lead.category.toUpperCase()} · {lead.read}</span>
              <h2 style={{ fontFamily: T.heading, fontSize: 30, fontWeight: 700, letterSpacing: "-0.02em", lineHeight: 1.15, margin: "14px 0 12px" }}>{lead.title}</h2>
              <p style={{ fontSize: 15, lineHeight: 1.6, color: T.muted, margin: "0 0 18px" }}>{lead.excerpt}</p>
              <span style={{ color: T.accentHi, fontSize: 14.5, fontWeight: 600 }}>Read article →</span>
            </div>
            <div style={{ background: "linear-gradient(135deg, rgba(6,182,212,0.14), rgba(6,182,212,0.02))", minHeight: 240, display: "flex", alignItems: "center", justifyContent: "center", borderLeft: `1px solid ${T.border}` }}>
              <svg width="80" height="80" viewBox="0 0 24 24" fill="none" stroke={T.accent} strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round" style={{ opacity: 0.7 }}><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /><path d="M9 12l2 2 4-4" /></svg>
            </div>
          </div>
        </Link>

        {/* Rest grid */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(320px, 1fr))", gap: 20 }}>
          {rest.map((p, i) => (
            <Link key={p.slug} to={`/blog/${p.slug}`} style={{ display: "flex", flexDirection: "column", borderRadius: 16, border: `1px solid ${T.border}`, background: "rgba(255,255,255,0.02)", padding: "26px 24px", gap: 12, animationDelay: `${0.25 + i * 0.1}s` }} className="blog-card">
              <span style={{ fontFamily: T.mono, fontSize: 11, color: T.accentHi, letterSpacing: "0.05em" }}>{p.category.toUpperCase()} · {p.read}</span>
              <h3 style={{ fontFamily: T.heading, fontSize: 19, fontWeight: 700, lineHeight: 1.25, margin: 0, letterSpacing: "-0.01em" }}>{p.title}</h3>
              <p style={{ fontSize: 13.5, lineHeight: 1.55, color: T.muted, margin: 0, flex: 1 }}>{p.excerpt}</p>
              <span style={{ fontSize: 12.5, color: T.faint, marginTop: 4 }}>{fmt(p.date)}</span>
            </Link>
          ))}
        </div>
      </section>
      <MarketingFooter />
    </div>
  );
}
