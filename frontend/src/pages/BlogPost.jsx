import { useParams, Link, Navigate } from "react-router-dom";
import { primaryBtn } from "../components/ui";
import { MarketingNav, MarketingFooter } from "../components/marketing";
import { getPost, POSTS } from "../data/blog";
import { T } from "../theme";

const fmt = (d) => new Date(d).toLocaleDateString("en-US", { month: "long", day: "numeric", year: "numeric" });

export default function BlogPost() {
  const { slug } = useParams();
  const post = getPost(slug);
  if (!post) return <Navigate to="/blog" replace />;
  const more = POSTS.filter((p) => p.slug !== slug).slice(0, 2);

  return (
    <div>
      <MarketingNav />
      <article style={{ maxWidth: 720, margin: "0 auto", padding: "56px 28px 20px" }}>
        <Link to="/blog" style={{ fontSize: 13.5, color: T.muted, display: "inline-flex", alignItems: "center", gap: 6, marginBottom: 24 }}>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M15 18l-6-6 6-6" /></svg>All articles
        </Link>
        <span style={{ fontFamily: T.mono, fontSize: 12, color: T.accentHi, letterSpacing: "0.06em" }}>{post.category.toUpperCase()} · {post.read} read</span>
        <h1 style={{ fontFamily: T.heading, fontSize: "clamp(30px, 4.5vw, 44px)", fontWeight: 800, letterSpacing: "-0.03em", lineHeight: 1.1, margin: "14px 0 20px" }}>{post.title}</h1>
        <div style={{ display: "flex", alignItems: "center", gap: 12, paddingBottom: 26, borderBottom: `1px solid ${T.border}`, marginBottom: 34 }}>
          <span style={{ width: 40, height: 40, borderRadius: "50%", background: "rgba(6,182,212,0.12)", color: T.accentHi, display: "flex", alignItems: "center", justifyContent: "center", fontFamily: T.heading, fontWeight: 700, fontSize: 13 }}>{post.initials}</span>
          <div>
            <div style={{ fontSize: 14, fontWeight: 600 }}>{post.author}</div>
            <div style={{ fontSize: 12.5, color: T.muted }}>{fmt(post.date)}</div>
          </div>
        </div>

        <div style={{ fontSize: 16.5, lineHeight: 1.75, color: "#D6DEE8" }}>
          {post.body.map((block, i) => {
            if (block[0] === "h") return <h2 key={i} style={{ fontFamily: T.heading, fontSize: 24, fontWeight: 700, letterSpacing: "-0.01em", color: T.text, margin: "38px 0 14px" }}>{block[1]}</h2>;
            if (block[0] === "quote") return <blockquote key={i} style={{ margin: "30px 0", padding: "6px 0 6px 22px", borderLeft: `3px solid ${T.accent}`, fontFamily: T.heading, fontSize: 21, fontWeight: 600, color: T.text, lineHeight: 1.4 }}>{block[1]}</blockquote>;
            return <p key={i} style={{ margin: "0 0 20px" }}>{block[1]}</p>;
          })}
        </div>
      </article>

      {/* CTA */}
      <section style={{ maxWidth: 720, margin: "0 auto", padding: "24px 28px" }}>
        <div style={{ padding: "34px 34px", borderRadius: 18, border: "1px solid rgba(6,182,212,0.28)", background: "linear-gradient(180deg, rgba(6,182,212,0.08), transparent)", textAlign: "center" }}>
          <h3 style={{ fontFamily: T.heading, fontSize: 22, fontWeight: 700, margin: "0 0 10px" }}>See where your app stands</h3>
          <p style={{ color: T.muted, margin: "0 0 20px", fontSize: 15 }}>Run a free scan and get a prioritised, fixable report in minutes.</p>
          <Link to="/auth" state={{ mode: "signup" }} className="btn-primary" style={{ ...primaryBtn, display: "inline-block", padding: "13px 26px" }}>Start free →</Link>
        </div>
      </section>

      {/* More */}
      <section style={{ maxWidth: 1120, margin: "0 auto", padding: "50px 28px 20px" }}>
        <h3 style={{ fontFamily: T.heading, fontSize: 22, fontWeight: 700, marginBottom: 20 }}>Keep reading</h3>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(320px, 1fr))", gap: 20 }}>
          {more.map((p) => (
            <Link key={p.slug} to={`/blog/${p.slug}`} style={{ display: "flex", flexDirection: "column", borderRadius: 16, border: `1px solid ${T.border}`, background: "rgba(255,255,255,0.02)", padding: "24px 22px", gap: 10 }} className="blog-card">
              <span style={{ fontFamily: T.mono, fontSize: 11, color: T.accentHi }}>{p.category.toUpperCase()}</span>
              <h4 style={{ fontFamily: T.heading, fontSize: 17.5, fontWeight: 700, lineHeight: 1.25, margin: 0 }}>{p.title}</h4>
              <p style={{ fontSize: 13.5, lineHeight: 1.55, color: T.muted, margin: 0 }}>{p.excerpt}</p>
            </Link>
          ))}
        </div>
      </section>
      <MarketingFooter />
    </div>
  );
}
