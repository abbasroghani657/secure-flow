import { useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { Logo, primaryBtn, Spinner } from "../components/ui";
import { useAuth } from "../auth";
import { T } from "../theme";

function strength(pw) {
  let s = 0;
  if (pw.length >= 8) s++;
  if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) s++;
  if (/\d/.test(pw)) s++;
  if (/[^A-Za-z0-9]/.test(pw)) s++;
  const labels = ["Too short", "Weak", "Fair", "Good", "Strong"];
  const colors = [T.faint, "#F87171", "#FBBF24", "#22D3EE", T.accent];
  return { score: s, label: labels[s], color: colors[s] };
}

const PANEL_POINTS = [
  ["Scan what you own", "Prove domain ownership first — every scan is authorised and defensible."],
  ["310+ checks, one report", "Web, API, mobile, cloud, containers and source code in a single pass."],
  ["Fix-first prioritisation", "Ranked by CISA-KEV and EPSS, so you patch what's actually being attacked."],
];

export default function Auth() {
  const loc = useLocation();
  const [mode, setMode] = useState(loc.state?.mode === "signup" ? "signup" : "login");
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPw, setShowPw] = useState(false);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const { login, register } = useAuth();
  const nav = useNavigate();
  const pendingUrl = loc.state?.url;

  const isLogin = mode === "login";
  const st = strength(password);

  async function submit(e) {
    e.preventDefault();
    setErr(""); setBusy(true);
    try {
      if (isLogin) await login(email, password);
      else await register(name, email, password);
      nav(pendingUrl ? "/scans/new" : "/dashboard", { state: pendingUrl ? { url: pendingUrl } : undefined });
    } catch (e2) {
      setErr(e2.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div style={{ minHeight: "100vh", display: "grid", gridTemplateColumns: "1.05fr 1fr" }} className="auth-grid">
      {/* Brand / animated panel */}
      <aside style={{ position: "relative", overflow: "hidden", borderRight: `1px solid ${T.border}`, background: "linear-gradient(160deg, #0B1117, #0A0E12 60%)", display: "flex", flexDirection: "column", justifyContent: "space-between", padding: "36px 44px" }} className="auth-panel">
        {/* decorative animated layers */}
        <div style={{ position: "absolute", inset: 0, background: "radial-gradient(ellipse 60% 40% at 25% 15%, rgba(6,182,212,0.18), transparent 60%)", pointerEvents: "none" }} />
        <div style={{ position: "absolute", inset: 0, backgroundImage: "linear-gradient(rgba(255,255,255,0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.03) 1px, transparent 1px)", backgroundSize: "38px 38px", maskImage: "radial-gradient(ellipse 80% 70% at 30% 30%, #000, transparent 75%)", WebkitMaskImage: "radial-gradient(ellipse 80% 70% at 30% 30%, #000, transparent 75%)", pointerEvents: "none" }} />
        <div style={{ position: "absolute", left: 0, right: 0, height: 140, top: 0, background: `linear-gradient(180deg, ${T.accent}22, transparent)`, animation: "authSweep 5.5s ease-in-out infinite", pointerEvents: "none" }} />

        <div style={{ position: "relative" }}><Link to="/"><Logo /></Link></div>

        <div style={{ position: "relative", maxWidth: 400 }}>
          <h2 style={{ fontFamily: T.heading, fontSize: 34, fontWeight: 800, letterSpacing: "-0.03em", lineHeight: 1.1, margin: "0 0 14px" }}>Secure. Scan. Ship.</h2>
          <p style={{ color: T.muted, fontSize: 15.5, lineHeight: 1.6, margin: "0 0 30px" }}>Catch the misconfigurations, leaked secrets and injectable inputs that turn into breaches — before they do.</p>
          <div style={{ display: "grid", gap: 18 }}>
            {PANEL_POINTS.map(([h, d]) => (
              <div key={h} style={{ display: "flex", gap: 13 }}>
                <span style={{ width: 30, height: 30, borderRadius: 9, flex: "none", background: "rgba(6,182,212,0.12)", border: "1px solid rgba(6,182,212,0.3)", display: "flex", alignItems: "center", justifyContent: "center" }}>
                  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke={T.accent} strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round"><path d="M20 6L9 17l-5-5" /></svg>
                </span>
                <div>
                  <div style={{ fontSize: 14.5, fontWeight: 600, color: T.text }}>{h}</div>
                  <div style={{ fontSize: 13, color: T.muted, lineHeight: 1.5 }}>{d}</div>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div style={{ position: "relative", display: "flex", gap: 18, color: T.faint, fontSize: 12, fontFamily: T.mono, flexWrap: "wrap" }}>
          {["OWASP 2025", "CWE", "CISA KEV", "EPSS"].map((t) => <span key={t}>{t}</span>)}
        </div>
      </aside>

      {/* Form */}
      <main style={{ display: "flex", alignItems: "center", justifyContent: "center", padding: "40px 28px" }}>
        <div style={{ width: "100%", maxWidth: 400, animation: "fadeUp 0.45s ease both" }}>
          <div style={{ marginBottom: 24 }} className="auth-mobile-logo"><Link to="/"><Logo /></Link></div>
          <h1 style={{ fontFamily: T.heading, fontSize: 28, fontWeight: 700, margin: "0 0 4px", letterSpacing: "-0.02em" }}>
            {isLogin ? "Welcome back" : "Create your account"}
          </h1>
          <p style={{ color: T.muted, fontSize: 14.5, margin: "0 0 26px" }}>
            {isLogin ? "Log in to view your scans and reports." : "Free tier, no credit card. Start scanning in seconds."}
          </p>

          <div style={{ display: "flex", padding: 4, background: "rgba(255,255,255,0.04)", borderRadius: 12, marginBottom: 22 }}>
            {["login", "signup"].map((m) => {
              const active = (m === "login") === isLogin;
              return (
                <button key={m} type="button" onClick={() => { setMode(m); setErr(""); }}
                  style={{ flex: 1, padding: "9px 0", borderRadius: 9, border: "none", cursor: "pointer", fontFamily: T.body, fontSize: 14, fontWeight: 600, background: active ? T.accent : "transparent", color: active ? T.accentInk : T.muted, transition: "background .15s" }}>
                  {m === "login" ? "Log in" : "Sign up"}
                </button>
              );
            })}
          </div>

          <form onSubmit={submit} style={{ display: "grid", gap: 15 }}>
            {!isLogin && (
              <Field label="Full name">
                <input value={name} onChange={(e) => setName(e.target.value)} required placeholder="Ada Lovelace" style={input} />
              </Field>
            )}
            <Field label="Email">
              <input value={email} onChange={(e) => setEmail(e.target.value)} required type="email" placeholder="you@company.com" style={input} />
            </Field>
            <Field label="Password">
              <div style={{ position: "relative" }}>
                <input value={password} onChange={(e) => setPassword(e.target.value)} required type={showPw ? "text" : "password"} placeholder="••••••••" style={{ ...input, paddingRight: 52 }} />
                <button type="button" onClick={() => setShowPw((v) => !v)} aria-label="Toggle password" style={{ position: "absolute", right: 8, top: "50%", transform: "translateY(-50%)", background: "none", border: "none", color: T.muted, cursor: "pointer", fontSize: 12.5, padding: 6 }}>
                  {showPw ? "Hide" : "Show"}
                </button>
              </div>
            </Field>
            {!isLogin && password && (
              <div style={{ display: "flex", alignItems: "center", gap: 10, marginTop: -4 }}>
                <div style={{ flex: 1, height: 5, borderRadius: 999, background: "rgba(255,255,255,0.08)", overflow: "hidden" }}>
                  <div style={{ width: `${(st.score / 4) * 100}%`, height: "100%", background: st.color, transition: "width 0.25s" }} />
                </div>
                <span style={{ fontSize: 12, color: st.color, minWidth: 60 }}>{st.label}</span>
              </div>
            )}

            {err && <div style={{ fontSize: 13, color: "#F87171", background: "rgba(220,38,38,0.1)", border: "1px solid rgba(248,113,113,0.3)", borderRadius: 10, padding: "10px 12px" }}>{err}</div>}

            <button type="submit" disabled={busy} style={{ ...primaryBtn, width: "100%", marginTop: 4, opacity: busy ? 0.7 : 1, display: "flex", alignItems: "center", justifyContent: "center", gap: 8 }}>
              {busy && <Spinner />}
              {isLogin ? "Log in" : "Create account"}
            </button>
          </form>

          <p style={{ textAlign: "center", color: T.faint, fontSize: 12.5, marginTop: 20, lineHeight: 1.5 }}>
            By continuing you agree to only scan websites you own or are authorised to test.
          </p>
        </div>
      </main>
    </div>
  );
}

function Field({ label, children }) {
  return (
    <label style={{ display: "grid", gap: 7 }}>
      <span style={{ fontSize: 13, fontWeight: 500, color: T.muted }}>{label}</span>
      {children}
    </label>
  );
}

const input = {
  width: "100%", padding: "13px 15px", borderRadius: 11,
  border: `1px solid ${T.borderStrong}`, background: "rgba(255,255,255,0.05)",
  color: T.text, fontSize: 14.5, fontFamily: T.body, boxSizing: "border-box",
};
