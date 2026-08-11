import { useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { Logo, primaryBtn, Spinner } from "../components/ui";
import { useAuth } from "../auth";
import { API_BASE } from "../api";
import { T } from "../theme";

const OAUTH_ERRORS = {
  oauth_unconfigured: "Social login isn't enabled yet on this instance. Use email and password for now.",
  oauth_failed: "Social sign-in didn't complete. Please try again.",
  oauth_state: "Social sign-in expired. Please try again.",
  oauth_token: "Couldn't verify with the provider. Please try again.",
  oauth_no_email: "That account didn't share a verified email. Use email and password instead.",
};

function GoogleMark() {
  return (
    <svg width="17" height="17" viewBox="0 0 48 48"><path fill="#FFC107" d="M43.6 20.5H42V20H24v8h11.3c-1.6 4.7-6.1 8-11.3 8-6.6 0-12-5.4-12-12s5.4-12 12-12c3.1 0 5.9 1.2 8 3.1l5.7-5.7C34.6 6.1 29.6 4 24 4 12.9 4 4 12.9 4 24s8.9 20 20 20 20-8.9 20-20c0-1.3-.1-2.3-.4-3.5z" /><path fill="#FF3D00" d="M6.3 14.7l6.6 4.8C14.7 15.1 19 12 24 12c3.1 0 5.9 1.2 8 3.1l5.7-5.7C34.6 6.1 29.6 4 24 4 16.3 4 9.7 8.3 6.3 14.7z" /><path fill="#4CAF50" d="M24 44c5.5 0 10.4-2.1 14.1-5.5l-6.5-5.5C29.6 34.6 26.9 36 24 36c-5.2 0-9.6-3.3-11.2-8l-6.5 5C9.6 39.6 16.2 44 24 44z" /><path fill="#1976D2" d="M43.6 20.5H42V20H24v8h11.3c-.8 2.2-2.2 4.1-4.1 5.5l6.5 5.5C41.9 35.7 44 30.3 44 24c0-1.3-.1-2.3-.4-3.5z" /></svg>
  );
}
function GithubMark() {
  return (
    <svg width="17" height="17" viewBox="0 0 24 24" fill="currentColor"><path d="M12 .5C5.7.5.5 5.7.5 12c0 5.1 3.3 9.4 7.9 10.9.6.1.8-.2.8-.5v-2c-3.2.7-3.9-1.4-3.9-1.4-.5-1.3-1.3-1.7-1.3-1.7-1.1-.7.1-.7.1-.7 1.2.1 1.8 1.2 1.8 1.2 1 1.8 2.7 1.3 3.4 1 .1-.8.4-1.3.7-1.6-2.6-.3-5.3-1.3-5.3-5.7 0-1.3.5-2.3 1.2-3.1-.1-.3-.5-1.5.1-3.1 0 0 1-.3 3.3 1.2 1-.3 2-.4 3-.4s2 .1 3 .4C17.3 4.7 18.3 5 18.3 5c.6 1.6.2 2.8.1 3.1.8.8 1.2 1.8 1.2 3.1 0 4.4-2.7 5.4-5.3 5.7.4.4.8 1.1.8 2.2v3.3c0 .3.2.6.8.5 4.6-1.5 7.9-5.8 7.9-10.9C23.5 5.7 18.3.5 12 .5z" /></svg>
  );
}

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
  ["Scan what you own", "Prove domain ownership first, every scan is authorised and defensible."],
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
  const [aupConsent, setAupConsent] = useState(false);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const { login, register } = useAuth();
  const nav = useNavigate();
  const pendingUrl = loc.state?.url;

  const isLogin = mode === "login";
  const st = strength(password);
  const oauthErr = OAUTH_ERRORS[new URLSearchParams(loc.search).get("error")];

  async function submit(e) {
    e.preventDefault();
    if (!isLogin && !aupConsent) {
      setErr("You must agree to the Acceptable Use Policy to create an account.");
      return;
    }
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
          <p style={{ color: T.muted, fontSize: 15.5, lineHeight: 1.6, margin: "0 0 30px" }}>Catch the misconfigurations, leaked secrets and injectable inputs that turn into breaches, before they do.</p>
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

          {oauthErr && (
            <div style={{ fontSize: 13, color: "#FBBF24", background: "rgba(251,191,36,0.1)", border: "1px solid rgba(251,191,36,0.3)", borderRadius: 10, padding: "10px 12px", marginBottom: 18 }}>{oauthErr}</div>
          )}

          <div style={{ display: "grid", gap: 10, marginBottom: 18 }}>
            <a href={`${API_BASE}/api/auth/oauth/google`} className="btn-ghost" style={{ ...socialBtn }}>
              <GoogleMark /> Continue with Google
            </a>
            <a href={`${API_BASE}/api/auth/oauth/github`} className="btn-ghost" style={{ ...socialBtn }}>
              <GithubMark /> Continue with GitHub
            </a>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 12, margin: "0 0 18px", color: T.faint, fontSize: 12.5 }}>
            <span style={{ flex: 1, height: 1, background: T.border }} /> or with email <span style={{ flex: 1, height: 1, background: T.border }} />
          </div>

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
            {isLogin && (
              <div style={{ display: "flex", justifyContent: "flex-end", marginTop: -10 }}>
                <Link to="/forgot-password" style={{ fontSize: 12.5, color: T.accent, textDecoration: "none" }}>Forgot password?</Link>
              </div>
            )}
            {!isLogin && password && (
              <div style={{ display: "flex", alignItems: "center", gap: 10, marginTop: -4 }}>
                <div style={{ flex: 1, height: 5, borderRadius: 999, background: "rgba(255,255,255,0.08)", overflow: "hidden" }}>
                  <div style={{ width: `${(st.score / 4) * 100}%`, height: "100%", background: st.color, transition: "width 0.25s" }} />
                </div>
                <span style={{ fontSize: 12, color: st.color, minWidth: 60 }}>{st.label}</span>
              </div>
            )}

            {!isLogin && (
              <div style={{ display: "flex", alignItems: "flex-start", gap: 10, marginTop: 4 }}>
                <input 
                  type="checkbox" 
                  id="aup" 
                  checked={aupConsent} 
                  onChange={(e) => setAupConsent(e.target.checked)} 
                  style={{ marginTop: 3, accentColor: T.accent }}
                />
                <label htmlFor="aup" style={{ fontSize: 13, color: T.muted, lineHeight: 1.5, cursor: "pointer" }}>
                  I agree to the <Link to="/legal/aup" style={{ color: T.accent, textDecoration: "none" }} target="_blank">Acceptable Use Policy (AUP)</Link> and <Link to="/legal/terms" style={{ color: T.accent, textDecoration: "none" }} target="_blank">Terms of Service</Link>. I confirm I will only scan infrastructure I own or have explicit authorization to test.
                </label>
              </div>
            )}

            {err && <div style={{ fontSize: 13, color: "#F87171", background: "rgba(220,38,38,0.1)", border: "1px solid rgba(248,113,113,0.3)", borderRadius: 10, padding: "10px 12px" }}>{err}</div>}

            <button type="submit" disabled={busy || (!isLogin && !aupConsent)} style={{ ...primaryBtn, width: "100%", marginTop: 4, opacity: (busy || (!isLogin && !aupConsent)) ? 0.7 : 1, display: "flex", alignItems: "center", justifyContent: "center", gap: 8 }}>
              {busy && <Spinner />}
              {isLogin ? "Log in" : "Create account"}
            </button>
          </form>

          <p style={{ textAlign: "center", color: T.faint, fontSize: 12.5, marginTop: 20, lineHeight: 1.5 }}>
            Enterprise-grade security scanning for developers and security teams.
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

const socialBtn = {
  display: "flex", alignItems: "center", justifyContent: "center", gap: 10,
  padding: "11px 16px", borderRadius: 11, border: `1px solid ${T.borderStrong}`,
  background: "rgba(255,255,255,0.03)", color: T.text, fontSize: 14, fontWeight: 600,
  fontFamily: T.body, cursor: "pointer",
};
