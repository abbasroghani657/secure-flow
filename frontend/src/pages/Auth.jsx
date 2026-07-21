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
  const colors = [T.faint, "#F87171", "#FBBF24", "#33D98A", T.accent];
  return { score: s, label: labels[s], color: colors[s] };
}

export default function Auth() {
  const [mode, setMode] = useState("login");
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPw, setShowPw] = useState(false);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const { login, register } = useAuth();
  const nav = useNavigate();
  const loc = useLocation();
  const pendingUrl = loc.state?.url;

  const isLogin = mode === "login";
  const st = strength(password);

  async function submit(e) {
    e.preventDefault();
    setErr("");
    setBusy(true);
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
    <div style={{ minHeight: "100vh", display: "flex", flexDirection: "column" }}>
      <div style={{ padding: "20px 32px" }}><Link to="/"><Logo /></Link></div>
      <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center", padding: 24 }}>
        <div style={{ width: "100%", maxWidth: 420, animation: "fadeUp 0.4s ease both" }}>
          <div style={{ padding: "34px 32px", borderRadius: 18, border: `1px solid ${T.border}`, background: T.panel }}>
            <h1 style={{ fontFamily: T.heading, fontSize: 26, fontWeight: 700, margin: "0 0 4px" }}>
              {isLogin ? "Welcome back" : "Create your account"}
            </h1>
            <p style={{ color: T.muted, fontSize: 14, margin: "0 0 24px" }}>
              {isLogin ? "Log in to view your scans." : "Start scanning your sites in seconds."}
            </p>

            <div style={{ display: "flex", padding: 4, background: "rgba(255,255,255,0.04)", borderRadius: 12, marginBottom: 22 }}>
              {["login", "signup"].map((m) => {
                const active = (m === "login") === isLogin;
                return (
                  <button key={m} type="button" onClick={() => { setMode(m === "login" ? "login" : "signup"); setErr(""); }}
                    style={{ flex: 1, padding: "9px 0", borderRadius: 9, border: "none", cursor: "pointer", fontFamily: T.body, fontSize: 14, fontWeight: 600, background: active ? T.accent : "transparent", color: active ? T.accentInk : T.muted }}>
                    {m === "login" ? "Log in" : "Sign up"}
                  </button>
                );
              })}
            </div>

            <form onSubmit={submit} style={{ display: "grid", gap: 14 }}>
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
                  <input value={password} onChange={(e) => setPassword(e.target.value)} required type={showPw ? "text" : "password"} placeholder="••••••••" style={{ ...input, paddingRight: 44 }} />
                  <button type="button" onClick={() => setShowPw((v) => !v)} aria-label="Toggle password" style={{ position: "absolute", right: 8, top: "50%", transform: "translateY(-50%)", background: "none", border: "none", color: T.muted, cursor: "pointer", fontSize: 12, padding: 6 }}>
                    {showPw ? "Hide" : "Show"}
                  </button>
                </div>
              </Field>
              {!isLogin && password && (
                <div style={{ display: "flex", alignItems: "center", gap: 10, marginTop: -4 }}>
                  <div style={{ flex: 1, height: 5, borderRadius: 999, background: "rgba(255,255,255,0.08)", overflow: "hidden" }}>
                    <div style={{ width: `${(st.score / 4) * 100}%`, height: "100%", background: st.color, transition: "width 0.2s" }} />
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
          </div>
          <p style={{ textAlign: "center", color: T.faint, fontSize: 12.5, marginTop: 18 }}>
            By continuing you agree to only scan websites you own or are authorised to test.
          </p>
        </div>
      </div>
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
  width: "100%",
  padding: "12px 14px",
  borderRadius: 11,
  border: `1px solid ${T.borderStrong}`,
  background: "rgba(255,255,255,0.05)",
  color: T.text,
  fontSize: 14.5,
  fontFamily: T.body,
};
