import { useEffect, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { AppNav, primaryBtn, ghostBtn, Spinner } from "../components/ui";
import { api } from "../api";
import { T } from "../theme";

const SCAN_TYPES = [
  { id: "web", label: "Web application", desc: "Full scan: headers, TLS, cookies, exposed files, and active injection tests." },
  { id: "deep", label: "Deep scan (Nuclei)", desc: "Everything in Web, plus the Nuclei engine's CVE & vulnerability templates. Slower." },
  { id: "llm", label: "LLM app (AI)", desc: "Test an AI/LLM endpoint for prompt injection, jailbreak & data leakage (OWASP LLM Top 10)." },
  { id: "mobile", label: "Mobile app (APK)", desc: "Upload an Android APK for static analysis — hardcoded secrets & insecure manifest (OWASP Mobile Top 10)." },
  { id: "sca", label: "Dependencies (SCA)", desc: "Upload a package.json / requirements.txt / lock file — finds known CVEs in your dependencies (OSV database)." },
  { id: "bola", label: "IDOR / BOLA (two accounts)", desc: "Use two accounts to test object-level authorization — can user B read user A's data? (OWASP API #1)." },
  { id: "headers", label: "Headers only", desc: "Quick check of security response headers." },
];

const inp = (T) => ({
  padding: "11px 13px", borderRadius: 10, border: `1px solid ${T.borderStrong}`,
  background: "rgba(255,255,255,0.05)", color: T.text, fontSize: 13, fontFamily: T.mono, width: "100%", boxSizing: "border-box",
});

export default function NewScan() {
  const loc = useLocation();
  const [targets, setTargets] = useState(null);
  const [selected, setSelected] = useState("");
  const [type, setType] = useState("web");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [showAuth, setShowAuth] = useState(false);
  const [authCookie, setAuthCookie] = useState("");
  const [authBearer, setAuthBearer] = useState("");
  const [authCookieB, setAuthCookieB] = useState("");
  const [authBearerB, setAuthBearerB] = useState("");
  const [llmEndpoint, setLlmEndpoint] = useState("");
  const [llmBody, setLlmBody] = useState('{"prompt": "{{PROMPT}}"}');
  const [llmRespPath, setLlmRespPath] = useState("");
  const [apkFile, setApkFile] = useState(null);
  const [depFile, setDepFile] = useState(null);
  const nav = useNavigate();

  useEffect(() => {
    api.listTargets().then((ts) => {
      const verified = ts.filter((t) => t.verified);
      setTargets(verified);
      // Preselect a target matching a URL passed from the landing page, else the first.
      const hint = loc.state?.url?.replace(/^https?:\/\//, "").split("/")[0];
      const match = hint && verified.find((t) => t.host === hint);
      setSelected(match ? match.url : verified[0]?.url || "");
    }).catch((e) => setErr(e.message));
  }, []);

  async function submit(e) {
    e.preventDefault();
    setErr("");
    // File-upload scan types — no verified target needed.
    if (type === "mobile" || type === "sca") {
      const f = type === "mobile" ? apkFile : depFile;
      if (!f) { setErr(type === "mobile" ? "Choose an .apk file to scan." : "Choose a dependency file to scan."); return; }
      setBusy(true);
      try {
        const scan = type === "mobile" ? await api.uploadMobileScan(f) : await api.uploadScaScan(f);
        nav(`/scans/${scan.id}`);
      } catch (e2) {
        setErr(e2.message);
        setBusy(false);
      }
      return;
    }
    if (!selected) { setErr("Select a verified target."); return; }
    setBusy(true);
    try {
      const extra = {};
      if (showAuth && authCookie.trim()) extra.auth_cookie = authCookie.trim();
      if (showAuth && authBearer.trim()) extra.auth_bearer = authBearer.trim();
      if (type === "llm") {
        if (!llmEndpoint.trim()) { setErr("Enter the LLM endpoint URL."); setBusy(false); return; }
        extra.llm_endpoint = llmEndpoint.trim();
        extra.llm_body_template = llmBody.trim();
        extra.llm_response_path = llmRespPath.trim();
      }
      if (type === "bola") {
        const hasA = authCookie.trim() || authBearer.trim();
        const hasB = authCookieB.trim() || authBearerB.trim();
        if (!hasA || !hasB) { setErr("BOLA needs credentials for two different accounts (A and B)."); setBusy(false); return; }
        extra.auth_cookie = authCookie.trim();
        extra.auth_bearer = authBearer.trim();
        extra.auth_cookie_b = authCookieB.trim();
        extra.auth_bearer_b = authBearerB.trim();
      }
      const scan = await api.createScan(selected, type, extra);
      nav(`/scans/${scan.id}`);
    } catch (e2) {
      setErr(e2.message);
      setBusy(false);
    }
  }

  return (
    <div>
      <AppNav />
      <main style={{ maxWidth: 680, margin: "0 auto", padding: "44px 24px 80px" }}>
        <h1 style={{ fontFamily: T.heading, fontSize: 30, fontWeight: 700, letterSpacing: "-0.02em", margin: "0 0 6px" }}>New scan</h1>
        <p style={{ color: T.muted, fontSize: 14.5, margin: "0 0 32px" }}>Scans run only against targets you have verified.</p>

        {targets === null ? (
          <p style={{ color: T.muted }}>Loading…</p>
        ) : (
          <form onSubmit={submit} style={{ display: "grid", gap: 26 }}>
            {/* Scan type — always visible */}
            <div style={{ display: "grid", gap: 10 }}>
              <label style={{ fontSize: 13.5, fontWeight: 600, color: T.text }}>Scan type</label>
              <div style={{ display: "grid", gap: 10 }}>
                {SCAN_TYPES.map((t) => {
                  const active = type === t.id;
                  return (
                    <button type="button" key={t.id} onClick={() => setType(t.id)} style={{ textAlign: "left", padding: "16px 18px", borderRadius: 12, cursor: "pointer", border: `1.5px solid ${active ? T.accent : T.border}`, background: active ? "rgba(0,191,99,0.08)" : "rgba(255,255,255,0.02)", fontFamily: T.body }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                        <span style={{ width: 16, height: 16, borderRadius: "50%", border: `2px solid ${active ? T.accent : T.borderStrong}`, display: "flex", alignItems: "center", justifyContent: "center" }}>
                          {active && <span style={{ width: 7, height: 7, borderRadius: "50%", background: T.accent }} />}
                        </span>
                        <span style={{ fontSize: 14.5, fontWeight: 600, color: T.text }}>{t.label}</span>
                      </div>
                      <p style={{ margin: "8px 0 0 26px", fontSize: 13, color: T.muted }}>{t.desc}</p>
                    </button>
                  );
                })}
              </div>
            </div>

            {type === "mobile" || type === "sca" ? (
              /* File-upload scan (APK / dependency manifest) — no verified target needed */
              (() => {
                const isSca = type === "sca";
                const f = isSca ? depFile : apkFile;
                const set = isSca ? setDepFile : setApkFile;
                return (
                  <div style={{ display: "grid", gap: 8 }}>
                    <label style={{ fontSize: 13.5, fontWeight: 600, color: T.text }}>{isSca ? "Dependency file" : "Android APK file"}</label>
                    <label style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 10, padding: "28px 20px", borderRadius: 12, border: `1.5px dashed ${f ? T.accent : T.borderStrong}`, background: f ? "rgba(0,191,99,0.06)" : "rgba(255,255,255,0.02)", cursor: "pointer", textAlign: "center" }}>
                      <input type="file" accept={isSca ? ".json,.txt,.lock,.mod,.sum,.xml" : ".apk"} style={{ display: "none" }} onChange={(e) => set(e.target.files?.[0] || null)} />
                      <span style={{ fontSize: 14, color: f ? T.accentHi : T.muted, fontFamily: f ? T.mono : T.body }}>
                        {f ? `${f.name} (${(f.size / 1024).toFixed(0)} KB)` : (isSca ? "Click to choose package.json / requirements.txt / lock file" : "Click to choose an .apk file")}
                      </span>
                    </label>
                    <p style={{ margin: 0, fontSize: 12.5, color: T.muted }}>
                      {isSca ? "Your dependencies are checked against the OSV vulnerability database, then the file is deleted." : "The APK is analysed for hardcoded secrets and insecure manifest settings, then deleted. No target verification needed."}
                    </p>
                  </div>
                );
              })()
            ) : targets.length === 0 ? (
              <div style={{ textAlign: "center", padding: "40px 24px", border: `1px dashed ${T.borderStrong}`, borderRadius: 16 }}>
                <p style={{ color: T.muted, fontSize: 14.5, margin: "0 0 18px" }}>
                  This scan type needs a verified target. Add and verify a domain you own first.
                </p>
                <Link to="/targets" style={{ ...primaryBtn, display: "inline-block" }}>Go to Targets</Link>
              </div>
            ) : (
              <>
                <div style={{ display: "grid", gap: 8 }}>
                  <label style={{ fontSize: 13.5, fontWeight: 600, color: T.text }}>Target</label>
                  <div style={{ display: "grid", gap: 10 }}>
                    {targets.map((t) => {
                      const active = selected === t.url;
                      return (
                        <button type="button" key={t.id} onClick={() => setSelected(t.url)} style={{ textAlign: "left", display: "flex", alignItems: "center", gap: 12, padding: "14px 16px", borderRadius: 12, cursor: "pointer", border: `1.5px solid ${active ? T.accent : T.border}`, background: active ? "rgba(0,191,99,0.08)" : "rgba(255,255,255,0.02)", fontFamily: T.body }}>
                          <span style={{ width: 16, height: 16, borderRadius: "50%", border: `2px solid ${active ? T.accent : T.borderStrong}`, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
                            {active && <span style={{ width: 7, height: 7, borderRadius: "50%", background: T.accent }} />}
                          </span>
                          <span style={{ fontFamily: T.mono, fontSize: 14.5, color: T.text }}>{t.host}</span>
                          <span style={{ marginLeft: "auto", fontSize: 11.5, color: T.accent }}>verified</span>
                        </button>
                      );
                    })}
                  </div>
                  <Link to="/targets" style={{ fontSize: 12.5, color: T.muted }}>+ Add another target</Link>
                </div>

            {/* LLM endpoint config (only for LLM scans) */}
            {type === "llm" && (
              <div style={{ display: "grid", gap: 14, padding: "16px 18px", borderRadius: 12, border: `1px solid ${T.accent}`, background: "rgba(0,191,99,0.05)" }}>
                <div style={{ fontSize: 13.5, fontWeight: 600, color: T.accentHi }}>LLM endpoint configuration</div>
                <div style={{ display: "grid", gap: 6 }}>
                  <label style={{ fontSize: 12.5, fontWeight: 600 }}>Endpoint URL <span style={{ color: T.faint, fontWeight: 400 }}>(must be on a verified target)</span></label>
                  <input value={llmEndpoint} onChange={(e) => setLlmEndpoint(e.target.value)} placeholder="https://your-app.com/api/chat" style={inp(T)} />
                </div>
                <div style={{ display: "grid", gap: 6 }}>
                  <label style={{ fontSize: 12.5, fontWeight: 600 }}>Request body template <span style={{ color: T.faint, fontWeight: 400 }}>(use {"{{PROMPT}}"} where the user message goes)</span></label>
                  <textarea value={llmBody} onChange={(e) => setLlmBody(e.target.value)} rows={3} style={{ ...inp(T), resize: "vertical" }} />
                </div>
                <div style={{ display: "grid", gap: 6 }}>
                  <label style={{ fontSize: 12.5, fontWeight: 600 }}>Response field path <span style={{ color: T.faint, fontWeight: 400 }}>(optional, e.g. choices.0.message.content)</span></label>
                  <input value={llmRespPath} onChange={(e) => setLlmRespPath(e.target.value)} placeholder="choices.0.message.content" style={inp(T)} />
                </div>
                <p style={{ margin: 0, fontSize: 12, color: T.muted }}>Add an API key under "Authenticated scan" below (Bearer token) if your endpoint needs auth.</p>
              </div>
            )}

            {/* BOLA/IDOR — two accounts (required) */}
            {type === "bola" && (
              <div style={{ display: "grid", gap: 14, padding: "16px 18px", borderRadius: 12, border: `1px solid ${T.accent}`, background: "rgba(0,191,99,0.05)" }}>
                <div style={{ fontSize: 13.5, fontWeight: 600, color: T.accentHi }}>Two accounts (required)</div>
                <p style={{ margin: 0, fontSize: 12.5, color: T.muted, lineHeight: 1.5 }}>
                  Paste a session Cookie or Bearer token for <b style={{ color: T.text }}>two different accounts</b>. The scanner logs in as A, finds A's objects, then checks whether B can read them. Credentials are used for this scan only and deleted the moment it finishes.
                </p>
                {[["A", authCookie, setAuthCookie, authBearer, setAuthBearer], ["B", authCookieB, setAuthCookieB, authBearerB, setAuthBearerB]].map(([label, ck, setCk, br, setBr]) => (
                  <div key={label} style={{ display: "grid", gap: 8, padding: "12px 14px", borderRadius: 10, border: `1px solid ${T.border}` }}>
                    <div style={{ fontSize: 12.5, fontWeight: 700, color: T.text }}>Account {label}</div>
                    <input value={ck} onChange={(e) => setCk(e.target.value)} placeholder="Cookie: session=…" style={inp(T)} />
                    <input value={br} onChange={(e) => setBr(e.target.value)} placeholder="Bearer token (optional)" style={inp(T)} />
                  </div>
                ))}
              </div>
            )}

            {/* Optional authenticated scan (single session) — not shown for BOLA */}
            {type !== "bola" && (
            <div style={{ border: `1px solid ${T.border}`, borderRadius: 12, overflow: "hidden" }}>
              <button type="button" onClick={() => setShowAuth(!showAuth)} style={{ width: "100%", display: "flex", alignItems: "center", justifyContent: "space-between", background: "none", border: "none", cursor: "pointer", padding: "14px 16px", fontFamily: T.body, color: T.text }}>
                <span style={{ display: "flex", alignItems: "center", gap: 10 }}>
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke={T.accent} strokeWidth="1.8" strokeLinecap="round"><rect x="3" y="11" width="18" height="11" rx="2" /><path d="M7 11V7a5 5 0 0110 0v4" /></svg>
                  <span style={{ fontSize: 14, fontWeight: 600 }}>Authenticated scan <span style={{ color: T.muted, fontWeight: 400 }}>· optional, scans behind login</span></span>
                </span>
                <span style={{ color: T.muted, transform: showAuth ? "rotate(180deg)" : "none", transition: "transform 0.2s" }}>▾</span>
              </button>
              {showAuth && (
                <div style={{ padding: "0 16px 16px", display: "grid", gap: 12 }}>
                  <p style={{ margin: 0, fontSize: 12.5, color: T.muted, lineHeight: 1.5 }}>
                    Paste a valid session <b style={{ color: T.text }}>Cookie</b> or <b style={{ color: T.text }}>Bearer token</b> from your logged-in session. The scanner will crawl and test pages behind the login. Credentials are used for this scan only and deleted the moment it finishes.
                  </p>
                  <div style={{ display: "grid", gap: 6 }}>
                    <label style={{ fontSize: 12.5, fontWeight: 600 }}>Session cookie</label>
                    <input value={authCookie} onChange={(e) => setAuthCookie(e.target.value)} placeholder="session=abc123; csrftoken=def456" style={{ padding: "11px 13px", borderRadius: 10, border: `1px solid ${T.borderStrong}`, background: "rgba(255,255,255,0.05)", color: T.text, fontSize: 13, fontFamily: T.mono }} />
                  </div>
                  <div style={{ display: "grid", gap: 6 }}>
                    <label style={{ fontSize: 12.5, fontWeight: 600 }}>Bearer token <span style={{ color: T.faint, fontWeight: 400 }}>(without "Bearer ")</span></label>
                    <input value={authBearer} onChange={(e) => setAuthBearer(e.target.value)} placeholder="eyJhbGciOiJIUzI1NiIs..." style={{ padding: "11px 13px", borderRadius: 10, border: `1px solid ${T.borderStrong}`, background: "rgba(255,255,255,0.05)", color: T.text, fontSize: 13, fontFamily: T.mono }} />
                  </div>
                </div>
              )}
            </div>
            )}
              </>
            )}

            {err && <div style={{ fontSize: 13.5, color: "#F87171", background: "rgba(220,38,38,0.1)", border: "1px solid rgba(248,113,113,0.3)", borderRadius: 10, padding: "10px 12px" }}>{err}</div>}

            <button type="submit" disabled={busy || (type !== "mobile" && targets.length === 0)} style={{ ...primaryBtn, display: "inline-flex", alignItems: "center", justifyContent: "center", gap: 8, opacity: (busy || (type !== "mobile" && targets.length === 0)) ? 0.6 : 1 }}>
              {busy && <Spinner />} Launch scan
            </button>
          </form>
        )}
      </main>
    </div>
  );
}
