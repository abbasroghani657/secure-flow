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
  { id: "ios", label: "iOS app (IPA)", desc: "Upload an iOS IPA — secrets, ATS/transport security, URL schemes, and binary protections (OWASP Mobile Top 10)." },
  { id: "iac", label: "Infrastructure (IaC)", desc: "Upload a Terraform / CloudFormation / Kubernetes / Dockerfile — finds cloud & container misconfigurations." },
  { id: "secrets", label: "Secrets (source code)", desc: "Upload a source archive (.zip) — finds leaked API keys, tokens & private keys committed in your code." },
  { id: "cicd", label: "CI/CD pipeline", desc: "Upload a GitHub Actions / GitLab CI workflow — finds supply-chain risks: unpinned actions, script injection, over-broad tokens." },
  { id: "sast", label: "Source code (SAST)", desc: "Upload a source archive (.zip) — static analysis for injection, command exec, deserialization & weak crypto (Python/JS/PHP/Java/Go/Ruby)." },
  { id: "cspm", label: "Cloud posture (AWS)", desc: "Scan your AWS account with read-only keys — public buckets, open security groups, IAM/MFA, unencrypted storage, CloudTrail." },
  { id: "bola", label: "IDOR / BOLA (two accounts)", desc: "Use two accounts to test object-level authorization — can user B read user A's data? (OWASP API #1)." },
  { id: "headers", label: "Headers only", desc: "Quick check of security response headers." },
];

// Scan types that take a file upload instead of a verified target.
const UPLOAD_TYPES = ["mobile", "sca", "ios", "iac", "secrets", "cicd", "sast"];

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
  const [iosFile, setIosFile] = useState(null);
  const [iacFile, setIacFile] = useState(null);
  const [secretsFile, setSecretsFile] = useState(null);
  const [cicdFile, setCicdFile] = useState(null);
  const [sastFile, setSastFile] = useState(null);
  const [awsAccessKey, setAwsAccessKey] = useState("");
  const [awsSecretKey, setAwsSecretKey] = useState("");
  const [awsRegion, setAwsRegion] = useState("us-east-1");
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
    if (UPLOAD_TYPES.includes(type)) {
      const fileMap = { mobile: apkFile, sca: depFile, ios: iosFile, iac: iacFile, secrets: secretsFile, cicd: cicdFile, sast: sastFile };
      const uploadMap = { mobile: api.uploadMobileScan, sca: api.uploadScaScan, ios: api.uploadIosScan, iac: api.uploadIacScan, secrets: api.uploadSecretsScan, cicd: api.uploadCicdScan, sast: api.uploadSastScan };
      const f = fileMap[type];
      if (!f) { setErr("Choose a file to scan."); return; }
      setBusy(true);
      try {
        const scan = await uploadMap[type](f);
        nav(`/scans/${scan.id}`);
      } catch (e2) {
        setErr(e2.message);
        setBusy(false);
      }
      return;
    }
    // CSPM — scans an AWS account with read-only credentials (no target needed).
    if (type === "cspm") {
      if (!awsAccessKey.trim() || !awsSecretKey.trim()) { setErr("Enter your AWS access key and secret key."); return; }
      setBusy(true);
      try {
        const scan = await api.createCspmScan({
          aws_access_key: awsAccessKey.trim(),
          aws_secret_key: awsSecretKey.trim(),
          aws_region: awsRegion.trim() || "us-east-1",
        });
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

            {UPLOAD_TYPES.includes(type) ? (
              /* File-upload scan (APK / dependency manifest / IPA / IaC) — no verified target needed */
              (() => {
                const cfg = {
                  mobile: { label: "Android APK file", file: apkFile, set: setApkFile, accept: ".apk", prompt: "Click to choose an .apk file", note: "The APK is analysed for hardcoded secrets and insecure manifest settings, then deleted." },
                  sca: { label: "Dependency file", file: depFile, set: setDepFile, accept: ".json,.txt,.lock,.mod,.sum,.xml", prompt: "Click to choose package.json / requirements.txt / lock file", note: "Your dependencies are checked against the OSV vulnerability database, then the file is deleted." },
                  ios: { label: "iOS IPA file", file: iosFile, set: setIosFile, accept: ".ipa", prompt: "Click to choose an .ipa file", note: "The IPA is analysed for secrets, transport security, URL schemes and binary protections, then deleted." },
                  iac: { label: "IaC file", file: iacFile, set: setIacFile, accept: ".tf,.tf.json,.yaml,.yml,.json,.hcl,Dockerfile", prompt: "Click to choose a .tf / .yaml / Dockerfile / compose file", note: "The file is analysed for cloud & container misconfigurations (Terraform, CloudFormation, Kubernetes, Docker), then deleted." },
                  secrets: { label: "Source archive", file: secretsFile, set: setSecretsFile, accept: ".zip", prompt: "Click to choose a .zip of your source code", note: "Every text file is scanned for leaked API keys, tokens and private keys, then the archive is deleted. Nothing is sent anywhere." },
                  cicd: { label: "CI/CD workflow", file: cicdFile, set: setCicdFile, accept: ".yml,.yaml,.zip", prompt: "Click to choose a workflow .yml / .gitlab-ci.yml / .zip", note: "The workflow is analysed for supply-chain and pipeline misconfigurations (GitHub Actions, GitLab CI), then deleted." },
                  sast: { label: "Source archive", file: sastFile, set: setSastFile, accept: ".zip,.py,.js,.jsx,.ts,.tsx,.php,.java,.go,.rb", prompt: "Click to choose a .zip of your source code", note: "Every supported source file (Python/JS/PHP/Java/Go/Ruby) is statically analysed for dangerous code, then the archive is deleted. Nothing is sent anywhere." },
                }[type];
                const f = cfg.file;
                return (
                  <div style={{ display: "grid", gap: 8 }}>
                    <label style={{ fontSize: 13.5, fontWeight: 600, color: T.text }}>{cfg.label}</label>
                    <label style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 10, padding: "28px 20px", borderRadius: 12, border: `1.5px dashed ${f ? T.accent : T.borderStrong}`, background: f ? "rgba(0,191,99,0.06)" : "rgba(255,255,255,0.02)", cursor: "pointer", textAlign: "center" }}>
                      <input type="file" accept={cfg.accept} style={{ display: "none" }} onChange={(e) => cfg.set(e.target.files?.[0] || null)} />
                      <span style={{ fontSize: 14, color: f ? T.accentHi : T.muted, fontFamily: f ? T.mono : T.body }}>
                        {f ? `${f.name} (${(f.size / 1024).toFixed(0)} KB)` : cfg.prompt}
                      </span>
                    </label>
                    <p style={{ margin: 0, fontSize: 12.5, color: T.muted }}>{cfg.note}</p>
                  </div>
                );
              })()
            ) : type === "cspm" ? (
              /* CSPM — read-only AWS credentials, no verified target needed */
              <div style={{ display: "grid", gap: 14, padding: "16px 18px", borderRadius: 12, border: `1px solid ${T.accent}`, background: "rgba(0,191,99,0.05)" }}>
                <div style={{ fontSize: 13.5, fontWeight: 600, color: T.accentHi }}>AWS read-only credentials</div>
                <p style={{ margin: 0, fontSize: 12.5, color: T.muted, lineHeight: 1.5 }}>
                  Use an IAM key with the AWS-managed <b style={{ color: T.text }}>SecurityAudit</b> or <b style={{ color: T.text }}>ReadOnlyAccess</b> policy. Credentials are used for this scan only and <b style={{ color: T.text }}>deleted the moment it finishes</b> — never stored.
                </p>
                <div style={{ display: "grid", gap: 6 }}>
                  <label style={{ fontSize: 12.5, fontWeight: 600 }}>Access key ID</label>
                  <input value={awsAccessKey} onChange={(e) => setAwsAccessKey(e.target.value)} placeholder="AKIA…" style={inp(T)} />
                </div>
                <div style={{ display: "grid", gap: 6 }}>
                  <label style={{ fontSize: 12.5, fontWeight: 600 }}>Secret access key</label>
                  <input type="password" value={awsSecretKey} onChange={(e) => setAwsSecretKey(e.target.value)} placeholder="••••••••" style={inp(T)} />
                </div>
                <div style={{ display: "grid", gap: 6 }}>
                  <label style={{ fontSize: 12.5, fontWeight: 600 }}>Region</label>
                  <input value={awsRegion} onChange={(e) => setAwsRegion(e.target.value)} placeholder="us-east-1" style={inp(T)} />
                </div>
              </div>
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

            <button type="submit" disabled={busy || (!UPLOAD_TYPES.includes(type) && type !== "cspm" && targets.length === 0)} style={{ ...primaryBtn, display: "inline-flex", alignItems: "center", justifyContent: "center", gap: 8, opacity: (busy || (!UPLOAD_TYPES.includes(type) && type !== "cspm" && targets.length === 0)) ? 0.6 : 1 }}>
              {busy && <Spinner />} Launch scan
            </button>
          </form>
        )}
      </main>
    </div>
  );
}
