import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { AppNav, primaryBtn, ghostBtn, Spinner } from "../components/ui";
import { useUX } from "../components/UX";
import { api } from "../api";
import { T } from "../theme";

const card = {
  background: T.panel, border: `1px solid ${T.border}`, borderRadius: 16,
  padding: 24, marginBottom: 24,
};
const input = {
  width: "100%", background: T.bg, border: `1px solid ${T.borderStrong}`,
  color: T.text, borderRadius: 10, padding: "10px 12px", fontSize: 14,
  fontFamily: T.body, boxSizing: "border-box",
};
const label = { fontSize: 12.5, color: T.muted, marginBottom: 6, display: "block" };

const KINDS = [
  ["slack", "Slack"], ["teams", "Microsoft Teams"], ["discord", "Discord"], ["webhook", "Generic webhook"],
];
const EVENTS = [
  ["critical_high", "Critical / high or new issues"],
  ["new_only", "Only new issues"],
  ["all", "Every completed scan"],
];

function UpgradeGate({ what }) {
  return (
    <div style={{ ...card, textAlign: "center", padding: 40 }}>
      <div style={{ fontFamily: T.heading, fontSize: 20, fontWeight: 700, marginBottom: 8 }}>
        {what} is a Pro feature
      </div>
      <p style={{ color: T.muted, maxWidth: 460, margin: "0 auto 20px", lineHeight: 1.6 }}>
        Route findings into Slack, Teams or your own webhook, and run Pentrixa in your
        CI/CD pipeline with API tokens. Upgrade to unlock the whole workflow.
      </p>
      <Link to="/pricing" style={{ ...primaryBtn, textDecoration: "none", display: "inline-block" }}>
        View plans
      </Link>
    </div>
  );
}

export default function Settings() {
  const { confirm, toast } = useUX();
  const [plan, setPlan] = useState(null);
  const [err, setErr] = useState("");

  // integrations
  const [integrations, setIntegrations] = useState([]);
  const [kind, setKind] = useState("slack");
  const [ntarget, setNtarget] = useState("");
  const [nname, setNname] = useState("");
  const [nevents, setNevents] = useState("critical_high");
  const [savingI, setSavingI] = useState(false);
  const [testMsg, setTestMsg] = useState({});

  // tokens
  const [tokens, setTokens] = useState([]);
  const [tname, setTname] = useState("");
  const [freshToken, setFreshToken] = useState("");
  const [savingT, setSavingT] = useState(false);
  const [copied, setCopied] = useState(false);

  const pro = plan && plan.plan !== "free";

  async function load() {
    try {
      const p = await api.getPlan();
      setPlan(p);
      if (p.plan !== "free") {
        const [ints, toks] = await Promise.all([api.listIntegrations(), api.listTokens()]);
        setIntegrations(ints);
        setTokens(toks);
      }
    } catch (e) { setErr(e.message); }
  }
  useEffect(() => { load(); }, []);

  async function addIntegration(e) {
    e.preventDefault();
    setErr(""); setSavingI(true);
    try {
      await api.createIntegration({ kind, name: nname, target: ntarget, events: nevents });
      setNtarget(""); setNname("");
      const ints = await api.listIntegrations();
      setIntegrations(ints);
      toast("Channel connected");
    } catch (e2) { setErr(e2.message); toast(e2.message, "error"); } finally { setSavingI(false); }
  }

  async function testIntegration(id) {
    setTestMsg((m) => ({ ...m, [id]: "..." }));
    try {
      await api.testIntegration(id);
      setTestMsg((m) => ({ ...m, [id]: "sent" }));
      toast("Test message delivered");
    } catch (e) { setTestMsg((m) => ({ ...m, [id]: "failed" })); toast(e.message, "error"); }
  }

  async function removeIntegration(id) {
    const ok = await confirm({
      title: "Remove this channel?",
      message: "You'll stop receiving scan alerts here.",
      confirmLabel: "Remove", danger: true,
    });
    if (!ok) return;
    try {
      await api.deleteIntegration(id);
      setIntegrations((xs) => xs.filter((x) => x.id !== id));
      toast("Channel removed");
    } catch (e) { toast(e.message, "error"); }
  }

  async function createToken(e) {
    e.preventDefault();
    setErr(""); setSavingT(true); setFreshToken(""); setCopied(false);
    try {
      const t = await api.createToken(tname || "API token");
      setFreshToken(t.token);
      setTname("");
      setTokens(await api.listTokens());
      toast("Token created, copy it now");
    } catch (e2) { setErr(e2.message); toast(e2.message, "error"); } finally { setSavingT(false); }
  }

  async function revokeToken(id) {
    const ok = await confirm({
      title: "Revoke this token?",
      message: "Any CI pipeline or script using it will immediately stop working. This can't be undone.",
      confirmLabel: "Revoke", danger: true,
    });
    if (!ok) return;
    try {
      await api.revokeToken(id);
      setTokens(await api.listTokens());
      toast("Token revoked");
    } catch (e) { toast(e.message, "error"); }
  }

  if (!plan) return (<><AppNav /><div style={{ padding: 60, textAlign: "center" }}><Spinner /></div></>);

  return (
    <>
      <AppNav />
      <div style={{ maxWidth: 820, margin: "0 auto", padding: "40px 24px 80px" }}>
        <h1 style={{ fontFamily: T.heading, fontSize: 30, fontWeight: 700, margin: "0 0 6px" }}>Settings</h1>
        <p style={{ color: T.muted, margin: "0 0 32px" }}>
          Connect alerts and issue API tokens for the CLI and your CI/CD pipeline.
        </p>

        {err && (
          <div style={{ ...card, borderColor: "rgba(248,113,113,0.4)", color: "#F87171", padding: 14 }}>{err}</div>
        )}

        {!pro && <UpgradeGate what="Integrations & API access" />}

        {pro && (
          <>
            {/* ---- Integrations ---- */}
            <div style={card}>
              <h2 style={{ fontFamily: T.heading, fontSize: 19, fontWeight: 700, margin: "0 0 4px" }}>Alert channels</h2>
              <p style={{ color: T.muted, fontSize: 13.5, margin: "0 0 20px" }}>
                Paste an incoming-webhook URL from your workspace. When a scan finishes, matching results are posted there.
              </p>

              <form onSubmit={addIntegration} style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14, marginBottom: 20 }}>
                <div>
                  <label style={label}>Channel type</label>
                  <select style={input} value={kind} onChange={(e) => setKind(e.target.value)}>
                    {KINDS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
                  </select>
                </div>
                <div>
                  <label style={label}>Label (optional)</label>
                  <input style={input} value={nname} onChange={(e) => setNname(e.target.value)} placeholder="#security" />
                </div>
                <div style={{ gridColumn: "1 / 3" }}>
                  <label style={label}>Webhook URL</label>
                  <input style={input} value={ntarget} onChange={(e) => setNtarget(e.target.value)} placeholder="https://hooks.slack.com/services/..." required />
                </div>
                <div style={{ gridColumn: "1 / 3" }}>
                  <label style={label}>Notify me on</label>
                  <select style={input} value={nevents} onChange={(e) => setNevents(e.target.value)}>
                    {EVENTS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
                  </select>
                </div>
                <div style={{ gridColumn: "1 / 3" }}>
                  <button style={{ ...primaryBtn, opacity: savingI ? 0.6 : 1 }} disabled={savingI}>
                    {savingI ? "Connecting..." : "Connect channel"}
                  </button>
                </div>
              </form>

              {integrations.length === 0 && <p style={{ color: T.faint, fontSize: 13 }}>No channels connected yet.</p>}
              {integrations.map((i) => (
                <div key={i.id} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12, padding: "12px 14px", border: `1px solid ${T.border}`, borderRadius: 12, marginBottom: 10 }}>
                  <div style={{ minWidth: 0 }}>
                    <div style={{ fontSize: 14, fontWeight: 600 }}>{i.name} <span style={{ color: T.faint, fontWeight: 400 }}>· {i.kind}</span></div>
                    <div style={{ fontSize: 12, color: T.faint, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", maxWidth: 380 }}>{i.target}</div>
                  </div>
                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    {testMsg[i.id] && <span style={{ fontSize: 12, color: testMsg[i.id] === "sent" ? T.accent : T.faint }}>{testMsg[i.id]}</span>}
                    <button style={ghostBtn} onClick={() => testIntegration(i.id)}>Test</button>
                    <button style={{ ...ghostBtn, borderColor: "rgba(248,113,113,0.4)", color: "#F87171" }} onClick={() => removeIntegration(i.id)}>Remove</button>
                  </div>
                </div>
              ))}
            </div>

            {/* ---- API tokens ---- */}
            <div style={card}>
              <h2 style={{ fontFamily: T.heading, fontSize: 19, fontWeight: 700, margin: "0 0 4px" }}>API tokens</h2>
              <p style={{ color: T.muted, fontSize: 13.5, margin: "0 0 20px" }}>
                Use a token with the <code style={{ fontFamily: T.mono, color: T.accentHi }}>pentrixa</code> CLI or the GitHub Action to scan from CI. A token is shown once, at creation.
              </p>

              <form onSubmit={createToken} style={{ display: "flex", gap: 12, marginBottom: 18 }}>
                <input style={{ ...input, flex: 1 }} value={tname} onChange={(e) => setTname(e.target.value)} placeholder="Token name, e.g. GitHub Actions" />
                <button style={{ ...primaryBtn, opacity: savingT ? 0.6 : 1, whiteSpace: "nowrap" }} disabled={savingT}>
                  {savingT ? "Creating..." : "New token"}
                </button>
              </form>

              {freshToken && (
                <div style={{ background: T.bg, border: `1px solid ${T.accent}`, borderRadius: 12, padding: 14, marginBottom: 18 }}>
                  <div style={{ fontSize: 12.5, color: T.accentHi, marginBottom: 8 }}>Copy this now — you won't see it again.</div>
                  <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
                    <code style={{ fontFamily: T.mono, fontSize: 13, wordBreak: "break-all", flex: 1 }}>{freshToken}</code>
                    <button style={ghostBtn} onClick={() => { navigator.clipboard?.writeText(freshToken); setCopied(true); }}>
                      {copied ? "Copied" : "Copy"}
                    </button>
                  </div>
                </div>
              )}

              {tokens.length === 0 && <p style={{ color: T.faint, fontSize: 13 }}>No tokens yet.</p>}
              {tokens.map((t) => (
                <div key={t.id} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12, padding: "12px 14px", border: `1px solid ${T.border}`, borderRadius: 12, marginBottom: 10, opacity: t.revoked ? 0.5 : 1 }}>
                  <div>
                    <div style={{ fontSize: 14, fontWeight: 600 }}>
                      {t.name} {t.revoked && <span style={{ color: "#F87171", fontWeight: 400, fontSize: 12 }}>· revoked</span>}
                    </div>
                    <div style={{ fontSize: 12, color: T.faint, fontFamily: T.mono }}>
                      {t.prefix}…  ·  {t.last_used_at ? `last used ${new Date(t.last_used_at).toLocaleDateString()}` : "never used"}
                    </div>
                  </div>
                  {!t.revoked && (
                    <button style={{ ...ghostBtn, borderColor: "rgba(248,113,113,0.4)", color: "#F87171" }} onClick={() => revokeToken(t.id)}>Revoke</button>
                  )}
                </div>
              ))}

              <div style={{ marginTop: 16, padding: 14, background: T.bg, border: `1px solid ${T.border}`, borderRadius: 12 }}>
                <div style={{ fontSize: 12.5, color: T.muted, marginBottom: 8 }}>Run a scan in CI (fails the build on high/critical):</div>
                <pre style={{ fontFamily: T.mono, fontSize: 12.5, color: T.accentHi, margin: 0, whiteSpace: "pre-wrap" }}>
{`export PENTRIXA_TOKEN=ptx_xxx
pentrixa scan https://staging.example.com --fail-on high`}
                </pre>
              </div>
            </div>
          </>
        )}
      </div>
    </>
  );
}
