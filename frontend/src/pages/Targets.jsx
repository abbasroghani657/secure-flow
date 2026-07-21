import { useEffect, useState } from "react";
import { AppNav, primaryBtn, ghostBtn, Spinner } from "../components/ui";
import { api } from "../api";
import { T } from "../theme";

export default function Targets() {
  const [targets, setTargets] = useState(null);
  const [url, setUrl] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [openId, setOpenId] = useState(null);

  async function load() {
    try {
      setTargets(await api.listTargets());
    } catch (e) {
      setErr(e.message);
    }
  }
  useEffect(() => { load(); }, []);

  async function add(e) {
    e.preventDefault();
    setErr("");
    setBusy(true);
    try {
      const t = await api.createTarget(url);
      setUrl("");
      await load();
      setOpenId(t.id); // reveal verification instructions
    } catch (e2) {
      setErr(e2.message);
    } finally {
      setBusy(false);
    }
  }

  async function remove(id) {
    if (!confirm("Remove this target?")) return;
    await api.deleteTarget(id);
    load();
  }

  return (
    <div>
      <AppNav />
      <main style={{ maxWidth: 780, margin: "0 auto", padding: "40px 24px 80px" }}>
        <h1 style={{ fontFamily: T.heading, fontSize: 30, fontWeight: 700, letterSpacing: "-0.02em", margin: "0 0 4px" }}>Targets</h1>
        <p style={{ color: T.muted, fontSize: 14.5, margin: "0 0 28px" }}>
          Add the websites you own. Prove ownership once, then scan them any time.
        </p>

        <form onSubmit={add} style={{ display: "flex", gap: 10, marginBottom: 30, flexWrap: "wrap" }}>
          <input value={url} onChange={(e) => setUrl(e.target.value)} required placeholder="your-website.com" style={{ flex: 1, minWidth: 240, padding: "13px 15px", borderRadius: 12, border: `1px solid ${T.borderStrong}`, background: "rgba(255,255,255,0.05)", color: T.text, fontSize: 15, fontFamily: T.mono }} />
          <button type="submit" disabled={busy} style={{ ...primaryBtn, display: "inline-flex", alignItems: "center", gap: 8, opacity: busy ? 0.7 : 1 }}>
            {busy && <Spinner />} Add target
          </button>
        </form>

        {err && <div style={{ color: "#F87171", marginBottom: 16 }}>{err}</div>}

        {targets === null ? (
          <p style={{ color: T.muted }}>Loading…</p>
        ) : targets.length === 0 ? (
          <div style={{ textAlign: "center", padding: "64px 24px", border: `1px dashed ${T.borderStrong}`, borderRadius: 16, color: T.muted }}>
            No targets yet. Add a domain you own above.
          </div>
        ) : (
          <div style={{ display: "grid", gap: 12 }}>
            {targets.map((t) => (
              <TargetRow key={t.id} t={t} open={openId === t.id} onOpen={() => setOpenId(openId === t.id ? null : t.id)} onChange={load} onRemove={() => remove(t.id)} />
            ))}
          </div>
        )}
      </main>
    </div>
  );
}

function TargetRow({ t, open, onOpen, onChange, onRemove }) {
  const [detail, setDetail] = useState(null);
  const [verifying, setVerifying] = useState(false);
  const [msg, setMsg] = useState("");

  useEffect(() => {
    if (open && !t.verified && !detail) api.getTarget(t.id).then(setDetail).catch(() => {});
  }, [open]);

  async function verify() {
    setVerifying(true);
    setMsg("");
    try {
      const res = await api.verifyTarget(t.id);
      setMsg(res.message);
      if (res.verified) onChange();
    } catch (e) {
      setMsg(e.message);
    } finally {
      setVerifying(false);
    }
  }

  return (
    <div style={{ borderRadius: 14, border: `1px solid ${t.verified ? "rgba(0,191,99,0.35)" : T.border}`, background: "rgba(255,255,255,0.02)", overflow: "hidden" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 14, padding: "16px 18px" }}>
        <span style={{ width: 10, height: 10, borderRadius: "50%", background: t.verified ? T.accent : T.faint, flexShrink: 0 }} />
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontFamily: T.mono, fontSize: 15, color: T.text }}>{t.host}</div>
          <div style={{ fontSize: 12.5, color: t.verified ? T.accent : T.muted, marginTop: 3 }}>
            {t.verified ? `Verified via ${t.verification_method}` : "Not verified — prove ownership to scan"}
          </div>
        </div>
        {!t.verified && (
          <button onClick={onOpen} style={ghostBtn}>{open ? "Hide" : "Verify"}</button>
        )}
        {t.verified && (
          <a href="/scans/new" style={{ ...ghostBtn, textDecoration: "none" }}>Scan</a>
        )}
        <button onClick={onRemove} aria-label="Remove target" style={{ background: "none", border: "none", color: T.faint, cursor: "pointer", padding: 6 }}>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round"><path d="M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6" /></svg>
        </button>
      </div>

      {open && !t.verified && (
        <div style={{ borderTop: `1px solid ${T.border}`, padding: "18px", display: "grid", gap: 16 }}>
          <p style={{ margin: 0, fontSize: 13.5, color: T.muted }}>
            Complete <b style={{ color: T.text }}>any one</b> of these on <code style={{ fontFamily: T.mono, color: T.accentHi }}>{t.host}</code>, then click Verify.
          </p>
          {detail?.instructions?.map((step) => (
            <div key={step.method} style={{ padding: "14px 16px", borderRadius: 12, border: `1px solid ${T.border}` }}>
              <div style={{ fontSize: 13.5, fontWeight: 600, marginBottom: 4 }}>{step.title}</div>
              <div style={{ fontSize: 12.5, color: T.muted, marginBottom: 10 }}>{step.detail}</div>
              <CopyBox value={step.value} />
            </div>
          ))}
          {!detail && <p style={{ color: T.muted, fontSize: 13 }}>Loading instructions…</p>}
          {msg && <div style={{ fontSize: 13, color: msg.toLowerCase().includes("verif") && !msg.toLowerCase().includes("could not") ? T.accent : "#FBBF24" }}>{msg}</div>}
          <button onClick={verify} disabled={verifying} style={{ ...primaryBtn, justifySelf: "start", display: "inline-flex", alignItems: "center", gap: 8, opacity: verifying ? 0.7 : 1 }}>
            {verifying && <Spinner />} Verify now
          </button>
        </div>
      )}
    </div>
  );
}

function CopyBox({ value }) {
  const [copied, setCopied] = useState(false);
  return (
    <div style={{ display: "flex", gap: 8, alignItems: "stretch" }}>
      <code style={{ flex: 1, fontFamily: T.mono, fontSize: 12.5, color: T.accentHi, background: "rgba(0,0,0,0.35)", padding: "10px 12px", borderRadius: 8, overflow: "auto", whiteSpace: "nowrap" }}>{value}</code>
      <button onClick={() => { navigator.clipboard?.writeText(value); setCopied(true); setTimeout(() => setCopied(false), 1500); }} style={{ ...ghostBtn, whiteSpace: "nowrap" }}>
        {copied ? "Copied" : "Copy"}
      </button>
    </div>
  );
}
