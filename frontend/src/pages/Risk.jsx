import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { AppNav, primaryBtn } from "../components/ui";
import { api } from "../api";
import { T, SEVERITY } from "../theme";

const SEV_ORDER = ["critical", "high", "medium", "low", "info"];

export default function Risk() {
  const [data, setData] = useState(null);
  const [err, setErr] = useState("");
  const [sev, setSev] = useState("all");

  useEffect(() => {
    api.getRisk().then(setData).catch((e) => setErr(e.message));
  }, []);

  if (err) return <Shell><p style={{ color: "#F87171" }}>{err}</p></Shell>;
  if (!data) return <Shell><p style={{ color: T.muted }}>Building your risk register…</p></Shell>;

  const risks = sev === "all" ? data.risks : data.risks.filter((r) => r.severity === sev);
  const empty = data.total_risks === 0;

  return (
    <Shell>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-end", flexWrap: "wrap", gap: 16, marginBottom: 8 }}>
        <div>
          <h1 style={{ fontFamily: T.heading, fontSize: 30, fontWeight: 700, letterSpacing: "-0.02em", margin: "0 0 4px" }}>Risk register</h1>
          <p style={{ color: T.muted, fontSize: 14.5, margin: 0 }}>
            Every open issue across {data.targets_covered} target{data.targets_covered !== 1 ? "s" : ""}, deduplicated and ranked fix-first.
          </p>
        </div>
        <Link to="/scans/new" className="btn-primary" style={{ ...primaryBtn, textDecoration: "none" }}>New scan</Link>
      </div>

      {empty ? (
        <div style={{ textAlign: "center", padding: "70px 24px", color: T.muted, border: `1px dashed ${T.border}`, borderRadius: 16, marginTop: 24 }}>
          No open risk yet. Run a scan to populate your register.
        </div>
      ) : (
        <>
          {/* Severity summary */}
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(96px, 1fr))", gap: 12, margin: "22px 0 30px" }} className="risk-summary">
            {SEV_ORDER.map((s) => (
              <button key={s} onClick={() => setSev(sev === s ? "all" : s)} style={{ cursor: "pointer", textAlign: "left", padding: "14px 16px", borderRadius: 14, border: `1px solid ${sev === s ? SEVERITY[s].color : SEVERITY[s].border}`, background: SEVERITY[s].bg, fontFamily: T.body }}>
                <div style={{ fontFamily: T.heading, fontSize: 26, fontWeight: 700, color: SEVERITY[s].color }}>{data.by_severity[s] || 0}</div>
                <div style={{ fontSize: 11.5, color: T.muted, textTransform: "uppercase", letterSpacing: "0.06em" }}>{SEVERITY[s].label}</div>
              </button>
            ))}
          </div>

          {/* Attack paths — the correlation layer */}
          {data.attack_paths.length > 0 && (
            <section style={{ marginBottom: 34 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 4 }}>
                <h2 style={{ fontFamily: T.heading, fontSize: 20, fontWeight: 700, margin: 0 }}>Attack paths</h2>
                <span style={{ fontSize: 11, fontWeight: 700, color: "#F87171", border: "1px solid rgba(248,113,113,0.4)", background: "rgba(248,113,113,0.1)", borderRadius: 999, padding: "2px 9px" }}>{data.attack_paths.length} chain{data.attack_paths.length !== 1 ? "s" : ""}</span>
              </div>
              <p style={{ color: T.muted, fontSize: 13.5, margin: "0 0 16px", maxWidth: 640 }}>
                Individual findings an attacker would chain together. These are your real exposure, fix any one link to break the chain.
              </p>
              <div style={{ display: "grid", gap: 14 }}>
                {data.attack_paths.map((p) => <AttackPathCard key={p.id} path={p} />)}
              </div>
            </section>
          )}

          {/* Risk register table */}
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12, marginBottom: 12, flexWrap: "wrap" }}>
            <h2 style={{ fontFamily: T.heading, fontSize: 20, fontWeight: 700, margin: 0 }}>
              All risks {sev !== "all" && <span style={{ color: SEVERITY[sev].color, fontSize: 14 }}>· {SEVERITY[sev].label}</span>}
            </h2>
            {sev !== "all" && <button onClick={() => setSev("all")} style={{ background: "none", border: `1px solid ${T.border}`, color: T.muted, fontSize: 12.5, padding: "6px 12px", borderRadius: 8, cursor: "pointer", fontFamily: T.body }}>Clear filter</button>}
          </div>
          <div style={{ display: "grid", gap: 8 }}>
            {risks.map((r) => <RiskRow key={r.check_id} r={r} />)}
          </div>
        </>
      )}
    </Shell>
  );
}

function AttackPathCard({ path }) {
  const s = SEVERITY[path.severity] || SEVERITY.info;
  return (
    <div style={{ borderRadius: 16, border: `1px solid ${s.border}`, background: "linear-gradient(180deg, rgba(248,113,113,0.04), rgba(255,255,255,0.015))", overflow: "hidden" }}>
      <div style={{ padding: "18px 20px", borderBottom: `1px solid ${T.border}` }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
          <span style={{ fontSize: 10.5, fontWeight: 700, letterSpacing: "0.06em", textTransform: "uppercase", padding: "3px 9px", borderRadius: 999, color: s.color, border: `1px solid ${s.border}`, background: s.bg }}>{s.label}</span>
          <h3 style={{ fontFamily: T.heading, fontSize: 17, fontWeight: 700, margin: 0 }}>{path.title}</h3>
        </div>
        <p style={{ fontSize: 13.5, lineHeight: 1.6, color: T.muted, margin: 0 }}>{path.story}</p>
      </div>
      <div style={{ padding: "16px 20px", display: "flex", alignItems: "stretch", gap: 0, flexWrap: "wrap" }}>
        {path.steps.map((st, i) => (
          <div key={i} style={{ display: "flex", alignItems: "center", gap: 0 }}>
            <div style={{ maxWidth: 240 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 5 }}>
                <span style={{ width: 22, height: 22, borderRadius: "50%", flex: "none", background: s.bg, border: `1px solid ${s.border}`, color: s.color, fontFamily: T.mono, fontSize: 11, fontWeight: 700, display: "flex", alignItems: "center", justifyContent: "center" }}>{i + 1}</span>
                <span style={{ fontSize: 12.5, fontWeight: 600, color: T.text }}>{st.label}</span>
              </div>
              <div style={{ paddingLeft: 30 }}>
                <div style={{ fontSize: 12, color: T.muted, lineHeight: 1.4 }}>{st.evidence.title}</div>
                <div style={{ fontSize: 11, color: T.faint, fontFamily: T.mono, marginTop: 2 }}>{st.evidence.target}</div>
              </div>
            </div>
            {i < path.steps.length - 1 && (
              <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke={s.color} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" style={{ flex: "none", margin: "0 6px", opacity: 0.7 }}><path d="M5 12h14" /><path d="m13 6 6 6-6 6" /></svg>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

function RiskRow({ r }) {
  const s = SEVERITY[r.severity] || SEVERITY.info;
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 14, padding: "13px 16px", borderRadius: 12, border: `1px solid ${T.border}`, background: "rgba(255,255,255,0.02)", opacity: r.accepted ? 0.6 : 1 }}>
      <span style={{ fontSize: 10, fontWeight: 700, letterSpacing: "0.05em", textTransform: "uppercase", padding: "3px 8px", borderRadius: 999, color: s.color, border: `1px solid ${s.border}`, background: s.bg, minWidth: 58, textAlign: "center", flex: "none" }}>{s.label}</span>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 14, fontWeight: 600, color: T.text, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
          {r.title}
          {r.accepted && <span style={{ marginLeft: 8, fontSize: 10, fontWeight: 700, textTransform: "uppercase", color: "#fbbf24", border: "1px solid rgba(251,191,36,0.4)", borderRadius: 999, padding: "1px 7px" }}>Accepted</span>}
        </div>
        <div style={{ fontSize: 12, color: T.faint, display: "flex", gap: 10, marginTop: 2, flexWrap: "wrap" }}>
          {r.owasp && <span style={{ fontFamily: T.mono, color: T.accentHi }}>{r.owasp.split(":")[0]}</span>}
          {r.cwe && <span style={{ fontFamily: T.mono }}>{r.cwe}</span>}
          {r.layer && <span>{r.layer}</span>}
        </div>
      </div>
      <div style={{ textAlign: "right", flex: "none" }}>
        <div style={{ fontSize: 12.5, color: T.muted }}>
          {r.target_count > 1
            ? <span><b style={{ color: T.text }}>{r.target_count}</b> targets</span>
            : <span style={{ fontFamily: T.mono, fontSize: 11.5, color: T.faint }}>{r.targets[0]}</span>}
        </div>
        {r.count > 1 && <div style={{ fontSize: 11, color: T.faint }}>×{r.count} occurrences</div>}
      </div>
    </div>
  );
}

function Shell({ children }) {
  return (
    <div>
      <AppNav />
      <main style={{ maxWidth: 960, margin: "0 auto", padding: "36px 24px 90px" }}>{children}</main>
    </div>
  );
}
