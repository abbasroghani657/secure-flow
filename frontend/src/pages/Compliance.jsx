import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { AppNav, primaryBtn, ghostBtn, Spinner } from "../components/ui";
import { api } from "../api";
import { T, SEVERITY } from "../theme";

function readyColor(pct) {
  if (pct >= 80) return "#34d399";
  if (pct >= 50) return "#fbbf24";
  return "#F87171";
}

export default function Compliance() {
  const [data, setData] = useState(null);
  const [err, setErr] = useState("");
  const [active, setActive] = useState(null);
  const [openCtrl, setOpenCtrl] = useState({});

  useEffect(() => {
    api.getCompliance().then((d) => { setData(d); setActive(d.frameworks[0]?.key); }).catch((e) => setErr(e.message));
  }, []);

  if (err) return <Shell><p style={{ color: "#F87171" }}>{err}</p></Shell>;
  if (!data) return <Shell><p style={{ color: T.muted }}>Assessing your controls…</p></Shell>;

  const fw = data.frameworks.find((f) => f.key === active) || data.frameworks[0];

  return (
    <Shell>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-end", flexWrap: "wrap", gap: 12, marginBottom: 6 }}>
        <div>
          <h1 style={{ fontFamily: T.heading, fontSize: 30, fontWeight: 700, letterSpacing: "-0.02em", margin: "0 0 4px" }}>Compliance</h1>
          <p style={{ color: T.muted, fontSize: 14.5, margin: 0 }}>
            Readiness against the major frameworks, scored from your open findings across {data.targets_covered} target{data.targets_covered !== 1 ? "s" : ""}.
          </p>
        </div>
        <button onClick={() => window.print()} style={{ ...ghostBtn, display: "inline-flex", alignItems: "center", gap: 8 }}>
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M6 9V2h12v7M6 18H4a2 2 0 01-2-2v-5a2 2 0 012-2h16a2 2 0 012 2v5a2 2 0 01-2 2h-2M6 14h12v8H6z" /></svg>
          Export for auditor
        </button>
      </div>

      {/* Framework cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))", gap: 12, margin: "22px 0 12px" }} className="compl-cards">
        {data.frameworks.map((f) => {
          const c = readyColor(f.readiness);
          return (
            <button key={f.key} onClick={() => setActive(f.key)} style={{ cursor: "pointer", textAlign: "left", padding: "16px 16px", borderRadius: 14, border: `1px solid ${f.key === active ? c : T.border}`, background: f.key === active ? `${c}12` : "rgba(255,255,255,0.02)", fontFamily: T.body }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline" }}>
                <span style={{ fontSize: 13.5, fontWeight: 700, color: T.text }}>{f.name}</span>
                <span style={{ fontFamily: T.heading, fontSize: 20, fontWeight: 800, color: c }}>{f.readiness}%</span>
              </div>
              <div style={{ fontSize: 11, color: T.faint, margin: "3px 0 10px" }}>{f.version}</div>
              <div style={{ height: 6, borderRadius: 999, background: "rgba(255,255,255,0.08)", overflow: "hidden" }}>
                <div style={{ width: `${f.readiness}%`, height: "100%", background: c, transition: "width 0.6s" }} />
              </div>
              <div style={{ fontSize: 11.5, color: T.muted, marginTop: 8 }}>{f.controls_met}/{f.controls_total} controls met</div>
            </button>
          );
        })}
      </div>

      {/* Active framework detail */}
      {fw && (
        <section style={{ marginTop: 22 }}>
          <div style={{ display: "flex", alignItems: "baseline", gap: 10, marginBottom: 4, flexWrap: "wrap" }}>
            <h2 style={{ fontFamily: T.heading, fontSize: 21, fontWeight: 700, margin: 0 }}>{fw.name} <span style={{ color: T.faint, fontSize: 14, fontWeight: 400 }}>{fw.version}</span></h2>
            <span style={{ fontFamily: T.heading, fontSize: 18, fontWeight: 800, color: readyColor(fw.readiness) }}>{fw.readiness}% ready</span>
          </div>
          <p style={{ color: T.muted, fontSize: 13.5, margin: "0 0 18px" }}>{fw.blurb}</p>

          <div style={{ display: "grid", gap: 8 }}>
            {fw.controls.map((c) => {
              const met = c.status === "met";
              const isOpen = !!openCtrl[fw.key + c.id];
              return (
                <div key={c.id} style={{ borderRadius: 12, border: `1px solid ${met ? "rgba(52,211,153,0.3)" : "rgba(248,113,113,0.3)"}`, background: met ? "rgba(52,211,153,0.05)" : "rgba(248,113,113,0.04)", overflow: "hidden" }}>
                  <button onClick={() => c.issue_count && setOpenCtrl((o) => ({ ...o, [fw.key + c.id]: !o[fw.key + c.id] }))} style={{ width: "100%", display: "flex", alignItems: "center", gap: 12, padding: "13px 15px", background: "none", border: "none", cursor: c.issue_count ? "pointer" : "default", textAlign: "left", fontFamily: T.body }}>
                    {met ? (
                      <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="#34d399" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" style={{ flex: "none" }}><path d="M20 6L9 17l-5-5" /></svg>
                    ) : (
                      <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="#F87171" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" style={{ flex: "none" }}><path d="M10.29 3.86 1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0Z" /><path d="M12 9v4M12 17h.01" /></svg>
                    )}
                    <span style={{ fontFamily: T.mono, fontSize: 11.5, fontWeight: 700, color: T.muted, minWidth: 66 }}>{c.id}</span>
                    <span style={{ flex: 1, minWidth: 0 }}>
                      <span style={{ fontSize: 14, fontWeight: 600, color: T.text }}>{c.title}</span>
                      <span style={{ display: "block", fontSize: 12, color: T.faint, marginTop: 1, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{c.description}</span>
                    </span>
                    <span style={{ fontSize: 12, fontWeight: 600, color: met ? "#34d399" : "#F87171", whiteSpace: "nowrap" }}>
                      {met ? "Met" : `${c.issue_count} issue${c.issue_count !== 1 ? "s" : ""}`}
                    </span>
                    {!!c.issue_count && <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke={T.muted} strokeWidth="2" strokeLinecap="round" style={{ transform: isOpen ? "rotate(180deg)" : "none", transition: "transform 0.2s", flex: "none" }}><path d="M6 9l6 6 6-6" /></svg>}
                  </button>
                  {isOpen && c.findings.length > 0 && (
                    <div style={{ padding: "0 15px 12px 44px", display: "grid", gap: 2 }}>
                      {c.findings.map((f, i) => (
                        <div key={i} style={{ display: "flex", gap: 10, alignItems: "center", fontSize: 13, padding: "7px 0", borderTop: `1px solid ${T.border}` }}>
                          <span style={{ fontSize: 9.5, fontWeight: 700, textTransform: "uppercase", color: SEVERITY[f.severity].color, minWidth: 48 }}>{SEVERITY[f.severity].label}</span>
                          <span style={{ color: T.text, flex: 1 }}>{f.title}</span>
                          <span style={{ fontFamily: T.mono, fontSize: 11, color: T.faint }}>{f.target}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </section>
      )}

      <p style={{ color: T.faint, fontSize: 12.5, lineHeight: 1.6, marginTop: 26, padding: "14px 16px", border: `1px dashed ${T.border}`, borderRadius: 12 }}>
        This assesses the <b style={{ color: T.muted }}>technically-detectable</b> controls a scan can observe. Full certification also requires policies, processes and an auditor's review, which this does not replace. Fix the flagged findings to raise each score.
        {" "}<Link to="/risk" style={{ color: T.accentHi }}>Go to the risk register →</Link>
      </p>
    </Shell>
  );
}

function Shell({ children }) {
  return (<div><AppNav /><main style={{ maxWidth: 960, margin: "0 auto", padding: "36px 24px 90px" }}>{children}</main></div>);
}
