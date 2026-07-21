import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { AppNav, primaryBtn } from "../components/ui";
import { api } from "../api";
import { T, scoreColor } from "../theme";

const STATUS_STYLE = {
  completed: { color: T.accent, label: "Completed" },
  running: { color: "#FBBF24", label: "Running" },
  queued: { color: T.muted, label: "Queued" },
  failed: { color: "#F87171", label: "Failed" },
};

export default function Dashboard() {
  const [scans, setScans] = useState(null);
  const [err, setErr] = useState("");

  async function load() {
    try {
      setScans(await api.listScans());
    } catch (e) {
      setErr(e.message);
    }
  }

  useEffect(() => {
    load();
    // Refresh while any scan is in progress.
    const t = setInterval(load, 2500);
    return () => clearInterval(t);
  }, []);

  async function remove(id, e) {
    e.preventDefault();
    if (!confirm("Delete this scan?")) return;
    await api.deleteScan(id);
    load();
  }

  return (
    <div>
      <AppNav />
      <main style={{ maxWidth: 980, margin: "0 auto", padding: "40px 24px 80px" }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 28, flexWrap: "wrap", gap: 12 }}>
          <div>
            <h1 style={{ fontFamily: T.heading, fontSize: 30, fontWeight: 700, letterSpacing: "-0.02em", margin: "0 0 4px" }}>Your scans</h1>
            <p style={{ color: T.muted, fontSize: 14.5, margin: 0 }}>Every scan you have run, newest first.</p>
          </div>
          <Link to="/scans/new" style={{ ...primaryBtn, display: "inline-flex", alignItems: "center", gap: 8 }}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M12 5v14M5 12h14" /></svg>
            New scan
          </Link>
        </div>

        {err && <div style={{ color: "#F87171", marginBottom: 16 }}>{err}</div>}

        {scans === null ? (
          <p style={{ color: T.muted }}>Loading…</p>
        ) : scans.length === 0 ? (
          <div style={{ textAlign: "center", padding: "72px 24px", border: `1px dashed ${T.borderStrong}`, borderRadius: 16 }}>
            <p style={{ color: T.muted, fontSize: 15, margin: "0 0 20px" }}>No scans yet. Run your first one.</p>
            <Link to="/scans/new" style={{ ...primaryBtn, display: "inline-block" }}>Start a scan</Link>
          </div>
        ) : (
          <div style={{ display: "grid", gap: 12 }}>
            {scans.map((s) => {
              const ss = STATUS_STYLE[s.status] || STATUS_STYLE.queued;
              const issues = s.critical_count + s.high_count + s.medium_count + s.low_count;
              return (
                <Link key={s.id} to={`/scans/${s.id}`} style={{ display: "block", color: "inherit" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 18, padding: "18px 20px", borderRadius: 14, border: `1px solid ${T.border}`, background: "rgba(255,255,255,0.02)" }}>
                    <div style={{ width: 52, height: 52, borderRadius: 12, border: `2px solid ${scoreColor(s.security_score)}`, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0, fontFamily: T.heading, fontWeight: 700, fontSize: 18, color: scoreColor(s.security_score) }}>
                      {s.security_score ?? "—"}
                    </div>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontFamily: T.mono, fontSize: 14.5, color: T.text, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", display: "flex", alignItems: "center", gap: 8 }}>
                        {s.target_url}
                        {s.trigger === "scheduled" && <span style={{ fontSize: 10, fontWeight: 600, color: T.accentHi, border: "1px solid rgba(0,191,99,0.3)", borderRadius: 999, padding: "1px 7px", flexShrink: 0 }}>scheduled</span>}
                        {s.status === "completed" && s.new_findings_count > 0 && <span style={{ fontSize: 10, fontWeight: 700, color: T.accentInk, background: T.accent, borderRadius: 999, padding: "1px 7px", flexShrink: 0 }}>{s.new_findings_count} new</span>}
                      </div>
                      <div style={{ fontSize: 12.5, color: T.muted, marginTop: 4 }}>
                        {new Date(s.created_at).toLocaleString()} · {s.scan_type}
                      </div>
                    </div>
                    {s.status === "running" || s.status === "queued" ? (
                      <div style={{ minWidth: 120, textAlign: "right" }}>
                        <span style={{ fontSize: 12.5, color: ss.color, fontWeight: 600 }}>{ss.label} {s.progress}%</span>
                        <div style={{ height: 5, width: 110, marginTop: 6, marginLeft: "auto", borderRadius: 999, background: "rgba(255,255,255,0.08)", overflow: "hidden" }}>
                          <div style={{ width: `${s.progress}%`, height: "100%", background: ss.color, transition: "width 0.4s" }} />
                        </div>
                      </div>
                    ) : s.status === "failed" ? (
                      <span style={{ fontSize: 12.5, color: ss.color, fontWeight: 600 }}>Failed</span>
                    ) : (
                      <div style={{ display: "flex", gap: 10, fontSize: 12.5, alignItems: "center" }}>
                        {s.critical_count > 0 && <Pill n={s.critical_count} c="#F87171" />}
                        {s.high_count > 0 && <Pill n={s.high_count} c="#FB923C" />}
                        {s.medium_count > 0 && <Pill n={s.medium_count} c="#FBBF24" />}
                        <span style={{ color: T.muted }}>{issues} issue{issues !== 1 ? "s" : ""}</span>
                      </div>
                    )}
                    <button onClick={(e) => remove(s.id, e)} aria-label="Delete scan" style={{ background: "none", border: "none", color: T.faint, cursor: "pointer", padding: 6 }}>
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round"><path d="M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6" /></svg>
                    </button>
                  </div>
                </Link>
              );
            })}
          </div>
        )}
      </main>
    </div>
  );
}

function Pill({ n, c }) {
  return <span style={{ minWidth: 20, textAlign: "center", padding: "2px 7px", borderRadius: 999, fontSize: 11.5, fontWeight: 700, color: c, border: `1px solid ${c}55`, background: `${c}18` }}>{n}</span>;
}
