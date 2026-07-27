import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { AppNav, primaryBtn } from "../components/ui";
import { useUX } from "../components/UX";
import { api } from "../api";
import { T, scoreColor } from "../theme";

const STATUS_STYLE = {
  completed: { color: T.accent, label: "Completed" },
  running: { color: "#FBBF24", label: "Running" },
  queued: { color: T.muted, label: "Queued" },
  failed: { color: "#F87171", label: "Failed" },
};

export default function Dashboard() {
  const { confirm, toast } = useUX();
  const [scans, setScans] = useState(null);
  const [err, setErr] = useState("");
  const [plan, setPlan] = useState(null);

  async function load() {
    try {
      setScans(await api.listScans());
    } catch (e) {
      setErr(e.message);
    }
  }

  useEffect(() => {
    load();
    api.getPlan().then(setPlan).catch(() => {});
    // Refresh while any scan is in progress.
    const t = setInterval(load, 2500);
    return () => clearInterval(t);
  }, []);

  async function remove(id, e) {
    e.preventDefault();
    const ok = await confirm({
      title: "Delete this scan?",
      message: "The scan and all its findings will be removed. This can't be undone.",
      confirmLabel: "Delete", danger: true,
    });
    if (!ok) return;
    try {
      await api.deleteScan(id);
      toast("Scan deleted");
      load();
    } catch (e2) { toast(e2.message, "error"); }
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

        {plan && plan.plan === "free" && (() => {
          const cap = plan.limits.scans_per_month;
          const used = plan.usage.scans_this_month;
          const pct = cap ? Math.min(100, Math.round((used / cap) * 100)) : 0;
          return (
            <div style={{ marginBottom: 22, padding: "16px 20px", borderRadius: 14, border: "1px solid rgba(6,182,212,0.28)", background: "linear-gradient(180deg, rgba(6,182,212,0.07), rgba(255,255,255,0.02))" }}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 14, flexWrap: "wrap" }}>
                <div>
                  <div style={{ fontSize: 14, fontWeight: 600 }}>You're on the <span style={{ color: T.accentHi }}>Free</span> plan</div>
                  <div style={{ fontSize: 12.5, color: T.muted, marginTop: 3 }}>
                    {used} of {cap} scans used this month · {plan.usage.targets} of {plan.limits.max_targets} target{plan.limits.max_targets !== 1 ? "s" : ""} · web scans only
                  </div>
                </div>
                <Link to="/pricing" className="btn-primary" style={{ ...primaryBtn, padding: "9px 18px", fontSize: 13.5, whiteSpace: "nowrap" }}>Upgrade to Pro →</Link>
              </div>
              <div style={{ marginTop: 12, height: 6, borderRadius: 999, background: "rgba(255,255,255,0.08)", overflow: "hidden" }}>
                <div style={{ width: `${pct}%`, height: "100%", background: `linear-gradient(90deg, ${T.accent}, ${T.accentHi})`, borderRadius: 999 }} />
              </div>
            </div>
          );
        })()}

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
                      {s.security_score ?? "-"}
                    </div>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontFamily: T.mono, fontSize: 14.5, color: T.text, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", display: "flex", alignItems: "center", gap: 8 }}>
                        {s.target_url}
                        {s.trigger === "scheduled" && <span style={{ fontSize: 10, fontWeight: 600, color: T.accentHi, border: "1px solid rgba(6,182,212,0.3)", borderRadius: 999, padding: "1px 7px", flexShrink: 0 }}>scheduled</span>}
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
