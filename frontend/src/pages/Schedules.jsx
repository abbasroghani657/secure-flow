import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { AppNav, primaryBtn, ghostBtn, Spinner } from "../components/ui";
import { api } from "../api";
import { T } from "../theme";

const DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
const SCAN_LABEL = { web: "Web application", deep: "Deep scan (Nuclei)", headers: "Headers only" };

export default function Schedules() {
  const [schedules, setSchedules] = useState(null);
  const [targets, setTargets] = useState([]);
  const [err, setErr] = useState("");
  const [creating, setCreating] = useState(false);

  // form state
  const [target, setTarget] = useState("");
  const [scanType, setScanType] = useState("web");
  const [cadence, setCadence] = useState("daily");
  const [hour, setHour] = useState(6);
  const [weekday, setWeekday] = useState(0);
  const [alertEmail, setAlertEmail] = useState(true);

  async function load() {
    try {
      const [sch, tg] = await Promise.all([api.listSchedules(), api.listTargets()]);
      setSchedules(sch);
      const verified = tg.filter((t) => t.verified);
      setTargets(verified);
      if (!target && verified[0]) setTarget(verified[0].url);
    } catch (e) {
      setErr(e.message);
    }
  }
  useEffect(() => { load(); }, []);

  async function create(e) {
    e.preventDefault();
    setErr("");
    setCreating(true);
    try {
      await api.createSchedule({ target_url: target, scan_type: scanType, cadence, hour_utc: Number(hour), weekday: Number(weekday), alert_email: alertEmail });
      await load();
    } catch (e2) {
      setErr(e2.message);
    } finally {
      setCreating(false);
    }
  }

  async function toggle(s) {
    await api.updateSchedule(s.id, { enabled: !s.enabled });
    load();
  }
  async function remove(id) {
    if (!confirm("Delete this schedule?")) return;
    await api.deleteSchedule(id);
    load();
  }

  return (
    <div>
      <AppNav />
      <main style={{ maxWidth: 820, margin: "0 auto", padding: "40px 24px 80px" }}>
        <h1 style={{ fontFamily: T.heading, fontSize: 30, fontWeight: 700, letterSpacing: "-0.02em", margin: "0 0 4px" }}>Scheduled monitoring</h1>
        <p style={{ color: T.muted, fontSize: 14.5, margin: "0 0 28px" }}>
          Run scans automatically on a schedule and get emailed when new issues appear. Times are in UTC.
        </p>

        {targets.length === 0 ? (
          <div style={{ textAlign: "center", padding: "48px 24px", border: `1px dashed ${T.borderStrong}`, borderRadius: 16, marginBottom: 30 }}>
            <p style={{ color: T.muted, margin: "0 0 18px" }}>You need a verified target before scheduling scans.</p>
            <Link to="/targets" style={{ ...primaryBtn, display: "inline-block" }}>Go to Targets</Link>
          </div>
        ) : (
          <form onSubmit={create} style={{ padding: "22px 24px", border: `1px solid ${T.border}`, borderRadius: 16, background: "rgba(255,255,255,0.02)", marginBottom: 34, display: "grid", gap: 16 }}>
            <div style={{ fontFamily: T.heading, fontWeight: 600, fontSize: 16 }}>New schedule</div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 14 }}>
              <Field label="Target">
                <select value={target} onChange={(e) => setTarget(e.target.value)} style={sel}>
                  {targets.map((t) => <option key={t.id} value={t.url}>{t.host}</option>)}
                </select>
              </Field>
              <Field label="Scan type">
                <select value={scanType} onChange={(e) => setScanType(e.target.value)} style={sel}>
                  <option value="web">Web application</option>
                  <option value="deep">Deep scan (Nuclei)</option>
                  <option value="headers">Headers only</option>
                </select>
              </Field>
              <Field label="Frequency">
                <select value={cadence} onChange={(e) => setCadence(e.target.value)} style={sel}>
                  <option value="daily">Daily</option>
                  <option value="weekly">Weekly</option>
                </select>
              </Field>
              {cadence === "weekly" && (
                <Field label="Day">
                  <select value={weekday} onChange={(e) => setWeekday(e.target.value)} style={sel}>
                    {DAYS.map((d, i) => <option key={d} value={i}>{d}</option>)}
                  </select>
                </Field>
              )}
              <Field label="Hour (UTC)">
                <select value={hour} onChange={(e) => setHour(e.target.value)} style={sel}>
                  {Array.from({ length: 24 }, (_, i) => <option key={i} value={i}>{String(i).padStart(2, "0")}:00</option>)}
                </select>
              </Field>
            </div>
            <label style={{ display: "flex", gap: 10, alignItems: "center", fontSize: 13.5, color: T.muted, cursor: "pointer" }}>
              <input type="checkbox" checked={alertEmail} onChange={(e) => setAlertEmail(e.target.checked)} style={{ accentColor: T.accent, width: 16, height: 16 }} />
              Email me when a scheduled scan finds new or high-severity issues
            </label>
            {err && <div style={{ color: "#F87171", fontSize: 13.5 }}>{err}</div>}
            <button type="submit" disabled={creating} style={{ ...primaryBtn, justifySelf: "start", display: "inline-flex", alignItems: "center", gap: 8, opacity: creating ? 0.7 : 1 }}>
              {creating && <Spinner />} Create schedule
            </button>
          </form>
        )}

        <h2 style={{ fontFamily: T.heading, fontSize: 18, fontWeight: 600, margin: "0 0 14px" }}>Active schedules</h2>
        {schedules === null ? (
          <p style={{ color: T.muted }}>Loading…</p>
        ) : schedules.length === 0 ? (
          <p style={{ color: T.muted, fontSize: 14 }}>No schedules yet.</p>
        ) : (
          <div style={{ display: "grid", gap: 12 }}>
            {schedules.map((s) => (
              <div key={s.id} style={{ display: "flex", alignItems: "center", gap: 16, padding: "16px 18px", borderRadius: 14, border: `1px solid ${T.border}`, background: "rgba(255,255,255,0.02)", opacity: s.enabled ? 1 : 0.55 }}>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontFamily: T.mono, fontSize: 14.5 }}>{s.host}</div>
                  <div style={{ fontSize: 12.5, color: T.muted, marginTop: 4 }}>
                    {SCAN_LABEL[s.scan_type] || s.scan_type} · {s.cadence === "weekly" ? `Weekly (${DAYS[s.weekday]})` : "Daily"} at {String(s.hour_utc).padStart(2, "0")}:00 UTC
                    {s.alert_email && " · email alerts on"}
                  </div>
                  <div style={{ fontSize: 12, color: s.enabled ? T.accent : T.faint, marginTop: 4 }}>
                    {s.enabled ? `Next run: ${s.next_run_at ? new Date(s.next_run_at + "Z").toLocaleString() : "—"}` : "Paused"}
                    {s.last_run_at && ` · Last: ${new Date(s.last_run_at + "Z").toLocaleString()}`}
                  </div>
                </div>
                <button onClick={() => toggle(s)} style={ghostBtn}>{s.enabled ? "Pause" : "Resume"}</button>
                <button onClick={() => remove(s.id)} aria-label="Delete schedule" style={{ background: "none", border: "none", color: T.faint, cursor: "pointer", padding: 6 }}>
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round"><path d="M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6" /></svg>
                </button>
              </div>
            ))}
          </div>
        )}
      </main>
    </div>
  );
}

function Field({ label, children }) {
  return (
    <label style={{ display: "grid", gap: 6 }}>
      <span style={{ fontSize: 12.5, fontWeight: 600, color: T.muted }}>{label}</span>
      {children}
    </label>
  );
}

const sel = {
  width: "100%",
  padding: "11px 12px",
  borderRadius: 10,
  border: `1px solid ${T.borderStrong}`,
  background: "#161916",
  color: T.text,
  fontSize: 14,
  fontFamily: T.body,
  cursor: "pointer",
};
