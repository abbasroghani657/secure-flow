import { useEffect, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useAuth } from "../auth";
import { api } from "../api";
import { T } from "../theme";

export function Logo({ size = 20 }) {
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 9, fontFamily: T.heading, fontWeight: 700, fontSize: size, letterSpacing: "-0.02em", color: T.text }}>
      <svg width={size + 4} height={size + 4} viewBox="0 0 24 24" fill="none" stroke={T.accent} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
        <path d="M9 12l2 2 4-4" />
      </svg>
      Pen<span style={{ color: T.accent }}>trixa</span>
    </span>
  );
}

// App shell nav for authenticated pages.
export function AppNav() {
  const { user, logout } = useAuth();
  const nav = useNavigate();
  const initials = (user?.name || "?").split(" ").map((w) => w[0]).slice(0, 2).join("").toUpperCase();
  return (
    <nav style={{ position: "sticky", top: 0, zIndex: 50, display: "flex", alignItems: "center", justifyContent: "space-between", gap: 24, padding: "12px 32px", background: "rgba(10,14,18,0.85)", backdropFilter: "blur(14px)", borderBottom: `1px solid ${T.border}` }}>
      <div style={{ display: "flex", alignItems: "center", gap: 28 }}>
        <Link to="/dashboard"><Logo size={18} /></Link>
        <div style={{ display: "flex", gap: 20, fontSize: 13.5 }}>
          <Link to="/dashboard" style={{ color: T.muted }}>Dashboard</Link>
          <Link to="/risk" style={{ color: T.muted }}>Risk</Link>
          <Link to="/compliance" style={{ color: T.muted }}>Compliance</Link>
          <Link to="/targets" style={{ color: T.muted }}>Targets</Link>
          <Link to="/schedules" style={{ color: T.muted }}>Schedules</Link>
          <Link to="/scans/new" style={{ color: T.muted }}>New Scan</Link>
          <Link to="/team" style={{ color: T.muted }}>Team</Link>
          <Link to="/settings" style={{ color: T.muted }}>Settings</Link>
        </div>
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
        <OrgSwitcher />
        <Link to="/account" style={{ fontSize: 13, color: T.muted }}>{user?.email}</Link>
        <button onClick={() => { logout(); nav("/"); }} style={ghostBtn}>Log out</button>
        <Link to="/account" title={`${user?.name} · Account`} style={{ width: 30, height: 30, borderRadius: "50%", background: T.accent, display: "flex", alignItems: "center", justifyContent: "center", fontFamily: T.heading, fontWeight: 700, fontSize: 12, color: T.accentInk }}>{initials}</Link>
      </div>
    </nav>
  );
}

// Compact workspace switcher: shows the active org, lets you hop between the
// workspaces you belong to.
function OrgSwitcher() {
  const { user } = useAuth();
  const [orgs, setOrgs] = useState(null);
  const [open, setOpen] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    api.listOrgs().then(setOrgs).catch(() => setOrgs([]));
  }, [user?.current_org_id]);

  useEffect(() => {
    function onDoc(e) { if (ref.current && !ref.current.contains(e.target)) setOpen(false); }
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, []);

  if (!orgs || orgs.length === 0) return null;
  const current = orgs.find((o) => o.id === user?.current_org_id) || orgs[0];

  async function pick(id) {
    if (id === current.id) { setOpen(false); return; }
    await api.switchOrg(id);
    window.location.reload();  // re-scope every page to the new workspace
  }

  return (
    <div ref={ref} style={{ position: "relative" }}>
      <button onClick={() => setOpen((v) => !v)} style={{ display: "flex", alignItems: "center", gap: 7, background: "rgba(255,255,255,0.04)", border: `1px solid ${T.border}`, color: T.text, fontFamily: T.body, fontSize: 12.5, fontWeight: 600, padding: "6px 10px", borderRadius: 9, cursor: "pointer", maxWidth: 170 }}>
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke={T.accent} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ flex: "none" }}><rect x="4" y="2" width="16" height="20" rx="2" /><path d="M9 22v-4h6v4M8 6h.01M16 6h.01M8 10h.01M16 10h.01" /></svg>
        <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{current.name}</span>
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke={T.muted} strokeWidth="2" strokeLinecap="round" style={{ flex: "none" }}><path d="M6 9l6 6 6-6" /></svg>
      </button>
      {open && (
        <div style={{ position: "absolute", top: "calc(100% + 6px)", right: 0, minWidth: 210, background: T.panel2, border: `1px solid ${T.borderStrong}`, borderRadius: 12, padding: 6, boxShadow: "0 16px 40px rgba(0,0,0,0.5)", zIndex: 100 }}>
          <div style={{ fontSize: 10.5, textTransform: "uppercase", letterSpacing: "0.06em", color: T.faint, padding: "6px 10px 4px" }}>Workspaces</div>
          {orgs.map((o) => (
            <button key={o.id} onClick={() => pick(o.id)} style={{ display: "flex", alignItems: "center", gap: 8, width: "100%", textAlign: "left", background: o.id === current.id ? "rgba(6,182,212,0.1)" : "none", border: "none", color: T.text, fontFamily: T.body, fontSize: 13, padding: "8px 10px", borderRadius: 8, cursor: "pointer" }}>
              <span style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{o.name}</span>
              {o.id === current.id && <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={T.accent} strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round"><path d="M20 6L9 17l-5-5" /></svg>}
              <span style={{ fontSize: 10.5, color: T.faint }}>{o.role}</span>
            </button>
          ))}
          <Link to="/team" onClick={() => setOpen(false)} style={{ display: "block", fontSize: 12.5, color: T.accentHi, padding: "8px 10px", borderTop: `1px solid ${T.border}`, marginTop: 4 }}>Manage team →</Link>
        </div>
      )}
    </div>
  );
}

export const ghostBtn = {
  background: "none",
  border: `1px solid ${T.borderStrong}`,
  color: T.text,
  fontSize: 13,
  fontWeight: 500,
  padding: "7px 14px",
  borderRadius: 10,
  cursor: "pointer",
  fontFamily: T.body,
};

export const primaryBtn = {
  background: T.accent,
  color: T.accentInk,
  border: "none",
  fontFamily: T.body,
  fontSize: 15,
  fontWeight: 600,
  padding: "13px 22px",
  borderRadius: 12,
  cursor: "pointer",
  transition: "box-shadow 0.2s",
};

export function Spinner({ size = 16 }) {
  return (
    <span style={{ display: "inline-block", width: size, height: size, border: `2px solid rgba(255,255,255,0.25)`, borderTopColor: "currentColor", borderRadius: "50%", animation: "spin 0.7s linear infinite" }} />
  );
}
