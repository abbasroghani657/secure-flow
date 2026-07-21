import { Link, useNavigate } from "react-router-dom";
import { useAuth } from "../auth";
import { T } from "../theme";

export function Logo({ size = 20 }) {
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 9, fontFamily: T.heading, fontWeight: 700, fontSize: size, letterSpacing: "-0.02em", color: T.text }}>
      <svg width={size + 4} height={size + 4} viewBox="0 0 24 24" fill="none" stroke={T.accent} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
        <path d="M9 12l2 2 4-4" />
      </svg>
      Secure<span style={{ color: T.accent }}>Flow</span>
    </span>
  );
}

// App shell nav for authenticated pages.
export function AppNav() {
  const { user, logout } = useAuth();
  const nav = useNavigate();
  const initials = (user?.name || "?").split(" ").map((w) => w[0]).slice(0, 2).join("").toUpperCase();
  return (
    <nav style={{ position: "sticky", top: 0, zIndex: 50, display: "flex", alignItems: "center", justifyContent: "space-between", gap: 24, padding: "12px 32px", background: "rgba(13,15,13,0.85)", backdropFilter: "blur(14px)", borderBottom: `1px solid ${T.border}` }}>
      <div style={{ display: "flex", alignItems: "center", gap: 28 }}>
        <Link to="/dashboard"><Logo size={18} /></Link>
        <div style={{ display: "flex", gap: 20, fontSize: 13.5 }}>
          <Link to="/dashboard" style={{ color: T.muted }}>Dashboard</Link>
          <Link to="/targets" style={{ color: T.muted }}>Targets</Link>
          <Link to="/schedules" style={{ color: T.muted }}>Schedules</Link>
          <Link to="/scans/new" style={{ color: T.muted }}>New Scan</Link>
        </div>
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
        <span style={{ fontSize: 13, color: T.muted }}>{user?.email}</span>
        <button onClick={() => { logout(); nav("/"); }} style={ghostBtn}>Log out</button>
        <span title={user?.name} style={{ width: 30, height: 30, borderRadius: "50%", background: T.accent, display: "flex", alignItems: "center", justifyContent: "center", fontFamily: T.heading, fontWeight: 700, fontSize: 12, color: T.accentInk }}>{initials}</span>
      </div>
    </nav>
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
