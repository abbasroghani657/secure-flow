import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { AppNav, primaryBtn, ghostBtn, Spinner } from "../components/ui";
import { useUX } from "../components/UX";
import { useAuth } from "../auth";
import { api } from "../api";
import { T } from "../theme";

const card = { background: T.panel, border: `1px solid ${T.border}`, borderRadius: 16, padding: 24, marginBottom: 22 };
const input = { background: T.bg, border: `1px solid ${T.borderStrong}`, color: T.text, borderRadius: 10, padding: "10px 12px", fontSize: 14, fontFamily: T.body, boxSizing: "border-box" };
const h2 = { fontFamily: T.heading, fontSize: 19, fontWeight: 700, margin: "0 0 4px" };

const ROLE_COLORS = { owner: "#F87171", admin: "#22D3EE", member: "#34d399", viewer: "#A3B1C2" };
const ROLE_RANK = { viewer: 0, member: 1, admin: 2, owner: 3 };
const ASSIGNABLE = ["viewer", "member", "admin", "owner"];

export default function Team() {
  const { user } = useAuth();
  const { toast, confirm } = useUX();
  const [org, setOrg] = useState(null);
  const [plan, setPlan] = useState(null);
  const [err, setErr] = useState("");

  const [email, setEmail] = useState("");
  const [role, setRole] = useState("member");
  const [inviting, setInviting] = useState(false);
  const [freshLink, setFreshLink] = useState("");

  const [newOrgName, setNewOrgName] = useState("");

  async function load() {
    try {
      const [o, p] = await Promise.all([api.getCurrentOrg(), api.getPlan()]);
      setOrg(o); setPlan(p);
    } catch (e) { setErr(e.message); }
  }
  useEffect(() => { load(); }, []);

  if (err) return <Shell><p style={{ color: "#F87171" }}>{err}</p></Shell>;
  if (!org) return <Shell><Spinner /></Shell>;

  const canManage = ROLE_RANK[org.my_role] >= ROLE_RANK.admin;
  const canTeams = plan?.limits?.teams;

  async function invite(e) {
    e.preventDefault();
    setInviting(true); setFreshLink("");
    try {
      const inv = await api.inviteMember(email.trim().toLowerCase(), role);
      setFreshLink(inv.accept_url);
      setEmail("");
      toast(`Invitation created for ${inv.email}`);
      load();
    } catch (e2) { toast(e2.message, "error"); } finally { setInviting(false); }
  }

  async function setMemberRole(m, newRole) {
    try { await api.changeRole(m.user_id, newRole); toast(`${m.name} is now ${newRole}`); load(); }
    catch (e) { toast(e.message, "error"); }
  }

  async function remove(m) {
    const self = m.user_id === user.id;
    const ok = await confirm({
      title: self ? "Leave this team?" : `Remove ${m.name}?`,
      message: self ? "You'll lose access to this workspace's targets and scans."
                    : `${m.name} will lose access to this workspace.`,
      confirmLabel: self ? "Leave" : "Remove", danger: true,
    });
    if (!ok) return;
    try { await api.removeMember(m.user_id); toast(self ? "You left the team" : `${m.name} removed`); if (self) location.href = "/dashboard"; else load(); }
    catch (e) { toast(e.message, "error"); }
  }

  async function revokeInvite(id) {
    try { await api.revokeInvite(id); toast("Invitation revoked"); load(); }
    catch (e) { toast(e.message, "error"); }
  }

  async function createTeam(e) {
    e.preventDefault();
    try { await api.createOrg(newOrgName.trim()); toast("Team workspace created"); location.reload(); }
    catch (e2) { toast(e2.message, "error"); }
  }

  return (
    <Shell>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-end", flexWrap: "wrap", gap: 12, marginBottom: 24 }}>
        <div>
          <h1 style={{ fontFamily: T.heading, fontSize: 30, fontWeight: 700, margin: "0 0 4px" }}>{org.name}</h1>
          <p style={{ color: T.muted, fontSize: 14, margin: 0 }}>
            {org.personal ? "Your personal workspace." : `Team workspace · ${org.members.length} member${org.members.length !== 1 ? "s" : ""}`}
            <span style={{ marginLeft: 10, color: ROLE_COLORS[org.my_role], fontWeight: 600, textTransform: "capitalize" }}>{org.my_role}</span>
          </p>
        </div>
      </div>

      {/* Members */}
      <div style={card}>
        <h2 style={h2}>Members</h2>
        <p style={{ color: T.muted, fontSize: 13.5, margin: "0 0 18px" }}>People who share this workspace's targets, scans and risk register.</p>
        <div style={{ display: "grid", gap: 8 }}>
          {org.members.map((m) => (
            <div key={m.user_id} style={{ display: "flex", alignItems: "center", gap: 12, padding: "11px 14px", border: `1px solid ${T.border}`, borderRadius: 12 }}>
              <span style={{ width: 34, height: 34, borderRadius: "50%", flex: "none", background: T.accent, color: T.accentInk, display: "flex", alignItems: "center", justifyContent: "center", fontFamily: T.heading, fontWeight: 700, fontSize: 13 }}>
                {(m.name || "?").split(" ").map((w) => w[0]).slice(0, 2).join("").toUpperCase()}
              </span>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontSize: 14, fontWeight: 600 }}>{m.name} {m.user_id === user.id && <span style={{ color: T.faint, fontWeight: 400 }}>(you)</span>}</div>
                <div style={{ fontSize: 12.5, color: T.faint }}>{m.email}</div>
              </div>
              {canManage && m.user_id !== user.id ? (
                <select value={m.role} onChange={(e) => setMemberRole(m, e.target.value)} style={{ ...input, padding: "6px 8px", fontSize: 12.5 }}
                        disabled={org.my_role !== "owner" && (m.role === "owner")}>
                  {ASSIGNABLE.filter((r) => r !== "owner" || org.my_role === "owner").map((r) => <option key={r} value={r}>{r}</option>)}
                </select>
              ) : (
                <span style={{ fontSize: 12, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.04em", color: ROLE_COLORS[m.role], border: `1px solid ${ROLE_COLORS[m.role]}55`, borderRadius: 999, padding: "3px 10px" }}>{m.role}</span>
              )}
              {(canManage || m.user_id === user.id) && !(m.role === "owner" && m.user_id === user.id) && (
                <button onClick={() => remove(m)} style={{ ...ghostBtn, borderColor: "rgba(248,113,113,0.4)", color: "#F87171", padding: "6px 10px", fontSize: 12 }}>
                  {m.user_id === user.id ? "Leave" : "Remove"}
                </button>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Invite / pending — admins only */}
      {canManage && (
        <div style={card}>
          <h2 style={h2}>Invite teammates</h2>
          {!canTeams ? (
            <div style={{ marginTop: 10, padding: 16, borderRadius: 12, border: "1px solid rgba(6,182,212,0.3)", background: "rgba(6,182,212,0.06)" }}>
              <p style={{ margin: "0 0 12px", color: T.muted, fontSize: 13.5 }}>Teams, roles and SSO are a <b style={{ color: T.accentHi }}>Business</b> feature. Upgrade to invite people into a shared workspace.</p>
              <Link to="/pricing" style={{ ...primaryBtn, textDecoration: "none", display: "inline-block" }}>View plans</Link>
            </div>
          ) : (
            <>
              <form onSubmit={invite} style={{ display: "flex", gap: 10, flexWrap: "wrap", marginTop: 8 }}>
                <input style={{ ...input, flex: 1, minWidth: 200 }} type="email" required placeholder="teammate@company.com" value={email} onChange={(e) => setEmail(e.target.value)} />
                <select style={input} value={role} onChange={(e) => setRole(e.target.value)}>
                  <option value="viewer">Viewer (read-only)</option>
                  <option value="member">Member (can scan)</option>
                  <option value="admin">Admin (manage team)</option>
                </select>
                <button style={{ ...primaryBtn, opacity: inviting ? 0.6 : 1 }} disabled={inviting}>{inviting ? "Inviting…" : "Send invite"}</button>
              </form>
              {freshLink && (
                <div style={{ marginTop: 14, padding: 12, background: T.bg, border: `1px solid ${T.accent}`, borderRadius: 10 }}>
                  <div style={{ fontSize: 12.5, color: T.accentHi, marginBottom: 6 }}>Share this invite link:</div>
                  <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
                    <code style={{ fontFamily: T.mono, fontSize: 12, wordBreak: "break-all", flex: 1 }}>{freshLink}</code>
                    <button style={ghostBtn} onClick={() => { navigator.clipboard?.writeText(freshLink); toast("Link copied"); }}>Copy</button>
                  </div>
                </div>
              )}
              {org.invitations.length > 0 && (
                <div style={{ marginTop: 18 }}>
                  <div style={{ fontSize: 12.5, color: T.muted, marginBottom: 8 }}>Pending invitations</div>
                  {org.invitations.map((i) => (
                    <div key={i.id} style={{ display: "flex", alignItems: "center", gap: 10, padding: "9px 12px", border: `1px solid ${T.border}`, borderRadius: 10, marginBottom: 6 }}>
                      <span style={{ flex: 1, fontSize: 13.5 }}>{i.email} <span style={{ color: T.faint }}>· {i.role}</span></span>
                      <button onClick={() => revokeInvite(i.id)} style={{ ...ghostBtn, padding: "5px 10px", fontSize: 12 }}>Revoke</button>
                    </div>
                  ))}
                </div>
              )}
            </>
          )}
        </div>
      )}

      {/* Create a team from a personal workspace */}
      {org.personal && (
        <div style={card}>
          <h2 style={h2}>Start a team</h2>
          <p style={{ color: T.muted, fontSize: 13.5, margin: "0 0 14px" }}>Create a shared workspace and invite your teammates. {!canTeams && "Business plan required."}</p>
          <form onSubmit={createTeam} style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
            <input style={{ ...input, flex: 1, minWidth: 200 }} placeholder="Acme Security Team" value={newOrgName} onChange={(e) => setNewOrgName(e.target.value)} required />
            <button style={primaryBtn} disabled={!canTeams}>Create workspace</button>
          </form>
        </div>
      )}
    </Shell>
  );
}

function Shell({ children }) {
  return (<div><AppNav /><main style={{ maxWidth: 760, margin: "0 auto", padding: "40px 24px 90px" }}>{children}</main></div>);
}
