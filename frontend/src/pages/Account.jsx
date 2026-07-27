import { useEffect, useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { AppNav, primaryBtn, ghostBtn, Spinner } from "../components/ui";
import { useAuth } from "../auth";
import { useUX } from "../components/UX";
import { api } from "../api";
import { T } from "../theme";

const card = { background: T.panel, border: `1px solid ${T.border}`, borderRadius: 16, padding: 26, marginBottom: 22 };
const input = { width: "100%", background: T.bg, border: `1px solid ${T.borderStrong}`, color: T.text, borderRadius: 10, padding: "10px 12px", fontSize: 14, fontFamily: T.body, boxSizing: "border-box" };
const label = { fontSize: 12.5, color: T.muted, marginBottom: 6, display: "block" };
const h2 = { fontFamily: T.heading, fontSize: 19, fontWeight: 700, margin: "0 0 4px" };
const sub = { color: T.muted, fontSize: 13.5, margin: "0 0 20px" };

const PLAN_LABEL = { free: "Free", pro: "Pro", business: "Business" };

export default function Account() {
  const { user, updateUser, logout } = useAuth();
  const { toast, confirm } = useUX();
  const nav = useNavigate();

  const [plan, setPlan] = useState(null);
  const [name, setName] = useState(user?.name || "");
  const [savingName, setSavingName] = useState(false);

  const [cur, setCur] = useState("");
  const [nw, setNw] = useState("");
  const [nw2, setNw2] = useState("");
  const [savingPw, setSavingPw] = useState(false);

  const [delPw, setDelPw] = useState("");
  const [deleting, setDeleting] = useState(false);

  useEffect(() => { api.getPlan().then(setPlan).catch(() => {}); }, []);
  useEffect(() => { setName(user?.name || ""); }, [user]);

  const initials = (user?.name || "?").split(" ").map((w) => w[0]).slice(0, 2).join("").toUpperCase();
  const nameChanged = name.trim() && name.trim() !== user?.name;

  async function saveName(e) {
    e.preventDefault();
    if (!nameChanged) return;
    setSavingName(true);
    try {
      const u = await api.updateProfile(name.trim());
      updateUser({ name: u.name });
      toast("Profile updated");
    } catch (e2) { toast(e2.message, "error"); } finally { setSavingName(false); }
  }

  async function savePassword(e) {
    e.preventDefault();
    if (nw !== nw2) { toast("New passwords do not match", "error"); return; }
    if (nw.length < 8) { toast("New password must be at least 8 characters", "error"); return; }
    setSavingPw(true);
    try {
      await api.changePassword(cur, nw);
      setCur(""); setNw(""); setNw2("");
      toast("Password changed");
    } catch (e2) { toast(e2.message, "error"); } finally { setSavingPw(false); }
  }

  async function deleteAccount() {
    if (!delPw) { toast("Enter your password to confirm", "error"); return; }
    const ok = await confirm({
      title: "Delete your account?",
      message: "This permanently deletes your account and every target, scan, schedule, integration and API token you own. This cannot be undone.",
      confirmLabel: "Delete everything", danger: true,
    });
    if (!ok) return;
    setDeleting(true);
    try {
      await api.deleteAccount(delPw);
      logout();
      toast("Your account has been deleted");
      nav("/");
    } catch (e2) { toast(e2.message, "error"); setDeleting(false); }
  }

  const planKey = plan?.plan || user?.plan || "free";

  return (
    <>
      <AppNav />
      <div style={{ maxWidth: 720, margin: "0 auto", padding: "40px 24px 90px" }}>
        <h1 style={{ fontFamily: T.heading, fontSize: 30, fontWeight: 700, margin: "0 0 26px" }}>Account</h1>

        {/* Identity header */}
        <div style={{ ...card, display: "flex", alignItems: "center", gap: 18 }}>
          <span style={{ width: 56, height: 56, borderRadius: "50%", flex: "none", background: T.accent, color: T.accentInk, display: "flex", alignItems: "center", justifyContent: "center", fontFamily: T.heading, fontWeight: 800, fontSize: 20 }}>{initials}</span>
          <div style={{ minWidth: 0, flex: 1 }}>
            <div style={{ fontFamily: T.heading, fontSize: 20, fontWeight: 700 }}>{user?.name}</div>
            <div style={{ fontSize: 13.5, color: T.muted, wordBreak: "break-all" }}>{user?.email}</div>
          </div>
          <span style={{ fontSize: 12, fontWeight: 700, letterSpacing: "0.04em", textTransform: "uppercase", color: planKey === "free" ? T.muted : T.accentInk, background: planKey === "free" ? "transparent" : T.accent, border: planKey === "free" ? `1px solid ${T.borderStrong}` : "none", borderRadius: 999, padding: "5px 12px", whiteSpace: "nowrap" }}>{PLAN_LABEL[planKey] || planKey} plan</span>
        </div>

        {/* Profile */}
        <form onSubmit={saveName} style={card}>
          <h2 style={h2}>Profile</h2>
          <p style={sub}>The name shown on your reports and in the app.</p>
          <label style={label}>Full name</label>
          <div style={{ display: "flex", gap: 10 }}>
            <input style={{ ...input, flex: 1 }} value={name} onChange={(e) => setName(e.target.value)} maxLength={80} />
            <button style={{ ...primaryBtn, opacity: nameChanged && !savingName ? 1 : 0.5, whiteSpace: "nowrap" }} disabled={!nameChanged || savingName}>
              {savingName ? "Saving..." : "Save"}
            </button>
          </div>
          <div style={{ marginTop: 14 }}>
            <label style={label}>Email</label>
            <input style={{ ...input, color: T.faint }} value={user?.email || ""} disabled />
            <div style={{ fontSize: 12, color: T.faint, marginTop: 6 }}>Email changes aren't self-serve yet. Contact support to change it.</div>
          </div>
        </form>

        {/* Password */}
        <form onSubmit={savePassword} style={card}>
          <h2 style={h2}>Password</h2>
          <p style={sub}>Use at least 8 characters. You'll stay signed in on this device.</p>
          <div style={{ display: "grid", gap: 12 }}>
            <div>
              <label style={label}>Current password</label>
              <input style={input} type="password" value={cur} onChange={(e) => setCur(e.target.value)} autoComplete="current-password" />
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
              <div>
                <label style={label}>New password</label>
                <input style={input} type="password" value={nw} onChange={(e) => setNw(e.target.value)} autoComplete="new-password" />
              </div>
              <div>
                <label style={label}>Confirm new password</label>
                <input style={input} type="password" value={nw2} onChange={(e) => setNw2(e.target.value)} autoComplete="new-password" />
              </div>
            </div>
            <div>
              <button style={{ ...primaryBtn, opacity: cur && nw && nw2 && !savingPw ? 1 : 0.5 }} disabled={!(cur && nw && nw2) || savingPw}>
                {savingPw ? "Updating..." : "Change password"}
              </button>
            </div>
          </div>
        </form>

        {/* Plan & usage */}
        <div style={card}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12, flexWrap: "wrap" }}>
            <div>
              <h2 style={h2}>Plan &amp; usage</h2>
              <p style={{ ...sub, marginBottom: 0 }}>
                You're on the <b style={{ color: T.text }}>{PLAN_LABEL[planKey] || planKey}</b> plan.
                {plan && ` ${plan.usage.scans_this_month} scan${plan.usage.scans_this_month !== 1 ? "s" : ""} this month, ${plan.usage.targets} target${plan.usage.targets !== 1 ? "s" : ""}.`}
              </p>
            </div>
            {planKey === "free"
              ? <Link to="/pricing" style={{ ...primaryBtn, textDecoration: "none", whiteSpace: "nowrap" }}>Upgrade</Link>
              : <Link to="/pricing" style={{ ...ghostBtn, textDecoration: "none", whiteSpace: "nowrap" }}>Manage plan</Link>}
          </div>
        </div>

        {/* Sign out */}
        <div style={{ ...card, display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12 }}>
          <div>
            <h2 style={{ ...h2, marginBottom: 2 }}>Sign out</h2>
            <p style={{ ...sub, margin: 0 }}>End your session on this device.</p>
          </div>
          <button style={ghostBtn} onClick={async () => { const ok = await confirm({ title: "Sign out?", message: "You'll need to log in again to access your dashboard.", confirmLabel: "Sign out" }); if (ok) { logout(); nav("/"); } }}>Log out</button>
        </div>

        {/* Danger zone */}
        <div style={{ ...card, border: "1px solid rgba(248,113,113,0.35)", background: "rgba(248,113,113,0.04)" }}>
          <h2 style={{ ...h2, color: "#F87171" }}>Delete account</h2>
          <p style={sub}>Permanently deletes your account and all your data. This cannot be undone.</p>
          <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
            <input style={{ ...input, flex: 1, minWidth: 200 }} type="password" placeholder="Enter your password to confirm" value={delPw} onChange={(e) => setDelPw(e.target.value)} autoComplete="current-password" />
            <button onClick={deleteAccount} disabled={deleting} style={{ background: "#F87171", border: "none", color: "#fff", fontFamily: T.body, fontSize: 14, fontWeight: 700, padding: "10px 18px", borderRadius: 10, cursor: "pointer", opacity: deleting ? 0.6 : 1, whiteSpace: "nowrap" }}>
              {deleting ? "Deleting..." : "Delete account"}
            </button>
          </div>
        </div>
      </div>
    </>
  );
}
