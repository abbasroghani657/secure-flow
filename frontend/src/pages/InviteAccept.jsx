import { useEffect, useState } from "react";
import { useParams, useNavigate, Link } from "react-router-dom";
import { primaryBtn, ghostBtn, Logo, Spinner } from "../components/ui";
import { useAuth } from "../auth";
import { useUX } from "../components/UX";
import { api } from "../api";
import { T } from "../theme";

export default function InviteAccept() {
  const { token } = useParams();
  const { user, loading } = useAuth();
  const { toast } = useUX();
  const nav = useNavigate();
  const [preview, setPreview] = useState(null);
  const [err, setErr] = useState("");
  const [accepting, setAccepting] = useState(false);

  useEffect(() => {
    if (loading) return;
    if (!user) {
      // Send them to log in, then back here.
      nav("/auth", { state: { next: `/invite/${token}` } });
      return;
    }
    api.previewInvite(token).then(setPreview).catch((e) => setErr(e.message));
  }, [user, loading, token, nav]);

  async function accept() {
    setAccepting(true);
    try {
      const org = await api.acceptInvite(token);
      toast(`You've joined ${org.name}`);
      nav("/dashboard");
    } catch (e) { toast(e.message, "error"); setAccepting(false); }
  }

  return (
    <div style={{ minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", padding: 24 }}>
      <div style={{ width: "100%", maxWidth: 440, background: T.panel, border: `1px solid ${T.border}`, borderRadius: 20, padding: 36, textAlign: "center" }}>
        <div style={{ display: "flex", justifyContent: "center", marginBottom: 22 }}><Logo /></div>
        {err ? (
          <>
            <h1 style={{ fontFamily: T.heading, fontSize: 22, fontWeight: 700, margin: "0 0 8px" }}>Invitation problem</h1>
            <p style={{ color: T.muted, fontSize: 14.5, margin: "0 0 22px" }}>{err}</p>
            <Link to="/dashboard" style={{ ...ghostBtn, textDecoration: "none", display: "inline-block" }}>Go to dashboard</Link>
          </>
        ) : !preview ? (
          <Spinner />
        ) : preview.valid ? (
          <>
            <h1 style={{ fontFamily: T.heading, fontSize: 23, fontWeight: 700, margin: "0 0 10px" }}>Join {preview.org_name}</h1>
            <p style={{ color: T.muted, fontSize: 14.5, lineHeight: 1.6, margin: "0 0 26px" }}>
              You've been invited to join <b style={{ color: T.text }}>{preview.org_name}</b> as a <b style={{ color: T.accentHi, textTransform: "capitalize" }}>{preview.role}</b>. You'll share the workspace's targets, scans and risk register.
            </p>
            <button onClick={accept} disabled={accepting} className="btn-primary" style={{ ...primaryBtn, width: "100%", opacity: accepting ? 0.6 : 1 }}>
              {accepting ? "Joining…" : `Accept and join`}
            </button>
            <Link to="/dashboard" style={{ display: "inline-block", marginTop: 14, fontSize: 13.5, color: T.muted }}>Not now</Link>
          </>
        ) : (
          <>
            <h1 style={{ fontFamily: T.heading, fontSize: 22, fontWeight: 700, margin: "0 0 8px" }}>Can't accept this invite</h1>
            <p style={{ color: T.muted, fontSize: 14.5, margin: "0 0 22px" }}>{preview.reason}</p>
            <Link to="/dashboard" style={{ ...ghostBtn, textDecoration: "none", display: "inline-block" }}>Go to dashboard</Link>
          </>
        )}
      </div>
    </div>
  );
}
