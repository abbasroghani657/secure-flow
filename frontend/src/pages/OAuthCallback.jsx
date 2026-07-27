import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Logo, Spinner } from "../components/ui";
import { useAuth } from "../auth";
import { T } from "../theme";

// Receives the token handed back by the backend OAuth callback in the URL
// fragment (#token=...), stores it, and drops the user into the dashboard.
export default function OAuthCallback() {
  const { loginWithToken } = useAuth();
  const nav = useNavigate();
  const [err, setErr] = useState("");

  useEffect(() => {
    const token = new URLSearchParams(window.location.hash.slice(1)).get("token");
    if (!token) { nav("/auth?error=oauth_failed", { replace: true }); return; }
    // clear the token from the address bar immediately
    window.history.replaceState(null, "", "/oauth");
    loginWithToken(token)
      .then(() => nav("/dashboard", { replace: true }))
      .catch(() => setErr("Could not complete sign-in. Please try again."));
  }, []);

  return (
    <div style={{ minHeight: "100vh", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: 18, background: T.bg }}>
      <Logo />
      {err ? (
        <p style={{ color: "#F87171", fontSize: 14 }}>{err}</p>
      ) : (
        <div style={{ display: "flex", alignItems: "center", gap: 10, color: T.muted, fontSize: 14 }}>
          <Spinner /> Signing you in…
        </div>
      )}
    </div>
  );
}
