import { useState, useEffect } from 'react';
import { useSearchParams, Link, useNavigate } from 'react-router-dom';
import { api } from '../api';
import { primaryBtn } from '../components/ui';
import { T } from '../theme';

const localInputStyle = { width: "100%", padding: "12px 16px", borderRadius: 8, border: "1px solid rgba(255,255,255,0.1)", background: "rgba(0,0,0,0.2)", color: "#fff", fontSize: 15, boxSizing: "border-box", outline: "none" };

export default function ResetPassword() {
  const [searchParams] = useSearchParams();
  const [status, setStatus] = useState('idle'); // idle, loading, success
  const [errorMsg, setErrorMsg] = useState('');
  const [password, setPassword] = useState('');
  const [token, setToken] = useState('');
  const navigate = useNavigate();

  useEffect(() => {
    const t = searchParams.get('token');
    if (!t) {
      setErrorMsg('No reset token provided. Please request a new password reset link.');
      return;
    }
    setToken(t);
    // Advanced Defense: Strip token from URL to prevent Referrer leakage
    window.history.replaceState({}, document.title, window.location.pathname);
  }, [searchParams]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!password || !token) return;

    if (password.length < 8) {
      setErrorMsg('Password must be at least 8 characters long.');
      return;
    }

    setStatus('loading');
    setErrorMsg('');

    try {
      await api.resetPassword(token, password);
      setStatus('success');
    } catch (err) {
      setStatus('idle');
      setErrorMsg(err.response?.data?.detail || 'Invalid or expired reset token. Please request a new link.');
    }
  };

  if (status === 'success') {
    return (
      <div style={{ minHeight: "100vh", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", padding: 20, background: "radial-gradient(circle at top, rgba(6, 182, 212, 0.05), transparent 60%)" }}>
        <div style={{ width: "100%", maxWidth: 440, background: "rgba(0,0,0,0.4)", border: `1px solid ${T.borderStrong}`, borderRadius: 16, padding: "40px 32px", boxShadow: "0 20px 40px rgba(0,0,0,0.4)", textAlign: "center", backdropFilter: "blur(10px)" }}>
          <div style={{ width: 64, height: 64, borderRadius: "50%", background: "rgba(34, 197, 94, 0.15)", color: "#22c55e", display: "flex", alignItems: "center", justifyContent: "center", margin: "0 auto 20px" }}>
            <svg width="32" height="32" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="2.5">
              <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7"></path>
            </svg>
          </div>
          <h2 style={{ fontSize: 22, fontWeight: 700, color: "#fff", margin: "0 0 8px" }}>Password Reset Successful</h2>
          <p style={{ color: T.faint, fontSize: 14, margin: "0 0 24px", lineHeight: 1.5 }}>
            Your password has been securely updated. All other active sessions have been signed out.
          </p>
          <button onClick={() => navigate('/auth')} style={{ ...primaryBtn, width: "100%", padding: "14px", fontSize: 15 }}>
            Log in with new password
          </button>
        </div>
      </div>
    );
  }

  return (
    <div style={{ minHeight: "100vh", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", padding: 20, background: "radial-gradient(circle at top, rgba(6, 182, 212, 0.05), transparent 60%)" }}>
      <div style={{ width: "100%", maxWidth: 440 }}>
        
        <div style={{ display: "flex", justifyContent: "center", marginBottom: 32 }}>
          <Link to="/" style={{ display: "flex", alignItems: "center", gap: 10, textDecoration: "none" }}>
            <div style={{ width: 40, height: 40, borderRadius: 10, background: "rgba(6, 182, 212, 0.1)", display: "flex", alignItems: "center", justifyContent: "center", border: "1px solid rgba(6, 182, 212, 0.2)" }}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#06b6d4" strokeWidth="2.5">
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                <path strokeLinecap="round" strokeLinejoin="round" d="m9 12 2 2 4-4" />
              </svg>
            </div>
            <span style={{ fontSize: 24, fontWeight: 800, color: "#fff", letterSpacing: "-0.5px" }}>Pentrixa</span>
          </Link>
        </div>

        <div style={{ background: "rgba(0,0,0,0.4)", border: `1px solid ${T.borderStrong}`, borderRadius: 16, padding: "40px 32px", boxShadow: "0 20px 40px rgba(0,0,0,0.4)", backdropFilter: "blur(10px)" }}>
          <h2 style={{ fontSize: 24, fontWeight: 700, color: "#fff", margin: "0 0 8px" }}>Create New Password</h2>
          <p style={{ color: T.faint, fontSize: 14, margin: "0 0 24px", lineHeight: 1.5 }}>
            Please enter your new password below.
          </p>

          {errorMsg && (
            <div style={{ background: "rgba(239, 68, 68, 0.1)", border: "1px solid rgba(239, 68, 68, 0.2)", borderRadius: 8, padding: 12, marginBottom: 24 }}>
              <p style={{ color: "#ef4444", fontSize: 14, fontWeight: 500, margin: 0 }}>{errorMsg}</p>
            </div>
          )}

          <form onSubmit={handleSubmit} style={{ display: "flex", flexDirection: "column", gap: 16 }}>
            <div>
              <label htmlFor="password" style={{ display: "block", fontSize: 14, fontWeight: 500, color: T.muted, marginBottom: 6 }}>
                New Password
              </label>
              <input
                id="password"
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                style={localInputStyle}
                placeholder="••••••••"
                minLength={8}
                disabled={!token}
              />
              <p style={{ color: "rgba(255,255,255,0.3)", fontSize: 12, marginTop: 8 }}>Must be at least 8 characters long.</p>
            </div>

            <button
              type="submit"
              disabled={status === 'loading' || !token}
              style={{ ...primaryBtn, width: "100%", padding: "14px", marginTop: 8, opacity: (status === 'loading' || !token) ? 0.7 : 1 }}
            >
              {status === 'loading' ? 'Updating...' : 'Securely Update Password'}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}
