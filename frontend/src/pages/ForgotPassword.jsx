import { useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api';
import { primaryBtn } from '../components/ui';
import { T } from '../theme';

const localInputStyle = { width: "100%", padding: "12px 16px", borderRadius: 8, border: "1px solid rgba(255,255,255,0.1)", background: "rgba(0,0,0,0.2)", color: "#fff", fontSize: 15, boxSizing: "border-box", outline: "none" };

export default function ForgotPassword() {
  const [email, setEmail] = useState('');
  const [status, setStatus] = useState('idle'); // idle, loading, success
  const [errorMsg, setErrorMsg] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!email) return;

    setStatus('loading');
    setErrorMsg('');

    try {
      await api.forgotPassword(email);
      setStatus('success');
    } catch (err) {
      if (err.response?.status === 429) {
        setErrorMsg('Please wait a few minutes before trying again.');
        setStatus('idle');
      } else {
        setStatus('success'); 
      }
    }
  };

  if (status === 'success') {
    return (
      <div style={{ minHeight: "100vh", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", padding: 20, background: "radial-gradient(circle at top, rgba(6, 182, 212, 0.05), transparent 60%)" }}>
        <div style={{ width: "100%", maxWidth: 440, background: "rgba(0,0,0,0.4)", border: `1px solid ${T.borderStrong}`, borderRadius: 16, padding: "40px 32px", boxShadow: "0 20px 40px rgba(0,0,0,0.4)", textAlign: "center", backdropFilter: "blur(10px)" }}>
          <div style={{ width: 64, height: 64, borderRadius: "50%", background: "rgba(34, 197, 94, 0.15)", color: "#22c55e", display: "flex", alignItems: "center", justifyContent: "center", margin: "0 auto 20px" }}>
            <svg width="32" height="32" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="2.5">
              <path strokeLinecap="round" strokeLinejoin="round" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"></path>
            </svg>
          </div>
          <h2 style={{ fontSize: 22, fontWeight: 700, color: "#fff", margin: "0 0 8px" }}>Check your email</h2>
          <p style={{ color: T.faint, fontSize: 14, margin: "0 0 8px", lineHeight: 1.5 }}>
            If an account exists for <span style={{ color: "#fff", fontWeight: 600 }}>{email}</span>, we have sent a secure password reset link.
          </p>
          <p style={{ color: "rgba(255,255,255,0.3)", fontSize: 13, margin: "0 0 24px" }}>
            (The link will expire in 1 hour)
          </p>
          <Link to="/auth" style={{ ...primaryBtn, width: "100%", padding: "14px", display: "block", textAlign: "center", background: "rgba(255,255,255,0.05)", color: "#fff", border: `1px solid ${T.borderStrong}` }}>
            Return to Login
          </Link>
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
          <h2 style={{ fontSize: 24, fontWeight: 700, color: "#fff", margin: "0 0 8px" }}>Reset Password</h2>
          <p style={{ color: T.faint, fontSize: 14, margin: "0 0 24px", lineHeight: 1.5 }}>
            Enter your email address and we'll send you a secure link to reset your password.
          </p>

          {errorMsg && (
            <div style={{ background: "rgba(239, 68, 68, 0.1)", border: "1px solid rgba(239, 68, 68, 0.2)", borderRadius: 8, padding: 12, marginBottom: 24 }}>
              <p style={{ color: "#ef4444", fontSize: 14, fontWeight: 500, margin: 0 }}>{errorMsg}</p>
            </div>
          )}

          <form onSubmit={handleSubmit} style={{ display: "flex", flexDirection: "column", gap: 16 }}>
            <div>
              <label htmlFor="email" style={{ display: "block", fontSize: 14, fontWeight: 500, color: T.muted, marginBottom: 6 }}>
                Email Address
              </label>
              <input
                id="email"
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                style={localInputStyle}
                placeholder="you@company.com"
              />
            </div>

            <button
              type="submit"
              disabled={status === 'loading'}
              style={{ ...primaryBtn, width: "100%", padding: "14px", marginTop: 8, opacity: status === 'loading' ? 0.7 : 1 }}
            >
              {status === 'loading' ? 'Sending...' : 'Send Reset Link'}
            </button>
          </form>

          <div style={{ marginTop: 24, textAlign: "center", fontSize: 14 }}>
            <span style={{ color: T.faint }}>Remembered your password? </span>
            <Link to="/auth" style={{ color: "#06b6d4", fontWeight: 500, textDecoration: "none" }}>
              Log in
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}
