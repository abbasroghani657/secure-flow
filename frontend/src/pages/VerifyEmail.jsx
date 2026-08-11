import { useEffect, useState } from 'react';
import { useSearchParams, Link, useNavigate } from 'react-router-dom';
import { api } from '../api';
import { primaryBtn } from '../components/ui';
import { T } from '../theme';

export default function VerifyEmail() {
  const [searchParams] = useSearchParams();
  const [status, setStatus] = useState('verifying'); // verifying, success, error
  const [errorMsg, setErrorMsg] = useState('');
  const navigate = useNavigate();

  useEffect(() => {
    const token = searchParams.get('token');
    
    if (!token) {
      setStatus('error');
      setErrorMsg('No verification token provided.');
      return;
    }

    // Advanced Defense: Strip token from URL to prevent Referrer leakage
    window.history.replaceState({}, document.title, window.location.pathname);
    
    // Call API
    api.verifyEmail(token)
      .then(() => {
        setStatus('success');
      })
      .catch((err) => {
        setStatus('error');
        setErrorMsg(err.response?.data?.detail || 'Invalid or expired verification link.');
      });
  }, [searchParams]);

  return (
    <div style={{ minHeight: "100vh", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", padding: 20, background: "radial-gradient(circle at top, rgba(6, 182, 212, 0.05), transparent 60%)" }}>
      
      <div style={{ width: "100%", maxWidth: 440, background: "rgba(0,0,0,0.4)", border: `1px solid ${T.borderStrong}`, borderRadius: 16, padding: "40px 32px", boxShadow: "0 20px 40px rgba(0,0,0,0.4)", textAlign: "center", backdropFilter: "blur(10px)" }}>
        
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

        <h2 style={{ fontSize: 24, fontWeight: 700, color: "#fff", margin: "0 0 8px" }}>Email Verification</h2>
        
        {status === 'verifying' && (
          <div style={{ marginTop: 32, display: "flex", flexDirection: "column", alignItems: "center" }}>
            <div style={{ width: 40, height: 40, border: `3px solid ${T.border}`, borderTopColor: "#06b6d4", borderRadius: "50%", animation: "spin 0.8s linear infinite", marginBottom: 16 }} />
            <p style={{ color: T.muted, margin: 0 }}>Verifying your secure token...</p>
          </div>
        )}

        {status === 'success' && (
          <div style={{ marginTop: 32 }}>
            <div style={{ width: 64, height: 64, borderRadius: "50%", background: "rgba(34, 197, 94, 0.15)", color: "#22c55e", display: "flex", alignItems: "center", justifyContent: "center", margin: "0 auto 20px" }}>
              <svg width="32" height="32" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="2.5">
                <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7"></path>
              </svg>
            </div>
            <p style={{ color: "#22c55e", fontWeight: 600, fontSize: 16, marginBottom: 32 }}>Your email has been successfully verified!</p>
            <button onClick={() => navigate('/dashboard')} style={{ ...primaryBtn, width: "100%", padding: "14px", fontSize: 15 }}>
              Continue to Dashboard
            </button>
          </div>
        )}

        {status === 'error' && (
          <div style={{ marginTop: 32 }}>
            <div style={{ width: 64, height: 64, borderRadius: "50%", background: "rgba(239, 68, 68, 0.15)", color: "#ef4444", display: "flex", alignItems: "center", justifyContent: "center", margin: "0 auto 20px" }}>
              <svg width="32" height="32" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="2.5">
                <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12"></path>
              </svg>
            </div>
            <p style={{ color: "#ef4444", fontWeight: 600, fontSize: 16, margin: "0 0 8px" }}>Verification Failed</p>
            <p style={{ color: T.faint, fontSize: 14, margin: "0 0 32px" }}>{errorMsg}</p>
            <button onClick={() => navigate('/auth')} style={{ width: "100%", padding: "14px", background: "rgba(255,255,255,0.05)", color: "#fff", border: `1px solid ${T.borderStrong}`, borderRadius: 8, cursor: "pointer", fontWeight: 600, fontSize: 15 }}>
              Back to Login
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
