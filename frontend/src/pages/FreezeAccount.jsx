import { useEffect, useState } from 'react';
import { useSearchParams, Link } from 'react-router-dom';
import { api } from '../api';
import { primaryBtn } from '../components/ui';
import { T } from '../theme';

export default function FreezeAccount() {
  const [searchParams] = useSearchParams();
  const [status, setStatus] = useState('freezing'); // freezing, done
  const [msg, setMsg] = useState('');

  useEffect(() => {
    const token = searchParams.get('token');
    
    if (!token) {
      setStatus('done');
      setMsg('No token provided.');
      return;
    }

    // Strip token from URL
    window.history.replaceState({}, document.title, window.location.pathname);
    
    // Call API
    api.freezeAccount(token)
      .then((res) => {
        setStatus('done');
        setMsg(res.data.msg || 'Account frozen.');
      })
      .catch((err) => {
        setStatus('done');
        // Mask errors
        setMsg('If the token was valid, the account has been frozen.');
      });
  }, [searchParams]);

  return (
    <div style={{ minHeight: "100vh", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", padding: 20, background: "radial-gradient(circle at top, rgba(239, 68, 68, 0.05), transparent 60%)" }}>
      <div style={{ width: "100%", maxWidth: 440, background: "rgba(0,0,0,0.4)", border: `1px solid rgba(239, 68, 68, 0.3)`, borderRadius: 16, padding: "40px 32px", boxShadow: "0 20px 40px rgba(0,0,0,0.4)", textAlign: "center", backdropFilter: "blur(10px)" }}>
        
        {status === 'freezing' && (
          <div style={{ display: "flex", flexDirection: "column", alignItems: "center" }}>
            <div style={{ width: 40, height: 40, border: `3px solid ${T.border}`, borderTopColor: "#ef4444", borderRadius: "50%", animation: "spin 0.8s linear infinite", marginBottom: 16 }} />
            <p style={{ color: T.muted, margin: 0 }}>Securing your account...</p>
          </div>
        )}

        {status === 'done' && (
          <>
            <div style={{ width: 64, height: 64, borderRadius: "50%", background: "rgba(239, 68, 68, 0.15)", color: "#ef4444", display: "flex", alignItems: "center", justifyContent: "center", margin: "0 auto 20px" }}>
              <svg width="32" height="32" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="2.5">
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path>
              </svg>
            </div>
            <h2 style={{ fontSize: 22, fontWeight: 700, color: "#fff", margin: "0 0 8px" }}>Account Lockdown</h2>
            <p style={{ color: "#ef4444", fontWeight: 600, fontSize: 16, margin: "0 0 16px" }}>
              {msg}
            </p>
            <p style={{ color: T.faint, fontSize: 14, margin: "0 0 32px", lineHeight: 1.5 }}>
              All active sessions have been terminated. You will not be able to log in until an administrator verifies your identity and unlocks the account.
            </p>
            <Link to="/" style={{ ...primaryBtn, width: "100%", padding: "14px", display: "block", textAlign: "center", background: "rgba(255,255,255,0.05)", color: "#fff", border: `1px solid ${T.borderStrong}` }}>
              Return to Homepage
            </Link>
          </>
        )}

      </div>
    </div>
  );
}
