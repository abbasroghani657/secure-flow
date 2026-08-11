import { useEffect, useState } from 'react';
import { useSearchParams, Link } from 'react-router-dom';
import { api } from '../api';

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
    
    // Call API (using GET as planned for 1-click email action)
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
    <div className="min-h-screen bg-black/95 flex flex-col items-center justify-center p-4">
      <div className="w-full max-w-md bg-zinc-900 border border-red-500/30 rounded-xl p-8 shadow-2xl text-center">
        
        {status === 'freezing' && (
          <div className="text-zinc-400">
            <div className="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-red-500 mb-4"></div>
            <p>Securing your account...</p>
          </div>
        )}

        {status === 'done' && (
          <>
            <div className="w-16 h-16 bg-red-500/20 text-red-500 rounded-full flex items-center justify-center mx-auto mb-4">
              <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path>
              </svg>
            </div>
            <h2 className="text-xl font-bold text-white mb-2">Account Lockdown</h2>
            <p className="text-zinc-300 font-medium mb-6">
              {msg}
            </p>
            <p className="text-zinc-500 text-sm mb-8">
              All active sessions have been terminated. You will not be able to log in until an administrator verifies your identity and unlocks the account.
            </p>
            <Link
              to="/"
              className="w-full block bg-zinc-800 hover:bg-zinc-700 text-white font-medium py-2 px-4 rounded-lg transition-colors"
            >
              Return to Homepage
            </Link>
          </>
        )}

      </div>
    </div>
  );
}
