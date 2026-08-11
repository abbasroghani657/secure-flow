import { useState, useEffect } from 'react';
import { useSearchParams, Link, useNavigate } from 'react-router-dom';
import { api } from '../api';

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
      <div className="min-h-screen bg-black/95 flex flex-col items-center justify-center p-4">
        <div className="w-full max-w-md bg-zinc-900 border border-zinc-800 rounded-xl p-8 shadow-2xl text-center">
          <div className="w-16 h-16 bg-green-500/20 text-green-400 rounded-full flex items-center justify-center mx-auto mb-4">
            <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7"></path>
            </svg>
          </div>
          <h2 className="text-xl font-bold text-white mb-2">Password Reset Successful</h2>
          <p className="text-zinc-400 text-sm mb-6">
            Your password has been securely updated. All other active sessions have been signed out.
          </p>
          <button
            onClick={() => navigate('/auth')}
            className="w-full bg-indigo-500 hover:bg-indigo-600 text-white font-medium py-2 px-4 rounded-lg transition-colors"
          >
            Log in with new password
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-black/95 flex flex-col items-center justify-center p-4">
      <div className="w-full max-w-md">
        <div className="flex justify-center mb-6">
          <Link to="/" className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg bg-indigo-500/20 flex items-center justify-center">
              <div className="w-4 h-4 text-indigo-400">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5" />
                </svg>
              </div>
            </div>
            <span className="text-xl font-bold text-white tracking-tight">Pentrixa</span>
          </Link>
        </div>

        <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-8 shadow-2xl">
          <h2 className="text-2xl font-bold text-white mb-2">Create New Password</h2>
          <p className="text-zinc-400 text-sm mb-6">
            Please enter your new password below.
          </p>

          {errorMsg && (
            <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-3 mb-6">
              <p className="text-sm text-red-400 font-medium">{errorMsg}</p>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label htmlFor="password" className="block text-sm font-medium text-zinc-400 mb-1">
                New Password
              </label>
              <input
                id="password"
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full bg-zinc-950 border border-zinc-800 text-white rounded-lg px-4 py-2 focus:outline-none focus:ring-2 focus:ring-indigo-500/50 transition-shadow"
                placeholder="••••••••"
                minLength={8}
                disabled={!token}
              />
              <p className="text-xs text-zinc-500 mt-2">Must be at least 8 characters long.</p>
            </div>

            <button
              type="submit"
              disabled={status === 'loading' || !token}
              className="w-full bg-indigo-500 hover:bg-indigo-600 text-white font-medium py-2 px-4 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center mt-6"
            >
              {status === 'loading' ? (
                <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin"></div>
              ) : (
                'Securely Update Password'
              )}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}
