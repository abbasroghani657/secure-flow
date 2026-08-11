import { useEffect, useState } from 'react';
import { useSearchParams, Link, useNavigate } from 'react-router-dom';
import { api } from '../api';

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
    <div className="min-h-screen bg-black/95 flex flex-col items-center justify-center p-4">
      <div className="w-full max-w-md bg-zinc-900 border border-zinc-800 rounded-xl p-8 shadow-2xl">
        
        <div className="flex justify-center mb-6">
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg bg-indigo-500/20 flex items-center justify-center">
              <div className="w-4 h-4 text-indigo-400">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5" />
                </svg>
              </div>
            </div>
            <span className="text-xl font-bold text-white tracking-tight">Pentrixa</span>
          </div>
        </div>

        <h2 className="text-2xl font-bold text-white text-center mb-2">
          Email Verification
        </h2>
        
        {status === 'verifying' && (
          <div className="text-center text-zinc-400 mt-6">
            <div className="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-500 mb-4"></div>
            <p>Verifying your secure token...</p>
          </div>
        )}

        {status === 'success' && (
          <div className="text-center mt-6">
            <div className="w-16 h-16 bg-green-500/20 text-green-400 rounded-full flex items-center justify-center mx-auto mb-4">
              <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7"></path>
              </svg>
            </div>
            <p className="text-green-400 font-medium mb-6">Your email has been successfully verified!</p>
            <button
              onClick={() => navigate('/dashboard')}
              className="w-full bg-indigo-500 hover:bg-indigo-600 text-white font-medium py-2 px-4 rounded-lg transition-colors"
            >
              Continue to Dashboard
            </button>
          </div>
        )}

        {status === 'error' && (
          <div className="text-center mt-6">
            <div className="w-16 h-16 bg-red-500/20 text-red-400 rounded-full flex items-center justify-center mx-auto mb-4">
              <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12"></path>
              </svg>
            </div>
            <p className="text-red-400 font-medium mb-2">Verification Failed</p>
            <p className="text-zinc-400 text-sm mb-6">{errorMsg}</p>
            <button
              onClick={() => navigate('/auth')}
              className="w-full border border-zinc-700 hover:bg-zinc-800 text-white font-medium py-2 px-4 rounded-lg transition-colors"
            >
              Back to Login
            </button>
          </div>
        )}

      </div>
    </div>
  );
}
