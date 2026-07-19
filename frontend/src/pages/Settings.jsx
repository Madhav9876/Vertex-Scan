import React, { useState, useEffect } from 'react';
import { User, Key, Copy, CheckCircle, Eye, EyeOff } from 'lucide-react';
import { authAPI } from '../lib/api';
import DecryptedText from '../components/DecryptedText';

export default function Settings() {
  const [user, setUser] = useState(null);
  const [apiKey, setApiKey] = useState('');
  const [showApiKey, setShowApiKey] = useState(false);
  const [copied, setCopied] = useState(false);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);

  useEffect(() => {
    const fetchUser = async () => {
      try {
        const res = await authAPI.me();
        setUser(res.data.user);
      } catch (err) {
        console.error('Fetch user error:', err);
      } finally {
        setLoading(false);
      }
    };
    fetchUser();
  }, []);

  const handleGenerateApiKey = async () => {
    setGenerating(true);
    try {
      const res = await authAPI.generateApiKey();
      setApiKey(res.data.api_key);
      setShowApiKey(true);
    } catch (err) {
      alert('Failed to generate API key.');
    } finally {
      setGenerating(false);
    }
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(apiKey);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  if (loading) {
    return <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-teal-600" /></div>;
  }

  return (
    <div className="max-w-2xl mx-auto">
      <div className="mb-8">
          <h1 className="text-2xl font-bold text-teal-600 dark:text-teal-400">
            <DecryptedText
              text="Settings"
              speed={50}
              maxIterations={10}
              animateOn="view"
              className="text-teal-600 dark:text-teal-400"
              encryptedClassName="text-slate-500 dark:text-slate-400"
            />
          </h1>
        <p className="text-gray-600 dark:text-gray-300 mt-1">Manage your account and API access.</p>
      </div>

      {/* Profile */}
      <div className="card mb-6">
        <div className="flex items-center gap-3 mb-4">
          <div className="w-10 h-10 bg-teal-100 dark:bg-teal-500/15 rounded-lg flex items-center justify-center">
            <User className="text-teal-600 dark:text-teal-400" size={20} />
          </div>
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Profile</h2>
        </div>
        <div className="space-y-3">
          <div>
            <label className="text-sm text-gray-600 dark:text-gray-300">Email</label>
            <p className="text-gray-900 dark:text-white font-medium">{user?.email}</p>
          </div>
          <div>
            <label className="text-sm text-gray-600 dark:text-gray-300">Full Name</label>
            <p className="text-gray-900 dark:text-white font-medium">{user?.full_name || 'Not set'}</p>
          </div>
          <div>
            <label className="text-sm text-gray-600 dark:text-gray-300">Role</label>
            <p className="text-gray-900 dark:text-white font-medium capitalize">{user?.role}</p>
          </div>
          <div>
            <label className="text-sm text-gray-600 dark:text-gray-300">Member Since</label>
            <p className="text-gray-900 dark:text-white font-medium">{new Date(user?.created_at).toLocaleDateString()}</p>
          </div>
        </div>
      </div>

      {/* API Key */}
      <div className="card">
        <div className="flex items-center gap-3 mb-4">
          <div className="w-10 h-10 bg-violet-100 dark:bg-violet-500/15 rounded-lg flex items-center justify-center">
            <Key className="text-violet-600 dark:text-violet-400" size={20} />
          </div>
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white">API Key</h2>
        </div>
        <p className="text-sm text-gray-600 dark:text-gray-300 mb-4">
          Generate an API key for CLI and automation access. Keep this key secure.
        </p>

        {apiKey ? (
          <div className="space-y-3">
            <div className="bg-amber-50 dark:bg-amber-900/30 border border-amber-200 dark:border-amber-800 rounded-lg p-3 text-sm text-amber-800 dark:text-amber-200">
              Save this key securely. It will not be shown again.
            </div>
            <div className="flex items-center gap-2">
              <div className="relative flex-1">
                <input
                  type={showApiKey ? 'text' : 'password'}
                  value={apiKey}
                  readOnly
                  className="input-field font-mono text-sm pr-10"
                />
                <button
                  onClick={() => setShowApiKey(!showApiKey)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400"
                >
                  {showApiKey ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
              <button onClick={handleCopy} className="btn-secondary">
                {copied ? <CheckCircle size={16} className="text-green-600" /> : <Copy size={16} />}
              </button>
            </div>
          </div>
        ) : (
          <button
            onClick={handleGenerateApiKey}
            disabled={generating}
            className="btn-primary"
          >
            {generating ? 'Generating...' : 'Generate API Key'}
          </button>
        )}
      </div>
    </div>
  );
}