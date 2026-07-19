import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Globe, Search, Shield, Lock, FileSearch, Info, ChevronDown, ChevronUp } from 'lucide-react';
import { scansAPI } from '../lib/api';
import DecryptedText from '../components/DecryptedText';

export default function NewScan() {
  const [targetUrl, setTargetUrl] = useState('');
  const [modules, setModules] = useState({
    headers: true,
    tls: true,
    directories: true,
  });
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [options, setOptions] = useState({
    timeout: 30,
    user_agent: 'Vertex-Scan/1.0',
  });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    if (!targetUrl.trim()) {
      setError('Please enter a target URL');
      return;
    }

    // Validate URL
    try {
      const urlToCheck = targetUrl.startsWith('http') ? targetUrl : `https://${targetUrl}`;
      new URL(urlToCheck);
    } catch {
      setError('Please enter a valid URL');
      return;
    }

    // Check at least one module selected
    if (!modules.headers && !modules.tls && !modules.directories) {
      setError('Please select at least one scanning module');
      return;
    }

    setLoading(true);
    try {
      const res = await scansAPI.create({
        target_url: targetUrl,
        modules,
        options,
      });
      navigate(`/scans/${res.data.scan.id}`);
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to create scan. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const toggleModule = (module) => {
    setModules(prev => ({ ...prev, [module]: !prev[module] }));
  };

  return (
    <div className="max-w-2xl mx-auto">
      <div className="mb-8">
          <h1 className="text-2xl font-bold text-sky-600 dark:text-sky-400">
            <DecryptedText
              text="New Security Scan"
              speed={50}
              maxIterations={10}
              animateOn="view"
              className="text-sky-600 dark:text-sky-400"
              encryptedClassName="text-slate-500 dark:text-slate-400"
            />
          </h1>
        <p className="text-gray-500 dark:text-gray-400 mt-1">Configure and launch a security scan against your target website.</p>
      </div>

      <form onSubmit={handleSubmit} className="space-y-6">
        {error && (
          <div className="bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800 text-red-700 dark:text-red-300 px-4 py-3 rounded-lg text-sm">{error}</div>
        )}

        {/* Target URL */}
        <div className="card">
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Target URL</label>
          <div className="relative">
            <Globe className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400 dark:text-gray-500" size={18} />
            <input
              type="text"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              className="input-field pl-10"
              placeholder="example.com or https://example.com"
            />
          </div>
          <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">Enter the domain or full URL of the website to scan.</p>
        </div>

        {/* Module Selection */}
        <div className="card">
          <h2 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-3">Scanning Modules</h2>
          <p className="text-xs text-gray-500 dark:text-gray-400 mb-4">Select the security checks to perform on the target.</p>
          <div className="space-y-3">
            <ModuleToggle
              icon={Shield}
              label="Security Headers"
              description="Check HTTP security headers (HSTS, CSP, X-Frame-Options, etc.)"
              checked={modules.headers}
              onChange={() => toggleModule('headers')}
              accent="indigo"
            />
            <ModuleToggle
              icon={Lock}
              label="TLS/SSL"
              description="Analyze certificate, protocol versions, and key strength"
              checked={modules.tls}
              onChange={() => toggleModule('tls')}
              accent="emerald"
            />
            <ModuleToggle
              icon={FileSearch}
              label="Directory Enumeration"
              description="Discover exposed paths, admin panels, and sensitive files"
              checked={modules.directories}
              onChange={() => toggleModule('directories')}
              accent="amber"
            />
          </div>
        </div>

        {/* Advanced Options */}
        <div className="card">
          <button
            type="button"
            onClick={() => setShowAdvanced(!showAdvanced)}
            className="flex items-center justify-between w-full text-sm font-medium text-gray-700 dark:text-gray-200"
          >
            <span className="flex items-center gap-2">
              <Info size={16} />
              Advanced Options
            </span>
            {showAdvanced ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
          </button>

          {showAdvanced && (
            <div className="mt-4 space-y-4 pt-4 border-t border-gray-200 dark:border-gray-800">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Timeout (seconds)</label>
                <input
                  type="number"
                  value={options.timeout}
                  onChange={(e) => setOptions({ ...options, timeout: parseInt(e.target.value) })}
                  className="input-field"
                  min="5"
                  max="120"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">User-Agent</label>
                <input
                  type="text"
                  value={options.user_agent}
                  onChange={(e) => setOptions({ ...options, user_agent: e.target.value })}
                  className="input-field"
                />
              </div>
            </div>
          )}
        </div>

        {/* Submit */}
        <button
          type="submit"
          disabled={loading}
          className="btn-primary w-full py-3 inline-flex items-center justify-center gap-2"
        >
          {loading ? (
            <>
              <svg className="animate-spin h-5 w-5" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
              </svg>
              Starting Scan...
            </>
          ) : (
            <>
              <Search size={18} />
              Start Security Scan
            </>
          )}
        </button>
      </form>
    </div>
  );
}

function ModuleToggle({ icon: Icon, label, description, checked, onChange, accent = 'primary' }) {
  const accentMap = {
    primary: { on: 'bg-primary-100 text-primary-600 dark:bg-primary-900/40 dark:text-primary-300', ring: 'bg-primary-600', checkedDot: 'translate-x-5' },
    indigo: { on: 'bg-indigo-100 text-indigo-600 dark:bg-indigo-500/15 dark:text-indigo-300', ring: 'bg-indigo-600', checkedDot: 'translate-x-5' },
    emerald: { on: 'bg-emerald-100 text-emerald-600 dark:bg-emerald-500/15 dark:text-emerald-300', ring: 'bg-emerald-600', checkedDot: 'translate-x-5' },
    amber: { on: 'bg-amber-100 text-amber-600 dark:bg-amber-500/15 dark:text-amber-300', ring: 'bg-amber-600', checkedDot: 'translate-x-5' },
  };
  const a = accentMap[accent] || accentMap.primary;
  return (
    <label className="flex items-start gap-3 p-3 rounded-lg border border-gray-200 dark:border-gray-700 cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors">
      <div className={`w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0 ${
        checked ? a.on : 'bg-gray-100 text-gray-400 dark:bg-gray-800 dark:text-gray-500'
      }`}>
        <Icon size={20} />
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex items-center justify-between">
          <span className="text-sm font-medium text-gray-900 dark:text-white">{label}</span>
          <div className={`w-10 h-6 rounded-full transition-colors relative ${
            checked ? a.ring : 'bg-gray-300 dark:bg-gray-600'
          }`}>
            <div className={`w-4 h-4 rounded-full bg-white absolute top-1 transition-transform ${
              checked ? a.checkedDot : 'translate-x-1'
            }`} />
            <input type="checkbox" checked={checked} onChange={onChange} className="sr-only" />
          </div>
        </div>
        <p className="text-xs text-gray-500 dark:text-gray-400 mt-0.5">{description}</p>
      </div>
    </label>
  );
}