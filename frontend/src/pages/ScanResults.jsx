import React, { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import { Shield, AlertTriangle, CheckCircle, XCircle, Download, Copy, ChevronDown, ChevronUp, RefreshCw, ArrowLeft, FileText, Code } from 'lucide-react';
import { scansAPI, reportsAPI } from '../lib/api';
import DecryptedText from '../components/DecryptedText';

const severityConfig = {
  critical: { color: 'bg-red-100 text-red-800 border-red-200', icon: XCircle, label: 'Critical' },
  high: { color: 'bg-orange-100 text-orange-800 border-orange-200', icon: AlertTriangle, label: 'High' },
  medium: { color: 'bg-amber-100 text-amber-800 border-amber-200', icon: AlertTriangle, label: 'Medium' },
  low: { color: 'bg-blue-100 text-blue-800 border-blue-200', icon: CheckCircle, label: 'Low' },
  info: { color: 'bg-gray-100 text-gray-800 border-gray-200', icon: CheckCircle, label: 'Info' },
};

export default function ScanResults() {
  const { id } = useParams();
  const [scan, setScan] = useState(null);
  const [findings, setFindings] = useState([]);
  const [modules, setModules] = useState([]);
  const [activeTab, setActiveTab] = useState('all');
  const [expandedFinding, setExpandedFinding] = useState(null);
  const [loading, setLoading] = useState(true);
  const [generatingReport, setGeneratingReport] = useState(false);

  const fetchScan = async () => {
    try {
      const res = await scansAPI.get(id);
      setScan(res.data.scan);
      setFindings(res.data.findings);
      setModules(res.data.modules);
    } catch (err) {
      console.error('Fetch scan error:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchScan(); }, [id]);

  // Poll for updates if scan is running
  useEffect(() => {
    if (scan && (scan.status === 'pending' || scan.status === 'running')) {
      const interval = setInterval(fetchScan, 3000);
      return () => clearInterval(interval);
    }
  }, [scan?.status]);

  const handleExport = async (format) => {
    setGeneratingReport(true);
    try {
      await reportsAPI.generate({ scan_id: id, format });
      alert(`Report generated in ${format.toUpperCase()} format.`);
    } catch (err) {
      alert('Failed to generate report.');
    } finally {
      setGeneratingReport(false);
    }
  };

  const handleMarkResolved = async (findingId) => {
    try {
      await scansAPI.updateFinding(id, findingId, { is_resolved: true });
      fetchScan();
    } catch (err) {
      console.error('Mark resolved error:', err);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="animate-spin text-primary-600" size={32} />
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="text-center py-12">
        <h2 className="text-xl font-semibold text-gray-900 dark:text-white">Scan not found</h2>
        <Link to="/dashboard" className="btn-primary mt-4 inline-block">Back to Dashboard</Link>
      </div>
    );
  }

  const isRunning = scan.status === 'pending' || scan.status === 'running';
  const filteredFindings = activeTab === 'all' ? findings : findings.filter(f => f.category === activeTab);
  const categories = ['all', ...new Set(findings.map(f => f.category))];

  const getGradeColor = (grade) => {
    if (!grade) return 'text-gray-400';
    const g = grade.charAt(0);
    if (g === 'A') return 'text-emerald-500';
    if (g === 'B') return 'text-amber-500';
    if (g === 'C') return 'text-yellow-500';
    if (g === 'D') return 'text-orange-500';
    if (g === 'F') return 'text-red-500';
    return 'text-gray-400';
  };

  return (
    <div>
      {/* Back button */}
      <Link to="/dashboard" className="inline-flex items-center gap-1 text-sm text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200 mb-4">
        <ArrowLeft size={16} /> Back to Dashboard
      </Link>

      {/* Grade Card */}
      <div className="card mb-6">
        <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4">
          <div className="flex items-center gap-4 sm:gap-6 min-w-0">
              <div className="text-center flex-shrink-0">
                <div className={`text-5xl sm:text-6xl font-bold ${getGradeColor(scan.grade)}`}>
                  {scan.grade || '-'}
                </div>
                <div className="text-sm text-gray-500 dark:text-gray-400 mt-1">
                  <DecryptedText
                    text="Grade"
                    speed={50}
                    maxIterations={6}
                    animateOn="view"
                    className="text-gray-500 dark:text-gray-400"
                    encryptedClassName="text-gray-600"
                  />
                </div>
              </div>
            <div className="min-w-0">
              <h1 className="text-lg sm:text-xl font-bold text-gray-900 dark:text-white break-all">{scan.target_url}</h1>
              <div className="flex flex-wrap items-center gap-x-3 gap-y-1 mt-2 text-sm text-gray-500 dark:text-gray-400">
                <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium ${
                  isRunning ? 'bg-yellow-100 text-yellow-800' : scan.status === 'completed' ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
                }`}>
                  {scan.status}
                </span>
                <span>Score: {scan.score || '-'}/100</span>
                {scan.duration_ms && <span>Duration: {Math.round(scan.duration_ms / 1000)}s</span>}
                <span>{new Date(scan.created_at).toLocaleString()}</span>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2 w-full lg:w-auto overflow-x-auto">
            <button onClick={() => handleExport('json')} disabled={generatingReport} className="btn-secondary text-sm flex-1 lg:flex-none justify-center whitespace-nowrap">
              <FileText size={14} /> JSON
            </button>
            <button onClick={() => handleExport('csv')} disabled={generatingReport} className="btn-secondary text-sm flex-1 lg:flex-none justify-center whitespace-nowrap">
              <Download size={14} /> CSV
            </button>
            <button onClick={() => handleExport('html')} disabled={generatingReport} className="btn-secondary text-sm flex-1 lg:flex-none justify-center whitespace-nowrap">
              <Code size={14} /> HTML
            </button>
          </div>
        </div>

        {/* Progress bar for running scans */}
        {isRunning && (
          <div className="mt-4">
            <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
              <div className="bg-primary-600 h-2 rounded-full animate-pulse" style={{ width: '60%' }} />
            </div>
            <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">Scan in progress...</p>
          </div>
        )}
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3 mb-6">
        {['critical', 'high', 'medium', 'low', 'info'].map(severity => {
          const count = findings.filter(f => f.severity === severity).length;
          const config = severityConfig[severity];
          return (
          <div key={severity} className={`card text-center p-4 ${count === 0 ? 'opacity-50' : ''}`}>
               <div className={`text-2xl font-bold ${config.color.split(' ')[1]}`}>{count}</div>
                <div className="text-xs text-gray-600 dark:text-gray-300 uppercase mt-1">{severity}</div>
             </div>
          );
        })}
      </div>

      {/* Module Tabs */}
      <div className="card mb-6">
        <div className="flex gap-2 border-b border-gray-200 dark:border-gray-800 -mx-4 px-4 sm:-mx-6 sm:px-6 pb-0 overflow-x-auto">
          {categories.map(cat => (
            <button
              key={cat}
              onClick={() => setActiveTab(cat)}
              className={`px-3 sm:px-4 py-2 text-sm font-medium border-b-2 transition-colors whitespace-nowrap ${
                activeTab === cat
                  ? 'border-primary-600 text-primary-600 dark:text-primary-400'
                  : 'border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200'
              }`}
            >
              {cat === 'all' ? 'All' : cat.charAt(0).toUpperCase() + cat.slice(1)}
              <span className="ml-1 text-xs text-gray-500 dark:text-gray-300">({cat === 'all' ? findings.length : findings.filter(f => f.category === cat).length})</span>
            </button>
          ))}
        </div>
      </div>

      {/* Findings List */}
      <div className="space-y-3">
        {filteredFindings.length === 0 ? (
          <div className="card text-center py-8">
            <CheckCircle className="mx-auto text-green-500" size={48} />
            <h3 className="mt-4 text-lg font-medium text-gray-900 dark:text-white">No findings</h3>
          <p className="text-sm text-gray-600 dark:text-gray-300">No issues found in this category.</p>
          </div>
        ) : (
          filteredFindings.map((finding) => {
            const config = severityConfig[finding.severity] || severityConfig.info;
            const Icon = config.icon;
            const isExpanded = expandedFinding === finding.id;

            return (
              <div key={finding.id} className="card hover:shadow-md transition-shadow">
                <button
                  onClick={() => setExpandedFinding(isExpanded ? null : finding.id)}
                  className="w-full text-left"
                >
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex items-start gap-3 min-w-0">
                      <Icon className={`mt-0.5 flex-shrink-0 ${finding.severity === 'critical' || finding.severity === 'high' ? 'text-red-500' : finding.severity === 'medium' ? 'text-amber-500' : 'text-blue-500'}`} size={20} />
                       <div className="min-w-0">
                         <h3 className="font-medium text-gray-900 dark:text-white">{finding.title}</h3>
                         <p className="text-sm text-gray-500 dark:text-gray-400 mt-0.5 line-clamp-2">{finding.description}</p>
                       </div>
                    </div>
                    <div className="flex items-center gap-2 flex-shrink-0">
                      <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${config.color}`}>
                        {config.label}
                      </span>
                      {isExpanded ? <ChevronUp size={16} className="text-gray-400" /> : <ChevronDown size={16} className="text-gray-400" />}
                    </div>
                  </div>
                </button>

                {isExpanded && (
                  <div className="mt-4 pt-4 border-t border-gray-200 dark:border-gray-800 space-y-4">
                    {finding.impact && (
                      <div>
                        <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Impact</h4>
                        <p className="text-sm text-gray-600 dark:text-gray-400">{finding.impact}</p>
                      </div>
                    )}

                    {finding.remediation && (
                      <div className="bg-blue-50 dark:bg-blue-900/30 border border-blue-200 dark:border-blue-800 rounded-lg p-3">
                        <h4 className="text-sm font-medium text-blue-800 dark:text-blue-300 mb-1">Remediation</h4>
                        <p className="text-sm text-blue-700 dark:text-blue-200">{finding.remediation}</p>
                      </div>
                    )}

                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                      {finding.current_value && (
                        <div>
                          <h4 className="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase mb-1">Current Value</h4>
                          <code className="text-sm bg-gray-100 dark:bg-gray-800 dark:text-gray-200 px-2 py-1 rounded block break-all">{finding.current_value}</code>
                        </div>
                      )}
                      {finding.recommended_value && (
                        <div>
                          <h4 className="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase mb-1">Recommended</h4>
                          <code className="text-sm bg-green-50 dark:bg-green-900/30 text-green-800 dark:text-green-300 px-2 py-1 rounded block break-all">{finding.recommended_value}</code>
                        </div>
                      )}
                    </div>

                    {finding.code_snippets && (
                      <div>
                        <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Configuration Examples</h4>
                        <div className="space-y-2">
                          {Object.entries(finding.code_snippets).map(([server, code]) => (
                            <div key={server} className="bg-gray-900 text-gray-100 rounded-lg p-3">
                              <div className="flex items-center justify-between mb-1">
                                <span className="text-xs font-medium text-gray-400 uppercase">{server}</span>
                                <button
                                  onClick={() => navigator.clipboard.writeText(code)}
                                  className="text-gray-400 hover:text-white"
                                >
                                  <Copy size={14} />
                                </button>
                              </div>
                              <pre className="text-xs overflow-x-auto"><code>{code}</code></pre>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    <div className="flex items-center gap-2 pt-2">
                       {finding.cwe_id && (
                         <span className="text-xs bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400 px-2 py-1 rounded">CWE: {finding.cwe_id}</span>
                       )}
                       {finding.confidence && (
                         <span className="text-xs bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400 px-2 py-1 rounded">Confidence: {finding.confidence}</span>
                       )}
                      {!finding.is_resolved && (
                        <button
                          onClick={() => handleMarkResolved(finding.id)}
                          className="ml-auto text-xs text-green-600 hover:text-green-700 font-medium"
                        >
                          Mark as Resolved
                        </button>
                      )}
                    </div>
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}