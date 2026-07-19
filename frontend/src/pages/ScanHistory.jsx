import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { Shield, Search, Filter, ArrowRight, RefreshCw, Trash2 } from 'lucide-react';
import { scansAPI } from '../lib/api';
import DecryptedText from '../components/DecryptedText';

export default function ScanHistory() {
  const [scans, setScans] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState('');
  const [page, setPage] = useState(0);
  const limit = 25;

  const fetchScans = async () => {
    setLoading(true);
    try {
      const res = await scansAPI.list({ status: statusFilter || undefined, limit, offset: page * limit });
      setScans(res.data.scans);
      setTotal(res.data.total);
    } catch (err) {
      console.error('Fetch scans error:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchScans(); }, [statusFilter, page]);

  const handleDelete = async (id, e) => {
    e.preventDefault();
    e.stopPropagation();
    if (!confirm('Are you sure you want to delete this scan?')) return;
    try {
      await scansAPI.delete(id);
      fetchScans();
    } catch (err) {
      console.error('Delete error:', err);
    }
  };

  const getGradeColor = (grade) => {
    if (!grade) return 'text-gray-400';
    const g = grade.charAt(0);
    if (g === 'A') return 'text-emerald-600';
    if (g === 'B') return 'text-amber-600';
    if (g === 'C') return 'text-yellow-600';
    if (g === 'D') return 'text-orange-600';
    if (g === 'F') return 'text-red-600';
    return 'text-gray-400';
  };

  const totalPages = Math.ceil(total / limit);

  return (
    <div>
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-6 sm:mb-8">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-fuchsia-400 dark:from-cyan-300 dark:to-fuchsia-300">
            <DecryptedText
              text="Scan History"
              speed={40}
              maxIterations={10}
              animateOn="view"
              className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-fuchsia-400 dark:from-cyan-300 dark:to-fuchsia-300"
              encryptedClassName="text-gray-600"
            />
          </h1>
          <p className="text-sm sm:text-base text-gray-600 dark:text-gray-300 mt-1">View and manage all your security scans.</p>
        </div>
        <Link to="/new-scan" className="btn-primary inline-flex items-center justify-center gap-2">
          <Search size={18} />
          New Scan
        </Link>
      </div>

      {/* Filters */}
      <div className="card mb-6">
        <div className="flex flex-wrap items-center gap-3">
          <Filter size={16} className="text-gray-400 flex-shrink-0" />
          <select
            value={statusFilter}
            onChange={(e) => { setStatusFilter(e.target.value); setPage(0); }}
            className="input-field w-auto flex-1 sm:flex-none min-w-[8rem]"
          >
            <option value="">All Status</option>
            <option value="completed">Completed</option>
            <option value="running">Running</option>
            <option value="failed">Failed</option>
            <option value="pending">Pending</option>
            <option value="cancelled">Cancelled</option>
          </select>
           <span className="text-sm text-gray-600 dark:text-gray-300 order-last sm:order-none w-full sm:w-auto">{total} total scans</span>
          <button onClick={fetchScans} className="btn-ghost p-2 ml-auto" aria-label="Refresh">
            <RefreshCw size={16} />
          </button>
        </div>
      </div>

      {/* Scans List */}
      {loading ? (
        <div className="flex items-center justify-center h-64">
          <RefreshCw className="animate-spin text-primary-600" size={32} />
        </div>
      ) : scans.length === 0 ? (
        <div className="card text-center py-12">
          <Shield className="mx-auto text-gray-300 dark:text-gray-600" size={48} />
          <h3 className="mt-4 text-lg font-medium text-gray-900 dark:text-white">No scans found</h3>
          <p className="text-sm text-gray-600 dark:text-gray-300 mt-1">Start your first scan to see results here.</p>
          <Link to="/new-scan" className="btn-primary inline-flex items-center gap-2 mt-4">
            <Search size={18} />
            Start a Scan
          </Link>
        </div>
      ) : (
        <div className="card p-0 overflow-hidden">
          <div className="divide-y divide-gray-200 dark:divide-gray-800">
            {scans.map((scan) => (
              <Link
                key={scan.id}
                to={`/scans/${scan.id}`}
                className="flex items-center justify-between p-4 hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors"
              >
                <div className="flex items-center gap-4 min-w-0">
                  <div className={`w-2 h-10 rounded-full flex-shrink-0 ${
                    scan.status === 'completed' ? 'bg-green-500' :
                    scan.status === 'running' ? 'bg-yellow-500' :
                    scan.status === 'failed' ? 'bg-red-500' : 'bg-gray-300 dark:bg-gray-600'
                  }`} />
                  <div className="min-w-0">
                    <p className="font-medium text-gray-900 dark:text-white truncate">{scan.target_url}</p>
                    <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5 text-xs sm:text-sm text-gray-500 dark:text-gray-400">
                      <span className="capitalize">{scan.status}</span>
                      <span className="hidden sm:inline">·</span>
                      <span>{new Date(scan.created_at).toLocaleString()}</span>
                      {scan.duration_ms && (
                        <>
                          <span className="hidden sm:inline">·</span>
                          <span>{Math.round(scan.duration_ms / 1000)}s</span>
                        </>
                      )}
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-2 sm:gap-3 flex-shrink-0">
                  {scan.grade && (
                    <span className={`text-lg font-bold ${getGradeColor(scan.grade)}`}>{scan.grade}</span>
                  )}
                  {scan.score !== null && (
                    <span className="hidden sm:inline text-sm text-gray-500 dark:text-gray-400">{scan.score}/100</span>
                  )}
                  <button
                    onClick={(e) => handleDelete(scan.id, e)}
                    className="p-1 text-gray-400 hover:text-red-600 dark:hover:text-red-400 transition-colors"
                    title="Delete scan"
                  >
                    <Trash2 size={16} />
                  </button>
                  <ArrowRight className="hidden sm:inline text-gray-300 dark:text-gray-600" size={16} />
                </div>
              </Link>
            ))}
          </div>
        </div>
      )}

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-center gap-2 mt-6">
          <button
            onClick={() => setPage(p => Math.max(0, p - 1))}
            disabled={page === 0}
            className="btn-secondary text-sm disabled:opacity-50"
          >
            Previous
          </button>
           <span className="text-sm text-gray-600 dark:text-gray-300">
              Page {page + 1} of {totalPages}
            </span>
          <button
            onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))}
            disabled={page >= totalPages - 1}
            className="btn-secondary text-sm disabled:opacity-50"
          >
            Next
          </button>
        </div>
      )}
    </div>
  );
}