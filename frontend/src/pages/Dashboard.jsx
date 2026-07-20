import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { Shield, AlertTriangle, Activity, Clock, ArrowRight, Plus, RefreshCw, TrendingUp } from 'lucide-react';
import { scansAPI } from '../lib/api';
import Antigravity from '../components/Antigravity';
import DecryptedText from '../components/DecryptedText';

const severityColors = {
  critical: { bg: 'bg-red-100', text: 'text-red-700', icon: 'text-red-500' },
  high: { bg: 'bg-orange-100', text: 'text-orange-700', icon: 'text-orange-500' },
  medium: { bg: 'bg-amber-100', text: 'text-amber-700', icon: 'text-amber-500' },
  low: { bg: 'bg-blue-100', text: 'text-blue-700', icon: 'text-blue-500' },
  info: { bg: 'bg-gray-100', text: 'text-gray-700', icon: 'text-gray-500' },
};

export default function Dashboard() {
  const [stats, setStats] = useState(null);
  const [recentScans, setRecentScans] = useState([]);
  const [loading, setLoading] = useState(true);

  const fetchData = async () => {
    try {
      const [statsRes, scansRes] = await Promise.all([
        scansAPI.stats(),
        scansAPI.list({ limit: 5 })
      ]);
      setStats(statsRes.data.stats);
      setRecentScans(scansRes.data.scans);
    } catch (err) {
      console.error('Dashboard fetch error:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchData(); }, []);

  if (loading) {
    return (
      <div className="relative w-full h-96 flex items-center justify-center overflow-hidden rounded-xl bg-slate-950">
        <div className="absolute inset-0">
          <Antigravity
            count={200}
            magnetRadius={10}
            ringRadius={5}
            waveSpeed={0.4}
            waveAmplitude={0.8}
            particleSize={1.5}
            lerpSpeed={0.05}
            color="#22D3EE"
            autoAnimate={true}
            rotationSpeed={0.3}
            depthFactor={1}
            pulseSpeed={3}
            particleShape="capsule"
            fieldStrength={15}
          />
        </div>
        <div className="relative z-10 flex flex-col items-center gap-3">
          <RefreshCw className="animate-spin text-cyan-400" size={32} />
          <p className="text-cyan-300/70">Loading your dashboard...</p>
        </div>
      </div>
    );
  }

  const statCards = [
    {
      label: 'Total Scans',
      value: stats?.total_scans || 0,
      icon: Activity,
      color: 'text-indigo-600 dark:text-indigo-400',
      bg: 'bg-indigo-50 dark:bg-indigo-500/10'
    },
    {
      label: 'Average Grade',
      value: stats?.average_score ? `${Math.round(stats.average_score)}/100` : 'N/A',
      icon: Shield,
      color: 'text-emerald-600 dark:text-emerald-400',
      bg: 'bg-emerald-50 dark:bg-emerald-500/10'
    },
    {
      label: 'Critical Findings',
      value: stats?.critical_findings || 0,
      icon: AlertTriangle,
      color: 'text-rose-600 dark:text-rose-400',
      bg: 'bg-rose-50 dark:bg-rose-500/10'
    },
    {
      label: 'Scans Completed',
      value: stats?.completed_scans || 0,
      icon: Clock,
      color: 'text-amber-600 dark:text-amber-400',
      bg: 'bg-amber-50 dark:bg-amber-500/10'
    }
  ];

  const getGradeColor = (grade) => {
    if (!grade) return 'text-gray-400';
    const g = grade.charAt(0).toUpperCase();
    if (g === 'A') return 'text-emerald-600';
    if (g === 'B') return 'text-amber-600';
    if (g === 'C') return 'text-yellow-600';
    if (g === 'D') return 'text-orange-600';
    if (g === 'F') return 'text-red-600';
    return 'text-gray-400';
  };

  return (
    <div>
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-6 sm:mb-8">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold text-indigo-600 dark:text-indigo-400">
            <DecryptedText
              text="Dashboard"
              speed={50}
              maxIterations={10}
              animateOn="view"
              className="text-indigo-600 dark:text-indigo-400"
              encryptedClassName="text-slate-500 dark:text-slate-400"
            />
          </h1>
          <p className="text-sm sm:text-base text-gray-600 dark:text-gray-300 mt-1">Overview of your security scanning activity</p>
        </div>
        <div className="flex items-center gap-3">
          <button onClick={fetchData} className="btn-ghost p-2" aria-label="Refresh">
            <RefreshCw size={18} />
          </button>
          <Link to="/new-scan" className="btn-primary inline-flex items-center gap-2 flex-1 sm:flex-none justify-center">
            <Plus size={18} />
            New Scan
          </Link>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        {statCards.map((stat) => {
          const Icon = stat.icon;
          return (
            <div key={stat.label} className="card flex items-center gap-4">
              <div className={`w-12 h-12 rounded-lg ${stat.bg} flex items-center justify-center`}>
                <Icon className={stat.color} size={24} />
              </div>
              <div>
                <p className="text-sm text-gray-600 dark:text-gray-300">{stat.label}</p>
                <p className={`text-2xl font-bold ${stat.color}`}>{stat.value}</p>
              </div>
            </div>
          );
        })}
      </div>

      {/* Recent Scans */}
        <div className="card">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Recent Scans</h2>
            <Link to="/history" className="text-sm text-indigo-600 dark:text-indigo-400 hover:text-indigo-700 dark:hover:text-indigo-300 font-medium inline-flex items-center gap-1">
              View All <ArrowRight size={14} />
            </Link>
          </div>

          {recentScans.length === 0 ? (
            <div className="text-center py-12">
              <Search className="mx-auto text-gray-300 dark:text-gray-600" size={48} />
              <h3 className="mt-4 text-lg font-medium text-gray-900 dark:text-white">No scans yet</h3>
              <p className="mt-2 text-sm text-gray-500 dark:text-gray-400">Start your first security scan to see results here.</p>
            <Link to="/new-scan" className="btn-primary inline-flex items-center gap-2 mt-4">
              <Plus size={18} />
              Start a Scan
            </Link>
          </div>
        ) : (
          <div className="space-y-3">
            {recentScans.map((scan) => (
          <Link
            key={scan.id}
            to={`/scans/${scan.id}`}
            className="flex items-center justify-between p-4 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors border border-gray-100 dark:border-gray-800"
          >
            <div className="flex items-center gap-4 min-w-0">
              <div className="flex-shrink-0">
                <Shield className="text-indigo-500 dark:text-indigo-400" size={20} />
              </div>
              <div className="min-w-0">
                <p className="font-medium text-gray-900 dark:text-white truncate">{scan.target_url}</p>
                <p className="text-sm text-gray-500 dark:text-gray-400">
                  {new Date(scan.created_at).toLocaleDateString()} · 
                  <span className="ml-1 capitalize">{scan.status}</span>
                </p>
              </div>
            </div>
            <div className="flex items-center gap-3 flex-shrink-0">
              {scan.grade && (
                <span className={`text-lg font-bold ${getGradeColor(scan.grade)}`}>
                  {scan.grade}
                </span>
              )}
              {scan.score != null && (
                <span className="text-sm text-gray-500 dark:text-gray-400">{scan.score}/100</span>
              )}
              <ArrowRight className="text-gray-300 dark:text-gray-600" size={16} />
            </div>
          </Link>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function Search() {
  return (
    <svg className="mx-auto text-gray-300" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <circle cx="11" cy="11" r="8" />
      <path d="m21 21-4.3-4.3" />
    </svg>
  );
}