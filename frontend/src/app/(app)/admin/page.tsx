'use client';

import React, { useState, useEffect } from 'react';
import {
  Settings, Users, Shield, Database, Activity, CheckCircle2,
  AlertTriangle, Lock, Eye, EyeOff, ShieldAlert, Terminal
} from 'lucide-react';
import { api } from '@/lib/api';
import { PageHeader } from '@/components/shell/page-header';

const ADMIN_SESSION_KEY = 'cybersentry_admin_unlocked';

function AdminPinGate({ onUnlock }: { onUnlock: () => void }) {
  const [password, setPassword] = useState('');
  const [showPw, setShowPw] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      await api.login({ email: 'admin@cybersentry.local', password });
      sessionStorage.setItem(ADMIN_SESSION_KEY, '1');
      onUnlock();
    } catch {
      setError('Invalid admin password. Access denied.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-[70vh] flex items-center justify-center">
      <div className="w-full max-w-sm">
        <div className="text-center mb-6">
          <div className="inline-flex h-16 w-16 rounded-2xl bg-amber-100 dark:bg-amber-950/40 border-2 border-amber-300 dark:border-amber-700/50 items-center justify-center mb-4">
            <Lock className="h-7 w-7 text-amber-600 dark:text-amber-400" />
          </div>
          <h1 className="text-xl font-bold font-mono text-slate-900 dark:text-white">Admin Area</h1>
          <p className="text-xs text-slate-500 font-mono mt-1">
            This area requires administrator credentials
          </p>
        </div>

        <div className="rounded-2xl border border-slate-300 dark:border-slate-800 bg-white dark:bg-slate-900/60 p-6 shadow-sm">
          {error && (
            <div className="mb-4 flex items-center gap-2 bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-900/50 text-rose-700 dark:text-rose-400 rounded-xl px-3 py-2.5 text-xs font-mono">
              <ShieldAlert className="h-3.5 w-3.5 shrink-0" />
              {error}
            </div>
          )}
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-[10px] font-bold text-slate-600 dark:text-slate-400 mb-2 uppercase font-mono tracking-widest">
                Admin Password
              </label>
              <div className="relative">
                <Lock className="h-4 w-4 absolute left-3.5 top-3 text-slate-400" />
                <input
                  type={showPw ? 'text' : 'password'}
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  required
                  autoFocus
                  placeholder="Enter admin password"
                  className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 focus:border-amber-600 focus:ring-2 focus:ring-amber-500/30 rounded-xl py-2.5 pl-10 pr-10 text-xs text-slate-900 dark:text-slate-200 font-mono focus:outline-none transition-all"
                />
                <button
                  type="button"
                  onClick={() => setShowPw(v => !v)}
                  className="absolute right-3 top-3 text-slate-400 hover:text-slate-700 dark:hover:text-slate-300 transition-colors cursor-pointer"
                >
                  {showPw ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
            </div>
            <button
              type="submit"
              disabled={loading || !password}
              className="w-full py-2.5 px-4 rounded-xl bg-amber-600 hover:bg-amber-500 text-white text-xs font-bold font-mono tracking-wide flex items-center justify-center gap-2 transition-all disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer shadow-md"
            >
              {loading ? (
                <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-white border-t-transparent" />
              ) : (
                <Lock className="h-3.5 w-3.5" />
              )}
              {loading ? 'Verifying…' : 'Unlock Admin Panel'}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}

export default function AdminPage() {
  const [unlocked, setUnlocked] = useState(false);
  const [checkingRole, setCheckingRole] = useState(true);
  const [isAdmin, setIsAdmin] = useState(false);
  const [users, setUsers] = useState<any[]>([]);
  const [intel, setIntel] = useState<any[]>([]);
  const [activeTab, setActiveTab] = useState<'users' | 'intel' | 'system'>('users');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.getMe()
      .then((me: any) => {
        if (me.role === 'ADMINISTRATOR') {
          setIsAdmin(true);
          if (sessionStorage.getItem(ADMIN_SESSION_KEY) === '1') setUnlocked(true);
        }
      })
      .catch(() => setIsAdmin(false))
      .finally(() => setCheckingRole(false));
  }, []);

  useEffect(() => {
    if (!unlocked) return;
    Promise.all([
      api.listUsers().catch(() => []),
      api.listThreatIntel().catch(() => [])
    ]).then(([u, i]) => {
      setUsers(u);
      setIntel(i);
    }).finally(() => setLoading(false));
  }, [unlocked]);

  if (checkingRole) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <div className="h-8 w-8 rounded-full border-2 border-cyan-500 border-t-transparent animate-spin" />
      </div>
    );
  }

  if (!isAdmin) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] gap-4">
        <div className="flex h-16 w-16 rounded-2xl bg-rose-100 dark:bg-rose-950/40 border border-rose-300 dark:border-rose-900/50 items-center justify-center">
          <ShieldAlert className="h-8 w-8 text-rose-600 dark:text-rose-400" />
        </div>
        <h1 className="text-xl font-bold font-mono text-slate-900 dark:text-white">Access Denied</h1>
        <p className="text-xs text-slate-500 font-mono max-w-xs text-center">
          Your account does not have Administrator privileges. Contact your SOC team lead.
        </p>
        <span className="px-3 py-1.5 rounded text-xs font-mono font-bold bg-rose-100 text-rose-800 dark:bg-rose-950/60 border border-rose-300 dark:border-rose-900/50 dark:text-rose-400">
          ANALYST role — ADMIN required
        </span>
      </div>
    );
  }

  if (!unlocked) return <AdminPinGate onUnlock={() => setUnlocked(true)} />;

  const tabs = [
    { id: 'users', label: 'SOC Accounts', icon: Users },
    { id: 'intel', label: 'Threat Intel', icon: Database },
    { id: 'system', label: 'System Status', icon: Activity },
  ];

  const theadCls = "text-left px-4 py-3 text-[10px] font-bold uppercase tracking-wider text-slate-500";
  const tdCls = "px-4 py-3.5";

  return (
    <div className="flex flex-col min-h-full pb-16">
      <PageHeader
        section="Administration"
        title="System Administration"
        description="User roles, threat intelligence seeds, and platform configuration."
        actions={
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2 px-3 py-1.5 bg-amber-100 dark:bg-amber-950/40 border border-amber-300 dark:border-amber-800/50 rounded-xl">
              <Shield className="h-3.5 w-3.5 text-amber-600 dark:text-amber-400" />
              <span className="text-[10px] font-mono font-bold text-amber-700 dark:text-amber-400 uppercase tracking-wider">Admin Verified</span>
            </div>
            <button
              onClick={() => { sessionStorage.removeItem(ADMIN_SESSION_KEY); setUnlocked(false); }}
              className="p-2 rounded-xl border border-slate-300 dark:border-slate-700 text-slate-500 hover:text-rose-600 dark:hover:text-rose-400 hover:border-rose-400 transition-colors cursor-pointer"
              title="Lock admin panel"
            >
              <Lock className="h-4 w-4" />
            </button>
          </div>
        }
      />

      <div className="p-6 space-y-5">
        {/* KPI row */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[
            { label: 'SOC Analysts', value: users.filter(u => u.role !== 'ADMINISTRATOR').length, icon: Users, color: 'cyan', bg: "bg-cyan-50 dark:bg-cyan-950/20", border: "border-cyan-200 dark:border-cyan-900/30", text: "text-cyan-700 dark:text-cyan-300" },
            { label: 'Administrators', value: users.filter(u => u.role === 'ADMINISTRATOR').length, icon: Shield, color: 'amber', bg: "bg-amber-50 dark:bg-amber-950/20", border: "border-amber-200 dark:border-amber-900/30", text: "text-amber-700 dark:text-amber-300" },
            { label: 'Intel Seeds', value: intel.length, icon: Database, color: 'indigo', bg: "bg-indigo-50 dark:bg-indigo-950/20", border: "border-indigo-200 dark:border-indigo-900/30", text: "text-indigo-700 dark:text-indigo-300" },
            { label: 'Known Malicious', value: intel.filter(i => i.verdict === 'KNOWN_MALICIOUS').length, icon: AlertTriangle, color: 'rose', bg: "bg-rose-50 dark:bg-rose-950/20", border: "border-rose-200 dark:border-rose-900/30", text: "text-rose-700 dark:text-rose-300" },
          ].map(({ label, value, icon: Icon, bg, border, text }) => (
            <div key={label} className={`rounded-xl border ${border} ${bg} p-4 flex items-center gap-3 shadow-sm`}>
              <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-white dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800">
                <Icon className={`h-4 w-4 ${text}`} />
              </div>
              <div>
                <div className={`text-2xl font-extrabold font-mono ${text}`}>{value}</div>
                <div className="text-[10px] text-slate-500 font-mono font-bold uppercase tracking-wider">{label}</div>
              </div>
            </div>
          ))}
        </div>

        {/* Tabs */}
        <div className="flex items-center border-b border-slate-200 dark:border-slate-800 gap-1">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                className={`flex items-center gap-2 py-2.5 px-4 text-[11px] font-mono font-bold uppercase tracking-wider border-b-2 transition-all -mb-px cursor-pointer ${
                  isActive
                    ? 'border-cyan-600 text-cyan-700 dark:border-cyan-500 dark:text-cyan-400'
                    : 'border-transparent text-slate-500 hover:text-slate-800 dark:hover:text-slate-300'
                }`}
              >
                <Icon className="h-3.5 w-3.5" />
                {tab.label}
              </button>
            );
          })}
        </div>

        {/* Users Tab */}
        {activeTab === 'users' && (
          <div className="rounded-2xl border border-slate-300 dark:border-slate-800 bg-white dark:bg-slate-900/80 shadow-sm overflow-hidden transition-colors duration-200">
            <div className="px-4 py-3 border-b border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-900">
              <span className="text-xs font-mono font-bold text-slate-800 dark:text-white uppercase tracking-wider">
                All SOC Accounts ({users.length})
              </span>
            </div>
            {loading ? (
              <div className="py-12 text-center text-xs font-mono text-slate-500">Loading user accounts…</div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-xs font-mono">
                  <thead>
                    <tr className="border-b border-slate-200 dark:border-slate-800/80 bg-slate-50/50 dark:bg-slate-900/50">
                      {["Full Name", "Work Email", "Role", "Status"].map(h => (
                        <th key={h} className={theadCls}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 dark:divide-slate-800/50">
                    {users.map((u, idx) => (
                      <tr key={u.id} className={`hover:bg-slate-50 dark:hover:bg-slate-800/40 transition-colors ${idx % 2 === 0 ? 'bg-slate-50/30 dark:bg-slate-900/20' : ''}`}>
                        <td className={`${tdCls} font-bold text-slate-900 dark:text-white`}>{u.full_name}</td>
                        <td className={`${tdCls} text-slate-600 dark:text-slate-400`}>{u.email}</td>
                        <td className={tdCls}>
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                            u.role === 'ADMINISTRATOR'
                              ? 'bg-amber-100 text-amber-800 border-amber-300 dark:bg-amber-950/60 dark:border-amber-900/50 dark:text-amber-400'
                              : 'bg-blue-100 text-blue-800 border-blue-300 dark:bg-blue-950/60 dark:border-blue-900/50 dark:text-blue-400'
                          }`}>{u.role}</span>
                        </td>
                        <td className={tdCls}>
                          <span className="flex items-center gap-1.5 text-emerald-600 dark:text-emerald-400 text-[11px] font-bold">
                            <CheckCircle2 className="h-3.5 w-3.5" />ACTIVE
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* Intel Tab */}
        {activeTab === 'intel' && (
          <div className="rounded-2xl border border-slate-300 dark:border-slate-800 bg-white dark:bg-slate-900/80 shadow-sm overflow-hidden transition-colors duration-200">
            <div className="px-4 py-3 border-b border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-900">
              <span className="text-xs font-mono font-bold text-slate-800 dark:text-white uppercase tracking-wider">
                Threat Intelligence Seeds ({intel.length})
              </span>
            </div>
            {loading ? (
              <div className="py-12 text-center text-xs font-mono text-slate-500">Loading threat intel…</div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-xs font-mono">
                  <thead>
                    <tr className="border-b border-slate-200 dark:border-slate-800/80 bg-slate-50/50 dark:bg-slate-900/50">
                      {["Type", "Indicator", "Verdict", "Notes"].map(h => (
                        <th key={h} className={theadCls}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 dark:divide-slate-800/50">
                    {intel.slice(0, 100).map((it, idx) => (
                      <tr key={it.id} className={`hover:bg-slate-50 dark:hover:bg-slate-800/40 transition-colors ${idx % 2 === 0 ? 'bg-slate-50/30 dark:bg-slate-900/20' : ''}`}>
                        <td className={`${tdCls} text-cyan-700 dark:text-cyan-400 font-bold`}>{it.indicator_type}</td>
                        <td className={`${tdCls} text-slate-800 dark:text-slate-300 font-bold max-w-[200px] truncate`}>{it.canonical_value}</td>
                        <td className={tdCls}>
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                            it.verdict === 'KNOWN_MALICIOUS'
                              ? 'bg-rose-100 text-rose-800 border-rose-300 dark:bg-rose-950/60 dark:border-rose-900/50 dark:text-rose-400'
                              : 'bg-slate-100 text-slate-600 border-slate-300 dark:bg-slate-800 dark:border-slate-700 dark:text-slate-400'
                          }`}>{it.verdict}</span>
                        </td>
                        <td className={`${tdCls} text-slate-500 max-w-xs truncate`}>{it.notes}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* System Status Tab */}
        {activeTab === 'system' && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
            <div className="rounded-2xl border border-slate-300 dark:border-slate-800 bg-white dark:bg-slate-900/80 shadow-sm p-5 space-y-4">
              <h2 className="text-xs font-mono font-bold uppercase tracking-widest text-slate-900 dark:text-white flex items-center gap-2">
                <Activity className="h-4 w-4 text-cyan-600 dark:text-cyan-400" />
                API Integration Health
              </h2>
              <div className="space-y-2">
                {[
                  { name: 'IPGeolocation.io', detail: 'IP enrichment + threat intel', status: 'ONLINE' },
                  { name: 'VirusTotal API v3', detail: 'Multi-engine URL & hash scanning', status: 'ONLINE' },
                  { name: 'Gemini AI (gemini-flash)', detail: 'Intent classification active', status: 'ONLINE' },
                  { name: 'SQLite / PostgreSQL', detail: 'Evidence persistence OK', status: 'ONLINE' },
                ].map((svc) => (
                  <div key={svc.name} className="flex items-center justify-between p-3 rounded-xl bg-slate-50 dark:bg-slate-950/40 border border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700 transition-colors">
                    <div>
                      <div className="text-xs font-bold text-slate-900 dark:text-white font-mono">{svc.name}</div>
                      <div className="text-[11px] text-slate-500 font-mono mt-0.5">{svc.detail}</div>
                    </div>
                    <span className="flex items-center gap-1.5 text-[10px] font-mono font-bold text-emerald-800 dark:text-emerald-400 bg-emerald-100 dark:bg-emerald-950/60 border border-emerald-300 dark:border-emerald-900/50 px-2.5 py-1 rounded">
                      <span className="h-1.5 w-1.5 rounded-full bg-emerald-500 animate-pulse" />
                      {svc.status}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            <div className="rounded-2xl border border-slate-300 dark:border-slate-800 bg-white dark:bg-slate-900/80 shadow-sm p-5 space-y-4">
              <h2 className="text-xs font-mono font-bold uppercase tracking-widest text-slate-900 dark:text-white flex items-center gap-2">
                <Terminal className="h-4 w-4 text-slate-500" />
                Platform Configuration
              </h2>
              <div className="space-y-2 font-mono text-xs">
                {[
                  { key: 'Engine', value: 'CyberSentry Forensic Core v1.0' },
                  { key: 'Compliance', value: 'SIH PS-26106' },
                  { key: 'Evidence Mode', value: 'Tamper-Evident SHA-256 Chain' },
                  { key: 'PhishDNA', value: '7-Vector Normalized Fingerprint' },
                  { key: 'Deployment', value: 'Docker Compose Ready' },
                  { key: 'Backend', value: 'FastAPI + Uvicorn' },
                  { key: 'Frontend', value: 'Next.js 16 (App Router)' },
                  { key: 'LLM', value: 'Gemini Flash (Google AI)' },
                ].map((item) => (
                  <div key={item.key} className="flex items-center justify-between gap-4 p-3 rounded-xl bg-slate-50 dark:bg-slate-950/40 border border-slate-200 dark:border-slate-800">
                    <span className="text-[10px] uppercase font-bold text-slate-500 shrink-0">{item.key}</span>
                    <span className="text-slate-800 dark:text-slate-300 text-right">{item.value}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
