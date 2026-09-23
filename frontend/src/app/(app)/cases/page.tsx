'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import {
  Briefcase, FolderOpen, ArrowRight, AlertTriangle, Upload,
  ShieldAlert, CheckCircle2, Clock, Database
} from 'lucide-react';
import { api } from '@/lib/api';
import { Case } from '@/types/api';
import { PageHeader } from '@/components/shell/page-header';

function SeverityBadge({ sev }: { sev: string }) {
  const cfg: Record<string, string> = {
    CRITICAL: "bg-rose-100 text-rose-800 border-rose-300 dark:bg-rose-950/60 dark:border-rose-900/50 dark:text-rose-400",
    HIGH:     "bg-orange-100 text-orange-800 border-orange-300 dark:bg-orange-950/60 dark:border-orange-900/50 dark:text-orange-400",
    MEDIUM:   "bg-amber-100 text-amber-800 border-amber-300 dark:bg-amber-950/60 dark:border-amber-900/50 dark:text-amber-400",
    LOW:      "bg-slate-100 text-slate-700 border-slate-300 dark:bg-slate-800 dark:border-slate-700 dark:text-slate-400",
  };
  return (
    <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${cfg[sev] ?? cfg.LOW}`}>
      {sev}
    </span>
  );
}

function StatusBadge({ st }: { st: string }) {
  const cfg: Record<string, string> = {
    OPEN:          "bg-blue-100 text-blue-800 border-blue-300 dark:bg-blue-950/60 dark:border-blue-900/50 dark:text-blue-400",
    INVESTIGATING: "bg-amber-100 text-amber-800 border-amber-300 dark:bg-amber-950/60 dark:border-amber-900/50 dark:text-amber-400",
    CONTAINED:     "bg-emerald-100 text-emerald-800 border-emerald-300 dark:bg-emerald-950/60 dark:border-emerald-900/50 dark:text-emerald-400",
    CLOSED:        "bg-slate-100 text-slate-600 border-slate-300 dark:bg-slate-800 dark:border-slate-700 dark:text-slate-500",
  };
  return (
    <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${cfg[st] ?? cfg.CLOSED}`}>
      {st}
    </span>
  );
}

export default function CasesPage() {
  const [cases, setCases] = useState<Case[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.listCases()
      .then((res) => setCases(res))
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  const open  = cases.filter(c => c.status === 'OPEN' || c.status === 'INVESTIGATING').length;
  const closed = cases.filter(c => c.status === 'CLOSED' || c.status === 'CONTAINED').length;
  const critical = cases.filter(c => c.severity === 'CRITICAL').length;

  return (
    <div className="flex flex-col min-h-full pb-16">
      <PageHeader
        section="SOC Workspace"
        title="Incident Investigation Cases"
        description="SOC triage cases, evidence attachments, and analyst determinations across all submitted evidence."
        meta={[{ label: "Total Cases", value: String(cases.length) }]}
        actions={
          <Link href="/analyze" className="btn-primary text-xs">
            <Upload className="h-3.5 w-3.5" />
            Submit Evidence
          </Link>
        }
      />

      <div className="p-6 space-y-5">
        {/* Stats row */}
        {!loading && cases.length > 0 && (
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            {[
              { label: "Total Cases", value: cases.length, icon: Briefcase, bg: "bg-cyan-50 dark:bg-cyan-950/30", border: "border-cyan-200 dark:border-cyan-900/40", text: "text-cyan-700 dark:text-cyan-300" },
              { label: "Active", value: open, icon: Clock, bg: "bg-amber-50 dark:bg-amber-950/30", border: "border-amber-200 dark:border-amber-900/40", text: "text-amber-700 dark:text-amber-300" },
              { label: "Resolved", value: closed, icon: CheckCircle2, bg: "bg-emerald-50 dark:bg-emerald-950/30", border: "border-emerald-200 dark:border-emerald-900/40", text: "text-emerald-700 dark:text-emerald-300" },
              { label: "Critical", value: critical, icon: ShieldAlert, bg: "bg-rose-50 dark:bg-rose-950/30", border: "border-rose-200 dark:border-rose-900/40", text: "text-rose-700 dark:text-rose-300" },
            ].map(({ label, value, icon: Icon, bg, border, text }) => (
              <div key={label} className={`rounded-xl border ${border} ${bg} p-4 shadow-sm`}>
                <div className="flex items-center gap-2 mb-1">
                  <Icon className={`h-3.5 w-3.5 ${text}`} />
                  <span className="text-[10px] font-mono font-bold uppercase tracking-widest text-slate-500 dark:text-slate-400">{label}</span>
                </div>
                <p className={`text-2xl font-bold font-mono ${text}`}>{value}</p>
              </div>
            ))}
          </div>
        )}

        {/* Cases table */}
        <div className="rounded-2xl border border-slate-300 dark:border-slate-800 bg-white dark:bg-slate-900/80 shadow-sm overflow-hidden transition-colors duration-200">
          <div className="flex items-center justify-between px-4 py-3 border-b border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-900">
            <div className="flex items-center gap-2">
              <Database className="h-4 w-4 text-cyan-600 dark:text-cyan-400" />
              <span className="text-xs font-mono font-bold text-slate-800 dark:text-white uppercase tracking-wider">
                Case Registry
              </span>
            </div>
            <span className="text-[11px] font-mono text-slate-500">
              {cases.length} total
            </span>
          </div>

          {loading ? (
            <div className="py-14 flex flex-col items-center gap-3">
              <div className="h-6 w-6 animate-spin rounded-full border-2 border-cyan-500 border-t-transparent" />
              <p className="text-xs font-mono text-slate-500">Loading investigation cases…</p>
            </div>
          ) : cases.length === 0 ? (
            <div className="py-16 flex flex-col items-center gap-4 text-center px-6">
              <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700">
                <FolderOpen className="h-6 w-6 text-slate-400 dark:text-slate-500" />
              </div>
              <div>
                <p className="text-sm font-bold text-slate-900 dark:text-white font-mono">No Cases Open</p>
                <p className="text-xs text-slate-500 font-mono mt-1 max-w-sm">
                  Record dispositions on analysis pages to track investigation cases.
                </p>
              </div>
              <Link href="/analyze" className="btn-primary text-xs mt-2">
                <Upload className="h-3.5 w-3.5" />
                Submit Email Evidence
              </Link>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-xs font-mono">
                <thead>
                  <tr className="border-b border-slate-200 dark:border-slate-800/80 bg-slate-50/50 dark:bg-slate-900/50">
                    {["Case Key", "Title & Summary", "Severity", "Status", "Evidence", "Created"].map((h) => (
                      <th key={h} className="text-left px-4 py-3 text-[10px] font-bold uppercase tracking-wider text-slate-500">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-800/50">
                  {cases.map((c, idx) => (
                    <tr
                      key={c.id}
                      className={`hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors group ${
                        idx % 2 === 0 ? "bg-slate-50/30 dark:bg-slate-900/20" : ""
                      }`}
                    >
                      <td className="px-4 py-3.5 text-cyan-700 dark:text-cyan-400 font-bold">
                        {c.case_key}
                      </td>
                      <td className="px-4 py-3.5 max-w-xs">
                        <div className="font-bold text-slate-900 dark:text-white font-sans">{c.title}</div>
                        {c.summary && (
                          <div className="text-[11px] text-slate-500 font-mono truncate max-w-[240px] mt-0.5">{c.summary}</div>
                        )}
                      </td>
                      <td className="px-4 py-3.5">
                        <SeverityBadge sev={c.severity} />
                      </td>
                      <td className="px-4 py-3.5">
                        <StatusBadge st={c.status} />
                      </td>
                      <td className="px-4 py-3.5 text-slate-700 dark:text-slate-300">
                        <span className="font-bold text-cyan-700 dark:text-cyan-400">{c.evidence_count}</span>{" "}
                        <span className="text-slate-500">attached</span>
                      </td>
                      <td className="px-4 py-3.5 text-slate-500 whitespace-nowrap">
                        {c.created_at ? c.created_at.substring(0, 10) : "Recent"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
