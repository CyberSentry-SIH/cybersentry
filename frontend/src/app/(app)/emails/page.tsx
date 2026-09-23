"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Mail, Upload, AlertTriangle, Hash, Clock, HardDrive, ArrowRight, Database } from "lucide-react";

import { PageHeader } from "@/components/shell/page-header";
import { CopyableValue } from "@/components/cybersentry/copyable-value";
import { api } from "@/lib/api";
import type { Evidence } from "@/types/api";
import { formatBytes } from "@/lib/utils";

export default function EmailsPage() {
  const [items, setItems] = useState<Evidence[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .listEvidence()
      .then(setItems)
      .catch((err) => setError(err.message || "Failed to load emails."))
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="flex flex-col min-h-full pb-16">
      <PageHeader
        section="Evidence Queue"
        title="Email Evidence Registry"
        description="Every .eml submitted for forensic analysis, with SHA-256 chain-of-custody preserved."
        meta={[{ label: "Total Evidence Items", value: String(items.length) }]}
        actions={
          <Link href="/analyze" className="btn-primary text-xs">
            <Upload className="h-3.5 w-3.5" />
            Analyze New Email
          </Link>
        }
      />

      <div className="flex flex-col gap-4 p-6">
        {error ? (
          <div className="rounded-xl border border-rose-300 dark:border-rose-900/50 bg-rose-50 dark:bg-rose-950/30 p-4 flex items-start gap-3">
            <AlertTriangle className="h-4 w-4 text-rose-600 dark:text-rose-400 shrink-0 mt-0.5" />
            <div>
              <p className="text-xs font-bold text-rose-700 dark:text-rose-300 font-mono">Failed to load emails</p>
              <p className="text-xs text-rose-600 dark:text-rose-400 mt-0.5">{error}</p>
            </div>
          </div>
        ) : (
          <div className="rounded-2xl border border-slate-300 dark:border-slate-800 bg-white dark:bg-slate-900/80 shadow-sm overflow-hidden transition-colors duration-200">
            {/* Table Header */}
            <div className="border-b border-slate-200 dark:border-slate-800 px-4 py-3 flex items-center justify-between bg-slate-50/70 dark:bg-slate-900">
              <div className="flex items-center gap-2">
                <Database className="h-4 w-4 text-cyan-600 dark:text-cyan-400" />
                <span className="text-xs font-mono font-bold text-slate-800 dark:text-white uppercase tracking-wider">
                  Forensic Evidence Queue
                </span>
              </div>
              <span className="text-[11px] font-mono text-slate-500">
                {items.length} item{items.length !== 1 ? "s" : ""}
              </span>
            </div>

            {loading ? (
              <div className="py-16 text-center">
                <div className="h-6 w-6 animate-spin rounded-full border-2 border-cyan-500 border-t-transparent mx-auto mb-3" />
                <p className="text-xs font-mono text-slate-500">Loading evidence queue…</p>
              </div>
            ) : items.length === 0 ? (
              <div className="py-16 flex flex-col items-center gap-4 text-center">
                <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700">
                  <Mail className="h-6 w-6 text-slate-400 dark:text-slate-500" />
                </div>
                <div>
                  <p className="text-sm font-bold text-slate-900 dark:text-white font-mono">No evidence submitted yet</p>
                  <p className="text-xs text-slate-500 font-mono mt-1">
                    Upload a .eml file to run your first forensic analysis.
                  </p>
                </div>
                <Link href="/analyze" className="btn-primary text-xs mt-2">
                  <Upload className="h-3.5 w-3.5" />
                  Analyze an Email
                </Link>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-xs font-mono">
                  <thead>
                    <tr className="border-b border-slate-200 dark:border-slate-800/80 bg-slate-50/50 dark:bg-slate-900/50">
                      <th className="text-left px-4 py-3 text-[10px] font-bold uppercase tracking-wider text-slate-500">
                        Evidence ID
                      </th>
                      <th className="text-left px-4 py-3 text-[10px] font-bold uppercase tracking-wider text-slate-500">
                        Filename
                      </th>
                      <th className="text-left px-4 py-3 text-[10px] font-bold uppercase tracking-wider text-slate-500">
                        SHA-256
                      </th>
                      <th className="text-left px-4 py-3 text-[10px] font-bold uppercase tracking-wider text-slate-500">
                        Size
                      </th>
                      <th className="text-left px-4 py-3 text-[10px] font-bold uppercase tracking-wider text-slate-500">
                        Collected
                      </th>
                      <th className="px-4 py-3"></th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 dark:divide-slate-800/50">
                    {items.map((e, idx) => (
                      <tr
                        key={e.id}
                        className={`hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors group ${
                          idx % 2 === 0 ? "bg-slate-50/30 dark:bg-slate-900/20" : ""
                        }`}
                      >
                        <td className="px-4 py-3">
                          <Link
                            href={`/analysis/${e.id}`}
                            className="text-cyan-700 dark:text-cyan-400 hover:text-cyan-600 dark:hover:text-cyan-300 font-bold transition-colors"
                          >
                            {e.evidence_id}
                          </Link>
                        </td>
                        <td className="px-4 py-3 max-w-[200px] truncate text-slate-800 dark:text-slate-300">
                          <Link href={`/analysis/${e.id}`} className="hover:text-cyan-600 dark:hover:text-white transition-colors font-medium">
                            {e.original_filename}
                          </Link>
                        </td>
                        <td className="px-4 py-3 min-w-0">
                          <CopyableValue value={e.sha256} truncate />
                        </td>
                        <td className="px-4 py-3 text-slate-600 dark:text-slate-400 whitespace-nowrap">
                          {formatBytes(e.size_bytes)}
                        </td>
                        <td className="px-4 py-3 text-slate-500 whitespace-nowrap">
                          {new Date(e.collected_at).toLocaleString()}
                        </td>
                        <td className="px-4 py-3">
                          <Link
                            href={`/analysis/${e.id}`}
                            className="opacity-0 group-hover:opacity-100 flex items-center gap-1 text-cyan-600 dark:text-cyan-400 text-[10px] transition-opacity font-mono font-bold"
                          >
                            Inspect <ArrowRight className="h-3 w-3" />
                          </Link>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
