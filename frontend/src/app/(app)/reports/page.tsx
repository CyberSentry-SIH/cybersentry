'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { FileText, Download, ShieldCheck, Upload, Clock, Hash } from 'lucide-react';
import { api } from '@/lib/api';
import { PageHeader } from '@/components/shell/page-header';

export default function ReportsPage() {
  const [evidenceList, setEvidenceList] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.listEvidence()
      .then((res) => setEvidenceList(res))
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="flex flex-col min-h-full pb-16">
      <PageHeader
        section="Reporting"
        title="Forensic Evidence Reports"
        description="On-demand immutable forensic reports generated per evidence item. Reports are only generated when you explicitly request them."
        meta={[{ label: "Evidence Items", value: String(evidenceList.length) }]}
        actions={
          <Link href="/analyze" className="btn-primary text-xs">
            <Upload className="h-3.5 w-3.5" />
            Submit Evidence
          </Link>
        }
      />

      <div className="p-6 space-y-4">
        {/* Info banner */}
        <div className="rounded-xl border border-cyan-200 dark:border-cyan-900/30 bg-cyan-50 dark:bg-cyan-950/20 px-4 py-3 flex items-start gap-3 shadow-sm">
          <ShieldCheck className="h-4 w-4 text-cyan-600 dark:text-cyan-400 shrink-0 mt-0.5" />
          <p className="text-xs font-mono text-cyan-800 dark:text-cyan-300">
            Reports are generated on-demand only — click the PDF button on a row to generate and download a forensic dossier for that specific email.
          </p>
        </div>

        {/* Table */}
        <div className="rounded-2xl border border-slate-300 dark:border-slate-800 bg-white dark:bg-slate-900/80 shadow-sm overflow-hidden transition-colors duration-200">
          <div className="flex items-center justify-between px-4 py-3 border-b border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-900">
            <div className="flex items-center gap-2">
              <FileText className="h-4 w-4 text-cyan-600 dark:text-cyan-400" />
              <span className="text-xs font-mono font-bold text-slate-800 dark:text-white uppercase tracking-wider">
                Evidence Dossier Registry
              </span>
            </div>
            <span className="text-[11px] font-mono text-slate-500">{evidenceList.length} items</span>
          </div>

          {loading ? (
            <div className="py-14 flex flex-col items-center gap-3">
              <div className="h-6 w-6 animate-spin rounded-full border-2 border-cyan-500 border-t-transparent mx-auto mb-3" />
              <p className="text-xs font-mono text-slate-500">Loading forensic dossiers…</p>
            </div>
          ) : evidenceList.length === 0 ? (
            <div className="py-16 flex flex-col items-center gap-4 text-center">
              <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700">
                <FileText className="h-6 w-6 text-slate-400 dark:text-slate-500" />
              </div>
              <div>
                <p className="text-sm font-bold text-slate-900 dark:text-white font-mono">No Evidence Submitted Yet</p>
                <p className="text-xs text-slate-500 font-mono mt-1">
                  Submit a .eml file to generate your first forensic dossier.
                </p>
              </div>
              <Link href="/analyze" className="btn-primary text-xs mt-2">
                <Upload className="h-3.5 w-3.5" />
                Analyze Email
              </Link>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-xs font-mono">
                <thead>
                  <tr className="border-b border-slate-200 dark:border-slate-800/80 bg-slate-50/50 dark:bg-slate-900/50">
                    {["Evidence ID", "Filename", "SHA-256 Digest", "Collected Date", ""].map((h, i) => (
                      <th key={i} className={`text-left px-4 py-3 text-[10px] font-bold uppercase tracking-wider text-slate-500 ${i === 4 ? 'text-right' : ''}`}>
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-800/50">
                  {evidenceList.map((e, idx) => (
                    <tr
                      key={e.id}
                      className={`hover:bg-slate-50 dark:hover:bg-slate-800/40 transition-colors group ${
                        idx % 2 === 0 ? 'bg-slate-50/30 dark:bg-slate-900/20' : ''
                      }`}
                    >
                      <td className="px-4 py-3.5 text-cyan-700 dark:text-cyan-400 font-bold">{e.evidence_id}</td>
                      <td className="px-4 py-3.5 text-slate-800 dark:text-slate-300 font-bold max-w-[200px] truncate">
                        <Link href={`/analysis/${e.id}`} className="hover:text-cyan-600 dark:hover:text-white transition-colors">
                          {e.original_filename}
                        </Link>
                      </td>
                      <td className="px-4 py-3.5 text-slate-500 text-[11px] truncate max-w-[180px]">
                        {e.sha256}
                      </td>
                      <td className="px-4 py-3.5 text-slate-500 whitespace-nowrap">
                        {e.collected_at ? e.collected_at.substring(0, 10) : 'Recent'}
                      </td>
                      <td className="px-4 py-3.5 text-right">
                        <div className="flex items-center justify-end gap-2">
                          <Link
                            href={`/analysis/${e.id}`}
                            className="btn-secondary text-[10px]"
                          >
                            Inspect
                          </Link>
                          <a
                            href={api.getPdfReportUrl(e.id)}
                            download={`${e.evidence_id}_dossier.pdf`}
                            className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-cyan-100 text-cyan-800 dark:bg-cyan-950/60 dark:text-cyan-400 border border-cyan-300 dark:border-cyan-900/50 text-[10px] font-mono font-bold hover:bg-cyan-200 dark:hover:bg-cyan-900/80 transition-colors cursor-pointer"
                          >
                            <Download className="h-3 w-3" />
                            PDF
                          </a>
                        </div>
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
