"use client";

import { useRef, useState } from "react";
import Link from "next/link";
import {
  UploadCloud, ShieldCheck, ArrowRight, Loader2, FileText,
  Shield, Clock, Hash, HardDrive, AlertTriangle, CheckCircle2
} from "lucide-react";

import { PageHeader } from "@/components/shell/page-header";
import { CopyableValue } from "@/components/cybersentry/copyable-value";
import { api } from "@/lib/api";
import type { Evidence } from "@/types/api";
import { formatBytes } from "@/lib/utils";

export default function AnalyzePage() {
  const inputRef = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [evidence, setEvidence] = useState<Evidence | null>(null);

  async function handleFile(file: File | null | undefined) {
    if (!file) return;
    setError(null);
    setEvidence(null);
    if (!file.name.toLowerCase().endsWith(".eml")) {
      setError("Only .eml files are accepted.");
      return;
    }
    setUploading(true);
    try {
      const res = await api.uploadEml(file);
      setEvidence(res);
    } catch (err: any) {
      setError(err.message || "Upload failed.");
    } finally {
      setUploading(false);
    }
  }

  return (
    <div className="flex flex-col min-h-full pb-16">
      <PageHeader
        section="Evidence Intake"
        title="Email Forensic Analysis"
        description="Submit a suspicious .eml file to trigger automated forensic inspection, threat scoring, and campaign correlation."
        meta={[{ label: "Accepted Format", value: ".eml (RFC 5322)" }]}
      />

      <div className="mx-auto flex w-full max-w-2xl flex-col gap-6 p-6">
        {/* Upload Zone */}
        <div
          onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
          onDragLeave={() => setDragging(false)}
          onDrop={(e) => { e.preventDefault(); setDragging(false); handleFile(e.dataTransfer.files?.[0]); }}
          className={`relative flex flex-col items-center gap-4 rounded-2xl border-2 border-dashed py-14 text-center transition-all cursor-pointer ${
            dragging
              ? "border-cyan-500/80 bg-cyan-100/50 dark:bg-cyan-950/20 shadow-lg"
              : "border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800/70 hover:border-cyan-500 hover:bg-slate-50 dark:hover:bg-slate-800"
          }`}
          onClick={() => inputRef.current?.click()}
        >
          {/* Corner markers */}
          <span className="absolute left-3 top-3 h-4 w-4 border-l-2 border-t-2 border-cyan-600 dark:border-cyan-500/50 rounded-tl" />
          <span className="absolute right-3 top-3 h-4 w-4 border-r-2 border-t-2 border-cyan-600 dark:border-cyan-500/50 rounded-tr" />
          <span className="absolute bottom-3 left-3 h-4 w-4 border-b-2 border-l-2 border-cyan-600 dark:border-cyan-500/50 rounded-bl" />
          <span className="absolute bottom-3 right-3 h-4 w-4 border-b-2 border-r-2 border-cyan-600 dark:border-cyan-500/50 rounded-br" />

          <div className={`flex h-16 w-16 items-center justify-center rounded-2xl transition-all ${
            uploading
              ? "bg-cyan-100 dark:bg-cyan-950/60 border border-cyan-300 dark:border-cyan-800"
              : dragging
              ? "bg-cyan-200 dark:bg-cyan-900/40 border border-cyan-400"
              : "bg-slate-100 dark:bg-slate-700/60 border border-slate-200 dark:border-slate-600"
          }`}>
            {uploading ? (
              <Loader2 className="h-7 w-7 animate-spin text-cyan-600 dark:text-cyan-400" />
            ) : (
              <UploadCloud className={`h-7 w-7 ${dragging ? "text-cyan-600 dark:text-cyan-300" : "text-slate-500 dark:text-slate-400"}`} />
            )}
          </div>

          <div>
            <p className="text-base font-bold text-slate-900 dark:text-white font-mono">
              {uploading ? "Analyzing email…" : dragging ? "Release to analyze" : "Drop .eml file here"}
            </p>
            <p className="mt-1 text-sm text-slate-500 dark:text-slate-400 font-mono">
              {uploading ? "Running forensic engines, PhishDNA fingerprinting…" : "or click to browse from your workstation"}
            </p>
          </div>

          <input
            ref={inputRef}
            type="file"
            accept=".eml"
            className="hidden"
            onChange={(e) => handleFile(e.target.files?.[0])}
          />

          <button
            type="button"
            disabled={uploading}
            onClick={(e) => { e.stopPropagation(); inputRef.current?.click(); }}
            className="btn-primary mt-2 text-xs font-mono disabled:opacity-50"
          >
            <FileText className="h-3.5 w-3.5" />
            {uploading ? "Processing…" : "Browse Files"}
          </button>
        </div>

        {/* Capability badges */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[
            { label: "SPF/DKIM/DMARC", icon: Shield, bg: "bg-cyan-50 dark:bg-cyan-950/30", border: "border-cyan-200 dark:border-cyan-900/40", text: "text-cyan-700 dark:text-cyan-400" },
            { label: "PhishDNA Match", icon: Hash, bg: "bg-indigo-50 dark:bg-indigo-950/30", border: "border-indigo-200 dark:border-indigo-900/40", text: "text-indigo-700 dark:text-indigo-400" },
            { label: "Relay Path Trace", icon: ArrowRight, bg: "bg-blue-50 dark:bg-blue-950/30", border: "border-blue-200 dark:border-blue-900/40", text: "text-blue-700 dark:text-blue-400" },
            { label: "Campaign Link", icon: AlertTriangle, bg: "bg-amber-50 dark:bg-amber-950/30", border: "border-amber-200 dark:border-amber-900/40", text: "text-amber-700 dark:text-amber-400" },
          ].map(({ label, icon: Icon, bg, border, text }) => (
            <div key={label} className={`rounded-xl border ${border} ${bg} p-3 text-center`}>
              <Icon className={`h-4 w-4 ${text} mx-auto mb-1`} />
              <p className={`text-[10px] font-mono font-bold ${text} uppercase tracking-wider`}>{label}</p>
            </div>
          ))}
        </div>

        {error ? (
          <div className="rounded-xl border border-rose-300 dark:border-rose-900/50 bg-rose-50 dark:bg-rose-950/30 p-4 flex items-start gap-3">
            <AlertTriangle className="h-4 w-4 text-rose-600 dark:text-rose-400 shrink-0 mt-0.5" />
            <div>
              <p className="text-xs font-bold text-rose-700 dark:text-rose-300 font-mono">Upload Failed</p>
              <p className="text-xs text-rose-600 dark:text-rose-400 mt-0.5">{error}</p>
            </div>
          </div>
        ) : null}

        {evidence ? (
          <>
            {/* Evidence Card */}
            <div className="rounded-2xl border border-emerald-300 dark:border-emerald-900/40 bg-white dark:bg-slate-800/80 overflow-hidden shadow-md">
              <div className="flex items-center gap-3 px-5 py-4 border-b border-slate-200 dark:border-slate-700">
                <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-emerald-100 dark:bg-emerald-950/60 border border-emerald-300 dark:border-emerald-900/50">
                  <CheckCircle2 className="h-4 w-4 text-emerald-600 dark:text-emerald-400" />
                </div>
                <div>
                  <h2 className="text-sm font-bold text-slate-900 dark:text-white font-mono">Evidence Preserved</h2>
                  <p className="text-[11px] text-slate-500 dark:text-slate-400 font-mono">SHA-256 custody chain initialized</p>
                </div>
              </div>

              <dl className="divide-y divide-slate-200 dark:divide-slate-700/60">
                {[
                  { label: "Evidence ID", value: evidence.evidence_id, icon: Hash },
                  { label: "Filename", value: evidence.original_filename, icon: FileText },
                  { label: "Size", value: formatBytes(evidence.size_bytes), icon: HardDrive },
                  { label: "MIME Type", value: evidence.mime_type, icon: Shield },
                  { label: "Received At", value: new Date(evidence.collected_at).toLocaleString(), icon: Clock },
                ].map(({ label, value, icon: Icon }) => (
                  <div key={label} className="flex items-center justify-between gap-4 px-5 py-3">
                    <dt className="flex items-center gap-2 text-[11px] font-mono font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                      <Icon className="h-3.5 w-3.5" />
                      {label}
                    </dt>
                    <dd className="font-mono text-xs text-slate-800 dark:text-slate-300 truncate max-w-[280px]">{value}</dd>
                  </div>
                ))}
                <div className="flex items-center justify-between gap-4 px-5 py-3">
                  <dt className="flex items-center gap-2 text-[11px] font-mono font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                    <Shield className="h-3.5 w-3.5" />
                    SHA-256
                  </dt>
                  <dd className="min-w-0">
                    <CopyableValue value={evidence.sha256} truncate />
                  </dd>
                </div>
              </dl>
            </div>

            <div className="flex items-center gap-3 rounded-xl border border-emerald-300 dark:border-emerald-900/30 bg-emerald-50 dark:bg-emerald-950/20 px-4 py-3">
              <ShieldCheck className="h-4 w-4 shrink-0 text-emerald-600 dark:text-emerald-400" />
              <p className="text-xs font-mono text-emerald-800 dark:text-emerald-300">
                Analysis pipeline triggered automatically. Evidence hash retained in chain-of-custody.
              </p>
            </div>

            <Link
              href={`/analysis/${evidence.id}`}
              className="btn-primary self-end text-xs font-mono"
            >
              View Forensic Report
              <ArrowRight className="h-3.5 w-3.5" />
            </Link>
          </>
        ) : null}
      </div>
    </div>
  );
}
