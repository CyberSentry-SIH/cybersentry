'use client';

import React, { useState, useEffect } from 'react';
import { GitCompare, ArrowRight, CheckCircle2, AlertTriangle, Layers, ArrowLeftRight, Loader2 } from 'lucide-react';
import { api } from '@/lib/api';
import { PageHeader } from '@/components/shell/page-header';

export default function ComparePage() {
  const [emails, setEmails] = useState<any[]>([]);
  const [emailA, setEmailA] = useState('');
  const [emailB, setEmailB] = useState('');
  const [diffResult, setDiffResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    api.listEvidence()
      .then((evList) => {
        const formatted = evList.map((e: any) => ({
          id: e.id,
          evidence_id: e.evidence_id,
          filename: e.original_filename
        }));
        setEmails(formatted);
        if (formatted.length >= 2) {
          setEmailA(formatted[0].id);
          setEmailB(formatted[1].id);
        }
      })
      .catch(console.error);
  }, []);

  const handleCompare = async () => {
    if (!emailA || !emailB || emailA === emailB) return;
    setLoading(true);
    try {
      const res = await api.compareEmails(emailA, emailB);
      setDiffResult(res);
    } catch (err: any) {
      alert(err.message || 'Comparison failed');
    } finally {
      setLoading(false);
    }
  };

  const selectClass = "w-full bg-slate-50 dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-xl p-3 text-xs text-slate-900 dark:text-slate-200 focus:outline-none focus:border-cyan-600 font-mono transition-colors hover:border-slate-400 dark:hover:border-slate-600";

  return (
    <div className="flex flex-col min-h-full pb-16">
      <PageHeader
        section="Analysis"
        title="Variant Differential Analysis"
        description='Differential analysis across polymorphic email variants &amp; shared campaign infrastructure — "What Changed?"'
      />

      <div className="p-6 space-y-6">
        {/* Selector Card */}
        <div className="rounded-2xl border border-slate-300 dark:border-slate-800 bg-white dark:bg-slate-900/80 shadow-sm p-5 space-y-5 transition-colors duration-200">
          <div className="grid grid-cols-1 md:grid-cols-5 gap-4 items-end">
            <div className="md:col-span-2">
              <label className="block text-[10px] font-mono font-bold uppercase tracking-widest text-slate-500 mb-2">
                Baseline — Variant A
              </label>
              <select value={emailA} onChange={(e) => setEmailA(e.target.value)} className={selectClass}>
                {emails.map((em) => (
                  <option key={em.id} value={em.id} className="bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-200">
                    {em.evidence_id} · {em.filename}
                  </option>
                ))}
              </select>
            </div>

            <div className="flex justify-center">
              <div className="h-10 w-10 rounded-full bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 flex items-center justify-center shadow-inner">
                <ArrowLeftRight className="h-4 w-4 text-cyan-600 dark:text-cyan-400" />
              </div>
            </div>

            <div className="md:col-span-2">
              <label className="block text-[10px] font-mono font-bold uppercase tracking-widest text-slate-500 mb-2">
                Mutation — Variant B
              </label>
              <select value={emailB} onChange={(e) => setEmailB(e.target.value)} className={selectClass}>
                {emails.map((em) => (
                  <option key={em.id} value={em.id} className="bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-200">
                    {em.evidence_id} · {em.filename}
                  </option>
                ))}
              </select>
            </div>
          </div>

          {emails.length === 0 && (
            <p className="text-xs font-mono text-slate-500 text-center py-2">
              No emails analyzed yet — submit evidence to compare variants.
            </p>
          )}

          <div className="flex justify-end pt-1 border-t border-slate-200 dark:border-slate-800">
            <button
              onClick={handleCompare}
              disabled={loading || emailA === emailB || !emailA || !emailB}
              className="btn-primary text-xs disabled:opacity-40 disabled:cursor-not-allowed"
            >
              {loading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <GitCompare className="h-3.5 w-3.5" />}
              {loading ? 'Comparing…' : 'Run Differential Analysis'}
              {!loading && <ArrowRight className="h-3.5 w-3.5" />}
            </button>
          </div>
        </div>

        {/* Results */}
        {diffResult && (
          <div className="space-y-5">
            {/* Similarity banner */}
            <div className="rounded-2xl border border-emerald-300 dark:border-emerald-900/40 bg-gradient-to-r from-emerald-50 via-teal-50 to-white dark:from-slate-900 dark:via-emerald-950/20 dark:to-slate-900 p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4 shadow-sm">
              <div>
                <p className="text-[10px] font-mono font-bold uppercase tracking-widest text-slate-500">Campaign Correlation Status</p>
                <p className="text-sm font-bold text-slate-900 dark:text-white mt-0.5 flex items-center gap-2">
                  <CheckCircle2 className="h-4 w-4 text-emerald-600 dark:text-emerald-400" />
                  {diffResult.campaign_relationship}
                </p>
              </div>
              <div className="text-right">
                <p className="text-4xl font-extrabold font-mono text-emerald-600 dark:text-emerald-400">{diffResult.similarity_score}%</p>
                <p className="text-[10px] font-mono text-slate-500 uppercase tracking-wider mt-0.5">PhishDNA Similarity</p>
              </div>
            </div>

            {/* Side-by-side variant cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {[
                { label: "VARIANT A", color: "cyan", data: diffResult.email_a, tag: "BASELINE",
                  from: diffResult.differences.from_a, domain: diffResult.differences.domain_a,
                  reply: diffResult.differences.reply_to_a, intent: diffResult.differences.intent_a },
                { label: "VARIANT B", color: "violet", data: diffResult.email_b, tag: "MUTATION",
                  from: diffResult.differences.from_b, domain: diffResult.differences.domain_b,
                  reply: diffResult.differences.reply_to_b, intent: diffResult.differences.intent_b },
              ].map(({ label, color, data, tag, from, domain, reply, intent }) => (
                <div key={label} className="rounded-2xl border border-slate-300 dark:border-slate-800 bg-white dark:bg-slate-900/70 p-4 font-mono text-xs space-y-3 shadow-sm">
                  <div className="flex items-center justify-between pb-2.5 border-b border-slate-200 dark:border-slate-800">
                    <span className="font-bold text-cyan-700 dark:text-cyan-400">{label}: {data.evidence_id}</span>
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-cyan-100 text-cyan-800 dark:bg-cyan-950/60 dark:text-cyan-400 border border-cyan-300 dark:border-cyan-900/50">{tag}</span>
                  </div>
                  {[
                    { k: "Subject", v: data.subject },
                    { k: "Sender", v: from },
                    { k: "Domain", v: domain },
                    { k: "Reply-To", v: reply || "None" },
                    { k: "Attack Intent", v: intent, highlight: true },
                  ].map(({ k, v, highlight }) => (
                    <div key={k}>
                      <span className="text-[9px] font-bold uppercase tracking-wider text-slate-500 block">{k}:</span>
                      <span className={highlight ? "text-rose-600 dark:text-rose-400 font-bold" : "text-slate-800 dark:text-slate-300"}>{v}</span>
                    </div>
                  ))}
                </div>
              ))}
            </div>

            {/* Mutated surface features */}
            <div className="rounded-2xl border border-slate-300 dark:border-rose-900/30 bg-white dark:bg-slate-900/70 p-5 space-y-4 shadow-sm">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <h3 className="text-xs font-mono font-bold uppercase tracking-widest text-slate-900 dark:text-white flex items-center gap-2">
                    <AlertTriangle className="h-4 w-4 text-rose-600 dark:text-rose-400" />
                    Surface Mutations &amp; Forensic Interpretation
                  </h3>
                  <p className="text-[11px] text-slate-500 font-mono mt-0.5">
                    What changed across variants and why it matters forensically
                  </p>
                </div>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-100 text-rose-800 dark:bg-rose-950/60 dark:border-rose-900/50 dark:text-rose-400 shrink-0">
                  OBSERVED VARIATION
                </span>
              </div>
              <div className="rounded-xl border border-slate-200 dark:border-slate-800 overflow-hidden divide-y divide-slate-200 dark:divide-slate-800/60">
                {(diffResult.mutated_surface_features || []).map((feat: any, idx: number) => (
                  <div key={idx} className="p-4 space-y-2 hover:bg-slate-50 dark:hover:bg-slate-800/30 transition-colors">
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-slate-900 dark:text-white font-mono text-xs">{feat.feature}</span>
                      {feat.changed ? (
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-100 text-rose-800 dark:bg-rose-950/60 dark:border-rose-900/50 dark:text-rose-400">MUTATED</span>
                      ) : (
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400">UNMODIFIED</span>
                      )}
                    </div>
                    <div className="grid grid-cols-2 gap-2 text-[11px] font-mono bg-slate-50 dark:bg-slate-950/60 p-2.5 rounded-lg border border-slate-200 dark:border-slate-800">
                      <div>
                        <span className="text-[9px] uppercase font-bold text-slate-500 block">Variant A</span>
                        <span className="text-slate-600 dark:text-slate-400 truncate block">{String(feat.variant_a)}</span>
                      </div>
                      <div>
                        <span className="text-[9px] uppercase font-bold text-slate-500 block">Variant B</span>
                        <span className="text-slate-900 dark:text-slate-200 font-bold truncate block">{String(feat.variant_b)}</span>
                      </div>
                    </div>
                    {feat.interpretation && (
                      <div className="p-2.5 rounded-lg bg-cyan-50 dark:bg-cyan-950/20 border border-cyan-200 dark:border-cyan-900/30 text-[11px] font-mono text-cyan-800 dark:text-cyan-300">
                        <span className="font-bold text-cyan-700 dark:text-cyan-400">Forensic Interpretation: </span>
                        {feat.interpretation}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>

            {/* Invariants + Infrastructure */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <div className="rounded-2xl border border-slate-300 dark:border-emerald-900/30 bg-white dark:bg-slate-900/70 p-5 space-y-3 shadow-sm">
                <h3 className="text-xs font-mono font-bold uppercase tracking-widest text-slate-900 dark:text-white flex items-center gap-2">
                  <CheckCircle2 className="h-4 w-4 text-emerald-600 dark:text-emerald-400" />
                  Retained Attack Invariants
                </h3>
                <p className="text-[11px] text-slate-500 font-mono">Core adversary intent, target brand &amp; strategy recognized by PhishDNA</p>
                <div className="rounded-xl border border-slate-200 dark:border-slate-800 overflow-hidden divide-y divide-slate-200 dark:divide-slate-800/60">
                  {(diffResult.retained_attack_invariants || []).map((inv: any, idx: number) => (
                    <div key={idx} className="p-3.5 flex items-center justify-between gap-3 hover:bg-slate-50 dark:hover:bg-slate-800/30 transition-colors">
                      <div>
                        <div className="text-[9px] text-slate-500 uppercase font-bold font-mono">{inv.invariant}</div>
                        <div className="text-emerald-700 dark:text-emerald-400 font-bold text-xs mt-0.5 font-mono">{inv.value}</div>
                      </div>
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-100 text-emerald-800 dark:bg-emerald-950/60 dark:border-emerald-900/50 dark:text-emerald-400 shrink-0">
                        INVARIANT
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="rounded-2xl border border-slate-300 dark:border-blue-900/30 bg-white dark:bg-slate-900/70 p-5 space-y-3 shadow-sm">
                <h3 className="text-xs font-mono font-bold uppercase tracking-widest text-slate-900 dark:text-white flex items-center gap-2">
                  <Layers className="h-4 w-4 text-blue-600 dark:text-blue-400" />
                  Infrastructure Relationships
                </h3>
                <p className="text-[11px] text-slate-500 font-mono">Corroborating origin IPs, /24 subnets, and host overlaps</p>
                <div className="rounded-xl border border-slate-200 dark:border-slate-800 overflow-hidden divide-y divide-slate-200 dark:divide-slate-800/60">
                  {(diffResult.infrastructure_relationships || []).map((infra: any, idx: number) => (
                    <div key={idx} className="p-3.5 flex items-center justify-between gap-3 hover:bg-slate-50 dark:hover:bg-slate-800/30 transition-colors">
                      <div>
                        <div className="text-[9px] text-slate-500 uppercase font-bold font-mono">{infra.relationship_type}</div>
                        <div className="text-slate-800 dark:text-slate-300 font-bold text-xs mt-0.5 font-mono">{infra.evidence}</div>
                      </div>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border shrink-0 ${
                        infra.matched
                          ? 'bg-blue-100 text-blue-800 border-blue-300 dark:bg-blue-950/60 dark:border-blue-900/50 dark:text-blue-400'
                          : 'bg-slate-100 text-slate-600 border-slate-300 dark:bg-slate-800 dark:border-slate-700 dark:text-slate-500'
                      }`}>
                        {infra.strength}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Shared indicators */}
            {diffResult.shared_indicators?.length > 0 && (
              <div className="rounded-2xl border border-slate-300 dark:border-slate-800 bg-white dark:bg-slate-900/70 p-5 space-y-3 shadow-sm">
                <h3 className="text-xs font-mono font-bold uppercase tracking-widest text-slate-900 dark:text-white flex items-center gap-2">
                  <Layers className="h-4 w-4 text-cyan-600 dark:text-cyan-400" />
                  Shared Campaign Artifacts &amp; IOCs ({diffResult.shared_indicators.length})
                </h3>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
                  {diffResult.shared_indicators.map((ind: any, i: number) => (
                    <div key={i} className="rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/40 p-3 font-mono text-xs">
                      <div className="text-[9px] text-cyan-700 dark:text-cyan-400 font-bold uppercase tracking-wider">{ind.type}</div>
                      <div className="text-slate-800 dark:text-slate-300 font-bold truncate mt-0.5">{ind.value}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
