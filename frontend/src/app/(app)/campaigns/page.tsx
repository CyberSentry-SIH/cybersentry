'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import {
  Layers, Activity, GitCompare, TrendingUp, TrendingDown,
  Minus, Clock, ChevronRight, Target, ArrowRight,
  Globe, FileText, Compass, AlertCircle, Zap, Database
} from 'lucide-react';
import { api } from '@/lib/api';
import { Campaign } from '@/types/api';
import { PageHeader } from '@/components/shell/page-header';

function StateBadge({ state }: { state: string }) {
  const cfg: Record<string, { cls: string; label: string }> = {
    EXPANDING: { cls: "bg-rose-100 text-rose-800 border-rose-300 dark:bg-rose-950/60 dark:border-rose-900/50 dark:text-rose-400", label: "EXPANDING" },
    ACTIVE:    { cls: "bg-amber-100 text-amber-800 border-amber-300 dark:bg-amber-950/60 dark:border-amber-900/50 dark:text-amber-400", label: "ACTIVE" },
    EMERGING:  { cls: "bg-yellow-100 text-yellow-800 border-yellow-300 dark:bg-yellow-950/60 dark:border-yellow-900/50 dark:text-yellow-400", label: "EMERGING" },
    CANDIDATE: { cls: "bg-blue-100 text-blue-800 border-blue-300 dark:bg-blue-950/60 dark:border-blue-900/50 dark:text-blue-400", label: "CANDIDATE" },
  };
  const c = cfg[state] ?? { cls: "bg-slate-100 text-slate-700 border-slate-300 dark:bg-slate-800 dark:border-slate-700 dark:text-slate-400", label: "MONITORING" };
  return (
    <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${c.cls}`}>
      {c.label}
    </span>
  );
}

function TrendIcon({ trend }: { trend: string }) {
  if (trend === 'INCREASING') return <TrendingUp className="h-3.5 w-3.5 text-rose-500" />;
  if (trend === 'DECREASING') return <TrendingDown className="h-3.5 w-3.5 text-emerald-500" />;
  return <Minus className="h-3.5 w-3.5 text-slate-400" />;
}

export default function CampaignsPage() {
  const [campaigns, setCampaigns] = useState<Campaign[]>([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<Campaign | null>(null);

  useEffect(() => {
    api.listCampaigns()
      .then((res) => { setCampaigns(res); if (res.length > 0) setSelected(res[0]); })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="flex flex-col min-h-full pb-16">
      <PageHeader
        section="Threat Intelligence"
        title="Campaign Correlation Intelligence"
        description="Evidence-based campaign clustering across normalized PhishDNA semantic vectors, intent cues, and infrastructure IOCs."
        meta={[{ label: "Active Clusters", value: String(campaigns.length) }]}
        actions={
          <Link href="/compare" className="btn-secondary text-xs">
            <GitCompare className="h-3.5 w-3.5" />
            Variant Diff
          </Link>
        }
      />

      <div className="p-6">
        {loading ? (
          <div className="rounded-2xl border border-slate-300 dark:border-slate-800 bg-white dark:bg-slate-900/60 p-12 text-center shadow-sm">
            <div className="h-6 w-6 animate-spin rounded-full border-2 border-cyan-500 border-t-transparent mx-auto mb-3" />
            <p className="text-xs font-mono text-slate-500">Loading correlated campaign clusters…</p>
          </div>
        ) : campaigns.length === 0 ? (
          <div className="rounded-2xl border border-slate-300 dark:border-slate-800 bg-white dark:bg-slate-900/60 p-12 flex flex-col items-center gap-4 text-center shadow-sm">
            <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700">
              <Layers className="h-6 w-6 text-slate-400 dark:text-slate-500" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-900 dark:text-white font-mono">No Threat Campaigns Detected</h3>
              <p className="text-xs text-slate-500 font-mono mt-1 max-w-sm">
                Analyze 2 or more related phishing emails to trigger evidence-based campaign correlation.
              </p>
            </div>
            <Link href="/analyze" className="btn-primary text-xs mt-2">
              <FileText className="h-3.5 w-3.5" />
              Upload Forensic Email
            </Link>
          </div>
        ) : (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
            {/* Campaign list */}
            <div className="lg:col-span-1 space-y-2">
              <p className="text-[10px] font-mono font-bold uppercase tracking-widest text-slate-500 dark:text-slate-400 mb-3">
                Correlated Clusters · {campaigns.length}
              </p>
              {campaigns.map((camp) => {
                const isSel = selected?.id === camp.id;
                return (
                  <div
                    key={camp.id}
                    onClick={() => setSelected(camp)}
                    className={`rounded-xl border p-3.5 cursor-pointer transition-all duration-150 ${
                      isSel
                        ? 'border-cyan-500 bg-cyan-50 dark:bg-cyan-950/40 shadow-sm'
                        : 'border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/60 hover:border-slate-300 dark:hover:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-900'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-1.5">
                      <span className={`font-mono text-[11px] font-bold ${isSel ? 'text-cyan-700 dark:text-cyan-400' : 'text-slate-500 dark:text-slate-400'}`}>
                        {camp.campaign_key}
                      </span>
                      <StateBadge state={camp.state} />
                    </div>
                    <h3 className="text-sm font-bold text-slate-900 dark:text-white leading-snug">{camp.name}</h3>
                    <div className="mt-2.5 pt-2 border-t border-slate-100 dark:border-slate-800/60 flex items-center justify-between text-[11px] font-mono text-slate-500">
                      <span className="flex items-center gap-1">
                        <FileText className="h-3 w-3" />
                        <strong className="text-slate-700 dark:text-slate-300">{camp.member_count}</strong> payloads
                      </span>
                      <span className="flex items-center gap-1">
                        Trend: <TrendIcon trend={camp.risk_trend} />
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Campaign detail */}
            <div className="lg:col-span-2">
              {selected ? (
                <div className="rounded-2xl border border-slate-300 dark:border-slate-800 bg-white dark:bg-slate-900/80 shadow-sm overflow-hidden transition-colors duration-200">
                  {/* Detail header */}
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 px-5 py-4 border-b border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-900">
                    <div>
                      <div className="flex items-center gap-2 mb-1">
                        <span className="text-cyan-700 dark:text-cyan-400 font-mono text-[11px] font-bold">{selected.campaign_key}</span>
                        <StateBadge state={selected.state} />
                      </div>
                      <h2 className="text-base font-bold text-slate-900 dark:text-white font-mono">{selected.name}</h2>
                    </div>
                    <Link href={`/campaigns/${selected.id}`} className="btn-primary text-xs shrink-0">
                      <Compass className="h-3.5 w-3.5" />
                      Investigate
                      <ArrowRight className="h-3.5 w-3.5" />
                    </Link>
                  </div>

                  {/* Metrics grid */}
                  <div className="grid grid-cols-2 sm:grid-cols-4 divide-x divide-y divide-slate-100 dark:divide-slate-800 border-b border-slate-200 dark:border-slate-800">
                    {[
                      { label: "Rel. Strength", value: selected.relationship_strength || "N/A", color: "text-cyan-700 dark:text-cyan-400" },
                      { label: "Payloads", value: String(selected.member_count), color: "text-blue-700 dark:text-blue-400" },
                      { label: "Risk Trend", value: selected.risk_trend, color: "text-amber-700 dark:text-amber-400" },
                      { label: "First Seen", value: selected.first_seen ? selected.first_seen.substring(0, 10) : "Recent", color: "text-slate-700 dark:text-slate-300" },
                    ].map((m) => (
                      <div key={m.label} className="px-4 py-3 text-center">
                        <p className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-500">{m.label}</p>
                        <p className={`text-sm font-bold font-mono mt-0.5 ${m.color}`}>{m.value}</p>
                      </div>
                    ))}
                  </div>

                  {/* Members */}
                  <div className="p-5 space-y-3">
                    <div className="flex items-center justify-between">
                      <h3 className="text-[10px] font-mono font-bold uppercase tracking-widest text-slate-500 flex items-center gap-2">
                        <Layers className="h-3.5 w-3.5 text-cyan-600 dark:text-cyan-400" />
                        Correlated Payloads ({selected.members?.length || 0})
                      </h3>
                      <Link href={`/campaigns/${selected.id}`} className="text-[11px] font-mono text-cyan-700 dark:text-cyan-400 hover:underline flex items-center gap-1 transition-colors">
                        Full Dossier <ChevronRight className="h-3 w-3" />
                      </Link>
                    </div>

                    {selected.members && selected.members.length > 0 ? (
                      <div className="rounded-xl border border-slate-200 dark:border-slate-800 overflow-hidden divide-y divide-slate-200 dark:divide-slate-800/60">
                        {selected.members.map((m: any, idx: number) => (
                          <div key={m.email_id || idx} className="flex items-center justify-between gap-4 px-4 py-3 hover:bg-slate-50 dark:hover:bg-slate-800/40 transition-colors">
                            <div className="min-w-0 space-y-0.5">
                              <div className="flex items-center gap-2 flex-wrap">
                                <span className="font-bold text-sm text-slate-900 dark:text-white truncate max-w-[200px]">
                                  {m.subject || 'No Subject'}
                                </span>
                                {m.similarity_score == null ? (
                                  <span className="px-2 py-0.5 rounded text-[9px] font-mono font-bold bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-400">
                                    ANCHOR BASELINE
                                  </span>
                                ) : (
                                  <span className="px-2 py-0.5 rounded text-[9px] font-mono font-bold bg-cyan-100 text-cyan-800 dark:bg-cyan-950/60 dark:border-cyan-900/50 dark:text-cyan-400 border border-cyan-300">
                                    {Math.round(m.similarity_score)}% DNA MATCH
                                  </span>
                                )}
                              </div>
                              <p className="text-[11px] font-mono text-slate-500">
                                From: {m.sender}
                                {m.relationship_reason && ` · ${Array.isArray(m.relationship_reason) ? m.relationship_reason[0] : m.relationship_reason}`}
                              </p>
                            </div>
                            <Link href={`/analysis/${m.email_id}`} className="btn-secondary text-[10px] shrink-0">
                              Forensics
                            </Link>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="rounded-xl border border-slate-200 dark:border-slate-800 p-6 text-center text-xs font-mono text-slate-500 bg-slate-50 dark:bg-slate-900/40">
                        No members registered in this cluster yet.
                      </div>
                    )}

                    {/* Timeline */}
                    {selected.events && selected.events.length > 0 && (
                      <div className="space-y-3 pt-2">
                        <h3 className="text-[10px] font-mono font-bold uppercase tracking-widest text-slate-500 flex items-center gap-2">
                          <Clock className="h-3.5 w-3.5 text-blue-600 dark:text-blue-400" />
                          State Evolution ({selected.events.length})
                        </h3>
                        <div className="pl-3 border-l-2 border-slate-200 dark:border-slate-800 ml-1 space-y-4">
                          {selected.events.map((ev: any, i: number) => (
                            <div key={ev.id || i} className="relative pl-4 text-xs font-mono">
                              <span className="absolute -left-[21px] top-1 h-2.5 w-2.5 rounded-full bg-cyan-600 ring-4 ring-white dark:ring-slate-900" />
                              <div className="flex items-center gap-2">
                                <span className="font-bold text-slate-900 dark:text-white">{ev.event_type}</span>
                                <span className="text-[10px] text-slate-500">
                                  {ev.event_time ? ev.event_time.substring(0, 19).replace('T', ' ') : ''}
                                </span>
                              </div>
                              <p className="text-slate-500 text-[11px] mt-0.5">{ev.summary}</p>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              ) : (
                <div className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/60 p-12 text-center text-xs font-mono text-slate-500">
                  Select a campaign from the list to view its evolution timeline.
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
