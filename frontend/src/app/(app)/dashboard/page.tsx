"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  AlertOctagon,
  AlertTriangle,
  FolderOpen,
  Radar,
  Upload,
  ArrowUpRight,
  Mail,
  ShieldCheck,
  TrendingUp,
  Activity,
  Layers,
  ArrowRight,
  Clock,
  Sparkles,
  Zap,
  Globe2
} from "lucide-react";

import { PageHeader } from "@/components/shell/page-header";
import { RiskMeter } from "@/components/cybersentry/risk-meter";
import { CampaignStateBadge } from "@/components/cybersentry/campaign-state-badge";
import { Button } from "@/components/ui/button";
import { ErrorState } from "@/components/cybersentry/error-state";
import { EmptyState } from "@/components/cybersentry/empty-state";
import { api } from "@/lib/api";
import type { DashboardStats, Campaign } from "@/types/api";
import type { Severity, CampaignState } from "@/types";

function severityFromScore(score: number): Severity {
  if (score >= 85) return "critical";
  if (score >= 65) return "high";
  if (score >= 35) return "medium";
  if (score > 0) return "low";
  return "informational";
}

function campaignStateFor(state: string): CampaignState {
  const s = state.toLowerCase();
  if (s === "expanding") return "expanding";
  if (s === "active") return "active";
  if (s === "emerging" || s === "candidate") return "emerging";
  return "monitoring";
}

export default function DashboardPage() {
  const [stats, setStats] = useState<any | null>(null);
  const [campaigns, setCampaigns] = useState<Campaign[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    Promise.all([api.getDashboardStats(), api.listCampaigns().catch(() => [])])
      .then(([s, c]) => {
        if (cancelled) return;
        setStats(s);
        setCampaigns(c);
      })
      .catch((err) => {
        if (!cancelled) setError(err.message || "Failed to load dashboard data.");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const activeCampaigns = campaigns
    .filter((c) => ["ACTIVE", "EXPANDING", "EMERGING"].includes(c.state))
    .slice(0, 5);

  return (
    <div className="flex flex-col space-y-8 pb-16">
      <PageHeader
        section="SOC Workspace"
        title="Threat Intelligence Dashboard"
        description="Real-time email forensic analysis, polymorphic campaign tracking, and origin attribution."
        meta={[
          { label: "Cluster Engine", value: "PhishDNA Active" },
          { label: "Indexed Samples", value: `${stats?.total_analyzed || 0} Emails` },
        ]}
        actions={
          <div className="flex items-center gap-3">
            <Button variant="outline" asChild className="hidden sm:inline-flex border-slate-300 dark:border-slate-700">
              <Link href="/campaigns">
                <Radar className="h-3.5 w-3.5 mr-1.5" />
                Campaign Explorer
              </Link>
            </Button>
            <Button asChild className="bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white shadow-md shadow-cyan-500/20 font-semibold font-mono text-xs">
              <Link href="/analyze">
                <Upload className="h-3.5 w-3.5 mr-1.5" />
                Analyze New Email
              </Link>
            </Button>
          </div>
        }
      />

      {error && (
        <ErrorState
          title="Could not load dashboard data"
          description={error}
          action={
            <Button size="sm" variant="outline" onClick={() => window.location.reload()}>
              Retry
            </Button>
          }
        />
      )}

      {/* TOP KPI CARDS - SPACIOUS & COLOR GRADED */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 sm:gap-6">
        {/* Scanned Emails */}
        <div className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/90 p-5 sm:p-6 shadow-sm hover:shadow-md transition-shadow relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">
              Total Scanned Emails
            </span>
            <div className="p-2.5 rounded-xl bg-blue-50 dark:bg-blue-950/60 text-blue-600 dark:text-cyan-400 border border-blue-100 dark:border-blue-900">
              <Mail className="h-5 w-5" />
            </div>
          </div>
          <div className="text-3xl font-extrabold font-mono text-slate-900 dark:text-white mt-3">
            {stats ? stats.total_analyzed : "—"}
          </div>
          <div className="flex items-center gap-1.5 mt-3 text-xs text-emerald-600 dark:text-emerald-400 font-medium">
            <TrendingUp className="h-3.5 w-3.5" />
            <span>100% SHA-256 Custody Verified</span>
          </div>
        </div>

        {/* Critical Findings */}
        <div className="rounded-2xl border border-rose-200 dark:border-rose-900/40 bg-white dark:bg-slate-900/90 p-5 sm:p-6 shadow-sm hover:shadow-md transition-shadow relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono font-bold uppercase tracking-wider text-rose-600 dark:text-rose-400">
              Critical Findings
            </span>
            <div className="p-2.5 rounded-xl bg-rose-50 dark:bg-rose-950/60 text-rose-600 dark:text-rose-400 border border-rose-100 dark:border-rose-900">
              <AlertOctagon className="h-5 w-5" />
            </div>
          </div>
          <div className="text-3xl font-extrabold font-mono text-rose-600 dark:text-rose-400 mt-3">
            {stats ? stats.critical_findings : "—"}
          </div>
          <div className="flex items-center gap-1.5 mt-3 text-xs text-rose-600 dark:text-rose-400 font-medium">
            <span>High Severity Threats</span>
          </div>
        </div>

        {/* Active Campaigns */}
        <div className="rounded-2xl border border-indigo-200 dark:border-indigo-900/40 bg-white dark:bg-slate-900/90 p-5 sm:p-6 shadow-sm hover:shadow-md transition-shadow relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono font-bold uppercase tracking-wider text-indigo-600 dark:text-indigo-400">
              Active Campaigns
            </span>
            <div className="p-2.5 rounded-xl bg-indigo-50 dark:bg-indigo-950/60 text-indigo-600 dark:text-indigo-400 border border-indigo-100 dark:border-indigo-900">
              <Radar className="h-5 w-5" />
            </div>
          </div>
          <div className="text-3xl font-extrabold font-mono text-indigo-600 dark:text-indigo-400 mt-3">
            {stats ? stats.active_campaigns : "—"}
          </div>
          <div className="flex items-center gap-1.5 mt-3 text-xs text-indigo-600 dark:text-indigo-400 font-medium">
            <span>PhishDNA Correlation Active</span>
          </div>
        </div>

        {/* High Severity Signals */}
        <div className="rounded-2xl border border-amber-200 dark:border-amber-900/40 bg-white dark:bg-slate-900/90 p-5 sm:p-6 shadow-sm hover:shadow-md transition-shadow relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono font-bold uppercase tracking-wider text-amber-600 dark:text-amber-400">
              High-Risk Signals
            </span>
            <div className="p-2.5 rounded-xl bg-amber-50 dark:bg-amber-950/60 text-amber-600 dark:text-amber-400 border border-amber-100 dark:border-amber-900">
              <AlertTriangle className="h-5 w-5" />
            </div>
          </div>
          <div className="text-3xl font-extrabold font-mono text-amber-600 dark:text-amber-400 mt-3">
            {stats ? stats.high_findings : "—"}
          </div>
          <div className="flex items-center gap-1.5 mt-3 text-xs text-amber-600 dark:text-amber-400 font-medium">
            <span>Urgency & Spoofing Flags</span>
          </div>
        </div>
      </div>

      {/* MAIN CONTENT TWO-COLUMN GRID */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        {/* LEFT COLUMN: Recent Forensic Ingestion Queue (7 cols) */}
        <div className="lg:col-span-7 space-y-6">
          <div className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/80 p-6 shadow-sm">
            <div className="flex items-center justify-between mb-6 pb-4 border-b border-slate-100 dark:border-slate-800">
              <div>
                <h3 className="text-base font-bold text-slate-900 dark:text-white tracking-tight flex items-center gap-2">
                  <Activity className="h-4 w-4 text-cyan-500" />
                  Recent Email Forensics Triage
                </h3>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                  Latest parsed message streams, risk scores, and intent classification
                </p>
              </div>
              <Link
                href="/emails"
                className="text-xs font-bold text-cyan-600 dark:text-cyan-400 hover:underline flex items-center gap-1 font-mono"
              >
                View all &rarr;
              </Link>
            </div>

            {loading ? (
              <div className="py-12 text-center text-xs text-slate-400 font-mono">
                Loading telemetry queue...
              </div>
            ) : !stats?.recent_analyses || stats.recent_analyses.length === 0 ? (
              <EmptyState
                icon={Mail}
                title="No emails analyzed yet"
                description="Upload an .eml or .msg file to trigger deep forensic inspection."
                action={
                  <Button asChild size="sm" className="mt-2 font-mono text-xs">
                    <Link href="/analyze">Analyze an Email</Link>
                  </Button>
                }
              />
            ) : (
              <div className="space-y-3.5">
                {stats.recent_analyses.map((item: any) => (
                  <Link
                    key={item.id}
                    href={`/analysis/${item.id}`}
                    className="group block rounded-xl border border-slate-200 dark:border-slate-800/80 bg-slate-50/50 dark:bg-slate-950/60 p-4 hover:border-cyan-500/50 dark:hover:border-cyan-500/50 hover:bg-white dark:hover:bg-slate-900/90 transition-all shadow-sm hover:shadow"
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2 mb-1.5">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase tracking-wider ${
                              item.risk_band === "CRITICAL" || item.risk_band === "HIGH"
                                ? "bg-rose-100 text-rose-700 dark:bg-rose-950/80 dark:text-rose-400 border border-rose-200 dark:border-rose-900"
                                : item.risk_band === "MEDIUM"
                                ? "bg-amber-100 text-amber-700 dark:bg-amber-950/80 dark:text-amber-400 border border-amber-200 dark:border-amber-900"
                                : "bg-emerald-100 text-emerald-700 dark:bg-emerald-950/80 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-900"
                            }`}
                          >
                            {item.risk_band} RISK
                          </span>
                          <span className="text-[11px] font-mono text-slate-400">
                            {item.analyzed_at ? new Date(item.analyzed_at).toLocaleDateString() : ""}
                          </span>
                        </div>

                        <h4 className="text-sm font-bold text-slate-900 dark:text-white truncate group-hover:text-cyan-600 dark:group-hover:text-cyan-400 transition-colors">
                          {item.subject || "(No Subject)"}
                        </h4>

                        <div className="flex items-center gap-3 mt-2 text-xs text-slate-500 dark:text-slate-400 font-mono">
                          <span className="truncate">Sender: {item.sender}</span>
                          {item.intent && item.intent !== "BENIGN_COMMUNICATION" && (
                            <span className="hidden sm:inline text-purple-400">• {item.intent}</span>
                          )}
                        </div>
                      </div>

                      <div className="shrink-0 flex flex-col items-end gap-1.5">
                        <div className="flex items-center gap-2">
                          <RiskMeter score={item.risk_score} severity={severityFromScore(item.risk_score)} />
                          <span className="font-mono text-xs font-bold text-slate-700 dark:text-slate-200">
                            {item.risk_score?.toFixed(0)}/100
                          </span>
                        </div>
                        <span className="text-[10px] font-mono text-slate-400 group-hover:text-cyan-500 transition-colors flex items-center gap-0.5">
                          Inspect <ArrowRight className="h-3 w-3" />
                        </span>
                      </div>
                    </div>
                  </Link>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* RIGHT COLUMN: Active Campaign Clusters (5 cols) */}
        <div className="lg:col-span-5 space-y-6">
          <div className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/80 p-6 shadow-sm">
            <div className="flex items-center justify-between mb-6 pb-4 border-b border-slate-100 dark:border-slate-800">
              <div>
                <h3 className="text-base font-bold text-slate-900 dark:text-white tracking-tight flex items-center gap-2">
                  <Radar className="h-4 w-4 text-indigo-500" />
                  Correlated Campaigns
                </h3>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                  PhishDNA clustered attack operations
                </p>
              </div>
              <Link
                href="/campaigns"
                className="text-xs font-bold text-indigo-600 dark:text-indigo-400 hover:underline flex items-center gap-1 font-mono"
              >
                All campaigns &rarr;
              </Link>
            </div>

            {loading ? (
              <div className="py-12 text-center text-xs text-slate-400 font-mono">
                Correlating clusters...
              </div>
            ) : activeCampaigns.length === 0 ? (
              <EmptyState
                icon={Radar}
                title="No active campaigns"
                description="Campaign clusters form automatically when polymorphic variants share attack DNA."
              />
            ) : (
              <div className="space-y-4">
                {activeCampaigns.map((camp) => (
                  <Link
                    key={camp.id}
                    href={`/campaigns/${camp.id}`}
                    className="group block rounded-xl border border-slate-200 dark:border-slate-800/80 bg-slate-50/50 dark:bg-slate-950/60 p-4 hover:border-indigo-500/50 dark:hover:border-indigo-500/50 hover:bg-white dark:hover:bg-slate-900 transition-all shadow-sm"
                  >
                    <div className="flex items-center justify-between mb-2">
                      <CampaignStateBadge state={campaignStateFor(camp.state)} />
                      <span className="text-[11px] font-mono text-slate-400">
                        {camp.member_count} {camp.member_count === 1 ? "variant" : "variants"}
                      </span>
                    </div>

                    <h4 className="text-sm font-bold text-slate-900 dark:text-white group-hover:text-indigo-600 dark:group-hover:text-indigo-400 transition-colors">
                      {camp.name}
                    </h4>

                    {camp.primary_intent && (
                      <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 line-clamp-2 font-mono">
                        Intent: {camp.primary_intent}
                      </p>
                    )}

                    <div className="flex items-center justify-between mt-3 pt-3 border-t border-slate-200/60 dark:border-slate-800/60 text-[11px] font-mono text-slate-400">
                      <span>Strength: {camp.relationship_strength || "HIGH"}</span>
                      <span className="group-hover:text-indigo-500 transition-colors flex items-center gap-1">
                        Explore <ArrowUpRight className="h-3 w-3" />
                      </span>
                    </div>
                  </Link>
                ))}
              </div>
            )}
          </div>

          {/* Quick Tools & Shortcuts */}
          <div className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-gradient-to-br from-slate-50 via-slate-100 to-blue-50 dark:from-slate-900 dark:via-slate-950 dark:to-cyan-950/30 p-5 shadow-sm">
            <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-700 dark:text-slate-300 mb-3 flex items-center gap-2">
              <Zap className="h-3.5 w-3.5 text-cyan-500" /> Quick Forensic Utilities
            </h4>
            <div className="grid grid-cols-2 gap-2.5">
              <Link
                href="/ip-locator"
                className="p-3 rounded-xl border border-slate-200 dark:border-slate-800 bg-white/80 dark:bg-slate-900/80 hover:border-cyan-500 text-left transition-colors"
              >
                <div className="text-xs font-bold text-slate-900 dark:text-white flex items-center gap-1.5">
                  <Globe2 className="h-3.5 w-3.5 text-cyan-500" /> IP Geolocation
                </div>
                <div className="text-[10px] text-slate-500 dark:text-slate-400 font-mono mt-0.5">
                  Trace relay ASNs
                </div>
              </Link>

              <Link
                href="/compare"
                className="p-3 rounded-xl border border-slate-200 dark:border-slate-800 bg-white/80 dark:bg-slate-900/80 hover:border-indigo-500 text-left transition-colors"
              >
                <div className="text-xs font-bold text-slate-900 dark:text-white flex items-center gap-1.5">
                  <Layers className="h-3.5 w-3.5 text-indigo-500" /> DNA Diff Tool
                </div>
                <div className="text-[10px] text-slate-500 dark:text-slate-400 font-mono mt-0.5">
                  Compare polymorphic variants
                </div>
              </Link>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
