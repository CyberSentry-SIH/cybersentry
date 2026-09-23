'use client';

import React, { useState, useEffect } from 'react';
import { useParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import {
  Layers,
  Activity,
  GitCompare,
  TrendingUp,
  TrendingDown,
  Minus,
  Clock,
  ChevronRight,
  ShieldAlert,
  AlertTriangle,
  Crosshair,
  Target,
  Zap,
  Globe,
  FileText,
  ArrowLeft,
  CheckCircle2,
  Lock,
  Download,
  Fingerprint,
  Cpu,
  Share2,
  Server,
  Terminal,
  Shield,
  ExternalLink,
  Copy,
  Check,
  Info
} from 'lucide-react';
import { api } from '@/lib/api';
import { CampaignInvestigation } from '@/types/api';

export default function CampaignInvestigationPage() {
  const params = useParams();
  const router = useRouter();
  const id = params.id as string;

  const [investigation, setInvestigation] = useState<CampaignInvestigation | null>(null);
  const [loading, setLoading] = useState(true);
  const [selectedPairIndex, setSelectedPairIndex] = useState(0);
  const [copiedText, setCopiedText] = useState<string | null>(null);

  useEffect(() => {
    if (id) {
      setLoading(true);
      api.getCampaignInvestigation(id)
        .then((data) => {
          setInvestigation(data);
        })
        .catch((err) => {
          console.error('Error fetching campaign investigation:', err);
        })
        .finally(() => setLoading(false));
    }
  }, [id]);

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(text);
    setTimeout(() => setCopiedText(null), 2000);
  };

  const getStateBadge = (state: string) => {
    switch (state) {
      case 'EXPANDING':
        return <span className="badge-critical px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold">EXPANDING ACTIVITY</span>;
      case 'ACTIVE':
        return <span className="badge-high px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold">ACTIVE CAMPAIGN</span>;
      case 'EMERGING':
        return <span className="badge-medium px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold">EMERGING VARIANT</span>;
      case 'CANDIDATE':
        return <span className="badge-low px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold">CANDIDATE BASELINE</span>;
      default:
        return <span className="badge-low px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold">{state}</span>;
    }
  };

  const getTrendIcon = (trend: string) => {
    switch (trend) {
      case 'INCREASING':
        return <TrendingUp className="w-4 h-4 text-rose-500" />;
      case 'DECREASING':
        return <TrendingDown className="w-4 h-4 text-emerald-500" />;
      default:
        return <Minus className="w-4 h-4 text-slate-400" />;
    }
  };

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[400px] space-y-3">
        <div className="w-10 h-10 rounded-full border-2 border-cyan-500 border-t-transparent animate-spin" />
        <div className="text-center">
          <p className="text-sm font-semibold text-slate-800 dark:text-slate-200">Assembling Unified Campaign Investigation</p>
          <p className="text-xs text-slate-500 dark:text-slate-400 font-mono mt-0.5">Correlating variants, extracting indicators & evaluating invariant semantics...</p>
        </div>
      </div>
    );
  }

  if (!investigation) {
    return (
      <div className="text-center py-16 max-w-md mx-auto">
        <div className="w-12 h-12 rounded-2xl bg-rose-50 dark:bg-rose-950/50 border border-rose-200 dark:border-rose-900/50 text-rose-600 dark:text-rose-400 flex items-center justify-center mx-auto mb-4 shadow-sm">
          <AlertTriangle className="w-6 h-6" />
        </div>
        <h2 className="text-base font-bold text-slate-900 dark:text-white">Campaign Not Found</h2>
        <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">The requested campaign dossier could not be located in the repository.</p>
        <Link href="/campaigns" className="btn-secondary text-xs mt-4 inline-flex items-center gap-1.5 font-mono">
          <ArrowLeft className="w-3.5 h-3.5" /> Return to Campaign Intelligence
        </Link>
      </div>
    );
  }

  const activePair = investigation.variance_timeline[selectedPairIndex];

  return (
    <div className="space-y-7 max-w-7xl mx-auto pb-16 animate-fade-in">
      {/* Breadcrumb & Navigation */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center gap-2 text-xs font-mono text-slate-500 dark:text-slate-400">
          <Link href="/campaigns" className="hover:text-cyan-600 dark:hover:text-cyan-400 flex items-center gap-1.5 transition-colors">
            <ArrowLeft className="h-3.5 w-3.5" /> Campaigns
          </Link>
          <span className="text-slate-300 dark:text-slate-700">/</span>
          <span className="text-slate-700 dark:text-slate-300 font-medium">Investigation</span>
          <span className="text-slate-300 dark:text-slate-700">/</span>
          <span className="text-cyan-600 dark:text-cyan-400 font-bold truncate max-w-[200px]">
            {investigation.campaign_key}
          </span>
        </div>

        <div className="flex items-center gap-3">
          {investigation.evidence_refs && investigation.evidence_refs.length > 0 && (
            <a
              href={api.getPdfReportUrl(investigation.evidence_refs[0])}
              target="_blank"
              rel="noreferrer"
              className="btn-primary text-xs font-semibold py-2 px-3.5"
            >
              <Download className="h-3.5 w-3.5" />
              Export Forensic Dossier
            </a>
          )}
        </div>
      </div>

      {/* Campaign Banner Header */}
      <div className="rounded-2xl p-6 sm:p-7 bg-gradient-to-r from-cyan-50/50 via-white to-slate-50/50 dark:from-cyan-950/30 dark:via-slate-900/90 dark:to-slate-900 border border-cyan-200 dark:border-cyan-900/40 space-y-4 shadow-sm transition-colors duration-200">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-2.5">
              <span className="font-mono text-xs font-bold text-cyan-700 dark:text-cyan-300 bg-cyan-100/80 dark:bg-cyan-950/80 px-2.5 py-0.5 rounded-full border border-cyan-200 dark:border-cyan-800">
                {investigation.campaign_key}
              </span>
              {getStateBadge(investigation.state)}
              <span className="text-xs font-mono text-slate-500 dark:text-slate-400 flex items-center gap-1.5 bg-white dark:bg-slate-800/90 px-2.5 py-0.5 rounded-full border border-slate-200 dark:border-slate-700 shadow-xs">
                Risk Trend: {getTrendIcon(investigation.risk_trend)} <strong className="text-slate-800 dark:text-slate-200">{investigation.risk_trend}</strong>
              </span>
            </div>
            <h1 className="text-2xl font-bold text-slate-900 dark:text-white tracking-tight">
              {investigation.name}
            </h1>
            <p className="text-xs text-slate-600 dark:text-slate-400 font-mono">
              Orchestrated Campaign Investigation: Extract Indicators → Correlate Payloads → Explain Mutations → Validate Invariants
            </p>
          </div>

          <div className="flex items-center gap-4 bg-white dark:bg-slate-800/90 border border-slate-200 dark:border-slate-700/80 rounded-2xl p-4 shadow-sm flex-shrink-0 font-mono">
            <div className="text-center">
              <span className="text-[10px] text-slate-400 dark:text-slate-500 block uppercase font-bold">Relationship Strength</span>
              <span className="text-xl font-bold text-cyan-600 dark:text-cyan-400 mt-0.5 block">
                {investigation.relationship_strength || 'Correlated'}
              </span>
            </div>
            <div className="h-8 w-px bg-slate-200 dark:bg-slate-700" />
            <div className="text-center">
              <span className="text-[10px] text-slate-400 dark:text-slate-500 block uppercase font-bold">Observed Payloads</span>
              <span className="text-xl font-bold text-slate-900 dark:text-white mt-0.5 block">
                {investigation.member_count}
              </span>
            </div>
          </div>
        </div>

        {/* Framing Notice */}
        <div className="p-3.5 rounded-xl bg-cyan-100/60 dark:bg-cyan-950/40 border border-cyan-200 dark:border-cyan-800/60 text-xs font-mono text-cyan-900 dark:text-cyan-200 flex items-center gap-2.5">
          <Info className="w-4 h-4 text-cyan-600 dark:text-cyan-400 flex-shrink-0" />
          <span>
            <strong>Investigation Scope:</strong> Campaign detection and correlation occurred during message ingestion. This dossier performs deep forensic analysis across the established cluster.
          </span>
        </div>
      </div>

      {/* SECTION 1: Correlated Payloads (Emails) */}
      <div className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/90 p-6 space-y-4 shadow-sm">
        <div className="flex items-center justify-between">
          <h2 className="text-xs font-bold text-slate-900 dark:text-white uppercase font-mono tracking-wider flex items-center gap-2">
            <Layers className="w-4 h-4 text-cyan-500" />
            Correlated Payloads & Polymorphic Variants ({investigation.related_emails.length})
          </h2>
          <span className="text-xs font-mono text-slate-500 dark:text-slate-400">
            Multi-Family Evidence Corroborated
          </span>
        </div>

        <div className="border border-slate-200 dark:border-slate-800 rounded-xl overflow-hidden divide-y divide-slate-100 dark:divide-slate-800/80 bg-white dark:bg-slate-900/80">
          {investigation.related_emails.map((em, idx) => (
            <div key={em.email_id || idx} className="p-4 bg-white dark:bg-slate-900/80 hover:bg-slate-50/80 dark:hover:bg-slate-800/50 flex flex-col md:flex-row md:items-center justify-between gap-4 text-xs font-mono transition-colors">
              <div className="space-y-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="w-6 h-6 rounded-md bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 flex items-center justify-center font-bold text-[11px]">
                    #{idx + 1}
                  </span>
                  <span className="font-bold text-slate-900 dark:text-white font-sans text-sm truncate">
                    {em.subject || 'Untitled Suspicious Payload'}
                  </span>
                  {em.evidence_id && (
                    <span className="text-[10px] px-2 py-0.5 rounded bg-cyan-50 dark:bg-cyan-950/60 text-cyan-700 dark:text-cyan-300 font-bold border border-cyan-200 dark:border-cyan-800">
                      {em.evidence_id}
                    </span>
                  )}
                </div>
                <div className="text-[11px] text-slate-500 dark:text-slate-400 flex flex-wrap items-center gap-x-4 gap-y-1 pl-8">
                  <span>From: <strong className="text-slate-700 dark:text-slate-300">{em.from_address || 'Unknown'}</strong></span>
                  {em.sent_at && <span>Seen: {em.sent_at.substring(0, 19).replace('T', ' ')} UTC</span>}
                </div>
                {em.relationship_reason && em.relationship_reason.length > 0 && (
                  <div className="pl-8 pt-1 text-[11px] text-slate-600 dark:text-slate-400 flex flex-wrap gap-1">
                    {em.relationship_reason.map((r: string, rIdx: number) => (
                      <span key={rIdx} className="bg-slate-100 dark:bg-slate-800 px-2 py-0.5 rounded text-[10px] text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-700">
                        • {r}
                      </span>
                    ))}
                  </div>
                )}
              </div>

              <div className="flex items-center gap-2 shrink-0 self-end md:self-center">
                <Link
                  href={`/analysis/${em.email_id}`}
                  className="btn-secondary text-[11px] py-1.5 px-3"
                >
                  Forensic Breakdown <ChevronRight className="w-3.5 h-3.5" />
                </Link>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* SECTION 2: Retained Attack Invariants vs Infrastructure Relationships */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Card A: Retained Attack Invariants */}
        <div className="rounded-2xl border border-emerald-200 dark:border-emerald-900/40 bg-emerald-50/20 dark:bg-emerald-950/20 p-6 space-y-4 shadow-sm">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-xs font-bold text-slate-900 dark:text-white uppercase font-mono tracking-wider flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-500" />
                Retained Attack Invariants (Semantic Layer)
              </h2>
              <p className="text-[11px] text-slate-500 dark:text-slate-400 font-mono mt-0.5">
                Core adversary objectives and social engineering tactics preserved across mutations
              </p>
            </div>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-100 dark:bg-emerald-950/80 text-emerald-800 dark:text-emerald-300 font-bold border border-emerald-200 dark:border-emerald-800">
              PhishDNA Invariants
            </span>
          </div>

          <div className="border border-slate-200 dark:border-slate-800 rounded-xl overflow-hidden divide-y divide-slate-200 dark:divide-slate-800 bg-white dark:bg-slate-900/80 font-mono text-xs">
            {investigation.attack_invariants && investigation.attack_invariants.length > 0 ? (
              investigation.attack_invariants.map((inv, idx) => (
                <div key={idx} className="p-3.5 flex items-center justify-between gap-3 hover:bg-slate-50 dark:hover:bg-slate-800/50">
                  <div>
                    <div className="text-[10px] text-slate-400 dark:text-slate-500 uppercase font-bold">{inv.invariant}</div>
                    <div className="text-emerald-700 dark:text-emerald-400 font-bold text-xs mt-0.5">{inv.value}</div>
                  </div>
                  <span className="px-2.5 py-0.5 rounded text-[10px] font-bold bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800 shrink-0">
                    INVARIANT PRESERVED
                  </span>
                </div>
              ))
            ) : (
              <div className="p-4 text-center text-slate-400 dark:text-slate-500">Baseline attack invariants being established...</div>
            )}
          </div>
        </div>

        {/* Card B: Infrastructure Relationships */}
        <div className="rounded-2xl border border-cyan-200 dark:border-cyan-900/40 bg-cyan-50/20 dark:bg-cyan-950/20 p-6 space-y-4 shadow-sm">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-xs font-bold text-slate-900 dark:text-white uppercase font-mono tracking-wider flex items-center gap-2">
                <Server className="w-4 h-4 text-cyan-500" />
                Infrastructure Relationships (Physical/Network Layer)
              </h2>
              <p className="text-[11px] text-slate-500 dark:text-slate-400 font-mono mt-0.5">
                Corroborating network hosting, IP routing, and domain infrastructure linkages
              </p>
            </div>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-cyan-100 dark:bg-cyan-950/80 text-cyan-800 dark:text-cyan-300 font-bold border border-cyan-200 dark:border-cyan-800">
              Corroborating Evidence
            </span>
          </div>

          <div className="border border-slate-200 dark:border-slate-800 rounded-xl overflow-hidden divide-y divide-slate-200 dark:divide-slate-800 bg-white dark:bg-slate-900/80 font-mono text-xs">
            {investigation.infrastructure_relationships && investigation.infrastructure_relationships.length > 0 ? (
              investigation.infrastructure_relationships.map((infra, idx) => (
                <div key={idx} className="p-3.5 flex items-center justify-between gap-3 hover:bg-slate-50 dark:hover:bg-slate-800/50">
                  <div>
                    <div className="text-[10px] text-slate-400 dark:text-slate-500 uppercase font-bold">{infra.relationship_type}</div>
                    <div className="text-slate-900 dark:text-white font-bold text-xs mt-0.5">{infra.evidence}</div>
                  </div>
                  <span className={`px-2.5 py-0.5 rounded text-[10px] font-bold border shrink-0 ${
                    infra.matched
                      ? 'bg-cyan-50 dark:bg-cyan-950/60 text-cyan-700 dark:text-cyan-300 border-cyan-200 dark:border-cyan-800'
                      : 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 border-slate-200 dark:border-slate-700'
                  }`}>
                    {infra.strength}
                  </span>
                </div>
              ))
            ) : (
              <div className="p-4 text-center text-slate-400 dark:text-slate-500">Evaluating infrastructure relationships...</div>
            )}
          </div>
        </div>
      </div>

      {/* SECTION 3: Differential Variant Variance & Interpretations */}
      {investigation.variance_timeline && investigation.variance_timeline.length > 0 && (
        <div className="rounded-2xl border border-rose-200 dark:border-rose-900/40 bg-gradient-to-br from-rose-50/20 via-white to-amber-50/20 dark:from-rose-950/20 dark:via-slate-900/90 dark:to-amber-950/20 p-6 space-y-5 shadow-sm">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-200 dark:border-slate-800">
            <div>
              <div className="flex items-center gap-2">
                <GitCompare className="w-4 h-4 text-rose-500" />
                <h2 className="text-xs font-bold text-slate-900 dark:text-white uppercase font-mono tracking-wider">
                  Differential Variant Analysis & Meaning Behind Changes
                </h2>
              </div>
              <p className="text-[11px] text-slate-500 dark:text-slate-400 font-mono mt-0.5">
                Surface mutations consistent with campaign variation or evasion vs. invariant core
              </p>
            </div>

            {investigation.variance_timeline.length > 1 && (
              <div className="flex items-center gap-2 font-mono text-xs">
                <span className="text-slate-500 dark:text-slate-400 text-[11px]">Variant Pair:</span>
                {investigation.variance_timeline.map((_, i) => (
                  <button
                    key={i}
                    onClick={() => setSelectedPairIndex(i)}
                    className={`px-3 py-1 rounded-lg font-bold transition-all ${
                      selectedPairIndex === i
                        ? 'bg-rose-600 dark:bg-rose-500 text-white shadow-sm'
                        : 'bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-700'
                    }`}
                  >
                    Pair #{i + 1}
                  </button>
                ))}
              </div>
            )}
          </div>

          {activePair && (
            <div className="space-y-4">
              <div className="flex items-center justify-between font-mono text-xs bg-slate-50 dark:bg-slate-800/60 p-3 rounded-xl border border-slate-200 dark:border-slate-700">
                <div>
                  <span className="text-slate-400 dark:text-slate-500 block text-[10px] uppercase font-bold">Comparison Context</span>
                  <span className="font-bold text-slate-800 dark:text-slate-200">
                    {activePair.from_evidence_id || activePair.from_email_id.substring(0, 8)} ↔ {activePair.to_evidence_id || activePair.to_email_id.substring(0, 8)}
                  </span>
                </div>
                <div className="text-right">
                  <span className="text-slate-400 dark:text-slate-500 block text-[10px] uppercase font-bold">Pair Relationship Strength</span>
                  <span className="font-bold text-rose-600 dark:text-rose-400">
                    {activePair.relationship_strength || `${activePair.similarity_score}%`}
                  </span>
                </div>
              </div>

              {/* Mutations & Forensic Interpretations */}
              <div className="border border-slate-200 dark:border-slate-800 rounded-xl overflow-hidden divide-y divide-slate-200 dark:divide-slate-800 bg-white dark:bg-slate-900/80 font-mono text-xs">
                {activePair.mutated_surface_features.map((feat, idx) => (
                  <div key={idx} className="p-4 space-y-2 hover:bg-slate-50/60 dark:hover:bg-slate-800/60">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-slate-900 dark:text-white text-xs">{feat.feature}</span>
                        {feat.changed ? (
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-50 dark:bg-rose-950/60 text-rose-700 dark:text-rose-300 border border-rose-200 dark:border-rose-900/50">
                            MUTATED
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300">
                            UNMODIFIED
                          </span>
                        )}
                      </div>
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-[11px] bg-slate-50 dark:bg-slate-800/60 p-2.5 rounded-lg border border-slate-200 dark:border-slate-700">
                      <div>
                        <span className="text-slate-400 dark:text-slate-500 block text-[9px] uppercase font-bold">Variant A Baseline</span>
                        <span className="text-slate-700 dark:text-slate-300 font-semibold">{feat.variant_a}</span>
                      </div>
                      <div>
                        <span className="text-slate-400 dark:text-slate-500 block text-[9px] uppercase font-bold">Variant B Mutation</span>
                        <span className="text-slate-900 dark:text-white font-semibold">{feat.variant_b}</span>
                      </div>
                    </div>

                    <div className="p-2.5 rounded-lg bg-cyan-50/60 dark:bg-cyan-950/40 border border-cyan-100 dark:border-cyan-900/50 text-[11px] text-cyan-900 dark:text-cyan-200">
                      <span className="font-bold text-cyan-700 dark:text-cyan-300">Forensic Interpretation: </span>
                      {feat.interpretation}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* SECTION 4: Scoped Campaign Indicators (Extracted IOC Telemetry) */}
      <div className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/90 p-6 space-y-5 shadow-sm">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-xs font-bold text-slate-900 dark:text-white uppercase font-mono tracking-wider flex items-center gap-2">
              <Crosshair className="w-4 h-4 text-cyan-500" />
              Campaign Indicator Extraction (Scoped IOC Profile)
            </h2>
            <p className="text-[11px] text-slate-500 dark:text-slate-400 font-mono mt-0.5">
              Aggregated IOC telemetry across all corroborated campaign members for firewall & gateway blocklists
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 font-mono text-xs">
          {/* Sender Domains */}
          <div className="p-4 rounded-xl bg-slate-50/80 dark:bg-slate-800/50 border border-slate-200 dark:border-slate-700/60 space-y-2">
            <span className="text-[10px] text-slate-400 dark:text-slate-500 uppercase font-bold block">
              Observed Sender Domains ({investigation.indicators.sender_domains.length})
            </span>
            <div className="space-y-1.5 max-h-36 overflow-y-auto">
              {investigation.indicators.sender_domains.map((d, i) => (
                <div key={i} className="flex items-center justify-between bg-white dark:bg-slate-900/90 p-2 rounded-lg border border-slate-200 dark:border-slate-700 text-[11px]">
                  <span className="text-slate-900 dark:text-white font-bold truncate">{d}</span>
                  <button onClick={() => copyToClipboard(d)} className="text-slate-400 dark:text-slate-500 hover:text-cyan-600 dark:hover:text-cyan-400 p-1">
                    {copiedText === d ? <Check className="w-3 h-3 text-emerald-500" /> : <Copy className="w-3 h-3" />}
                  </button>
                </div>
              ))}
            </div>
          </div>

          {/* Infrastructure IPs */}
          <div className="p-4 rounded-xl bg-slate-50/80 dark:bg-slate-800/50 border border-slate-200 dark:border-slate-700/60 space-y-2">
            <span className="text-[10px] text-slate-400 dark:text-slate-500 uppercase font-bold block">
              Origin Infrastructure IPs ({investigation.indicators.infrastructure_ips.length})
            </span>
            <div className="space-y-1.5 max-h-36 overflow-y-auto">
              {investigation.indicators.infrastructure_ips.map((ip, i) => (
                <div key={i} className="flex items-center justify-between bg-white dark:bg-slate-900/90 p-2 rounded-lg border border-slate-200 dark:border-slate-700 text-[11px]">
                  <span className="text-cyan-600 dark:text-cyan-400 font-bold truncate">{ip}</span>
                  <button onClick={() => copyToClipboard(ip)} className="text-slate-400 dark:text-slate-500 hover:text-cyan-600 dark:hover:text-cyan-400 p-1">
                    {copiedText === ip ? <Check className="w-3 h-3 text-emerald-500" /> : <Copy className="w-3 h-3" />}
                  </button>
                </div>
              ))}
            </div>
          </div>

          {/* URL Linked Domains */}
          <div className="p-4 rounded-xl bg-slate-50/80 dark:bg-slate-800/50 border border-slate-200 dark:border-slate-700/60 space-y-2">
            <span className="text-[10px] text-slate-400 dark:text-slate-500 uppercase font-bold block">
              Landing Phishing Hosts ({investigation.indicators.url_linked_domains.length})
            </span>
            <div className="space-y-1.5 max-h-36 overflow-y-auto">
              {investigation.indicators.url_linked_domains.map((ud, i) => (
                <div key={i} className="flex items-center justify-between bg-white dark:bg-slate-900/90 p-2 rounded-lg border border-slate-200 dark:border-slate-700 text-[11px]">
                  <span className="text-rose-600 dark:text-rose-400 font-bold truncate">{ud}</span>
                  <button onClick={() => copyToClipboard(ud)} className="text-slate-400 dark:text-slate-500 hover:text-cyan-600 dark:hover:text-cyan-400 p-1">
                    {copiedText === ud ? <Check className="w-3 h-3 text-emerald-500" /> : <Copy className="w-3 h-3" />}
                  </button>
                </div>
              ))}
            </div>
          </div>

          {/* PhishDNA Fingerprints */}
          <div className="p-4 rounded-xl bg-slate-50/80 dark:bg-slate-800/50 border border-slate-200 dark:border-slate-700/60 space-y-2 lg:col-span-2">
            <span className="text-[10px] text-slate-400 dark:text-slate-500 uppercase font-bold block">
              PhishDNA Normalized Fingerprints ({investigation.indicators.phishdna_fingerprints.length})
            </span>
            <div className="space-y-1.5 max-h-36 overflow-y-auto">
              {investigation.indicators.phishdna_fingerprints.map((fp, i) => (
                <div key={i} className="flex items-center justify-between bg-white dark:bg-slate-900/90 p-2 rounded-lg border border-slate-200 dark:border-slate-700 text-[11px]">
                  <span className="text-slate-800 dark:text-slate-200 font-bold truncate">{fp}</span>
                  <button onClick={() => copyToClipboard(fp)} className="text-slate-400 dark:text-slate-500 hover:text-cyan-600 dark:hover:text-cyan-400 p-1">
                    {copiedText === fp ? <Check className="w-3 h-3 text-emerald-500" /> : <Copy className="w-3 h-3" />}
                  </button>
                </div>
              ))}
            </div>
          </div>

          {/* Attachment Hashes */}
          <div className="p-4 rounded-xl bg-slate-50/80 dark:bg-slate-800/50 border border-slate-200 dark:border-slate-700/60 space-y-2">
            <span className="text-[10px] text-slate-400 dark:text-slate-500 uppercase font-bold block">
              Attachment Hashes ({investigation.indicators.attachment_hashes.length})
            </span>
            <div className="space-y-1.5 max-h-36 overflow-y-auto">
              {investigation.indicators.attachment_hashes.length > 0 ? (
                investigation.indicators.attachment_hashes.map((h, i) => (
                  <div key={i} className="flex items-center justify-between bg-white dark:bg-slate-900/90 p-2 rounded-lg border border-slate-200 dark:border-slate-700 text-[11px]">
                    <span className="text-slate-800 dark:text-slate-200 font-bold truncate">{h.substring(0, 16)}...</span>
                    <button onClick={() => copyToClipboard(h)} className="text-slate-400 dark:text-slate-500 hover:text-cyan-600 dark:hover:text-cyan-400 p-1">
                      {copiedText === h ? <Check className="w-3 h-3 text-emerald-500" /> : <Copy className="w-3 h-3" />}
                    </button>
                  </div>
                ))
              ) : (
                <div className="text-slate-400 dark:text-slate-500 p-2 text-[11px]">No malicious attachments in campaign.</div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* SECTION 5: Campaign Evolution Timeline */}
      <div className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/90 p-6 space-y-4 shadow-sm">
        <h2 className="text-xs font-bold text-slate-900 dark:text-white uppercase font-mono tracking-wider flex items-center gap-2">
          <Clock className="w-4 h-4 text-cyan-500" />
          Campaign Activity Evolution Timeline ({investigation.campaign_timeline.length})
        </h2>

        {investigation.campaign_timeline.length > 0 ? (
          <div className="space-y-3 pl-3 border-l-2 border-cyan-300 dark:border-cyan-800 ml-2">
            {investigation.campaign_timeline.map((ev, i) => (
              <div key={i} className="relative pl-4 text-xs font-mono space-y-1">
                <span className="absolute -left-[19px] top-1 w-2.5 h-2.5 rounded-full bg-cyan-600 dark:bg-cyan-400 ring-4 ring-white dark:ring-slate-900" />
                <div className="flex items-center gap-2">
                  <span className="font-bold text-slate-900 dark:text-white">{ev.event_type}</span>
                  <span className="text-[10px] text-slate-400 dark:text-slate-500">{ev.event_time ? ev.event_time.substring(0, 19).replace('T', ' ') : ''} UTC</span>
                </div>
                <p className="text-slate-600 dark:text-slate-300 font-sans text-xs">{ev.summary}</p>
              </div>
            ))}
          </div>
        ) : (
          <div className="p-6 text-center text-slate-400 dark:text-slate-500 font-mono text-xs bg-slate-50 dark:bg-slate-800/40 rounded-xl border border-slate-200 dark:border-slate-800">
            Initial campaign anchor established. Awaiting subsequent polymorphic mutations.
          </div>
        )}
      </div>
    </div>
  );
}
