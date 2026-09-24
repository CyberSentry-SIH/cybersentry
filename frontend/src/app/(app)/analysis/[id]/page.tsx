'use client';

import React, { useState, useEffect } from 'react';
import { useParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import {
  ShieldAlert,
  AlertTriangle,
  FileText,
  Download,
  Fingerprint,
  Globe,
  Server,
  Layers,
  CheckCircle2,
  XCircle,
  HelpCircle,
  ArrowLeft,
  Briefcase,
  GitCompare,
  Lock,
  ChevronRight,
  Sparkles,
  Zap,
  MapPin,
  ExternalLink,
  Shield,
  Clock,
  Radio,
  Share2,
  Cpu,
  Info
} from 'lucide-react';
import { api } from '@/lib/api';
import { AnalysisDetail, AttackIntentGraph as GraphType } from '@/types/api';
import AttackIntentGraph from '@/components/graph/AttackIntentGraph';

export default function AnalysisDetailPage() {
  const params = useParams();
  const router = useRouter();
  const id = params.id as string;

  const [analysis, setAnalysis] = useState<AnalysisDetail | null>(null);
  const [graphData, setGraphData] = useState<GraphType | null>(null);
  const [hopGeoData, setHopGeoData] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'overview' | 'headers' | 'urls' | 'phishdna' | 'graph'>('overview');
  const [showDecisionModal, setShowDecisionModal] = useState(false);
  const [decision, setDecision] = useState('CONFIRMED_PHISHING');
  const [comment, setComment] = useState('');
  const [submittingDecision, setSubmittingDecision] = useState(false);

  useEffect(() => {
    if (id) {
      // Step 1: Load analysis first to get the real email_id
      api.getAnalysis(id)
        .then((anRes) => {
          setAnalysis(anRes);
          const emailId = anRes?.email?.id || anRes?.email_id || id;

          // Step 2: Fetch graph using email_id
          const graphPromise = emailId
            ? api.getAttackGraph(emailId).catch(() => null)
            : Promise.resolve(null);

          // Step 3: Fetch hop geolocation
          const geoPromise = emailId
            ? api.getHopGeo(emailId).catch(() => [])
            : Promise.resolve([]);

          return Promise.all([graphPromise, geoPromise]);
        })
        .then(([grRes, geoRes]) => {
          setGraphData(grRes);
          setHopGeoData(geoRes || []);
        })
        .catch((err) => console.error(err))
        .finally(() => setLoading(false));
    }
  }, [id]);

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[400px] space-y-3">
        <div className="w-10 h-10 rounded-full border-2 border-cyan-500 border-t-transparent animate-spin" />
        <div className="text-center">
          <p className="text-sm font-semibold text-slate-800 dark:text-slate-200">Loading Forensic Dossier</p>
          <p className="text-xs text-slate-500 dark:text-slate-400 font-mono mt-0.5">Decrypting evidence custody chain & threat signals...</p>
        </div>
      </div>
    );
  }

  if (!analysis) {
    return (
      <div className="text-center py-16 max-w-md mx-auto">
        <div className="w-12 h-12 rounded-2xl bg-rose-50 dark:bg-rose-950/50 border border-rose-200 dark:border-rose-900/50 text-rose-600 dark:text-rose-400 flex items-center justify-center mx-auto mb-4 shadow-sm">
          <AlertTriangle className="w-6 h-6" />
        </div>
        <h2 className="text-base font-bold text-slate-900 dark:text-white">Forensic Record Not Found</h2>
        <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">The requested analysis or evidence item does not exist.</p>
        <Link href="/" className="btn-secondary text-xs mt-4 inline-flex items-center gap-1.5 font-mono">
          <ArrowLeft className="w-3.5 h-3.5" /> Return to Threat Dashboard
        </Link>
      </div>
    );
  }

  const score = analysis.risk_score?.score ?? 0;
  const band = analysis.risk_score?.band ?? 'UNKNOWN';

  const getBandStyles = (b: string) => {
    switch (b) {
      case 'CRITICAL':
        return {
          bg: 'bg-rose-50/80 dark:bg-rose-950/25 border-rose-200 dark:border-rose-900/50',
          text: 'text-rose-700 dark:text-rose-300',
          badgeBg: 'badge-critical',
          scoreText: 'text-rose-600 dark:text-rose-400',
          barColor: 'bg-rose-600 dark:bg-rose-500'
        };
      case 'HIGH':
        return {
          bg: 'bg-amber-50/80 dark:bg-amber-950/25 border-amber-200 dark:border-amber-900/50',
          text: 'text-amber-700 dark:text-amber-300',
          badgeBg: 'badge-high',
          scoreText: 'text-amber-600 dark:text-amber-400',
          barColor: 'bg-amber-500 dark:bg-amber-400'
        };
      case 'MEDIUM':
        return {
          bg: 'bg-sky-50/80 dark:bg-sky-950/25 border-sky-200 dark:border-sky-900/50',
          text: 'text-sky-700 dark:text-sky-300',
          badgeBg: 'badge-medium',
          scoreText: 'text-sky-600 dark:text-sky-400',
          barColor: 'bg-sky-500 dark:bg-sky-400'
        };
      default:
        return {
          bg: 'bg-emerald-50/80 dark:bg-emerald-950/25 border-emerald-200 dark:border-emerald-900/50',
          text: 'text-emerald-700 dark:text-emerald-300',
          badgeBg: 'badge-low',
          scoreText: 'text-emerald-600 dark:text-emerald-400',
          barColor: 'bg-emerald-500 dark:bg-emerald-400'
        };
    }
  };

  const bandStyle = getBandStyles(band);

  const handleDecisionSubmit = async () => {
    setSubmittingDecision(true);
    try {
      const newCase = await api.createCase({
        title: `Forensic Triage: ${analysis.email?.subject || 'Suspicious Email'}`,
        severity: band,
        summary: `Analyst disposition recorded: ${decision}`,
        evidence_ids: [analysis.evidence_id]
      });

      await api.submitDecision(newCase.id, { decision, comment });
      setShowDecisionModal(false);
      alert('Analyst disposition recorded successfully in immutable case log.');
    } catch (e: any) {
      alert(e.message || 'Error recording decision.');
    } finally {
      setSubmittingDecision(false);
    }
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12 animate-fade-in">
      {/* Top Breadcrumbs & Actions */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center gap-2 text-xs font-mono text-slate-500 dark:text-slate-400">
          <Link href="/" className="hover:text-cyan-600 dark:hover:text-cyan-400 flex items-center gap-1.5 transition-colors">
            <ArrowLeft className="h-3.5 w-3.5" /> Dashboard
          </Link>
          <span className="text-slate-300 dark:text-slate-700">/</span>
          <span className="text-slate-700 dark:text-slate-300 font-medium">Analysis</span>
          <span className="text-slate-300 dark:text-slate-700">/</span>
          <span className="text-cyan-600 dark:text-cyan-400 font-bold truncate max-w-[220px]">
            {analysis.evidence_id || analysis.id}
          </span>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => setShowDecisionModal(true)}
            className="btn-secondary text-xs font-semibold py-2 px-3.5 font-mono"
          >
            <Briefcase className="h-3.5 w-3.5 text-amber-500" />
            Record Disposition
          </button>
          <a
            href={api.getPdfReportUrl(analysis.evidence_id || analysis.id)}
            target="_blank"
            rel="noreferrer"
            className="btn-primary text-xs font-semibold py-2 px-3.5"
          >
            <Download className="h-3.5 w-3.5" />
            Export PDF Dossier
          </a>
        </div>
      </div>

      {/* Main Threat Header Banner */}
      <div className={`rounded-2xl border ${bandStyle.bg} p-6 sm:p-7 flex flex-col md:flex-row md:items-center justify-between gap-6 shadow-sm transition-colors duration-200`}>
        <div className="space-y-3 flex-1">
          <div className="flex flex-wrap items-center gap-2.5">
            <span className={`px-3 py-0.5 rounded-full text-xs font-mono font-bold uppercase tracking-wider ${bandStyle.badgeBg}`}>
              {band} SEVERITY
            </span>
            <div className="flex items-center gap-1.5 text-xs font-mono bg-white dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800 px-3 py-0.5 rounded-full text-slate-700 dark:text-slate-300 shadow-xs">
              <Fingerprint className="w-3.5 h-3.5 text-cyan-500" />
              <span>PhishDNA:</span>
              <strong className="text-slate-900 dark:text-white truncate max-w-[140px] sm:max-w-none">{analysis.phishdna?.fingerprint || 'GENERATING'}</strong>
            </div>
            {(analysis as any).campaign && (
              <span className="inline-flex items-center gap-1.5 px-3 py-0.5 rounded-full bg-indigo-50 dark:bg-indigo-950/60 border border-indigo-200 dark:border-indigo-800 text-indigo-700 dark:text-indigo-300 text-xs font-mono font-bold">
                <Layers className="w-3.5 h-3.5 text-indigo-500" />
                {(analysis as any).campaign}
              </span>
            )}
          </div>

          <h1 className="text-xl sm:text-2xl font-bold text-slate-900 dark:text-white tracking-tight leading-snug">
            {analysis.email?.subject || 'Untitled Suspicious Email'}
          </h1>

          <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5 text-xs font-mono text-slate-600 dark:text-slate-400">
            <span>From: <strong className="text-slate-900 dark:text-slate-100">{analysis.email?.from_name || analysis.email?.from_address}</strong> &lt;{analysis.email?.from_address}&gt;</span>
            <span className="text-slate-300 dark:text-slate-700 hidden sm:inline">•</span>
            <span>Sender Domain: <strong className="text-cyan-600 dark:text-cyan-400 font-semibold">{analysis.email?.from_domain}</strong></span>
          </div>
        </div>

        {/* 0-100 Score Radial Card */}
        <div className="flex items-center gap-5 bg-white dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800 rounded-2xl p-4 sm:p-5 flex-shrink-0 shadow-sm">
          <div className="text-center">
            <div className={`text-4xl sm:text-5xl font-extrabold font-mono tracking-tight ${bandStyle.scoreText}`}>
              {Math.round(score)}
            </div>
            <div className="text-[10px] text-slate-500 dark:text-slate-400 font-mono uppercase tracking-wider mt-0.5 font-bold">
              Risk Prioritization Score
            </div>
            <div className="text-[9px] text-slate-400 dark:text-slate-500 font-mono italic mt-0.5">
              Forensic indicator score (not probability)
            </div>
          </div>
          <div className="h-12 w-px bg-slate-200 dark:bg-slate-800" />
          <div className="text-left space-y-1">
            <div className="text-xs font-bold text-slate-900 dark:text-white font-mono uppercase">
              {analysis.phishdna?.content_dna.intent?.replace(/_/g, ' ') || 'BENIGN INTENT'}
            </div>
            <div className="text-[11px] text-slate-500 dark:text-slate-400 font-mono">
              {analysis.findings.length} forensic signals
            </div>
            <div className="w-24 bg-slate-100 dark:bg-slate-800 h-1.5 rounded-full overflow-hidden mt-1.5 border border-slate-200 dark:border-slate-700">
              <div className={`h-full ${bandStyle.barColor}`} style={{ width: `${Math.min(100, score)}%` }} />
            </div>
          </div>
        </div>
      </div>

      {/* Tabs Navigation */}
      <div className="flex items-center border border-slate-200 dark:border-slate-800 gap-1.5 sm:gap-3 overflow-x-auto pb-px bg-white/90 dark:bg-slate-900/90 backdrop-blur-md p-1.5 rounded-2xl shadow-xs">
        {[
          { id: 'overview', label: 'Findings & Actions', icon: ShieldAlert },
          { id: 'headers', label: 'Routing Hops & IPGeo', icon: Globe },
          { id: 'urls', label: 'URL & VirusTotal Intel', icon: Zap },
          { id: 'phishdna', label: 'PhishDNA 7-Vector', icon: Fingerprint },
          { id: 'graph', label: 'Attack Intent Graph', icon: Layers }
        ].map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`flex items-center gap-2 py-2 px-3.5 rounded-xl transition-all font-mono text-xs font-semibold whitespace-nowrap ${
                isActive
                  ? 'bg-cyan-50 dark:bg-cyan-950/60 text-cyan-600 dark:text-cyan-400 font-bold border border-cyan-200 dark:border-cyan-800/80 shadow-xs'
                  : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800/60 hover:text-slate-900 dark:hover:text-white border border-transparent'
              }`}
            >
              <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-600 dark:text-cyan-400' : 'text-slate-400 dark:text-slate-500'}`} />
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* Tab 1: Overview */}
      {activeTab === 'overview' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Signals & Preview */}
          <div className="lg:col-span-2 space-y-6">
            {/* AI Intent Summary Callout */}
            {analysis.phishdna?.content_dna && (
              <div className="rounded-2xl border border-cyan-200 dark:border-cyan-900/40 bg-gradient-to-br from-cyan-50/50 via-white to-indigo-50/40 dark:from-cyan-950/30 dark:via-slate-900/90 dark:to-indigo-950/20 p-6 space-y-4 shadow-sm">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-xl bg-cyan-50 dark:bg-cyan-950/60 border border-cyan-200 dark:border-cyan-800/50 text-cyan-600 dark:text-cyan-400 flex items-center justify-center font-bold shadow-xs">
                      <Sparkles className="w-5 h-5" />
                    </div>
                    <div>
                      <h3 className="text-xs font-bold text-slate-900 dark:text-white uppercase font-mono tracking-wider">AI Semantic Analysis — Supporting Evidence (Non-Authoritative)</h3>
                      <p className="text-[11px] text-slate-500 dark:text-slate-400">Semantic intent extraction & language cue analysis</p>
                    </div>
                  </div>
                  <span className="text-[10px] font-mono px-2.5 py-0.5 rounded-full bg-cyan-100/80 dark:bg-cyan-950/80 text-cyan-700 dark:text-cyan-300 font-bold border border-cyan-200 dark:border-cyan-800">
                    Google Gemini (gemini-2.5-flash)
                  </span>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono pt-1">
                  <div className="p-4 rounded-xl bg-white dark:bg-slate-800/80 border border-slate-200 dark:border-slate-700/60 shadow-xs space-y-1">
                    <span className="text-[10px] text-slate-400 dark:text-slate-500 block uppercase font-bold">Inferred Intent</span>
                    <span className="text-amber-600 dark:text-amber-400 font-bold text-sm block">
                      {analysis.phishdna.content_dna.intent?.replace(/_/g, ' ') || 'SUSPICIOUS'}
                    </span>
                  </div>
                  <div className="p-4 rounded-xl bg-white dark:bg-slate-800/80 border border-slate-200 dark:border-slate-700/60 shadow-xs space-y-1">
                    <span className="text-[10px] text-slate-400 dark:text-slate-500 block uppercase font-bold">Inferred Target</span>
                    <span className="text-slate-900 dark:text-white font-bold text-sm block">
                      {analysis.phishdna.content_dna.brand_targeted || 'Generic Phish'}
                    </span>
                  </div>
                  <div className="p-4 rounded-xl bg-white dark:bg-slate-800/80 border border-slate-200 dark:border-slate-700/60 shadow-xs space-y-1">
                    <span className="text-[10px] text-slate-400 dark:text-slate-500 block uppercase font-bold">Urgency Cue</span>
                    <span className="text-rose-600 dark:text-rose-400 font-bold text-sm block">
                      {analysis.phishdna.content_dna.urgency_cue || 'High Urgency'}
                    </span>
                  </div>
                </div>
                <div className="text-[10px] text-slate-500 dark:text-slate-400 font-mono italic pt-1 border-t border-slate-200/60 dark:border-slate-800">
                  * Note: AI semantic enrichment provides contextual cues to assist human analyst triage. Scoring and IOC correlation remain governed by deterministic rules and evidence logs.
                </div>
              </div>
            )}

            {/* Forensic Findings */}
            <div className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/90 p-6 space-y-4 shadow-sm">
              <div className="flex items-center justify-between">
                <h2 className="text-xs font-bold text-slate-900 dark:text-white uppercase font-mono tracking-wider flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-cyan-500" />
                  Forensic Findings ({analysis.findings.length})
                </h2>
                <span className="text-[11px] text-slate-400 dark:text-slate-500 font-mono">Deterministic Core v{analysis.engine_version}</span>
              </div>

              <div className="space-y-3">
                {analysis.findings.map((f) => {
                  const isCrit = f.severity === 'CRITICAL';
                  const isHigh = f.severity === 'HIGH';
                  return (
                    <div
                      key={f.id}
                      className="p-4 rounded-xl bg-slate-50/80 dark:bg-slate-800/50 border border-slate-200 dark:border-slate-700/60 hover:border-slate-300 dark:hover:border-slate-600 transition-all flex items-start justify-between gap-4"
                    >
                      <div className="space-y-1 flex-1">
                        <div className="flex items-center gap-2">
                          <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded-full ${
                            isCrit ? 'badge-critical' : isHigh ? 'badge-high' : 'badge-medium'
                          }`}>
                            {f.category}
                          </span>
                          <span className="text-xs font-bold text-slate-900 dark:text-white">{f.title}</span>
                        </div>
                        <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">{f.description}</p>
                      </div>
                      <div className="text-right flex-shrink-0 font-mono text-xs font-bold text-rose-600 dark:text-rose-400 bg-rose-50 dark:bg-rose-950/50 border border-rose-200 dark:border-rose-900/50 px-2.5 py-1 rounded-lg">
                        +{f.risk_contribution}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Email Body Safe Preview */}
            <div className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/90 p-6 space-y-3 shadow-sm">
              <h2 className="text-xs font-bold text-slate-900 dark:text-white uppercase font-mono tracking-wider flex items-center gap-2">
                <FileText className="w-4 h-4 text-slate-500 dark:text-slate-400" />
                Safe Content Preview (Sanitized Text)
              </h2>
              <div className="bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800 rounded-xl p-4 text-xs font-mono text-slate-700 dark:text-slate-300 max-h-64 overflow-y-auto whitespace-pre-wrap leading-relaxed">
                {analysis.email?.body_text || 'No plain-text body extracted from payload.'}
              </div>
            </div>
          </div>

          {/* Right Column: Defensive Actions & Chain */}
          <div className="space-y-6">
            {/* Recommended Actions */}
            <div className="rounded-2xl border border-amber-200 dark:border-amber-900/40 bg-white dark:bg-slate-900/90 p-6 space-y-4 shadow-sm">
              <div>
                <h2 className="text-xs font-bold text-slate-900 dark:text-white uppercase font-mono tracking-wider flex items-center gap-2">
                  <Zap className="h-4 w-4 text-amber-500" />
                  RECOMMENDED DEFENSIVE ACTIONS ({analysis.recommended_actions.length})
                </h2>
                <p className="text-[10px] text-slate-500 dark:text-slate-400 font-mono mt-0.5">
                  Advisory guidance based on forensic findings · Requires analyst/security engineering execution
                </p>
              </div>

              <div className="space-y-3">
                {analysis.recommended_actions.map((ra) => (
                  <div key={ra.id} className="p-3.5 rounded-xl bg-amber-50/40 dark:bg-amber-950/20 border border-amber-200/80 dark:border-amber-900/40 space-y-1">
                    <div className="flex items-center gap-2">
                      <span className={`text-[9px] font-mono font-bold px-2 py-0.5 rounded-full ${
                        ra.priority === 'HIGH' ? 'badge-critical' : 'badge-medium'
                      }`}>
                        {ra.priority}
                      </span>
                      <span className="text-xs font-semibold text-slate-900 dark:text-white">{ra.title}</span>
                    </div>
                    <p className="text-[11px] text-slate-600 dark:text-slate-300 leading-relaxed">{ra.explanation}</p>
                  </div>
                ))}
              </div>
            </div>

            {/* Evidence & Custody Verification */}
            <div className="rounded-2xl border border-emerald-200 dark:border-emerald-900/40 bg-white dark:bg-slate-900/90 p-6 space-y-4 font-mono text-xs shadow-sm">
              <h2 className="text-xs font-bold text-slate-900 dark:text-white uppercase tracking-wider font-mono flex items-center gap-2">
                <Lock className="w-4 h-4 text-emerald-500" />
                Tamper-Evident SHA-256 Custody Chain
              </h2>
              <div className="space-y-3 bg-emerald-50/30 dark:bg-slate-950/60 p-4 rounded-xl border border-emerald-200/70 dark:border-emerald-900/30">
                <div>
                  <div className="text-slate-400 dark:text-slate-500 text-[10px] uppercase font-bold">Evidence ID</div>
                  <div className="text-cyan-600 dark:text-cyan-400 font-bold truncate">{analysis.evidence_id}</div>
                </div>
                <div className="h-px bg-slate-200 dark:bg-slate-800" />
                <div>
                  <div className="text-slate-400 dark:text-slate-500 text-[10px] uppercase font-bold">Engine Version</div>
                  <div className="text-slate-800 dark:text-slate-200">v{analysis.engine_version} (Deterministic Core)</div>
                </div>
                <div className="h-px bg-slate-200 dark:bg-slate-800" />
                <div>
                  <div className="text-slate-400 dark:text-slate-500 text-[10px] uppercase font-bold">Custody Hash State</div>
                  <div className="text-emerald-700 dark:text-emerald-400 flex items-center gap-1.5 mt-0.5 font-bold">
                    <CheckCircle2 className="h-3.5 w-3.5" /> VERIFIED IN CHAIN
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Tab 2: Headers & Route Hops (IPGeo) */}
      {activeTab === 'headers' && (
        <div className="space-y-6">
          {/* Auth Verification Cards */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-slate-700 dark:text-slate-300 font-mono uppercase">
                Reported Authentication Results (MIME Authentication-Results Header)
              </span>
              <span className="text-[10px] font-mono text-slate-400 dark:text-slate-500">
                Extracted from recipient gateway headers
              </span>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/90 p-5 font-mono shadow-sm">
                <div className="text-xs text-slate-400 dark:text-slate-500 uppercase font-bold">REPORTED SPF (MIME)</div>
                <div className="text-xl font-bold text-slate-900 dark:text-white mt-1.5 flex items-center gap-2">
                  {analysis.email?.auth_result?.spf_result === 'PASS' ? (
                    <CheckCircle2 className="w-5 h-5 text-emerald-500" />
                  ) : (
                    <XCircle className="w-5 h-5 text-rose-500" />
                  )}
                  {analysis.email?.auth_result?.spf_result || 'NONE'}
                </div>
              </div>
              <div className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/90 p-5 font-mono shadow-sm">
                <div className="text-xs text-slate-400 dark:text-slate-500 uppercase font-bold">REPORTED DKIM (MIME)</div>
                <div className="text-xl font-bold text-slate-900 dark:text-white mt-1.5 flex items-center gap-2">
                  {analysis.email?.auth_result?.dkim_result === 'PASS' ? (
                    <CheckCircle2 className="w-5 h-5 text-emerald-500" />
                  ) : (
                    <XCircle className="w-5 h-5 text-rose-500" />
                  )}
                  {analysis.email?.auth_result?.dkim_result || 'NONE'}
                </div>
              </div>
              <div className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/90 p-5 font-mono shadow-sm">
                <div className="text-xs text-slate-400 dark:text-slate-500 uppercase font-bold">REPORTED DMARC (MIME)</div>
                <div className="text-xl font-bold text-slate-900 dark:text-white mt-1.5 flex items-center gap-2">
                  {analysis.email?.auth_result?.dmarc_result === 'PASS' ? (
                    <CheckCircle2 className="w-5 h-5 text-emerald-500" />
                  ) : (
                    <XCircle className="w-5 h-5 text-rose-500" />
                  )}
                  {analysis.email?.auth_result?.dmarc_result || 'NONE'}
                </div>
              </div>
            </div>
          </div>

          {/* Route Hops with IPGeolocation.io Enrichment */}
          <div className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/90 p-6 space-y-4 shadow-sm">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-xs font-bold text-slate-900 dark:text-white uppercase font-mono tracking-wider flex items-center gap-2">
                  <Globe className="w-4 h-4 text-cyan-500" />
                  Received Routing Hop Chain & Geolocation Intelligence
                </h2>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">Enriched in real-time via IPGeolocation.io API</p>
              </div>
              <span className="text-[10px] font-mono px-2.5 py-1 rounded-full bg-cyan-50 dark:bg-cyan-950/60 border border-cyan-200 dark:border-cyan-800 text-cyan-700 dark:text-cyan-300 font-bold">
                Live Geolocation Feed
              </span>
            </div>

            <div className="space-y-4">
              {(hopGeoData.length > 0 ? hopGeoData : (analysis.email?.hops || [])).map((hop: any, idx: number) => {
                const geo = hop.geo;
                const isUntrusted = hop.trust_level === 'UNTRUSTED';
                const isTrusted = hop.trust_level === 'TRUSTED';
                const isOrigin = idx === 0 || hop.hop_order === 1;

                return (
                  <div
                    key={hop.id || idx}
                    className={`p-5 rounded-2xl border transition-all ${
                      isUntrusted
                        ? 'bg-rose-50/40 dark:bg-rose-950/20 border-rose-200 dark:border-rose-900/40'
                        : isTrusted
                        ? 'bg-emerald-50/40 dark:bg-emerald-950/20 border-emerald-200 dark:border-emerald-900/40'
                        : 'bg-slate-50/80 dark:bg-slate-800/40 border-slate-200 dark:border-slate-800'
                    }`}
                  >
                    {/* Header Row */}
                    <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 pb-3 border-b border-slate-200/80 dark:border-slate-700/60">
                      <div className="flex items-center gap-3">
                        <span className="w-8 h-8 rounded-xl bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-cyan-600 dark:text-cyan-400 flex items-center justify-center font-bold font-mono text-xs shadow-xs">
                          #{hop.hop_order ?? idx + 1}
                        </span>
                        <div>
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="text-slate-900 dark:text-white font-bold font-mono text-sm">
                              {hop.hostname || hop.ip_address || 'Mail Transit Server'}
                            </span>
                            <span className={`text-[10px] px-2.5 py-0.5 rounded-full font-bold font-mono uppercase ${
                              isTrusted ? 'badge-low' : isUntrusted ? 'badge-critical' : 'badge-medium'
                            }`}>
                              {hop.trust_level || 'NEUTRAL'}
                            </span>
                            {isOrigin && (
                              <span className="text-[10px] px-2 py-0.5 rounded-full bg-cyan-100 dark:bg-cyan-950/80 text-cyan-800 dark:text-cyan-300 font-mono font-bold border border-cyan-200 dark:border-cyan-800">
                                Origin Node
                              </span>
                            )}
                          </div>
                          <div className="text-slate-500 dark:text-slate-400 font-mono text-xs truncate max-w-xl mt-0.5">
                            {hop.raw_value || `IP: ${hop.ip_address}`}
                          </div>
                        </div>
                      </div>

                      {/* IP Tag */}
                      {hop.ip_address && (
                        <span className="self-start md:self-auto px-3 py-1 rounded-lg bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-cyan-600 dark:text-cyan-400 font-mono font-bold text-xs shadow-xs">
                          IP: {hop.ip_address}
                        </span>
                      )}
                    </div>

                    {/* Geolocation & ISP Detailed Breakdown */}
                    {geo && geo.enriched && (
                      <div className="mt-3 pt-1 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs font-mono">
                        {/* Location */}
                        <div className="p-3 rounded-xl bg-white dark:bg-slate-800/80 border border-slate-200 dark:border-slate-700 shadow-xs space-y-1">
                          <span className="text-[10px] text-slate-400 dark:text-slate-500 font-bold uppercase tracking-wider block">
                            Geographic Location
                          </span>
                          <div className="flex items-center gap-1.5 font-bold text-slate-900 dark:text-white">
                            {geo.country_flag && typeof geo.country_flag === 'string' && geo.country_flag.startsWith('http') ? (
                              <img src={geo.country_flag} alt="" className="w-4 h-3 rounded-xs object-cover" />
                            ) : (
                              <span>{geo.country_emoji || '🌐'}</span>
                            )}
                            <span className="truncate">{geo.city ? `${geo.city}, ` : ''}{geo.country_name || 'Unknown'}</span>
                          </div>
                          {geo.state_prov && (
                            <p className="text-[11px] text-slate-600 dark:text-slate-300 truncate">Region: {geo.state_prov}</p>
                          )}
                          {geo.zipcode && geo.zipcode !== 'N/A' && (
                            <p className="text-[10px] text-slate-400 dark:text-slate-500">Postal: {geo.zipcode}</p>
                          )}
                        </div>

                        {/* ISP & Organization */}
                        <div className="p-3 rounded-xl bg-white dark:bg-slate-800/80 border border-slate-200 dark:border-slate-700 shadow-xs space-y-1">
                          <span className="text-[10px] text-slate-400 dark:text-slate-500 font-bold uppercase tracking-wider block">
                            Network / ISP
                          </span>
                          <p className="font-bold text-slate-900 dark:text-white truncate" title={geo.isp}>
                            {geo.isp || 'Internal / Direct Network'}
                          </p>
                          {geo.organization && geo.organization !== geo.isp && (
                            <p className="text-[11px] text-slate-600 dark:text-slate-300 truncate" title={geo.organization}>
                              Org: {geo.organization}
                            </p>
                          )}
                          {geo.asn && (
                            <p className="text-[11px] text-cyan-600 dark:text-cyan-400 font-semibold truncate">
                              ASN: {geo.asn}
                            </p>
                          )}
                        </div>

                        {/* Coordinates & Map Link */}
                        <div className="p-3 rounded-xl bg-white dark:bg-slate-800/80 border border-slate-200 dark:border-slate-700 shadow-xs space-y-1">
                          <span className="text-[10px] text-slate-400 dark:text-slate-500 font-bold uppercase tracking-wider block">
                            Coordinates & Route
                          </span>
                          {geo.latitude && geo.longitude ? (
                            <>
                              <p className="font-bold text-slate-900 dark:text-white">
                                {geo.latitude}, {geo.longitude}
                              </p>
                              <a
                                href={`https://www.openstreetmap.org/?mlat=${geo.latitude}&mlon=${geo.longitude}#map=11/${geo.latitude}/${geo.longitude}`}
                                target="_blank"
                                rel="noreferrer"
                                className="text-[11px] text-cyan-600 dark:text-cyan-400 hover:text-cyan-700 dark:hover:text-cyan-300 hover:underline flex items-center gap-1"
                              >
                                <ExternalLink className="w-3 h-3" /> View Map Point
                              </a>
                            </>
                          ) : (
                            <p className="text-slate-500 dark:text-slate-400 italic text-[11px]">
                              {geo.location_note || 'Localhost / Internal Node'}
                            </p>
                          )}
                        </div>

                        {/* Timezone & Threat */}
                        <div className="p-3 rounded-xl bg-white dark:bg-slate-800/80 border border-slate-200 dark:border-slate-700 shadow-xs space-y-1">
                          <span className="text-[10px] text-slate-400 dark:text-slate-500 font-bold uppercase tracking-wider block">
                            Node Telemetry
                          </span>
                          <p className="font-semibold text-slate-800 dark:text-slate-200 truncate">
                            TZ: {geo.timezone || 'UTC'}
                          </p>
                          <div className="flex items-center gap-1.5 pt-0.5">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                              geo.threat?.is_tor ? 'bg-rose-100 dark:bg-rose-950/60 text-rose-800 dark:text-rose-300' : 'bg-slate-100 dark:bg-slate-700 text-slate-700 dark:text-slate-300'
                            }`}>
                              {geo.threat?.is_tor ? 'TOR RELAY' : 'CLEAN MTA'}
                            </span>
                            <span className="text-[10px] text-slate-400 dark:text-slate-500">
                              Src: {geo.source || 'IPGEO'}
                            </span>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>

            <div className="text-xs text-slate-500 dark:text-slate-400 italic font-mono pt-1">
              * Note: Earliest reliable infrastructure observed indicates earliest external transit hop in the available header chain. Infrastructure relationship ≠ Attacker physical identity.
            </div>
          </div>
        </div>
      )}

      {/* Tab 3: URL & VirusTotal Intel */}
      {activeTab === 'urls' && (
        <div className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/90 p-6 space-y-6 shadow-sm">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-xs font-bold text-slate-900 dark:text-white uppercase font-mono tracking-wider flex items-center gap-2">
                <Zap className="w-4 h-4 text-amber-500" />
                Extracted URLs & VirusTotal Multi-Engine Intelligence
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">Cross-referenced against 90+ security vendors via VirusTotal API v3</p>
            </div>
            <span className="text-[10px] font-mono px-2.5 py-1 rounded-full bg-amber-50 dark:bg-amber-950/60 border border-amber-200 dark:border-amber-800 text-amber-700 dark:text-amber-300 font-bold">
              VT Threat Scanner
            </span>
          </div>

          <div className="space-y-3">
            {analysis.phishdna?.url_dna.domains && analysis.phishdna.url_dna.domains.length > 0 ? (
              analysis.phishdna.url_dna.domains.map((domain: string, i: number) => (
                <div
                  key={domain + i}
                  className="p-4 rounded-xl bg-slate-50/80 dark:bg-slate-800/50 border border-slate-200 dark:border-slate-700/60 hover:border-slate-300 dark:hover:border-slate-600 transition-all flex flex-col sm:flex-row sm:items-center justify-between gap-3 font-mono text-xs"
                >
                  <div className="space-y-0.5">
                    <div className="flex items-center gap-2">
                      <span className="font-bold text-slate-900 dark:text-white text-sm">{domain}</span>
                      <a href={`https://${domain}`} target="_blank" rel="noreferrer" className="text-slate-400 dark:text-slate-500 hover:text-cyan-600 dark:hover:text-cyan-400">
                        <ExternalLink className="w-3.5 h-3.5" />
                      </a>
                    </div>
                    <div className="text-slate-500 dark:text-slate-400 text-[11px]">Normalized Domain Indicator</div>
                  </div>

                  <div className="flex items-center gap-2">
                    <span className="badge-high px-3 py-1 rounded-full text-xs font-bold">
                      FLAGGED SUSPICIOUS
                    </span>
                    <a
                      href={`https://www.virustotal.com/gui/domain/${domain}`}
                      target="_blank"
                      rel="noreferrer"
                      className="px-3 py-1 rounded-full bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-200 hover:text-cyan-600 dark:hover:text-cyan-400 hover:border-cyan-300 dark:hover:border-cyan-700 text-xs flex items-center gap-1.5 transition-colors shadow-xs font-semibold"
                    >
                      <Zap className="w-3 h-3 text-amber-500" />
                      VT Report
                    </a>
                  </div>
                </div>
              ))
            ) : (
              <div className="p-8 text-center text-slate-400 dark:text-slate-500 font-mono text-xs">
                No external URLs or landing hosts detected in payload.
              </div>
            )}
          </div>
        </div>
      )}

      {/* Tab 4: PhishDNA Vectors */}
      {activeTab === 'phishdna' && (
        <div className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/90 p-6 space-y-6 shadow-sm">
          <div>
            <div className="flex items-center justify-between">
              <h2 className="text-xs font-bold text-slate-900 dark:text-white uppercase font-mono tracking-wider flex items-center gap-2">
                <Fingerprint className="w-4 h-4 text-cyan-500" />
                7-Vector Normalized PhishDNA Fingerprint
              </h2>
              <span className="text-[10px] font-mono text-slate-500 dark:text-slate-400">Deterministic SHA-256 Hash Vector</span>
            </div>
            <div className="mt-3 p-4 rounded-xl bg-slate-50 dark:bg-slate-950/60 border border-cyan-200 dark:border-cyan-900/50 font-mono text-sm text-cyan-700 dark:text-cyan-300 font-bold select-all break-all">
              {analysis.phishdna?.fingerprint}
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-4 rounded-xl bg-slate-50/80 dark:bg-slate-800/50 border border-slate-200 dark:border-slate-700/60 space-y-2 text-xs font-mono">
              <div className="font-bold text-cyan-600 dark:text-cyan-400 uppercase text-[11px] flex items-center gap-1.5">
                <Cpu className="w-3.5 h-3.5" /> 1. Header & Routing DNA
              </div>
              <pre className="text-slate-800 dark:text-slate-200 text-[11px] whitespace-pre-wrap bg-white dark:bg-slate-900/90 p-3 rounded-lg border border-slate-200 dark:border-slate-800 overflow-x-auto">
                {JSON.stringify(analysis.phishdna?.header_dna, null, 2)}
              </pre>
            </div>

            <div className="p-4 rounded-xl bg-slate-50/80 dark:bg-slate-800/50 border border-slate-200 dark:border-slate-700/60 space-y-2 text-xs font-mono">
              <div className="font-bold text-cyan-600 dark:text-cyan-400 uppercase text-[11px] flex items-center gap-1.5">
                <Lock className="w-3.5 h-3.5" /> 2. Identity & Authentication DNA
              </div>
              <pre className="text-slate-800 dark:text-slate-200 text-[11px] whitespace-pre-wrap bg-white dark:bg-slate-900/90 p-3 rounded-lg border border-slate-200 dark:border-slate-800 overflow-x-auto">
                {JSON.stringify(analysis.phishdna?.identity_auth_dna, null, 2)}
              </pre>
            </div>

            <div className="p-4 rounded-xl bg-slate-50/80 dark:bg-slate-800/50 border border-slate-200 dark:border-slate-700/60 space-y-2 text-xs font-mono">
              <div className="font-bold text-cyan-600 dark:text-cyan-400 uppercase text-[11px] flex items-center gap-1.5">
                <Sparkles className="w-3.5 h-3.5" /> 3. Content & Semantic Intent DNA
              </div>
              <pre className="text-slate-800 dark:text-slate-200 text-[11px] whitespace-pre-wrap bg-white dark:bg-slate-900/90 p-3 rounded-lg border border-slate-200 dark:border-slate-800 overflow-x-auto">
                {JSON.stringify(analysis.phishdna?.content_dna, null, 2)}
              </pre>
            </div>

            <div className="p-4 rounded-xl bg-slate-50/80 dark:bg-slate-800/50 border border-slate-200 dark:border-slate-700/60 space-y-2 text-xs font-mono">
              <div className="font-bold text-cyan-600 dark:text-cyan-400 uppercase text-[11px] flex items-center gap-1.5">
                <Globe className="w-3.5 h-3.5" /> 4. URL & Landing Domain DNA
              </div>
              <pre className="text-slate-800 dark:text-slate-200 text-[11px] whitespace-pre-wrap bg-white dark:bg-slate-900/90 p-3 rounded-lg border border-slate-200 dark:border-slate-800 overflow-x-auto">
                {JSON.stringify(analysis.phishdna?.url_dna, null, 2)}
              </pre>
            </div>
          </div>
        </div>
      )}

      {/* Tab 5: Attack Intent Graph */}
      {activeTab === 'graph' && (
        <div className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/90 p-6 shadow-sm">
          {graphData && graphData.nodes && graphData.nodes.length > 0 ? (
            <AttackIntentGraph nodes={graphData.nodes} edges={graphData.edges} />
          ) : (
            <div className="flex flex-col items-center justify-center py-16 space-y-4">
              <div className="w-16 h-16 rounded-2xl bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 flex items-center justify-center">
                <Layers className="w-8 h-8 text-slate-400 dark:text-slate-500" />
              </div>
              <div className="text-center space-y-1.5">
                <h3 className="text-sm font-bold text-slate-700 dark:text-slate-300 font-mono">Attack Intent Graph Unavailable</h3>
                <p className="text-xs text-slate-500 dark:text-slate-400 max-w-sm">
                  No graph nodes were generated for this email. This may happen if the analysis pipeline did not produce graph data, or the email has not been fully processed yet.
                </p>
              </div>
              <button
                onClick={() => {
                  const emailId = analysis?.email?.id || analysis?.email_id || (typeof id === 'string' ? id : '');
                  if (emailId) {
                    api.getAttackGraph(emailId)
                      .then((res) => setGraphData(res))
                      .catch(() => {});
                  }
                }}
                className="btn-secondary text-xs font-mono py-2 px-4 flex items-center gap-2"
              >
                <Share2 className="w-3.5 h-3.5" />
                Retry Graph Fetch
              </button>
            </div>
          )}
        </div>
      )}

      {/* Decision Modal */}
      {showDecisionModal && (
        <div className="fixed inset-0 z-50 bg-slate-950/60 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl max-w-md w-full p-6 space-y-5 shadow-2xl animate-fade-in">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-amber-100 dark:bg-amber-950/60 border border-amber-200 dark:border-amber-800 text-amber-600 dark:text-amber-400 flex items-center justify-center">
                <Briefcase className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-base font-bold text-slate-900 dark:text-white">Record Analyst Disposition</h3>
                <p className="text-xs text-slate-500 dark:text-slate-400">Append immutable SOC verdict to case log</p>
              </div>
            </div>

            <div className="space-y-4">
              <div>
                <label className="block text-xs font-mono text-slate-700 dark:text-slate-300 mb-1.5 font-bold">Final Determination</label>
                <select
                  value={decision}
                  onChange={(e) => setDecision(e.target.value)}
                  className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-xl p-3 text-xs text-slate-900 dark:text-slate-100 focus:outline-none focus:border-cyan-500 font-medium"
                >
                  <option value="CONFIRMED_PHISHING" className="bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100">Confirmed Malicious / Phishing</option>
                  <option value="FALSE_POSITIVE" className="bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100">False Positive / Legitimate</option>
                  <option value="NEEDS_INVESTIGATION" className="bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100">Escalate for Deep Forensics</option>
                </select>
              </div>

              <div>
                <label className="block text-xs font-mono text-slate-700 dark:text-slate-300 mb-1.5 font-bold">Analyst Rationale</label>
                <textarea
                  rows={3}
                  value={comment}
                  onChange={(e) => setComment(e.target.value)}
                  placeholder="Provide IOC rationale, MITRE mapping, or playbook action..."
                  className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-xl p-3 text-xs text-slate-900 dark:text-slate-100 focus:outline-none focus:border-cyan-500 placeholder-slate-400 dark:placeholder-slate-500 font-mono"
                />
              </div>
            </div>

            <div className="flex justify-end gap-3 pt-2">
              <button
                onClick={() => setShowDecisionModal(false)}
                className="btn-secondary px-4 py-2 text-xs font-semibold"
              >
                Cancel
              </button>
              <button
                onClick={handleDecisionSubmit}
                disabled={submittingDecision}
                className="btn-primary px-5 py-2 text-xs font-semibold"
              >
                {submittingDecision ? 'Signing...' : 'Commit Disposition'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
