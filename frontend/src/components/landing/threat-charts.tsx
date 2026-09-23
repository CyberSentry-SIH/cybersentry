"use client";

import React, { useState } from "react";
import {
  ShieldAlert,
  Activity,
  Zap,
  TrendingUp,
  Cpu,
  Layers,
  Sparkles,
  Search,
  CheckCircle2,
  AlertTriangle,
  Flame,
  Globe2,
  Database
} from "lucide-react";

export function ThreatIntelligenceCharts() {
  const [activeTab, setActiveTab] = useState<"velocity" | "vectors" | "dna">("velocity");

  return (
    <div className="rounded-2xl border border-slate-300/80 dark:border-slate-700/60 bg-white/90 dark:bg-slate-800/90 p-6 md:p-8 shadow-xl backdrop-blur-xl relative overflow-hidden transition-colors duration-200">
      {/* Ambient background glow */}
      <div className="absolute -right-20 -top-20 h-64 w-64 rounded-full bg-cyan-500/10 blur-3xl pointer-events-none" />
      <div className="absolute -left-20 -bottom-20 h-64 w-64 rounded-full bg-indigo-500/10 blur-3xl pointer-events-none" />

      {/* Header with Navigation Pills */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-200 dark:border-slate-700/80 pb-6 mb-6">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="flex h-2.5 w-2.5 rounded-full bg-emerald-500 animate-ping" />
            <span className="text-xs font-mono font-medium uppercase tracking-wider text-cyan-700 dark:text-cyan-400">
              Live Threat Engine Telemetry
            </span>
          </div>
          <h3 className="text-xl md:text-2xl font-bold text-slate-900 dark:text-white tracking-tight">
            Forensic Intelligence & Attack Correlation
          </h3>
        </div>

        {/* Tab Controls */}
        <div className="flex bg-slate-100 dark:bg-slate-900 p-1 rounded-xl border border-slate-300 dark:border-slate-800 self-start md:self-auto">
          <button
            onClick={() => setActiveTab("velocity")}
            className={`px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
              activeTab === "velocity"
                ? "bg-gradient-to-r from-cyan-600 to-blue-600 text-white shadow-md"
                : "text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white"
            }`}
          >
            Ingestion Velocity
          </button>
          <button
            onClick={() => setActiveTab("vectors")}
            className={`px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
              activeTab === "vectors"
                ? "bg-gradient-to-r from-cyan-600 to-blue-600 text-white shadow-md"
                : "text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white"
            }`}
          >
            Attack Vectors
          </button>
          <button
            onClick={() => setActiveTab("dna")}
            className={`px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
              activeTab === "dna"
                ? "bg-gradient-to-r from-cyan-600 to-blue-600 text-white shadow-md"
                : "text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white"
            }`}
          >
            PhishDNA Variance
          </button>
        </div>
      </div>

      {/* TAB 1: Ingestion Velocity & Verdict Metrics */}
      {activeTab === "velocity" && (
        <div className="space-y-6 animate-fade-in">
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 md:gap-4">
            <div className="rounded-xl border border-slate-300/80 dark:border-slate-700/80 bg-slate-50/70 dark:bg-slate-900/60 p-4 shadow-sm">
              <span className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">Scanned Velocity</span>
              <div className="text-2xl font-bold font-mono text-slate-900 dark:text-white mt-1">1,482 <span className="text-xs font-normal text-cyan-600 dark:text-cyan-400">eml/min</span></div>
              <div className="flex items-center gap-1 mt-2 text-xs text-emerald-600 dark:text-emerald-400 font-medium">
                <TrendingUp className="h-3.5 w-3.5" /> +18.4% peak burst
              </div>
            </div>

            <div className="rounded-xl border border-rose-200 dark:border-rose-950/40 bg-rose-50/80 dark:bg-rose-950/20 p-4 shadow-sm">
              <span className="text-xs font-medium text-rose-700 dark:text-rose-300 uppercase tracking-wider">Phishing Blocked</span>
              <div className="text-2xl font-bold font-mono text-rose-600 dark:text-rose-400 mt-1">429 <span className="text-xs font-normal text-rose-600 dark:text-rose-300">threats</span></div>
              <div className="flex items-center gap-1 mt-2 text-xs text-rose-600 dark:text-rose-400 font-medium">
                <Flame className="h-3.5 w-3.5" /> 28.9% critical ratio
              </div>
            </div>

            <div className="rounded-xl border border-amber-200 dark:border-amber-950/40 bg-amber-50/80 dark:bg-amber-950/20 p-4 shadow-sm">
              <span className="text-xs font-medium text-amber-700 dark:text-amber-300 uppercase tracking-wider">Spoofed / Lookalike</span>
              <div className="text-2xl font-bold font-mono text-amber-600 dark:text-amber-400 mt-1">184 <span className="text-xs font-normal text-amber-600 dark:text-amber-300">domains</span></div>
              <div className="flex items-center gap-1 mt-2 text-xs text-amber-600 dark:text-amber-400 font-medium">
                <ShieldAlert className="h-3.5 w-3.5" /> Homoglyph & Display Spoof
              </div>
            </div>

            <div className="rounded-xl border border-cyan-200 dark:border-cyan-950/40 bg-cyan-50/80 dark:bg-cyan-950/20 p-4 shadow-sm">
              <span className="text-xs font-medium text-cyan-700 dark:text-cyan-300 uppercase tracking-wider">Kaggle Phish URLs</span>
              <div className="text-2xl font-bold font-mono text-cyan-600 dark:text-cyan-400 mt-1">73,575 <span className="text-xs font-normal text-cyan-600 dark:text-cyan-300">indexed</span></div>
              <div className="flex items-center gap-1 mt-2 text-xs text-cyan-600 dark:text-cyan-400 font-medium">
                <Database className="h-3.5 w-3.5" /> Real-time cross correlation
              </div>
            </div>
          </div>

          {/* Graphical Ingestion Waveform Simulator */}
          <div className="rounded-xl border border-slate-300/80 dark:border-slate-800 bg-slate-50/60 dark:bg-slate-900/80 p-5">
            <div className="flex items-center justify-between mb-4">
              <span className="text-xs font-mono font-bold text-slate-700 dark:text-slate-300 uppercase tracking-wider flex items-center gap-2">
                <Activity className="h-4 w-4 text-cyan-600 dark:text-cyan-400" />
                Live 24-Hour Threat Ingestion & Quarantine Activity
              </span>
              <span className="text-xs font-mono text-slate-500">Auto-refreshing (1s)</span>
            </div>

            <div className="h-44 w-full flex items-end gap-1.5 pt-4 pb-2 border-b border-slate-200 dark:border-slate-800">
              {[35, 42, 60, 48, 75, 90, 65, 82, 95, 78, 88, 110, 85, 95, 120, 105, 130, 98, 115, 140, 125, 150, 138, 160, 145, 170, 155, 180, 165, 190, 175, 200].map((val, idx) => {
                const heightPct = Math.min(100, Math.round((val / 210) * 100));
                const isPeak = val > 160;
                return (
                  <div key={idx} className="flex-1 flex flex-col items-center gap-1 group relative h-full justify-end">
                    <div
                      style={{ height: `${heightPct}%` }}
                      className={`w-full rounded-t transition-all duration-300 group-hover:brightness-125 ${
                        isPeak
                          ? "bg-gradient-to-t from-rose-500 to-rose-400 shadow-sm"
                          : "bg-gradient-to-t from-blue-500 via-cyan-500 to-cyan-400"
                      }`}
                    />
                  </div>
                );
              })}
            </div>

            <div className="flex justify-between items-center text-[10px] font-mono text-slate-500 mt-3">
              <span>00:00 UTC</span>
              <span>06:00 UTC</span>
              <span>12:00 UTC</span>
              <span>18:00 UTC</span>
              <span>LIVE</span>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: Attack Vectors Breakdown */}
      {activeTab === "vectors" && (
        <div className="space-y-6 animate-fade-in">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="rounded-xl border border-slate-300/80 dark:border-slate-800 bg-slate-50/60 dark:bg-slate-900/80 p-5">
              <h4 className="text-sm font-bold text-slate-900 dark:text-white mb-4 flex items-center gap-2">
                <Zap className="h-4 w-4 text-amber-500" />
                Dominant Impersonation Lure Categories
              </h4>
              <div className="space-y-3">
                {[
                  { name: "Banking & Indian KYC Phishing (SBI / HDFC / Paytm)", pct: 38, color: "bg-rose-500" },
                  { name: "Executive Display Name Spoofing (CEO / CFO Fraud)", pct: 26, color: "bg-amber-500" },
                  { name: "IT Security & Credential Expire Lures (M365 / Okta)", pct: 21, color: "bg-cyan-500" },
                  { name: "Urgent Payment & Invoice Routing Fraud", pct: 15, color: "bg-blue-500" },
                ].map((item, idx) => (
                  <div key={idx} className="space-y-1">
                    <div className="flex justify-between text-xs font-mono">
                      <span className="text-slate-700 dark:text-slate-300 truncate">{item.name}</span>
                      <span className="font-bold text-slate-900 dark:text-white">{item.pct}%</span>
                    </div>
                    <div className="h-2 w-full rounded-full bg-slate-200 dark:bg-slate-800 overflow-hidden">
                      <div className={`h-full rounded-full ${item.color}`} style={{ width: `${item.pct}%` }} />
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="rounded-xl border border-slate-300/80 dark:border-slate-800 bg-slate-50/60 dark:bg-slate-900/80 p-5">
              <h4 className="text-sm font-bold text-slate-900 dark:text-white mb-4 flex items-center gap-2">
                <Globe2 className="h-4 w-4 text-cyan-600 dark:text-cyan-400" />
                Infrastructure & Origin Relay Distribution
              </h4>
              <div className="space-y-3">
                {[
                  { name: "Tor Exit Relays / Anonymized Proxies", pct: 34, color: "bg-purple-500" },
                  { name: "Compromised Residential ASNs", pct: 29, color: "bg-indigo-500" },
                  { name: "Bulletproof Offshore VPS Hosting", pct: 22, color: "bg-rose-500" },
                  { name: "Cloud Provider Egress (AWS/GCP/DigitalOcean)", pct: 15, color: "bg-cyan-500" },
                ].map((item, idx) => (
                  <div key={idx} className="space-y-1">
                    <div className="flex justify-between text-xs font-mono">
                      <span className="text-slate-700 dark:text-slate-300 truncate">{item.name}</span>
                      <span className="font-bold text-slate-900 dark:text-white">{item.pct}%</span>
                    </div>
                    <div className="h-2 w-full rounded-full bg-slate-200 dark:bg-slate-800 overflow-hidden">
                      <div className={`h-full rounded-full ${item.color}`} style={{ width: `${item.pct}%` }} />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: PhishDNA Variance */}
      {activeTab === "dna" && (
        <div className="space-y-6 animate-fade-in">
          <div className="rounded-xl border border-slate-300/80 dark:border-slate-800 bg-slate-50/60 dark:bg-slate-900/80 p-5">
            <h4 className="text-sm font-bold text-slate-900 dark:text-white mb-2 flex items-center gap-2">
              <Sparkles className="h-4 w-4 text-cyan-600 dark:text-cyan-400" />
              PhishDNA Invariant Extraction vs Polymorphic Mutation Rate
            </h4>
            <p className="text-xs text-slate-600 dark:text-slate-400 mb-6 leading-relaxed">
              When adversaries mutate email headers, sender IP subnets, and body copy, CyberSentry correlates structural anchor invariants (DOM layout entropy, CSS class hierarchies, and font fingerprints) to group isolated emails into unified attack campaigns.
            </p>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              {[
                { title: "HTML DOM Tree Stability", score: "94.8%", sub: "High structural similarity across mutating variants", tone: "text-cyan-600 dark:text-cyan-400" },
                { title: "Lure Semantic Alignment", score: "89.2%", sub: "Invariant urgency & credential harvest themes", tone: "text-indigo-600 dark:text-indigo-400" },
                { title: "Campaign Clustering Precision", score: "97.4%", sub: "Zero false-positive merges across 73k Kaggle samples", tone: "text-emerald-600 dark:text-emerald-400" },
              ].map((card, i) => (
                <div key={i} className="rounded-xl border border-slate-300/80 dark:border-slate-800 bg-white dark:bg-slate-950/70 p-4 flex flex-col justify-between shadow-sm">
                  <div>
                    <span className="text-xs font-mono font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">{card.title}</span>
                    <div className={`text-3xl font-extrabold font-mono ${card.tone} mt-2`}>{card.score}</div>
                  </div>
                  <p className="text-[11px] text-slate-600 dark:text-slate-400 mt-3 pt-3 border-t border-slate-200 dark:border-slate-800/80">{card.sub}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
