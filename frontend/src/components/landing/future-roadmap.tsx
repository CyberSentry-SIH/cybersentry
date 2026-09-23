"use client";

import React from "react";
import {
  Cpu,
  Puzzle,
  MailCheck,
  Share2,
  Sparkles,
  ArrowRight,
  CheckCircle
} from "lucide-react";

export function FutureRoadmapSection() {
  const roadmapItems = [
    {
      icon: Cpu,
      badge: "CORE ARCHITECTURE",
      title: "Proprietary Local LLM / SLM (Air-Gapped)",
      description:
        "Replacing external cloud LLM dependencies (Google Gemini) with a self-hosted, domain-specific Small Language Model fine-tuned on forensic email headers, lure semantics, and attack trees for 100% on-premise DPDP Act compliance.",
      highlights: [
        "Zero telemetry egress: runs entirely on-premise",
        "Fine-tuned on 500k+ enterprise email threat corpora",
        "Sub-100ms deterministic inference on standard GPUs/CPUs",
      ],
      gradient: "from-cyan-500/15 via-blue-500/10 to-transparent",
      border: "border-cyan-500/30",
      accent: "text-cyan-600 dark:text-cyan-400"
    },
    {
      icon: Puzzle,
      badge: "IN-BROWSER DEFENSE",
      title: "Native Chrome & Firefox Extension Suite",
      description:
        "Real-time browser extension that monitors Gmail, Outlook 365, and webmail sessions directly in the browser, calling CyberSentry's fast-path scan API (<500ms) to display in-line origin verdicts before employees click.",
      highlights: [
        "In-line trust badges inside Gmail & Outlook Web",
        "Real-time URL redirection & homoglyph interceptor",
        "One-click 'Report to CyberSentry SOC' workflow",
      ],
      gradient: "from-amber-500/15 via-orange-500/10 to-transparent",
      border: "border-amber-500/30",
      accent: "text-amber-600 dark:text-amber-400"
    },
    {
      icon: MailCheck,
      badge: "ENTERPRISE CONNECTOR",
      title: "Native Gmail API & Microsoft 365 Graph Sync",
      description:
        "Direct API integration with Google Workspace and Microsoft 365 using Pub/Sub webhooks to continuously ingest, analyze, and automatically quarantine suspicious messages across the entire corporate directory.",
      highlights: [
        "Continuous mailbox ingestion via Google Pub/Sub & M365 Graph",
        "Automated inbox quarantine without client agent installation",
        "Bidirectional SOC SOAR playbook triggers",
      ],
      gradient: "from-purple-500/15 via-indigo-500/10 to-transparent",
      border: "border-purple-500/30",
      accent: "text-purple-600 dark:text-purple-400"
    },
    {
      icon: Share2,
      badge: "FEDERATED INTEL",
      title: "STIX 2.1 & TAXII Threat Intelligence Hub",
      description:
        "Bidirectional threat exchange with national CERTs and global intelligence feeds, automatically converting correlated PhishDNA invariants into standardized STIX 2.1 bundles for automated firewall & SIEM sync.",
      highlights: [
        "Automated STIX 2.1 JSON bundle export & IOC ingestion",
        "Community-driven bulletproof relay peer sharing",
        "Real-time integration with Splunk, QRadar, and Microsoft Sentinel",
      ],
      gradient: "from-emerald-500/15 via-teal-500/10 to-transparent",
      border: "border-emerald-500/30",
      accent: "text-emerald-600 dark:text-emerald-400"
    },
  ];

  return (
    <section className="py-20 relative overflow-hidden">
      {/* Glow elements */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 h-96 w-96 rounded-full bg-cyan-500/10 blur-[120px] pointer-events-none" />

      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="text-center max-w-3xl mx-auto mb-16">
          <div className="inline-flex items-center gap-2 rounded-full border border-cyan-500/30 bg-cyan-100/70 dark:bg-cyan-950/60 px-3.5 py-1 text-xs font-mono font-bold tracking-wider text-cyan-700 dark:text-cyan-400 mb-4 shadow-sm">
            <Sparkles className="h-3.5 w-3.5" /> FUTURE ROADMAP & CAPABILITIES
          </div>
          <h2 className="text-3xl sm:text-4xl font-extrabold tracking-tight text-slate-900 dark:text-white mb-4">
            Next-Generation Forensic Intelligence Architecture
          </h2>
          <p className="text-base sm:text-lg text-slate-600 dark:text-slate-400 leading-relaxed">
            Engineering proprietary local intelligence models, native browser extensions, and enterprise mail connectors to deliver sovereign, air-gapped threat detection.
          </p>
        </div>

        {/* Roadmap Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 lg:gap-8">
          {roadmapItems.map((item, idx) => (
            <div
              key={idx}
              className={`rounded-2xl border ${item.border} bg-white/90 dark:bg-slate-800/80 p-6 sm:p-8 backdrop-blur-xl shadow-lg transition-all duration-300 hover:-translate-y-1 hover:shadow-xl relative flex flex-col justify-between overflow-hidden group`}
            >
              {/* Background gradient overlay */}
              <div className={`absolute inset-0 bg-gradient-to-br ${item.gradient} opacity-50 group-hover:opacity-100 transition-opacity pointer-events-none`} />

              <div className="relative z-10">
                <div className="flex items-center justify-between gap-4 mb-4">
                  <div className={`p-3 rounded-xl bg-slate-100 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 ${item.accent} shadow-inner`}>
                    <item.icon className="h-6 w-6" />
                  </div>
                  <span className="px-3 py-1 rounded-full text-[10px] font-mono font-bold tracking-wider bg-slate-100 dark:bg-slate-900 text-slate-700 dark:text-slate-300 border border-slate-300 dark:border-slate-800">
                    {item.badge}
                  </span>
                </div>

                <h3 className="text-xl font-bold text-slate-900 dark:text-white mb-2.5 tracking-tight group-hover:text-cyan-600 dark:group-hover:text-cyan-300 transition-colors">
                  {item.title}
                </h3>
                <p className="text-sm text-slate-600 dark:text-slate-400 leading-relaxed mb-6">
                  {item.description}
                </p>

                <div className="space-y-2.5 pt-4 border-t border-slate-200 dark:border-slate-800/80">
                  {item.highlights.map((h, i) => (
                    <div key={i} className="flex items-center gap-2.5 text-xs text-slate-700 dark:text-slate-300">
                      <CheckCircle className={`h-4 w-4 shrink-0 ${item.accent}`} />
                      <span>{h}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="relative z-10 mt-6 pt-4 flex items-center justify-between text-xs font-semibold text-slate-500 dark:text-slate-400 group-hover:text-cyan-600 dark:group-hover:text-cyan-400 transition-colors">
                <span>Phase Readiness: In Active Development</span>
                <ArrowRight className="h-4 w-4 transition-transform group-hover:translate-x-1" />
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
