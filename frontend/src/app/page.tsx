import Link from "next/link";
import {
  ShieldAlert,
  ArrowRight,
  Fingerprint,
  Layers,
  FileCheck2,
  Lock,
  Globe,
  Database,
  Building2,
  Landmark,
  ShieldCheck,
  Cpu,
  Sparkles,
  Zap,
  Activity,
  Terminal
} from "lucide-react";

import { LogoMark } from "@/components/brand/logo";
import { ThreatIntelligenceCharts } from "@/components/landing/threat-charts";
import { FutureRoadmapSection } from "@/components/landing/future-roadmap";
import { ThemeToggle } from "@/components/theme/theme-toggle";

const sectors = [
  { icon: Building2, label: "Banking & Financial Services (BFSI)" },
  { icon: Landmark, label: "Government & National Infrastructure" },
  { icon: ShieldCheck, label: "Enterprise Security Operations (SOC)" },
];

const capabilities = [
  {
    icon: Fingerprint,
    title: "PhishDNA™ Multi-Vector Structural Fingerprinting",
    description:
      "Perceptual DOM hashing, CSS style invariant extraction, and sender impersonation entropy scoring. Dissects polymorphic campaigns even when attackers alter body text and URLs.",
    points: [
      "Jaccard & Levenshtein header graph matching",
      "Invariant detection across mutated email variants",
      "Threshold-tuned correlation clustering (0.75+)",
    ],
    border: "border-cyan-500/30",
  },
  {
    icon: Globe,
    title: "MTA Transmission Hop & Geo-Infrastructure Engine",
    description:
      "Deterministic hop-by-hop Received header parser. Classifies origin infrastructure, flags Tor exit relays, bulletproof hosts, and multi-cloud forwarding anomalies.",
    points: [
      "Subnet & ASN classification (MaxMind GeoLite2)",
      "FCrDNS and HELO/EHLO identity mismatch analysis",
      "Dynamic GeoJSON transmission route mapping",
    ],
    border: "border-blue-500/30",
  },
  {
    icon: Lock,
    title: "Indian DPDP Act & PII Redaction Layer",
    description:
      "Strict data protection before any AI enrichment or storage. Masks Aadhaar, PAN, UPI IDs, Indian phone numbers, and employee credentials using regex & NER.",
    points: [
      "Deterministic pre-analysis tokenization",
      "Zero cleartext PII sent to external threat feeds",
      "DPDP 2023 & ISO/IEC 27037 forensic chain integrity",
    ],
    border: "border-indigo-500/30",
  },
  {
    icon: FileCheck2,
    title: "Cryptographic Chain of Custody & Court Admissibility",
    description:
      "Immutable SHA-256 evidence hashing, chained event logs, and on-demand CERT-In / ISO 27037 incident disclosure packages with cryptographic verification.",
    points: [
      "Tamper-evident custody ledger",
      "Self-verifying signed forensic JSON exports",
      "One-click CERT-In incident disclosure PDF bundle",
    ],
    border: "border-emerald-500/30",
  },
];

const steps = [
  {
    num: "01",
    title: "RFC Ingestion",
    description:
      "Parse RFC 5322 MIME structures, nested attachments, Received hops, and unescaped HTML DOM trees.",
  },
  {
    num: "02",
    title: "Deep Signal Extraction",
    description:
      "Analyze SPF/DKIM/DMARC alignment, lookalike homoglyphs, brand impersonation lures, and ASN reputation.",
  },
  {
    num: "03",
    title: "Graph Correlation",
    description:
      "Synthesize PhishDNA vectors to map global campaigns, uncover shared adversary infrastructure, and track variants.",
  },
  {
    num: "04",
    title: "Forensic Output",
    description:
      "Generate immutable forensic evidence chains, live kill-chain graphs, and CERT-In compliance documentation.",
  },
];

export default function LandingPage() {
  return (
    <div className="min-h-screen bg-[var(--bg-base)] text-[var(--text-primary)] selection:bg-cyan-500 selection:text-white font-sans antialiased overflow-x-hidden transition-colors duration-200">
      {/* Dynamic Background Pattern */}
      <div className="fixed inset-0 cyber-grid opacity-60 pointer-events-none" />
      <div className="fixed top-0 left-1/4 h-96 w-96 rounded-full bg-cyan-500/10 blur-[140px] pointer-events-none" />
      <div className="fixed top-1/3 right-10 h-96 w-96 rounded-full bg-indigo-500/10 blur-[150px] pointer-events-none" />

      {/* HEADER NAVIGATION */}
      <header className="sticky top-0 z-50 border-b border-slate-200/80 dark:border-slate-800/80 bg-white/85 dark:bg-[#0f172a]/90 backdrop-blur-xl transition-colors duration-200">
        <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-4 sm:px-6 lg:px-8">
          <Link href="/" className="flex items-center gap-3 group">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-cyan-500 via-blue-600 to-indigo-700 shadow-lg shadow-cyan-500/25 group-hover:scale-105 transition-transform">
              <LogoMark className="h-5 w-5 text-white" />
            </div>
            <div>
              <span className="text-lg font-bold tracking-tight text-slate-900 dark:text-white font-mono flex items-center gap-1.5">
                CYBER<span className="text-cyan-600 dark:text-cyan-400">SENTRY</span>
              </span>
              <span className="hidden sm:block text-[9px] font-mono uppercase tracking-widest text-slate-500 dark:text-slate-400 -mt-1">
                Forensic & Threat Intelligence
              </span>
            </div>
          </Link>

          <nav className="flex items-center gap-2 sm:gap-4">
            <Link
              href="/#telemetry"
              className="hidden md:inline-block text-xs font-semibold text-slate-600 dark:text-slate-300 hover:text-cyan-600 dark:hover:text-cyan-400 transition-colors"
            >
              Live Telemetry
            </Link>
            <Link
              href="/#roadmap"
              className="hidden md:inline-block text-xs font-semibold text-slate-600 dark:text-slate-300 hover:text-cyan-600 dark:hover:text-cyan-400 transition-colors"
            >
              Future Roadmap
            </Link>

            {/* Theme Toggle Button */}
            <ThemeToggle />

            <Link
              href="/login"
              className="inline-flex items-center justify-center rounded-lg border border-slate-300 dark:border-slate-700/80 bg-white/90 dark:bg-slate-800/90 px-3.5 py-2 text-xs font-semibold text-slate-700 dark:text-slate-200 shadow-sm hover:border-cyan-500 hover:text-cyan-600 dark:hover:text-white transition-all cursor-pointer"
            >
              SOC Analyst Login
            </Link>
            <Link
              href="/dashboard"
              className="btn-primary"
            >
              <span>Launch Platform</span>
              <ArrowRight className="h-3.5 w-3.5" />
            </Link>
          </nav>
        </div>
      </header>

      {/* HERO SECTION */}
      <section className="relative pt-16 pb-20 sm:pt-24 sm:pb-28">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
          <div className="text-center max-w-4xl mx-auto">
            {/* Live Indicator Badge */}
            <div className="inline-flex items-center gap-2 rounded-full border border-cyan-500/30 bg-cyan-100/70 dark:bg-cyan-950/60 px-3.5 py-1 text-xs font-mono font-medium text-cyan-800 dark:text-cyan-300 mb-8 backdrop-blur-md shadow-md">
              <span className="flex h-2 w-2 rounded-full bg-cyan-500 animate-pulse" />
              <span>Next-Gen Problem Statement 26106 Overhaul Complete</span>
            </div>

            <h1 className="text-4xl sm:text-6xl lg:text-7xl font-extrabold tracking-tight text-slate-900 dark:text-white leading-[1.1] mb-6">
              AI-Powered Email Threat Detection,{" "}
              <span className="gradient-cyber-text">GeoLocation & Forensic Intelligence</span>
            </h1>

            <p className="text-lg sm:text-xl text-slate-600 dark:text-slate-300 max-w-3xl mx-auto leading-relaxed mb-10 font-normal">
              Detect spoofed, impersonated, and polymorphic phishing emails in real time. Trace transmission paths to origin MTAs, correlate global attack campaigns with PhishDNA™, and generate court-admissible forensic evidence.
            </p>

            <div className="flex flex-col sm:flex-row items-center justify-center gap-4 mb-16">
              <Link
                href="/dashboard"
                className="w-full sm:w-auto inline-flex items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-cyan-600 via-blue-600 to-indigo-600 px-8 py-3.5 text-sm font-bold text-white shadow-xl shadow-cyan-500/25 hover:scale-[1.02] active:scale-[0.98] transition-all font-mono"
              >
                <span>OPEN LIVE SOC CONSOLE</span>
                <ArrowRight className="h-4 w-4" />
              </Link>
              <Link
                href="/login"
                className="w-full sm:w-auto inline-flex items-center justify-center gap-2 rounded-xl border border-slate-300 dark:border-slate-700 bg-white/90 dark:bg-slate-800/90 px-8 py-3.5 text-sm font-semibold text-slate-700 dark:text-slate-200 hover:border-cyan-500 hover:text-cyan-600 dark:hover:text-white transition-all shadow-sm"
              >
                <span>Demo Credentials Access</span>
              </Link>
            </div>

            {/* Quick Sector Trust Bar */}
            <div className="pt-8 border-t border-slate-200 dark:border-slate-800/80">
              <p className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-4">
                Engineered for High-Assurance Defense Across Critical Sectors
              </p>
              <div className="flex flex-wrap items-center justify-center gap-3 sm:gap-6">
                {sectors.map((s, i) => (
                  <div
                    key={i}
                    className="flex items-center gap-2 rounded-lg border border-slate-300/80 dark:border-slate-800 bg-white/80 dark:bg-slate-800/60 px-3.5 py-1.5 text-xs text-slate-700 dark:text-slate-300 font-medium backdrop-blur-sm shadow-sm"
                  >
                    <s.icon className="h-3.5 w-3.5 text-cyan-600 dark:text-cyan-400" />
                    <span>{s.label}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* LIVE TELEMETRY & CHARTS SECTION */}
      <section id="telemetry" className="py-12 relative">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
          <ThreatIntelligenceCharts />
        </div>
      </section>

      {/* CORE CAPABILITIES GRID */}
      <section className="py-20 relative">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
          <div className="text-center max-w-3xl mx-auto mb-16">
            <h2 className="text-3xl sm:text-4xl font-extrabold tracking-tight text-slate-900 dark:text-white mb-4">
              Comprehensive Multi-Layered Threat Architecture
            </h2>
            <p className="text-base sm:text-lg text-slate-600 dark:text-slate-400">
              From raw header parsing down to multi-hop ASNs, PhishDNA clustering, and Indian-context PII masking.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 lg:gap-8">
            {capabilities.map((c, i) => (
              <div
                key={i}
                className={`rounded-2xl border border-slate-300/80 dark:border-slate-800 bg-white/80 dark:bg-slate-800/70 p-6 sm:p-8 backdrop-blur-xl shadow-lg transition-all duration-300 hover:scale-[1.01] hover:border-cyan-500/50 flex flex-col justify-between`}
              >
                <div>
                  <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-cyan-50 dark:bg-slate-900 border border-cyan-200 dark:border-slate-800 text-cyan-600 dark:text-cyan-400 mb-6 shadow-inner">
                    <c.icon className="h-6 w-6" />
                  </div>
                  <h3 className="text-xl font-bold text-slate-900 dark:text-white mb-3 tracking-tight">
                    {c.title}
                  </h3>
                  <p className="text-sm text-slate-600 dark:text-slate-400 leading-relaxed mb-6">
                    {c.description}
                  </p>
                </div>

                <div className="space-y-2 pt-4 border-t border-slate-200 dark:border-slate-800/80">
                  {c.points.map((p, j) => (
                    <div key={j} className="flex items-center gap-2 text-xs text-slate-700 dark:text-slate-300 font-medium">
                      <span className="h-1.5 w-1.5 rounded-full bg-cyan-500" />
                      <span>{p}</span>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* HOW IT WORKS - 4 STEPS */}
      <section className="py-20 border-y border-slate-200 dark:border-slate-800 bg-slate-100/50 dark:bg-slate-900/40 relative">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
          <div className="text-center max-w-3xl mx-auto mb-16">
            <span className="text-xs font-mono font-bold uppercase tracking-wider text-cyan-600 dark:text-cyan-400">
              OPERATIONAL WORKFLOW
            </span>
            <h2 className="text-3xl sm:text-4xl font-extrabold tracking-tight text-slate-900 dark:text-white mt-2">
              From Ingestion to Forensic Admissibility
            </h2>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
            {steps.map((s, i) => (
              <div
                key={i}
                className="rounded-xl border border-slate-300/80 dark:border-slate-800 bg-white/90 dark:bg-slate-800/80 p-6 relative flex flex-col justify-between shadow-sm"
              >
                <div>
                  <span className="text-3xl font-extrabold font-mono text-cyan-600/40 dark:text-cyan-500/40 block mb-4">
                    {s.num}
                  </span>
                  <h4 className="text-base font-bold text-slate-900 dark:text-white mb-2">{s.title}</h4>
                  <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">{s.description}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* FUTURE ROADMAP SECTION */}
      <section id="roadmap">
        <FutureRoadmapSection />
      </section>

      {/* CALL TO ACTION */}
      <section className="py-20 relative overflow-hidden">
        <div className="mx-auto max-w-5xl px-4 sm:px-6 lg:px-8">
          <div className="rounded-3xl border border-cyan-500/30 bg-gradient-to-br from-white via-cyan-50/50 to-blue-50/50 dark:from-slate-900 dark:via-slate-900 dark:to-cyan-950/40 p-8 sm:p-12 text-center relative overflow-hidden shadow-2xl">
            <div className="absolute -right-20 -bottom-20 h-64 w-64 rounded-full bg-cyan-500/20 blur-3xl pointer-events-none" />

            <h2 className="text-3xl sm:text-4xl font-extrabold tracking-tight text-slate-900 dark:text-white mb-4">
              Ready to Investigate Threats with High Assurance?
            </h2>
            <p className="text-base text-slate-600 dark:text-slate-300 max-w-2xl mx-auto mb-8">
              Explore the live CyberSentry SOC dashboard, evaluate polymorphic campaign clusters, and inspect origin attribution graphs.
            </p>

            <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
              <Link
                href="/dashboard"
                className="w-full sm:w-auto inline-flex items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 px-8 py-3.5 text-sm font-bold text-white shadow-lg shadow-cyan-500/30 hover:brightness-110 transition-all font-mono"
              >
                <span>OPEN DASHBOARD</span>
                <ArrowRight className="h-4 w-4" />
              </Link>
              <Link
                href="/login"
                className="w-full sm:w-auto inline-flex items-center justify-center gap-2 rounded-xl border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 px-8 py-3.5 text-sm font-semibold text-slate-700 dark:text-slate-200 hover:border-cyan-500 hover:text-cyan-600 dark:hover:text-white transition-all shadow-sm"
              >
                <span>SOC Analyst Login</span>
              </Link>
            </div>
          </div>
        </div>
      </section>

      {/* FOOTER */}
      <footer className="border-t border-slate-200 dark:border-slate-800 bg-white/80 dark:bg-[#0f172a] py-12 text-slate-600 dark:text-slate-400 text-xs transition-colors duration-200">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2 font-mono text-slate-800 dark:text-slate-300">
            <LogoMark className="h-4 w-4 text-cyan-600 dark:text-cyan-400" />
            <span>CyberSentry V2 — AI-Powered Email Forensic Intelligence Platform</span>
          </div>
          <p className="text-slate-500 dark:text-slate-400 text-center sm:text-right">
            Aligning with RFC 5321/5322 Standards, NIST SP 800-86 & India DPDP Act 2023.
          </p>
        </div>
      </footer>
    </div>
  );
}
