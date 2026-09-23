"use client";

import { useState, useEffect, type FormEvent } from "react";
import Link from "next/link";
import { Eye, EyeOff, Loader2, ShieldAlert, ShieldCheck, KeyRound, UserCheck, ArrowRight, Activity } from "lucide-react";

import { LogoMark } from "@/components/brand/logo";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { ThemeToggle } from "@/components/theme/theme-toggle";
import { api } from "@/lib/api";

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export default function LoginPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [serverOnline, setServerOnline] = useState<boolean | null>(null);
  const [fieldErrors, setFieldErrors] = useState<{
    email?: string;
    password?: string;
  }>({});
  const [authError, setAuthError] = useState<string | null>(null);

  useEffect(() => {
    api.getHealth()
      .then((res) => {
        setServerOnline(res?.status === "OK" || res !== null);
      })
      .catch(() => {
        setServerOnline(false);
      });
  }, []);

  function validate(): boolean {
    const errors: typeof fieldErrors = {};
    if (!email.trim()) {
      errors.email = "Email is required.";
    } else if (!EMAIL_PATTERN.test(email)) {
      errors.email = "Enter a valid email address.";
    }
    if (!password) {
      errors.password = "Password is required.";
    }
    setFieldErrors(errors);
    return Object.keys(errors).length === 0;
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setAuthError(null);
    if (!validate()) return;

    setLoading(true);
    try {
      await api.login({ email, password });
      window.location.href = "/dashboard";
    } catch (err: any) {
      setAuthError(err.message || "Invalid email or password.");
    } finally {
      setLoading(false);
    }
  }

  function fillAccount(accEmail: string, accPass: string) {
    setEmail(accEmail);
    setPassword(accPass);
    setFieldErrors({});
    setAuthError(null);
  }

  return (
    <div className="relative min-h-screen flex items-center justify-center bg-[var(--bg-base)] px-4 py-12 text-[var(--text-primary)] selection:bg-cyan-500 selection:text-white overflow-hidden font-sans transition-colors duration-200">
      {/* Ambient background glows */}
      <div className="fixed inset-0 cyber-grid opacity-50 pointer-events-none" />
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 h-96 w-96 rounded-full bg-cyan-500/15 blur-[120px] pointer-events-none" />
      <div className="absolute bottom-10 right-10 h-80 w-80 rounded-full bg-indigo-500/10 blur-[140px] pointer-events-none" />

      {/* Top Bar Theme Toggle */}
      <div className="absolute top-4 right-4 z-50 flex items-center gap-2">
        <ThemeToggle />
      </div>

      <div className="w-full max-w-md relative z-10">
        {/* Brand Header */}
        <div className="flex flex-col items-center gap-3 text-center mb-8">
          <Link href="/" className="group flex flex-col items-center gap-2">
            <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-gradient-to-br from-cyan-500 via-blue-600 to-indigo-700 shadow-xl shadow-cyan-500/25 group-hover:scale-105 transition-transform">
              <LogoMark className="h-7 w-7 text-white" />
            </div>
            <h1 className="text-2xl font-extrabold tracking-tight text-slate-900 dark:text-white font-mono flex items-center gap-1.5 mt-1">
              CYBER<span className="text-cyan-600 dark:text-cyan-400">SENTRY</span>
            </h1>
          </Link>
          <p className="text-xs font-mono uppercase tracking-widest text-slate-500 dark:text-slate-400">
            SOC Forensic &amp; Campaign Intelligence Console
          </p>
        </div>

        {/* Main Card */}
        <div className="rounded-2xl border border-slate-300/80 dark:border-slate-700/80 bg-white/90 dark:bg-slate-800/90 shadow-2xl backdrop-blur-2xl p-6 sm:p-8 relative overflow-hidden transition-colors duration-200">
          {/* Top accent line */}
          <div className="absolute top-0 inset-x-0 h-1 bg-gradient-to-r from-cyan-500 via-blue-500 to-indigo-500" />

          <div className="flex items-center justify-between mb-6">
            <h2 className="text-lg font-bold text-slate-900 dark:text-white tracking-tight">SOC Access Authentication</h2>
            <div className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full border text-[10px] font-mono font-bold ${
              serverOnline === true
                ? "bg-emerald-100 dark:bg-emerald-950/60 border-emerald-300 dark:border-emerald-800 text-emerald-800 dark:text-emerald-400"
                : serverOnline === false
                ? "bg-rose-100 dark:bg-rose-950/60 border-rose-300 dark:border-rose-800 text-rose-800 dark:text-rose-400"
                : "bg-amber-100 dark:bg-amber-950/60 border-amber-300 dark:border-amber-800 text-amber-800 dark:text-amber-400"
            }`}>
              <span className={`h-1.5 w-1.5 rounded-full ${
                serverOnline === true
                  ? "bg-emerald-500 animate-pulse"
                  : serverOnline === false
                  ? "bg-rose-500"
                  : "bg-amber-500 animate-ping"
              }`} />
              <span>{serverOnline === true ? "SERVER ONLINE" : serverOnline === false ? "SERVER OFFLINE" : "CONNECTING..."}</span>
            </div>
          </div>

          {authError && (
            <div className="mb-6 rounded-xl border border-rose-300 dark:border-rose-800/80 bg-rose-50 dark:bg-rose-950/50 p-4 text-xs text-rose-800 dark:text-rose-300 flex items-start gap-3 animate-fade-in">
              <ShieldAlert className="h-5 w-5 text-rose-600 dark:text-rose-400 shrink-0 mt-0.5" />
              <div>
                <p className="font-bold">Authentication Refused</p>
                <p className="mt-0.5 opacity-90">{authError}</p>
              </div>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-xs font-mono font-semibold uppercase tracking-wider text-slate-700 dark:text-slate-300 mb-1.5">
                Official SOC Email
              </label>
              <Input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="analyst@cybersentry.local"
                className="bg-slate-50 dark:bg-slate-900/90 border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white placeholder:text-slate-400 dark:placeholder:text-slate-500 focus-visible:ring-cyan-500 font-mono text-xs h-11"
                autoComplete="email"
              />
              {fieldErrors.email && (
                <p className="text-[11px] text-rose-600 dark:text-rose-400 font-mono mt-1">{fieldErrors.email}</p>
              )}
            </div>

            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label className="block text-xs font-mono font-semibold uppercase tracking-wider text-slate-700 dark:text-slate-300">
                  Password
                </label>
              </div>
              <div className="relative">
                <Input
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••••••"
                  className="bg-slate-50 dark:bg-slate-900/90 border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white placeholder:text-slate-400 dark:placeholder:text-slate-500 focus-visible:ring-cyan-500 font-mono text-xs h-11 pr-10"
                  autoComplete="current-password"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-700 dark:hover:text-slate-300"
                >
                  {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
              {fieldErrors.password && (
                <p className="text-[11px] text-rose-600 dark:text-rose-400 font-mono mt-1">{fieldErrors.password}</p>
              )}
            </div>

            <Button
              type="submit"
              disabled={loading}
              className="w-full h-11 rounded-xl bg-gradient-to-r from-cyan-600 via-blue-600 to-indigo-600 hover:from-cyan-500 hover:to-blue-500 text-white font-mono font-bold text-xs shadow-lg shadow-cyan-500/25 transition-all cursor-pointer"
            >
              {loading ? (
                <span className="flex items-center gap-2">
                  <Loader2 className="h-4 w-4 animate-spin" />
                  AUTHENTICATING &amp; CREATING SESSION...
                </span>
              ) : (
                <span className="flex items-center gap-2">
                  <span>ENTER SOC ENVIRONMENT</span>
                  <ArrowRight className="h-4 w-4" />
                </span>
              )}
            </Button>
          </form>

          {/* Quick autofill for demo and evaluation */}
          <div className="mt-6 pt-6 border-t border-slate-200 dark:border-slate-700/80">
            <p className="text-[11px] font-mono uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-3 text-center">
              Quick Autofill Demo Roles
            </p>
            <div className="grid grid-cols-2 gap-2">
              <button
                type="button"
                onClick={() => fillAccount("analyst@cybersentry.local", "Analyst@CyberSentry123!")}
                className="p-2.5 rounded-xl border border-slate-300/80 dark:border-slate-700/80 bg-slate-50/80 dark:bg-slate-900/60 hover:bg-white dark:hover:bg-slate-800 hover:border-cyan-500 text-left transition-all cursor-pointer group"
              >
                <div className="flex items-center gap-1.5 text-xs font-mono font-bold text-cyan-700 dark:text-cyan-400">
                  <ShieldCheck className="h-3.5 w-3.5" /> Lead Analyst
                </div>
                <div className="text-[10px] text-slate-500 font-mono truncate mt-0.5">analyst@cybersentry.local</div>
              </button>

              <button
                type="button"
                onClick={() => fillAccount("admin@cybersentry.local", "Admin@CyberSentry123!")}
                className="p-2.5 rounded-xl border border-slate-300/80 dark:border-slate-700/80 bg-slate-50/80 dark:bg-slate-900/60 hover:bg-white dark:hover:bg-slate-800 hover:border-amber-500 text-left transition-all cursor-pointer group"
              >
                <div className="flex items-center gap-1.5 text-xs font-mono font-bold text-amber-700 dark:text-amber-400">
                  <KeyRound className="h-3.5 w-3.5" /> SOC Admin
                </div>
                <div className="text-[10px] text-slate-500 font-mono truncate mt-0.5">admin@cybersentry.local</div>
              </button>
            </div>
          </div>
        </div>

        {/* Back Link */}
        <div className="text-center mt-6">
          <Link href="/" className="text-xs text-slate-500 hover:text-cyan-600 dark:hover:text-cyan-400 font-mono transition-colors">
            &larr; Return to CyberSentry Homepage
          </Link>
        </div>
      </div>
    </div>
  );
}
