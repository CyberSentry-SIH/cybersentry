"use client";

import React, { useEffect, useState } from "react";
import { Moon, Sun } from "lucide-react";
import { useTheme } from "./theme-provider";

export function ThemeToggle({ className }: { className?: string }) {
  const { theme, toggleTheme } = useTheme();
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  if (!mounted) {
    return (
      <div className={`h-8 w-8 rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-100 dark:bg-slate-800 ${className || ""}`} />
    );
  }

  const isDark = theme === "dark";

  return (
    <button
      type="button"
      onClick={toggleTheme}
      className={`relative inline-flex h-8 w-8 items-center justify-center rounded-lg border border-slate-300 dark:border-slate-700/80 bg-white/90 dark:bg-slate-800/90 text-slate-700 dark:text-slate-200 shadow-sm hover:border-cyan-500 hover:text-cyan-600 dark:hover:text-cyan-400 focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500 transition-all duration-200 cursor-pointer ${className || ""}`}
      title={isDark ? "Switch to Low-Dim Bluish Light Mode" : "Switch to Low-Dim Dark Cyber Mode"}
      aria-label="Toggle theme"
    >
      {isDark ? (
        <Sun className="h-4 w-4 text-amber-400 transition-transform duration-300 rotate-0 scale-100" />
      ) : (
        <Moon className="h-4 w-4 text-cyan-600 transition-transform duration-300 rotate-0 scale-100" />
      )}
    </button>
  );
}
