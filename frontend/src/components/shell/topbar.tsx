"use client";

import { Bell, Search, AlertOctagon, Radar, FolderOpen } from "lucide-react";

import { useCurrentUser } from "@/lib/auth-context";
import { Input } from "@/components/ui/input";
import { Separator } from "@/components/ui/separator";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Button } from "@/components/ui/button";
import { ThemeToggle } from "@/components/theme/theme-toggle";

const notifications = [
  {
    icon: AlertOctagon,
    tone: "text-rose-600 dark:text-rose-400",
    title: "Critical finding on AN-1042",
    meta: "Credential harvesting + impersonation · 2 min ago",
  },
  {
    icon: Radar,
    tone: "text-cyan-600 dark:text-cyan-400",
    title: "CMP-0091 moved to Expanding",
    meta: "New domain observed · 12 min ago",
  },
  {
    icon: FolderOpen,
    tone: "text-blue-600 dark:text-blue-400",
    title: "Case CS-00038 assigned to you",
    meta: "1 hr ago",
  },
];

export function TopBar() {
  const user = useCurrentUser();

  if (!user) return null;

  return (
    <header className="relative z-10 flex h-12 shrink-0 items-center gap-3 border-b border-slate-200 dark:border-slate-800 bg-white/95 dark:bg-slate-900/95 backdrop-blur-md px-4 shadow-sm transition-colors duration-200">
      <div className="hidden shrink-0 items-center gap-2 text-xs font-mono sm:flex">
        <span className="text-slate-600 dark:text-slate-400 font-medium">{user.organization}</span>
        <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold uppercase tracking-wider bg-cyan-100 dark:bg-cyan-950/60 text-cyan-700 dark:text-cyan-400 border border-cyan-300 dark:border-cyan-900/50">
          PRODUCTION
        </span>
      </div>

      <Separator orientation="vertical" className="hidden h-5 sm:block bg-slate-200 dark:bg-slate-800" />

      <div className="relative w-full max-w-md">
        <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-400 dark:text-slate-500" />
        <Input
          placeholder="Search emails, domains, IPs, URLs, campaigns…"
          className="h-8 border-slate-300 dark:border-slate-700/80 bg-slate-50 dark:bg-slate-800/90 pl-8 text-xs font-mono text-slate-800 dark:text-slate-200 placeholder:text-slate-400 dark:placeholder:text-slate-500 focus-visible:border-cyan-500 focus-visible:ring-cyan-500/30"
          aria-label="Global search"
        />
      </div>

      <div className="ml-auto flex items-center gap-2">
        <ThemeToggle />

        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button
              variant="ghost"
              size="icon"
              aria-label="Notifications"
              title="Notifications"
              className="relative h-8 w-8 border border-slate-300 dark:border-slate-700/80 bg-white/90 dark:bg-slate-800/90 hover:bg-slate-100 dark:hover:bg-slate-700 hover:border-cyan-500 transition-all cursor-pointer"
            >
              <Bell className="h-4 w-4 text-slate-600 dark:text-slate-400" />
              <span className="absolute right-1.5 top-1.5 h-1.5 w-1.5 rounded-full bg-rose-500 animate-pulse" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-80 p-0 bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-800 shadow-xl">
            <div className="flex items-center justify-between px-3 py-2 border-b border-slate-200 dark:border-slate-800">
              <span className="text-xs font-mono font-bold text-slate-700 dark:text-slate-300 uppercase tracking-wider">
                Threat Alerts
              </span>
              <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-100 dark:bg-rose-950/60 text-rose-700 dark:text-rose-400 border border-rose-300 dark:border-rose-900/50">
                {notifications.length} NEW
              </span>
            </div>
            {notifications.map((n) => {
              const Icon = n.icon;
              return (
                <DropdownMenuItem
                  key={n.title}
                  className="items-start gap-2.5 py-2.5 hover:bg-slate-100 dark:hover:bg-slate-800 cursor-pointer"
                >
                  <Icon className={`mt-0.5 h-4 w-4 shrink-0 ${n.tone}`} />
                  <div className="min-w-0">
                    <p className="text-xs font-medium text-slate-800 dark:text-slate-200">{n.title}</p>
                    <p className="truncate text-[11px] text-slate-500 dark:text-slate-400">{n.meta}</p>
                  </div>
                </DropdownMenuItem>
              );
            })}
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </header>
  );
}
