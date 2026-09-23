"use client";

import { useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { ChevronsLeft, ChevronsRight, Shield } from "lucide-react";

import { navGroups } from "@/config/nav";
import { useCurrentUser } from "@/lib/auth-context";
import { cn } from "@/lib/utils";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import {
  DropdownMenu,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { AccountMenuContent } from "@/components/shell/account-menu-content";

export function Sidebar() {
  const pathname = usePathname();
  const user = useCurrentUser();
  const [collapsed, setCollapsed] = useState(false);

  if (!user) return null;

  return (
    <aside
      className={cn(
        "relative z-10 hidden shrink-0 flex-col border-r border-slate-200 dark:border-slate-800 bg-white/95 dark:bg-slate-900/95 shadow-sm transition-[width] duration-200 md:flex",
        collapsed ? "w-14" : "w-[220px]"
      )}
    >
      {/* Brand header */}
      <div
        className={cn(
          "flex items-center gap-2.5 border-b border-slate-200 dark:border-slate-800/80 px-3 py-3.5",
          collapsed && "justify-center px-0"
        )}
      >
        <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-lg bg-gradient-to-br from-cyan-600 to-blue-600 shadow-md">
          <Shield className="h-4 w-4 text-white" />
        </div>
        {!collapsed ? (
          <div className="min-w-0 leading-tight">
            <p className="truncate text-sm font-bold tracking-tight font-mono text-slate-900 dark:text-white">
              CYBER<span className="text-cyan-600 dark:text-cyan-400">SENTRY</span>
            </p>
            <p className="text-[10px] font-mono text-slate-500">SOC FORENSICS v1.0</p>
          </div>
        ) : null}
      </div>

      {/* Navigation */}
      <nav
        aria-label="Primary"
        className="flex flex-1 flex-col gap-3 overflow-y-auto px-2 py-3"
      >
        {navGroups.map((group) => {
          const items = group.items.filter(
            (item) => !item.roles || item.roles.includes(user.role)
          );
          if (items.length === 0) return null;

          return (
            <div key={group.label} className="flex flex-col gap-0.5">
              {!collapsed ? (
                <p className="px-2.5 pb-1 text-[10px] font-mono font-bold uppercase tracking-widest text-slate-400 dark:text-slate-500">
                  {group.label}
                </p>
              ) : null}
              {items.map((item) => {
                const isActive =
                  pathname === item.href || pathname.startsWith(`${item.href}/`);
                const Icon = item.icon;

                const link = (
                  <Link
                    key={item.href}
                    href={item.href}
                    aria-current={isActive ? "page" : undefined}
                    className={cn(
                      "group relative flex items-center gap-2.5 rounded-lg px-2.5 py-2 text-sm transition-all duration-150",
                      collapsed && "justify-center px-0",
                      isActive
                        ? "bg-cyan-100/80 text-cyan-900 border-cyan-300 dark:bg-cyan-950/60 dark:text-cyan-300 dark:border-cyan-900/50 shadow-sm"
                        : "text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 hover:text-slate-900 dark:hover:text-slate-200 border border-transparent"
                    )}
                  >
                    {isActive && (
                      <span
                        className="absolute left-0 top-1/2 h-4 w-0.5 -translate-y-1/2 rounded-full bg-cyan-500"
                        aria-hidden="true"
                      />
                    )}
                    <Icon
                      className={cn(
                        "h-4 w-4 shrink-0 transition-colors",
                        isActive
                          ? "text-cyan-600 dark:text-cyan-400"
                          : "text-slate-400 dark:text-slate-500 group-hover:text-slate-700 dark:group-hover:text-slate-300"
                      )}
                    />
                    {!collapsed ? (
                      <span className="truncate text-xs font-medium">{item.label}</span>
                    ) : null}
                  </Link>
                );

                if (!collapsed) return link;

                return (
                  <Tooltip key={item.href} delayDuration={200}>
                    <TooltipTrigger asChild>{link}</TooltipTrigger>
                    <TooltipContent side="right" className="bg-slate-900 border-slate-700 text-slate-200 text-xs font-mono">
                      {item.label}
                    </TooltipContent>
                  </Tooltip>
                );
              })}
            </div>
          );
        })}
      </nav>

      {/* Collapse toggle */}
      <button
        type="button"
        onClick={() => setCollapsed((c) => !c)}
        aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
        className={cn(
          "flex items-center gap-2 border-t border-slate-200 dark:border-slate-800 px-3.5 py-2 text-xs font-mono text-slate-500 transition-colors hover:bg-slate-100 dark:hover:bg-slate-800 hover:text-slate-900 dark:hover:text-slate-300 cursor-pointer",
          collapsed && "justify-center px-0"
        )}
      >
        {collapsed ? (
          <ChevronsRight className="h-3.5 w-3.5" />
        ) : (
          <>
            <ChevronsLeft className="h-3.5 w-3.5" />
            Collapse
          </>
        )}
      </button>

      {/* Account footer */}
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <button
            type="button"
            aria-label="Account menu"
            className={cn(
              "flex items-center gap-2 border-t border-slate-200 dark:border-slate-800 px-3 py-2.5 text-left transition-colors hover:bg-slate-100 dark:hover:bg-slate-800/60 cursor-pointer",
              collapsed && "justify-center px-0"
            )}
          >
            <span className="relative shrink-0">
              <Avatar className="h-7 w-7 border border-cyan-300 dark:border-cyan-900/50 bg-slate-100 dark:bg-slate-900">
                <AvatarFallback className="text-[10px] font-mono font-bold text-cyan-700 dark:text-cyan-400 bg-cyan-100 dark:bg-cyan-950/60">
                  {user.initials}
                </AvatarFallback>
              </Avatar>
              <span className="absolute -bottom-0.5 -right-0.5 flex h-2 w-2">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-60" />
                <span className="relative inline-flex h-2 w-2 rounded-full border border-white dark:border-slate-900 bg-emerald-500" />
              </span>
            </span>
            {!collapsed ? (
              <span className="min-w-0 leading-tight">
                <span className="block truncate text-xs font-medium text-slate-800 dark:text-slate-200">
                  {user.name}
                </span>
                <span className="block truncate text-[10px] font-mono capitalize text-slate-500">
                  {user.role}
                </span>
              </span>
            ) : null}
          </button>
        </DropdownMenuTrigger>
        <AccountMenuContent user={user} align="start" side="top" />
      </DropdownMenu>
    </aside>
  );
}
