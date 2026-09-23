import type { ReactNode } from "react";

import { TopBar } from "@/components/shell/topbar";
import { Sidebar } from "@/components/shell/sidebar";
import { TooltipProvider } from "@/components/ui/tooltip";

export function AppShell({ children }: { children: ReactNode }) {
  return (
    <TooltipProvider delayDuration={200}>
      <div className="flex h-dvh flex-col bg-[var(--bg-base)] text-[var(--text-primary)] transition-colors duration-200">
        <TopBar />
        <div className="flex min-h-0 flex-1">
          <Sidebar />
          <main className="min-w-0 flex-1 overflow-y-auto bg-[var(--bg-base)] relative transition-colors duration-200">
            {/* Ambient cyber grid */}
            <div className="absolute inset-0 cyber-grid opacity-40 pointer-events-none" />
            <div className="relative z-10">
              {children}
            </div>
          </main>
        </div>
      </div>
    </TooltipProvider>
  );
}
