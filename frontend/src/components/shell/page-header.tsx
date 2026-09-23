import type { ReactNode } from "react";
import { ChevronRight, Shield } from "lucide-react";

export interface PageHeaderMeta {
  label: string;
  value: string;
}

export function PageHeader({
  section,
  title,
  description,
  meta,
  actions,
  children,
}: {
  section?: string;
  title: string;
  description?: string;
  meta?: PageHeaderMeta[];
  actions?: ReactNode;
  children?: ReactNode;
}) {
  return (
    <div className="border-b border-slate-200 dark:border-slate-800 bg-white/80 dark:bg-slate-900/80 backdrop-blur-sm relative transition-colors duration-200">
      {/* Top accent line */}
      <div className="absolute top-0 inset-x-0 h-px bg-gradient-to-r from-transparent via-cyan-500/40 to-transparent" />

      {(section || (meta && meta.length > 0)) && (
        <div className="flex items-center justify-between gap-4 border-b border-slate-200/80 dark:border-slate-800/60 px-6 py-1.5">
          <div className="flex items-center gap-1.5 text-xs font-mono text-slate-500 dark:text-slate-400">
            <Shield className="h-2.5 w-2.5 text-cyan-600 dark:text-cyan-400" />
            <span className="text-cyan-700 dark:text-cyan-400/80 font-bold">CYBERSENTRY</span>
            {section ? (
              <>
                <ChevronRight className="h-3 w-3" />
                <span className="text-slate-600 dark:text-slate-400">{section}</span>
              </>
            ) : null}
          </div>
          {meta && meta.length > 0 ? (
            <div className="flex items-center gap-3">
              {meta.map((m, i) => (
                <span
                  key={m.label}
                  className="flex items-center gap-3 text-xs font-mono"
                >
                  {i > 0 ? (
                    <span className="h-3 w-px bg-slate-300 dark:bg-slate-800" aria-hidden="true" />
                  ) : null}
                  <span>
                    <span className="text-[10px] font-bold uppercase tracking-widest text-slate-500 dark:text-slate-500 mr-1.5">
                      {m.label}
                    </span>
                    <span className="text-slate-700 dark:text-slate-300">{m.value}</span>
                  </span>
                </span>
              ))}
            </div>
          ) : null}
        </div>
      )}

      <div className="flex items-start justify-between gap-4 px-6 py-4">
        <div className="min-w-0">
          <h1 className="text-base font-bold tracking-tight text-slate-900 dark:text-white font-mono flex items-center gap-2">
            {title}
          </h1>
          {description ? (
            <p className="mt-0.5 text-xs text-slate-600 dark:text-slate-400 font-mono">{description}</p>
          ) : null}
        </div>
        {actions ? (
          <div className="flex shrink-0 items-center gap-2">{actions}</div>
        ) : null}
      </div>

      {children ? (
        <div className="flex items-center gap-2 border-t border-slate-200 dark:border-slate-800 px-6 py-2">
          {children}
        </div>
      ) : null}
    </div>
  );
}
