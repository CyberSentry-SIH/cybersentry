import type { Severity } from "@/types";
import { cn } from "@/lib/utils";

const severityLabel: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  informational: "Informational",
};

const severityBar: Record<Severity, string> = {
  critical: "bg-state-critical",
  high: "bg-state-error",
  medium: "bg-state-warning",
  low: "bg-state-info",
  informational: "bg-text-muted",
};

export function SeverityBreakdown({
  data,
}: {
  data: { severity: Severity; count: number }[];
}) {
  const max = Math.max(...data.map((d) => d.count), 1);

  return (
    <div className="flex flex-col gap-2.5">
      {data.map((row) => (
        <div key={row.severity} className="flex items-center gap-3">
          <span className="w-24 shrink-0 text-xs text-text-secondary">
            {severityLabel[row.severity]}
          </span>
          <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-bg-elevated">
            <div
              className={cn("h-full rounded-full", severityBar[row.severity])}
              style={{ width: `${(row.count / max) * 100}%` }}
            />
          </div>
          <span className="w-6 shrink-0 text-right text-xs font-technical text-text-primary">
            {row.count}
          </span>
        </div>
      ))}
    </div>
  );
}
