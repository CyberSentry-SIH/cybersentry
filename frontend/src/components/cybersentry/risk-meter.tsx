import { AlertOctagon, AlertTriangle, AlertCircle, Info, Circle } from "lucide-react";

import type { Severity } from "@/types";
import { cn } from "@/lib/utils";

const severityConfig: Record<
  Severity,
  { label: string; icon: typeof AlertOctagon; text: string; bar: string }
> = {
  critical: {
    label: "Critical",
    icon: AlertOctagon,
    text: "text-state-critical",
    bar: "bg-state-critical",
  },
  high: {
    label: "High",
    icon: AlertTriangle,
    text: "text-state-error",
    bar: "bg-state-error",
  },
  medium: {
    label: "Medium",
    icon: AlertCircle,
    text: "text-state-warning",
    bar: "bg-state-warning",
  },
  low: { label: "Low", icon: Info, text: "text-state-info", bar: "bg-state-info" },
  informational: {
    label: "Informational",
    icon: Circle,
    text: "text-text-muted",
    bar: "bg-text-muted",
  },
};

export function RiskMeter({
  score,
  severity,
}: {
  score: number;
  severity: Severity;
}) {
  const config = severityConfig[severity];
  const Icon = config.icon;

  return (
    <div className="flex w-[92px] flex-col gap-1">
      <div className="flex items-center gap-1.5">
        <Icon className={cn("h-3.5 w-3.5 shrink-0", config.text)} />
        <span className={cn("font-technical text-sm font-semibold", config.text)}>
          {score}
        </span>
        <span className="text-xs text-text-muted">/100</span>
      </div>
      <div className="h-[3px] w-full overflow-hidden rounded-full bg-bg-elevated">
        <div
          className={cn("h-full", config.bar)}
          style={{ width: `${Math.min(100, Math.max(0, score))}%` }}
        />
      </div>
      <span className="label-eyebrow">{config.label}</span>
    </div>
  );
}
