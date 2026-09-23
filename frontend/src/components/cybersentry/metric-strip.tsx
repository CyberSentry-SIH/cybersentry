import type { LucideIcon } from "lucide-react";
import { ArrowDown, ArrowUp, Minus } from "lucide-react";

import { Sparkline } from "@/components/cybersentry/sparkline";
import { cn } from "@/lib/utils";

const toneText = {
  neutral: "text-text-primary",
  critical: "text-state-critical",
  warning: "text-state-warning",
  info: "text-state-info",
} as const;

const toneStroke = {
  neutral: "stroke-text-secondary",
  critical: "stroke-state-critical",
  warning: "stroke-state-warning",
  info: "stroke-state-info",
} as const;

const toneRail = {
  neutral: "bg-border-strong",
  critical: "bg-state-critical",
  warning: "bg-state-warning",
  info: "bg-state-info",
} as const;

export interface MetricStripItem {
  label: string;
  value: string | number;
  delta?: number;
  trend?: number[];
  icon: LucideIcon;
  tone?: keyof typeof toneText;
  /** Set true when an increase is a good sign (e.g. cases resolved). */
  invertGood?: boolean;
}

function DeltaChip({ delta, invertGood }: { delta: number; invertGood?: boolean }) {
  if (delta === 0) {
    return (
      <span className="inline-flex items-center gap-0.5 text-xs text-text-muted">
        <Minus className="h-3 w-3" />
        No change
      </span>
    );
  }
  const isUp = delta > 0;
  const isGood = invertGood ? isUp : !isUp;
  return (
    <span
      className={cn(
        "inline-flex items-center gap-0.5 text-xs font-medium",
        isGood ? "text-state-success" : "text-state-error"
      )}
    >
      {isUp ? <ArrowUp className="h-3 w-3" /> : <ArrowDown className="h-3 w-3" />}
      {Math.abs(delta)}
      <span className="text-text-muted">· 24h</span>
    </span>
  );
}

export function MetricStrip({ items }: { items: MetricStripItem[] }) {
  return (
    <div className="grid grid-cols-1 divide-y divide-border-default rounded-md border border-border-default bg-bg-surface shadow-[0_1px_2px_rgba(16,24,39,0.04)] sm:grid-cols-2 sm:divide-x sm:divide-y-0 xl:grid-cols-4">
      {items.map((item) => {
        const tone = item.tone ?? "neutral";
        const Icon = item.icon;
        return (
          <div key={item.label} className="relative flex flex-col gap-2 px-4 py-3.5">
            <span
              className={cn("absolute inset-y-0 left-0 w-[2px]", toneRail[tone])}
              aria-hidden="true"
            />
            <div className="flex items-center justify-between">
              <span className="label-eyebrow flex items-center gap-1.5">
                <Icon className={cn("h-3.5 w-3.5", toneText[tone])} />
                {item.label}
              </span>
              {item.trend ? (
                <Sparkline data={item.trend} strokeClassName={toneStroke[tone]} />
              ) : null}
            </div>
            <div className="flex items-baseline gap-2">
              <span
                className={cn(
                  "font-technical text-2xl font-semibold leading-none tracking-tight",
                  toneText[tone]
                )}
              >
                {item.value}
              </span>
              {typeof item.delta === "number" ? (
                <DeltaChip delta={item.delta} invertGood={item.invertGood} />
              ) : null}
            </div>
          </div>
        );
      })}
    </div>
  );
}
