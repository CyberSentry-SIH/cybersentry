import { AlertOctagon, AlertTriangle, AlertCircle, Info, Circle } from "lucide-react";

import type { Severity } from "@/types";
import { Badge, type badgeVariants } from "@/components/ui/badge";
import type { VariantProps } from "class-variance-authority";

const severityConfig: Record<
  Severity,
  { label: string; icon: typeof AlertOctagon; variant: VariantProps<typeof badgeVariants>["variant"] }
> = {
  critical: { label: "Critical", icon: AlertOctagon, variant: "critical" },
  high: { label: "High", icon: AlertTriangle, variant: "error" },
  medium: { label: "Medium", icon: AlertCircle, variant: "warning" },
  low: { label: "Low", icon: Info, variant: "info" },
  informational: { label: "Informational", icon: Circle, variant: "default" },
};

export function SeverityBadge({
  severity,
  score,
}: {
  severity: Severity;
  /** Optional numeric risk score (0-100) shown alongside the label. */
  score?: number;
}) {
  const config = severityConfig[severity];
  const Icon = config.icon;

  return (
    <Badge variant={config.variant}>
      <Icon />
      {config.label}
      {typeof score === "number" ? (
        <span className="font-technical">{score}</span>
      ) : null}
    </Badge>
  );
}
