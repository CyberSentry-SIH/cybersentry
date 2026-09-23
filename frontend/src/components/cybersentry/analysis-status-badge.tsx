import { Loader2, CheckCircle2, XCircle, Clock } from "lucide-react";

import { Badge, type badgeVariants } from "@/components/ui/badge";
import type { VariantProps } from "class-variance-authority";

export type AnalysisStatus = "queued" | "processing" | "complete" | "failed";

const config: Record<
  AnalysisStatus,
  { label: string; icon: typeof Clock; variant: VariantProps<typeof badgeVariants>["variant"] }
> = {
  queued: { label: "Queued", icon: Clock, variant: "default" },
  processing: { label: "Processing", icon: Loader2, variant: "info" },
  complete: { label: "Complete", icon: CheckCircle2, variant: "success" },
  failed: { label: "Failed", icon: XCircle, variant: "error" },
};

export function AnalysisStatusBadge({ status }: { status: AnalysisStatus }) {
  const c = config[status];
  const Icon = c.icon;
  return (
    <Badge variant={c.variant}>
      <Icon className={status === "processing" ? "animate-spin" : undefined} />
      {c.label}
    </Badge>
  );
}
