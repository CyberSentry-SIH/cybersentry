import { Sparkles, Radio, TrendingUp, Eye } from "lucide-react";

import type { CampaignState } from "@/types";
import { Badge, type badgeVariants } from "@/components/ui/badge";
import type { VariantProps } from "class-variance-authority";

const config: Record<
  CampaignState,
  { label: string; icon: typeof Sparkles; variant: VariantProps<typeof badgeVariants>["variant"] }
> = {
  emerging: { label: "Emerging", icon: Sparkles, variant: "info" },
  active: { label: "Active", icon: Radio, variant: "error" },
  expanding: { label: "Expanding", icon: TrendingUp, variant: "critical" },
  monitoring: { label: "Monitoring", icon: Eye, variant: "default" },
};

export function CampaignStateBadge({ state }: { state: CampaignState }) {
  const c = config[state];
  const Icon = c.icon;
  return (
    <Badge variant={c.variant}>
      <Icon />
      {c.label}
    </Badge>
  );
}
