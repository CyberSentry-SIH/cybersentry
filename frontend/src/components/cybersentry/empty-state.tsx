import type { LucideIcon } from "lucide-react";
import type { ReactNode } from "react";

import { cn } from "@/lib/utils";

export function EmptyState({
  icon: Icon,
  title,
  description,
  action,
  className,
}: {
  icon: LucideIcon;
  title: string;
  description?: string;
  action?: ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "flex flex-col items-center justify-center gap-2 rounded-md border border-dashed border-border-default px-6 py-12 text-center",
        className
      )}
    >
      <Icon className="h-5 w-5 text-text-muted" aria-hidden="true" />
      <p className="text-sm font-medium text-text-primary">{title}</p>
      {description ? (
        <p className="max-w-sm text-sm text-text-muted">{description}</p>
      ) : null}
      {action ? <div className="mt-2">{action}</div> : null}
    </div>
  );
}
