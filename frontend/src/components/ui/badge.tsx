import * as React from "react";
import { Slot } from "@radix-ui/react-slot";
import { cva, type VariantProps } from "class-variance-authority";

import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center gap-1 rounded-sm border px-1.5 py-0.5 text-xs font-medium leading-none w-fit whitespace-nowrap shrink-0 [&_svg]:size-3 [&_svg]:pointer-events-none",
  {
    variants: {
      variant: {
        default:
          "border-border-default bg-bg-elevated text-text-secondary",
        outline: "border-border-default bg-transparent text-text-secondary",
        critical:
          "border-state-critical/30 bg-state-critical-muted text-state-critical",
        error: "border-state-error/30 bg-state-error-muted text-state-error",
        warning:
          "border-state-warning/30 bg-state-warning-muted text-state-warning",
        success:
          "border-state-success/30 bg-state-success-muted text-state-success",
        info: "border-state-info/30 bg-state-info-muted text-state-info",
        accent:
          "border-accent-primary/30 bg-accent-primary-muted text-accent-primary",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  }
);

function Badge({
  className,
  variant,
  asChild = false,
  ...props
}: React.ComponentProps<"span"> &
  VariantProps<typeof badgeVariants> & { asChild?: boolean }) {
  const Comp = asChild ? Slot : "span";
  return (
    <Comp
      data-slot="badge"
      className={cn(badgeVariants({ variant, className }))}
      {...props}
    />
  );
}

export { Badge, badgeVariants };
