import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";

import { cn } from "@/lib/utils";

const alertVariants = cva(
  "relative w-full rounded-md border px-3 py-2.5 text-sm grid grid-cols-[auto_1fr] gap-x-2.5 gap-y-0.5 items-start [&>svg]:size-4 [&>svg]:translate-y-0.5",
  {
    variants: {
      variant: {
        default: "border-border-default bg-bg-elevated text-text-secondary [&>svg]:text-text-muted",
        info: "border-state-info/30 bg-state-info-muted text-text-secondary [&>svg]:text-state-info",
        success:
          "border-state-success/30 bg-state-success-muted text-text-secondary [&>svg]:text-state-success",
        warning:
          "border-state-warning/30 bg-state-warning-muted text-text-secondary [&>svg]:text-state-warning",
        destructive:
          "border-state-error/30 bg-state-error-muted text-text-secondary [&>svg]:text-state-error",
      },
    },
    defaultVariants: { variant: "default" },
  }
);

function Alert({
  className,
  variant,
  ...props
}: React.ComponentProps<"div"> & VariantProps<typeof alertVariants>) {
  return (
    <div
      role="alert"
      data-slot="alert"
      className={cn(alertVariants({ variant }), className)}
      {...props}
    />
  );
}

function AlertTitle({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="alert-title"
      className={cn(
        "col-start-2 text-sm font-medium leading-none text-text-primary",
        className
      )}
      {...props}
    />
  );
}

function AlertDescription({
  className,
  ...props
}: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="alert-description"
      className={cn(
        "col-start-2 text-sm text-text-secondary [&_p]:leading-relaxed",
        className
      )}
      {...props}
    />
  );
}

export { Alert, AlertTitle, AlertDescription };
