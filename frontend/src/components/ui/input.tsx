import * as React from "react";

import { cn } from "@/lib/utils";

function Input({ className, type, ...props }: React.ComponentProps<"input">) {
  return (
    <input
      type={type}
      data-slot="input"
      className={cn(
        "flex h-8 w-full rounded-sm border border-border-default bg-bg-elevated px-2.5 text-sm text-text-primary placeholder:text-text-muted transition-colors outline-none",
        "focus-visible:border-accent-primary focus-visible:ring-2 focus-visible:ring-accent-primary/30",
        "disabled:cursor-not-allowed disabled:opacity-50",
        className
      )}
      {...props}
    />
  );
}

export { Input };
