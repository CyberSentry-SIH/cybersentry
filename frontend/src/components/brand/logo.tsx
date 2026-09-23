import { ShieldCheck } from "lucide-react";

import { cn } from "@/lib/utils";

const sizeClasses = {
  sm: "h-7 w-7",
  lg: "h-12 w-12",
} as const;

const iconSizeClasses = {
  sm: "h-3.5 w-3.5",
  lg: "h-6 w-6",
} as const;

export function LogoMark({
  className,
  size = "sm",
}: {
  className?: string;
  size?: keyof typeof sizeClasses;
}) {
  return (
    <span
      className={cn(
        "relative flex shrink-0 items-center justify-center rounded-full bg-accent-primary shadow-[inset_0_0_0_2px_rgba(255,255,255,0.18)]",
        "ring-1 ring-accent-primary-strong/40",
        sizeClasses[size],
        className
      )}
    >
      <ShieldCheck
        className={cn(iconSizeClasses[size], "text-white")}
        strokeWidth={2.25}
      />
    </span>
  );
}

export function Logo({
  className,
  showWordmark = true,
}: {
  className?: string;
  showWordmark?: boolean;
}) {
  return (
    <span className={cn("flex items-center gap-2", className)}>
      <LogoMark />
      {showWordmark ? (
        <span className="text-sm font-semibold tracking-tight text-text-primary">
          CyberSentry
        </span>
      ) : null}
    </span>
  );
}
