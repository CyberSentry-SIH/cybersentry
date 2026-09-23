"use client";

import { useState } from "react";
import { Check, Copy } from "lucide-react";

import { cn } from "@/lib/utils";

export function CopyableValue({
  value,
  className,
  truncate = false,
}: {
  value: string;
  className?: string;
  truncate?: boolean;
}) {
  const [copied, setCopied] = useState(false);

  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // Clipboard access denied — fail silently, value remains selectable.
    }
  }

  return (
    <button
      type="button"
      onClick={handleCopy}
      className={cn(
        "group/copy font-technical inline-flex max-w-full items-center gap-1.5 rounded-sm text-left text-xs text-text-secondary transition-colors hover:text-text-primary",
        className
      )}
      title={value}
    >
      <span className={cn(truncate && "truncate")}>{value}</span>
      {copied ? (
        <Check className="h-3 w-3 shrink-0 text-state-success" />
      ) : (
        <Copy className="h-3 w-3 shrink-0 text-text-muted opacity-0 transition-opacity group-hover/copy:opacity-100" />
      )}
    </button>
  );
}
