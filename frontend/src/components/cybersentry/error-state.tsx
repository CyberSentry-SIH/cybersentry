import { AlertTriangle } from "lucide-react";
import type { ReactNode } from "react";

import { Alert, AlertTitle, AlertDescription } from "@/components/ui/alert";

export function ErrorState({
  title,
  description,
  action,
}: {
  title: string;
  description: string;
  action?: ReactNode;
}) {
  return (
    <Alert variant="warning">
      <AlertTriangle />
      <AlertTitle>{title}</AlertTitle>
      <AlertDescription>
        {description}
        {action ? <div className="mt-2">{action}</div> : null}
      </AlertDescription>
    </Alert>
  );
}
