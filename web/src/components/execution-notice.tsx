"use client";

import { ShieldAlert } from "lucide-react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { useExecutionStatus } from "@/hooks/use-execution-status";

export function ExecutionNotice() {
  const status = useExecutionStatus();
  if (status === "loading" || status === "ready") return null;

  return (
    <div className="shrink-0 px-4 py-2 lg:px-6">
      <Alert role="status">
        <ShieldAlert />
        <AlertTitle>{status === "paused" ? "Active tool execution is paused" : "Execution status is unavailable"}</AlertTitle>
        <AlertDescription>
          {status === "paused"
            ? "Text chat and analysis of saved material remain available. Commands, scans, browser actions, and custom tools are paused until an isolated runner is available."
            : "The server could not confirm whether active tools are available. Reload this page to check again."}
        </AlertDescription>
      </Alert>
    </div>
  );
}
