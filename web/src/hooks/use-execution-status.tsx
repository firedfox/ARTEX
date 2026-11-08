"use client";

import { createContext, type ReactNode, useContext, useEffect, useState } from "react";

import { api } from "@/lib/api";

type ExecutionStatus = "loading" | "paused" | "ready" | "unavailable";
const ExecutionContext = createContext<ExecutionStatus>("loading");

/** The authenticated layout shares one server status read with its banner and settings page. */
export function ExecutionStatusProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<ExecutionStatus>("loading");

  useEffect(() => {
    const controller = new AbortController();
    void api
      .stats(undefined, controller.signal)
      .then((stats) => {
        if (controller.signal.aborted) return;
        if (stats.execution_mode === "control-plane-only" || stats.isolated_runner_ready === false) {
          setStatus("paused");
        } else {
          setStatus(stats.isolated_runner_ready === true ? "ready" : "unavailable");
        }
      })
      .catch(() => {
        if (!controller.signal.aborted) setStatus("unavailable");
      });
    return () => controller.abort();
  }, []);

  return <ExecutionContext.Provider value={status}>{children}</ExecutionContext.Provider>;
}

export function useExecutionStatus() {
  return useContext(ExecutionContext);
}
