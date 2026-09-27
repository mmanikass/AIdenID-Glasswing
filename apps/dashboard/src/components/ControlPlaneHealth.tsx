"use client";

import { useEffect, useState } from "react";

import type { ControlPlaneHealthState } from "../controlPlaneHealth.js";

type DisplayState = ControlPlaneHealthState | "checking";

const HEALTH_POLL_INTERVAL_MS = 5_000;

export function ControlPlaneHealth() {
  const [state, setState] = useState<DisplayState>("checking");

  useEffect(() => {
    let disposed = false;
    let activeRequest: AbortController | undefined;

    async function refresh(): Promise<void> {
      activeRequest?.abort();
      const controller = new AbortController();
      activeRequest = controller;
      try {
        const response = await fetch("/api/status/health", {
          cache: "no-store",
          signal: controller.signal,
        });
        const body: unknown = await response.json();
        const nextState =
          response.ok &&
          body !== null &&
          typeof body === "object" &&
          !Array.isArray(body) &&
          (body as Readonly<Record<string, unknown>>).state === "connected"
            ? "connected"
            : "unavailable";
        if (!disposed) {
          setState(nextState);
        }
      } catch {
        if (!disposed && !controller.signal.aborted) {
          setState("unavailable");
        }
      }
    }

    void refresh();
    const interval = setInterval(() => void refresh(), HEALTH_POLL_INTERVAL_MS);
    return () => {
      disposed = true;
      clearInterval(interval);
      activeRequest?.abort();
    };
  }, []);

  const label =
    state === "checking"
      ? "checking"
      : state === "connected"
        ? "connected"
        : "unavailable";
  const colorMode =
    state === "connected" ? "runtime-live_control_plane" : "runtime-sample_data";

  return (
    <p className={`runtime-pill ${colorMode}`} role="status" aria-live="polite">
      Control plane: {label}
    </p>
  );
}
