import { fetchWithDashboardMutationTimeout } from "../clientMutationFetch.js";
import type { GlasswingRunResult } from "./types.js";

export class GlasswingApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    readonly detail?: string | undefined
  ) {
    super(detail === undefined ? `${code} (HTTP ${status})` : `${code}: ${detail}`);
    this.name = "GlasswingApiError";
  }
}

/**
 * The protected site reports errors as `{ error: { code, message } }`; the dashboard proxy and
 * the other dashboard routes use `{ error: "<code>", message? }`. Both shapes decode here, so a
 * site refusal surfaces by its code instead of collapsing to `http_<status>`.
 */
export function glasswingErrorFromBody(status: number, body: unknown): GlasswingApiError {
  const record = body !== null && typeof body === "object" ? (body as Record<string, unknown>) : {};
  const error = record.error;
  if (error !== null && typeof error === "object") {
    const nested = error as Record<string, unknown>;
    return new GlasswingApiError(
      status,
      typeof nested.code === "string" ? nested.code : `http_${status}`,
      typeof nested.message === "string" ? nested.message : undefined
    );
  }
  return new GlasswingApiError(
    status,
    typeof error === "string" ? error : `http_${status}`,
    typeof record.message === "string" ? record.message : undefined
  );
}

/**
 * A run result carries the `request` summary plus either a decision or a site error
 * `{ code, message }`. The site answers a refused run (grant does not cover the task, session
 * exchange refused) with a 403 that still has this shape.
 */
export function isGlasswingRunResult(body: unknown): body is GlasswingRunResult {
  if (body === null || typeof body !== "object") return false;
  const record = body as Record<string, unknown>;
  if (record.request === null || typeof record.request !== "object") return false;
  const error = record.error;
  const hasSiteError = error !== null && typeof error === "object" && typeof (error as Record<string, unknown>).code === "string";
  return hasSiteError || "decision" in record;
}

async function readJson(response: Response): Promise<unknown> {
  const text = await response.text();
  if (text.length === 0) return null;
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return null;
  }
}

async function parse<T>(response: Response): Promise<T> {
  const body = await readJson(response);
  if (!response.ok) {
    throw glasswingErrorFromBody(response.status, body);
  }
  return body as T;
}

export interface GlasswingSessionOutcome {
  readonly state: "ready" | "login_required" | "unavailable";
  /** Operator-facing diagnosis for the unavailable state. */
  readonly detail?: string | undefined;
}

/**
 * Classify the dev session route response. Two different 403 codes exist: login_required
 * (login is on, SSO owns the cookie) and dev_session_disabled (the dashboard was started
 * without the launcher flag). Only the first one is a login problem.
 */
export function glasswingSessionOutcome(status: number, body: unknown): GlasswingSessionOutcome {
  if (status === 204) return { state: "ready" };
  const error = glasswingErrorFromBody(status, body);
  if (error.code === "login_required") return { state: "login_required" };
  if (error.code === "dev_session_disabled") {
    return {
      state: "unavailable",
      detail: "dev_session_disabled: the dashboard was started without AIDENID_DASHBOARD_DEV_SESSION=true (pnpm dev sets it; never enable it on a network-exposed dashboard)."
    };
  }
  return { state: "unavailable", detail: error.message };
}

/** Obtain the dashboard operator cookie in the local-dev profile (no-op when login is on). */
export async function ensureGlasswingSession(): Promise<GlasswingSessionOutcome> {
  const response = await fetchWithDashboardMutationTimeout("/api/glasswing/session", { method: "POST", credentials: "same-origin" });
  return glasswingSessionOutcome(response.status, response.status === 204 ? null : await readJson(response));
}

export async function glasswingGet<T>(path: string): Promise<T> {
  const response = await fetchWithDashboardMutationTimeout(`/api/glasswing/${path}`, { method: "GET", credentials: "same-origin", cache: "no-store" });
  return parse<T>(response);
}

export async function glasswingPost<T>(path: string, body: unknown): Promise<T> {
  const response = await fetchWithDashboardMutationTimeout(`/api/glasswing/${path}`, {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body ?? {})
  });
  return parse<T>(response);
}

/**
 * Run a task for an agent. A refused run is still a run result (HTTP 403 with `error.code`),
 * returned as such so the console shows the refusal as a timeline row rather than a generic
 * failure banner. Anything that is not a run result is an error.
 */
export async function glasswingRun(agentId: string, body: unknown): Promise<GlasswingRunResult> {
  const response = await fetchWithDashboardMutationTimeout(`/api/glasswing/agents/${encodeURIComponent(agentId)}/run`, {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body ?? {})
  });
  const parsed = await readJson(response);
  if (isGlasswingRunResult(parsed)) {
    return parsed;
  }
  if (!response.ok) {
    throw glasswingErrorFromBody(response.status, parsed);
  }
  throw new GlasswingApiError(response.status, "run_result_malformed", "The protected site returned an unexpected run result.");
}
