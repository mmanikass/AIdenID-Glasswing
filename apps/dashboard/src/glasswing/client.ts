import { fetchWithDashboardMutationTimeout } from "../clientMutationFetch.js";

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

async function parse<T>(response: Response): Promise<T> {
  const text = await response.text();
  let body: unknown = null;
  if (text.length > 0) {
    try {
      body = JSON.parse(text);
    } catch {
      body = null;
    }
  }
  if (!response.ok) {
    const record = body !== null && typeof body === "object" ? (body as Record<string, unknown>) : {};
    throw new GlasswingApiError(
      response.status,
      typeof record.error === "string" ? record.error : `http_${response.status}`,
      typeof record.message === "string" ? record.message : undefined
    );
  }
  return body as T;
}

/** Obtain the dashboard operator cookie in the local-dev profile (no-op when login is on). */
export async function ensureGlasswingSession(): Promise<"ready" | "login_required" | "unavailable"> {
  const response = await fetchWithDashboardMutationTimeout("/api/glasswing/session", { method: "POST", credentials: "same-origin" });
  if (response.status === 204) return "ready";
  if (response.status === 403) return "login_required";
  return "unavailable";
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
