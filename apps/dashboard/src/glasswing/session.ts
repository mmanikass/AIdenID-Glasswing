import type { DashboardApiEnvironment } from "../dashboardApi.js";

export const DEV_SESSION_COOKIE = "aidenid_operator_token";
const DEV_SESSION_MAX_AGE_SECONDS = 8 * 60 * 60;

export type DevOperatorSessionOutcome =
  | { readonly ok: true; readonly cookie: { readonly name: string; readonly value: string; readonly secure: boolean; readonly maxAgeSeconds: number } }
  | { readonly ok: false; readonly status: 403 | 503; readonly error: "login_required" | "dev_session_disabled" | "operator_auth_not_configured" | "loopback_only" };

function isLoopback(hostname: string): boolean {
  return hostname === "127.0.0.1" || hostname === "localhost" || hostname === "[::1]" || hostname === "::1";
}

/** Set by the loopback launcher (`pnpm dev`); never by a deployment profile. */
export const DEV_SESSION_FLAG = "AIDENID_DASHBOARD_DEV_SESSION";

/**
 * Pure decision for the dev session route. Refuses when login is required, when the launcher
 * did not enable the route explicitly (AIDENID_DASHBOARD_DEV_SESSION=true), when no dashboard
 * request token is configured, or when the request is not addressed to a loopback host. The
 * flag is the real gate: the host name comes from the client-controlled Host header and is
 * only a second guard. This convenience must never turn a network-exposed dashboard into an
 * unauthenticated operator console.
 */
export function issueDevOperatorSession(
  env: DashboardApiEnvironment,
  input: { readonly loginRequired: boolean; readonly requestUrl: string }
): DevOperatorSessionOutcome {
  if (input.loginRequired) {
    return { ok: false, status: 403, error: "login_required" };
  }
  if (env[DEV_SESSION_FLAG]?.trim() !== "true") {
    return { ok: false, status: 403, error: "dev_session_disabled" };
  }
  const token = env.AIDENID_DASHBOARD_OPERATOR_REQUEST_TOKEN?.trim();
  if (!token) {
    return { ok: false, status: 503, error: "operator_auth_not_configured" };
  }
  let url: URL;
  try {
    url = new URL(input.requestUrl);
  } catch {
    return { ok: false, status: 403, error: "loopback_only" };
  }
  if (!isLoopback(url.hostname)) {
    return { ok: false, status: 403, error: "loopback_only" };
  }
  return {
    ok: true,
    cookie: { name: DEV_SESSION_COOKIE, value: token, secure: url.protocol === "https:", maxAgeSeconds: DEV_SESSION_MAX_AGE_SECONDS }
  };
}
