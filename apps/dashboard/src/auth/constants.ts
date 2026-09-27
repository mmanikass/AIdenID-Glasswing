// Shared auth constants for the AIdenID Clearance dashboard. Kept free of
// `next/headers` so it is safe to import from middleware (edge runtime).

export const SESSION_COOKIE = "__Host-aidenid_session";
export const SSO_STATE_COOKIE = "__Host-aidenid_sso_state";

const DEFAULT_DASHBOARD_URL = "https://dashboard.aidenid.com";

export interface DashboardAuthEnvironment extends Readonly<
  Record<string, string | undefined>
> {
  readonly AIDENID_DASHBOARD_URL?: string | undefined;
}

/**
 * Return the public dashboard origin used in the SSO redirect contract.
 * Production defaults to the canonical hostname instead of trusting Host or
 * X-Forwarded-Host. Local HTTP origins remain available for development.
 */
export function dashboardPublicOrigin(
  requestUrl: string,
  env: DashboardAuthEnvironment = process.env,
): string {
  const configured = env.AIDENID_DASHBOARD_URL?.trim();
  const requestOrigin = new URL(requestUrl);
  const candidate = new URL(
    configured && configured.length > 0
      ? configured
      : requestOrigin.hostname === "localhost" ||
          requestOrigin.hostname === "127.0.0.1"
        ? requestOrigin.origin
        : DEFAULT_DASHBOARD_URL,
  );
  const isLocalHttp =
    candidate.protocol === "http:" &&
    (candidate.hostname === "localhost" || candidate.hostname === "127.0.0.1");
  if (candidate.protocol !== "https:" && !isLocalHttp) {
    throw new Error("AIDENID_DASHBOARD_URL must use HTTPS outside localhost.");
  }
  if (candidate.username || candidate.password) {
    throw new Error("AIDENID_DASHBOARD_URL must not contain credentials.");
  }
  return candidate.origin;
}

/** Base URL of the sentinelayer API that owns the shared user identity. */
export function sentinelayerApiUrl(): string {
  return (
    process.env.SENTINELAYER_API_URL ?? "https://api.sentinelayer.com"
  ).replace(/\/+$/, "");
}

/** Base URL of the sentinelayer web app where Google/GitHub login lives. */
export function sentinelayerWebUrl(): string {
  return (
    process.env.SENTINELAYER_WEB_URL ?? "https://sentinelayer.com"
  ).replace(/\/+$/, "");
}

/**
 * Whether unauthenticated visitors are redirected to /login. Off by default so
 * deploying the login flow does not lock the dashboard until it is enabled.
 */
export function requireLogin(): boolean {
  return process.env.AIDENID_REQUIRE_LOGIN === "true";
}
