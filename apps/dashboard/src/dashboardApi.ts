import { createHash, timingSafeEqual } from "node:crypto";

export interface DashboardApiEnvironment extends Readonly<
  Record<string, string | undefined>
> {
  readonly AIDENID_DASHBOARD_CONTROL_PLANE_TIMEOUT_MS?: string | undefined;
  readonly AIDENID_DASHBOARD_OPERATOR_ACTOR_ID?: string | undefined;
  readonly AIDENID_DASHBOARD_OPERATOR_REQUEST_TOKEN?: string | undefined;
  readonly AIDENID_OPERATOR_TOKEN?: string | undefined;
}

export type DashboardOperatorAuthFailureCode =
  | "operator_auth_not_configured"
  | "operator_auth_shares_upstream_credential"
  | "operator_auth_required"
  | "invalid_operator_token";

export type DashboardOperatorAuthResult =
  | {
      readonly ok: true;
      readonly actorId: string;
    }
  | {
      readonly ok: false;
      readonly status: 401 | 503;
      readonly error: DashboardOperatorAuthFailureCode;
    };

export interface DashboardTimeoutSignal {
  readonly signal: AbortSignal;
  readonly timeoutMs: number;
  clear(): void;
}

export interface DashboardControlPlaneFetchOptions extends RequestInit {
  readonly timeoutMs: number;
}

const DEFAULT_CONTROL_PLANE_TIMEOUT_MS = 5_000;
const MIN_CONTROL_PLANE_TIMEOUT_MS = 250;
const MAX_CONTROL_PLANE_TIMEOUT_MS = 30_000;
const OPERATOR_TOKEN_COOKIE = "aidenid_operator_token";
const OPERATOR_TOKEN_HEADER = "x-aidenid-operator-token";

function configuredSecret(value: string | undefined): string | undefined {
  if (value === undefined) {
    return undefined;
  }
  const trimmed = value.trim();
  return trimmed.length === 0 ? undefined : trimmed;
}

/**
 * The credential a CLIENT must present to this dashboard. It is deliberately NOT allowed to fall
 * back to AIDENID_OPERATOR_TOKEN, which is the credential the dashboard presents UPSTREAM to the
 * control plane. Sharing one value between the two means every dashboard client holds the raw
 * control-plane operator credential and can bypass this dashboard entirely.
 */
function dashboardOperatorRequestToken(
  env: DashboardApiEnvironment,
): string | undefined {
  return configuredSecret(env.AIDENID_DASHBOARD_OPERATOR_REQUEST_TOKEN);
}

/**
 * Provisioning a distinct variable is not the same property as provisioning a distinct SECRET —
 * setting AIDENID_DASHBOARD_OPERATOR_REQUEST_TOKEN to the same value as the upstream credential
 * recreates the exact defect while looking correctly configured. Compared over digests so this
 * never leaks a length or timing signal.
 */
function shareUpstreamCredential(env: DashboardApiEnvironment): boolean {
  const request = configuredSecret(env.AIDENID_DASHBOARD_OPERATOR_REQUEST_TOKEN);
  const upstream = configuredSecret(env.AIDENID_OPERATOR_TOKEN);
  if (request === undefined || upstream === undefined) {
    return false;
  }
  return timingSafeEqual(sha256(request), sha256(upstream));
}

function dashboardOperatorActorId(env: DashboardApiEnvironment): string {
  return (
    configuredSecret(env.AIDENID_DASHBOARD_OPERATOR_ACTOR_ID) ??
    "dashboard_operator"
  );
}

function sha256(value: string): Buffer {
  return createHash("sha256").update(value, "utf8").digest();
}

function tokenMatches(candidate: string, expected: string): boolean {
  return timingSafeEqual(sha256(candidate), sha256(expected));
}

function bearerToken(value: string | null): string | undefined {
  if (value === null) {
    return undefined;
  }
  const match = /^Bearer\s+(.+)$/i.exec(value.trim());
  return match?.[1]?.trim();
}

function explicitHeaderToken(value: string | null): string | undefined {
  if (value === null) {
    return undefined;
  }
  const trimmed = value.trim();
  return trimmed.length === 0 ? undefined : trimmed;
}

function cookieToken(header: string | null): string | undefined {
  if (header === null) {
    return undefined;
  }
  for (const part of header.split(";")) {
    const separator = part.indexOf("=");
    if (separator === -1) {
      continue;
    }
    const name = part.slice(0, separator).trim();
    if (name !== OPERATOR_TOKEN_COOKIE) {
      continue;
    }
    const raw = part.slice(separator + 1).trim();
    try {
      const decoded = decodeURIComponent(raw);
      return decoded.length === 0 ? undefined : decoded;
    } catch {
      return raw.length === 0 ? undefined : raw;
    }
  }
  return undefined;
}

export function dashboardOperatorRequestAuthConfigured(
  env: DashboardApiEnvironment,
): boolean {
  return dashboardOperatorRequestToken(env) !== undefined;
}

export function extractDashboardOperatorCredentialFromHeaders(
  headers: Pick<Headers, "get">,
): string | undefined {
  return (
    bearerToken(headers.get("authorization")) ??
    explicitHeaderToken(headers.get(OPERATOR_TOKEN_HEADER)) ??
    cookieToken(headers.get("cookie"))
  );
}

export function extractDashboardOperatorCredential(
  request: Request,
): string | undefined {
  return extractDashboardOperatorCredentialFromHeaders(request.headers);
}

export function authorizeDashboardOperatorRequest(
  request: Request,
  env: DashboardApiEnvironment,
): DashboardOperatorAuthResult {
  return authorizeDashboardOperatorCredential(
    extractDashboardOperatorCredential(request),
    env,
  );
}

export function authorizeDashboardOperatorHeaders(
  headers: Pick<Headers, "get">,
  env: DashboardApiEnvironment,
): DashboardOperatorAuthResult {
  return authorizeDashboardOperatorCredential(
    extractDashboardOperatorCredentialFromHeaders(headers),
    env,
  );
}

function authorizeDashboardOperatorCredential(
  candidateToken: string | undefined,
  env: DashboardApiEnvironment,
): DashboardOperatorAuthResult {
  const expectedToken = dashboardOperatorRequestToken(env);
  if (expectedToken === undefined) {
    return { ok: false, status: 503, error: "operator_auth_not_configured" };
  }
  // Fail closed rather than authorize against a credential that is also our upstream one.
  if (shareUpstreamCredential(env)) {
    return {
      ok: false,
      status: 503,
      error: "operator_auth_shares_upstream_credential",
    };
  }
  if (candidateToken === undefined) {
    return { ok: false, status: 401, error: "operator_auth_required" };
  }
  if (!tokenMatches(candidateToken, expectedToken)) {
    return { ok: false, status: 401, error: "invalid_operator_token" };
  }
  return { ok: true, actorId: dashboardOperatorActorId(env) };
}

export function operatorAuthFailureResponse(
  result: Exclude<DashboardOperatorAuthResult, { readonly ok: true }>,
): Response {
  return Response.json({ error: result.error }, { status: result.status });
}

export function dashboardControlPlaneTimeoutMs(
  env: DashboardApiEnvironment,
): number {
  const raw = env.AIDENID_DASHBOARD_CONTROL_PLANE_TIMEOUT_MS;
  if (raw === undefined || raw.trim().length === 0) {
    return DEFAULT_CONTROL_PLANE_TIMEOUT_MS;
  }
  const parsed = Number(raw);
  if (!Number.isFinite(parsed)) {
    return DEFAULT_CONTROL_PLANE_TIMEOUT_MS;
  }
  return Math.min(
    MAX_CONTROL_PLANE_TIMEOUT_MS,
    Math.max(MIN_CONTROL_PLANE_TIMEOUT_MS, Math.trunc(parsed)),
  );
}

export function createDashboardTimeoutSignal(
  timeoutMs: number,
): DashboardTimeoutSignal {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  return {
    signal: controller.signal,
    timeoutMs,
    clear() {
      clearTimeout(timer);
    },
  };
}

export async function fetchDashboardControlPlaneWithTimeout(
  input: Parameters<typeof fetch>[0],
  options: DashboardControlPlaneFetchOptions,
): Promise<Response> {
  const { timeoutMs, ...init } = options;
  const timeout = createDashboardTimeoutSignal(timeoutMs);
  try {
    return await fetch(input, { ...init, signal: timeout.signal });
  } finally {
    timeout.clear();
  }
}

export function isDashboardTimeoutError(error: unknown): boolean {
  return (
    error instanceof Error &&
    (error.name === "AbortError" || error.name === "TimeoutError")
  );
}

export function dashboardUpstreamStatusForError(error: unknown): 502 | 504 {
  return isDashboardTimeoutError(error) ? 504 : 502;
}
