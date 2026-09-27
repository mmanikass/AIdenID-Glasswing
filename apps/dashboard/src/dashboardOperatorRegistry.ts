export type OperatorTrustTier = "unknown" | "trusted" | "restricted";
export type OperatorReputationStatus = "active" | "watchlist" | "suspended" | "expired";
export type OperatorDefaultAction = "allow" | "throttle" | "queue" | "sandbox" | "deny" | "price_required";

export interface OperatorReputationView {
  readonly id: string;
  readonly site_id: string;
  readonly operator_actor_id: string;
  readonly display_name?: string;
  readonly trust_tier: OperatorTrustTier;
  readonly status: OperatorReputationStatus;
  readonly reputation_score: number;
  readonly default_action: OperatorDefaultAction;
  readonly default_scope_routes: readonly string[];
  readonly default_scope_redirect_path?: string;
  readonly notes?: string;
  readonly last_reviewed_at?: string;
  readonly expires_at?: string;
  readonly updated_by: string;
  readonly created_at: string;
  readonly updated_at: string;
}

export interface OperatorRegistryEnvironment extends Readonly<
  Record<string, string | undefined>
> {
  readonly AIDENID_CONTROL_PLANE_URL?: string | undefined;
  readonly AIDENID_DASHBOARD_SITE_ID?: string | undefined;
  readonly AIDENID_DASHBOARD_REQUIRE_LIVE_DATA?: string | undefined;
}

export interface OperatorReputationListFilters {
  readonly status?: OperatorReputationStatus | undefined;
  readonly trustTier?: OperatorTrustTier | undefined;
  readonly limit?: number | undefined;
}

const DEFAULT_DASHBOARD_SITE_ID = "sit_demo";
const SITE_ID_REGEX = /^sit_[A-Za-z0-9_-]+$/;
const OPERATOR_ACTOR_ID_REGEX = /^[A-Za-z0-9:_-]{1,128}$/;

export function dashboardSiteId(env: OperatorRegistryEnvironment): string {
  const configured = env.AIDENID_DASHBOARD_SITE_ID?.trim();
  return configured !== undefined && configured.length > 0 ? configured : DEFAULT_DASHBOARD_SITE_ID;
}

export function dashboardRequireLiveOperatorData(env: OperatorRegistryEnvironment): boolean {
  return env.AIDENID_DASHBOARD_REQUIRE_LIVE_DATA === "true";
}

export function isValidSiteId(value: string): boolean {
  return SITE_ID_REGEX.test(value);
}

export function isValidOperatorActorId(value: string): boolean {
  return OPERATOR_ACTOR_ID_REGEX.test(value);
}

export function buildOperatorReputationListUrl(
  controlPlaneUrl: string,
  siteId: string,
  filters: OperatorReputationListFilters = {}
): string {
  const url = new URL("/v1/operators/reputation", controlPlaneUrl);
  url.searchParams.set("site_id", siteId);
  if (filters.status !== undefined) {
    url.searchParams.set("status", filters.status);
  }
  if (filters.trustTier !== undefined) {
    url.searchParams.set("trust_tier", filters.trustTier);
  }
  if (filters.limit !== undefined) {
    url.searchParams.set("limit", String(filters.limit));
  }
  return url.toString();
}

export function buildOperatorReputationDetailUrl(
  controlPlaneUrl: string,
  siteId: string,
  operatorActorId: string
): string {
  const url = new URL(
    `/v1/operators/reputation/${encodeURIComponent(operatorActorId)}`,
    controlPlaneUrl
  );
  url.searchParams.set("site_id", siteId);
  return url.toString();
}

export interface OperatorReputationUpsertPayload {
  readonly site_id: string;
  readonly display_name?: string;
  readonly trust_tier: OperatorTrustTier;
  readonly status: OperatorReputationStatus;
  readonly reputation_score: number;
  readonly default_action?: OperatorDefaultAction;
  readonly default_scope_routes?: readonly string[];
  readonly default_scope_redirect_path?: string;
  readonly notes?: string;
  readonly last_reviewed_at?: string;
  readonly expires_at?: string | null;
}

export type OperatorReputationUpsertValidationError =
  | "missing_trust_tier"
  | "invalid_trust_tier"
  | "missing_status"
  | "invalid_status"
  | "invalid_reputation_score"
  | "invalid_default_action"
  | "invalid_default_scope_routes"
  | "invalid_default_scope_redirect_path"
  | "invalid_display_name"
  | "invalid_notes"
  | "invalid_last_reviewed_at"
  | "invalid_expires_at";

export type OperatorReputationUpsertParseResult =
  | { readonly ok: true; readonly payload: OperatorReputationUpsertPayload }
  | { readonly ok: false; readonly error: OperatorReputationUpsertValidationError };

const TRUST_TIERS: readonly OperatorTrustTier[] = ["unknown", "trusted", "restricted"];
const STATUSES: readonly OperatorReputationStatus[] = ["active", "watchlist", "suspended", "expired"];
const DECISION_ACTIONS: readonly OperatorDefaultAction[] = ["allow", "throttle", "queue", "sandbox", "deny", "price_required"];
const DEFAULT_SCOPE_ROUTE_REGEX = /^\/[A-Za-z0-9._~!$&'()*+,;=:@/%-]*(?:\/\*)?$/;
const DEFAULT_SCOPE_REDIRECT_PATH_REGEX = /^\/[A-Za-z0-9._~!$&'()*+,;=:@/%-]*$/;

function isOperatorTrustTier(value: unknown): value is OperatorTrustTier {
  return typeof value === "string" && (TRUST_TIERS as readonly string[]).includes(value);
}

function isOperatorReputationStatus(value: unknown): value is OperatorReputationStatus {
  return typeof value === "string" && (STATUSES as readonly string[]).includes(value);
}

function isDecisionAction(value: unknown): value is OperatorDefaultAction {
  return typeof value === "string" && (DECISION_ACTIONS as readonly string[]).includes(value);
}

function trimmedString(value: unknown, max: number): string | undefined {
  if (typeof value !== "string") {
    return undefined;
  }
  const trimmed = value.trim();
  return trimmed.length === 0 || trimmed.length > max ? undefined : trimmed;
}

function parseScopeRoutes(value: unknown): readonly string[] | undefined | false {
  if (value === undefined) {
    return undefined;
  }
  if (!Array.isArray(value) || value.length > 32) {
    return false;
  }
  const routes: string[] = [];
  for (const route of value) {
    if (typeof route !== "string") {
      return false;
    }
    const trimmed = route.trim();
    if (trimmed.length === 0 || trimmed.length > 256 || !DEFAULT_SCOPE_ROUTE_REGEX.test(trimmed)) {
      return false;
    }
    routes.push(trimmed);
  }
  return [...new Set(routes)];
}

/**
 * Validates and normalizes a request body for upserting an operator reputation
 * record. Mirrors the shape and bounds of the control-plane zod schema so the
 * dashboard rejects bad input at the BFF instead of generating a confusing
 * 400 from the upstream API.
 */
export function parseOperatorReputationUpsert(
  rawBody: unknown,
  siteId: string
): OperatorReputationUpsertParseResult {
  const body = rawBody !== null && typeof rawBody === "object" && !Array.isArray(rawBody)
    ? (rawBody as Readonly<Record<string, unknown>>)
    : undefined;
  if (body === undefined) {
    return { ok: false, error: "missing_trust_tier" };
  }

  const trustTierRaw = body["trust_tier"];
  if (trustTierRaw === undefined) {
    return { ok: false, error: "missing_trust_tier" };
  }
  if (!isOperatorTrustTier(trustTierRaw)) {
    return { ok: false, error: "invalid_trust_tier" };
  }

  const statusRaw = body["status"];
  if (statusRaw === undefined) {
    return { ok: false, error: "missing_status" };
  }
  if (!isOperatorReputationStatus(statusRaw)) {
    return { ok: false, error: "invalid_status" };
  }

  const scoreRaw = body["reputation_score"];
  if (typeof scoreRaw !== "number" || !Number.isInteger(scoreRaw) || scoreRaw < 0 || scoreRaw > 100) {
    return { ok: false, error: "invalid_reputation_score" };
  }

  const defaultActionRaw = body["default_action"] ?? "allow";
  if (!isDecisionAction(defaultActionRaw)) {
    return { ok: false, error: "invalid_default_action" };
  }

  const defaultScopeRoutes = parseScopeRoutes(body["default_scope_routes"]);
  if (defaultScopeRoutes === false) {
    return { ok: false, error: "invalid_default_scope_routes" };
  }

  const defaultScopeRedirectRaw = body["default_scope_redirect_path"];
  let defaultScopeRedirectPath: string | undefined;
  if (defaultScopeRedirectRaw !== undefined) {
    defaultScopeRedirectPath = trimmedString(defaultScopeRedirectRaw, 256);
    if (defaultScopeRedirectPath === undefined || !DEFAULT_SCOPE_REDIRECT_PATH_REGEX.test(defaultScopeRedirectPath)) {
      return { ok: false, error: "invalid_default_scope_redirect_path" };
    }
  }

  const displayNameRaw = body["display_name"];
  let displayName: string | undefined;
  if (displayNameRaw !== undefined) {
    displayName = trimmedString(displayNameRaw, 128);
    if (displayName === undefined) {
      return { ok: false, error: "invalid_display_name" };
    }
  }

  const notesRaw = body["notes"];
  let notes: string | undefined;
  if (notesRaw !== undefined) {
    notes = trimmedString(notesRaw, 1024);
    if (notes === undefined) {
      return { ok: false, error: "invalid_notes" };
    }
  }

  const lastReviewedAtRaw = body["last_reviewed_at"];
  let lastReviewedAt: string | undefined;
  if (lastReviewedAtRaw !== undefined) {
    if (typeof lastReviewedAtRaw !== "string") {
      return { ok: false, error: "invalid_last_reviewed_at" };
    }
    const parsed = Date.parse(lastReviewedAtRaw);
    if (Number.isNaN(parsed)) {
      return { ok: false, error: "invalid_last_reviewed_at" };
    }
    lastReviewedAt = lastReviewedAtRaw;
  }

  const expiresAtRaw = body["expires_at"];
  let expiresAt: string | null | undefined;
  if (expiresAtRaw !== undefined) {
    if (expiresAtRaw === null) {
      expiresAt = null;
    } else if (typeof expiresAtRaw !== "string") {
      return { ok: false, error: "invalid_expires_at" };
    } else {
      const parsed = Date.parse(expiresAtRaw);
      if (Number.isNaN(parsed)) {
        return { ok: false, error: "invalid_expires_at" };
      }
      expiresAt = new Date(parsed).toISOString();
    }
  }

  return {
    ok: true,
    payload: {
      site_id: siteId,
      trust_tier: trustTierRaw,
      status: statusRaw,
      reputation_score: scoreRaw,
      default_action: defaultActionRaw,
      default_scope_routes: defaultScopeRoutes ?? [],
      ...(defaultScopeRedirectPath === undefined ? {} : { default_scope_redirect_path: defaultScopeRedirectPath }),
      ...(displayName === undefined ? {} : { display_name: displayName }),
      ...(notes === undefined ? {} : { notes }),
      ...(lastReviewedAt === undefined ? {} : { last_reviewed_at: lastReviewedAt }),
      ...(expiresAt === undefined ? {} : { expires_at: expiresAt })
    }
  };
}
