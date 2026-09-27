export type AgentIdentitySubmissionStatus = "pending_review" | "approved" | "rejected";

export interface AgentIdentitySubmissionView {
  readonly id: string;
  readonly site_id: string;
  readonly request_id?: string;
  readonly purpose: string;
  readonly requested_access_duration_seconds: number;
  readonly requested_access_expires_at: string;
  readonly purpose_rationale?: string;
  readonly provider_name: string;
  readonly operator_actor_id?: string;
  readonly contact_url: string;
  readonly jwks_url?: string;
  readonly delegation_authority_jwk_thumbprint_sha256?: string;
  readonly cascade_attestation: readonly string[];
  readonly declaration?: string;
  readonly status: AgentIdentitySubmissionStatus;
  readonly submitted_at: string;
  readonly reviewed_at?: string;
  readonly review_decision?: AgentIdentityReviewAction;
  readonly reviewer_identity_hash_sha256?: string;
  readonly review_reason?: string;
  readonly approved_operator_actor_id?: string;
  readonly operator_reputation_id?: string;
  readonly assigned_trust_tier?: AgentIdentityReviewTrustTier;
  readonly assigned_operator_status?: AgentIdentityReviewOperatorStatus;
  readonly assigned_reputation_score?: number;
}

export type AgentIdentityReviewAction = "approve" | "reject";
export type AgentIdentityReviewTrustTier = "restricted" | "trusted";
export type AgentIdentityReviewOperatorStatus = "active" | "watchlist";
export type AgentIdentityDefaultAction = "allow" | "throttle" | "queue" | "sandbox" | "deny" | "price_required";

export interface AgentIdentitySubmissionReviewRequest {
  readonly action: AgentIdentityReviewAction;
  readonly operator_actor_id?: string;
  readonly trust_tier?: AgentIdentityReviewTrustTier;
  readonly operator_status?: AgentIdentityReviewOperatorStatus;
  readonly reputation_score?: number;
  readonly default_action?: AgentIdentityDefaultAction;
  readonly default_scope_routes?: readonly string[];
  readonly default_scope_redirect_path?: string;
  readonly approval_expires_at?: string;
  readonly display_name?: string;
  readonly notes?: string;
  readonly review_reason?: string;
}

export interface AgentIdentitySubmissionReviewResponse {
  readonly submission: AgentIdentitySubmissionView;
  readonly operator?: unknown;
}

export interface AgentIdentitySubmissionListFilters {
  readonly status?: AgentIdentitySubmissionStatus | undefined;
  readonly limit?: number | undefined;
}

const SUBMISSION_STATUSES: readonly AgentIdentitySubmissionStatus[] = ["pending_review", "approved", "rejected"];
const REVIEW_ACTIONS: readonly AgentIdentityReviewAction[] = ["approve", "reject"];
const REVIEW_TRUST_TIERS: readonly AgentIdentityReviewTrustTier[] = ["restricted", "trusted"];
const REVIEW_OPERATOR_STATUSES: readonly AgentIdentityReviewOperatorStatus[] = ["active", "watchlist"];
const DECISION_ACTIONS: readonly AgentIdentityDefaultAction[] = ["allow", "throttle", "queue", "sandbox", "deny", "price_required"];
const DEFAULT_SCOPE_ROUTE_REGEX = /^\/[A-Za-z0-9._~!$&'()*+,;=:@/%-]*(?:\/\*)?$/;
const DEFAULT_SCOPE_REDIRECT_PATH_REGEX = /^\/[A-Za-z0-9._~!$&'()*+,;=:@/%-]*$/;

export function isAgentIdentitySubmissionStatus(value: unknown): value is AgentIdentitySubmissionStatus {
  return typeof value === "string" && (SUBMISSION_STATUSES as readonly string[]).includes(value);
}

function isOptionalString(value: unknown): boolean {
  return value === undefined || typeof value === "string";
}

export function buildAgentIdentitySubmissionListUrl(
  controlPlaneUrl: string,
  siteId: string,
  filters: AgentIdentitySubmissionListFilters = {}
): string {
  const url = new URL("/v1/identities/submissions", controlPlaneUrl);
  url.searchParams.set("site_id", siteId);
  if (filters.status !== undefined) {
    url.searchParams.set("status", filters.status);
  }
  if (filters.limit !== undefined) {
    url.searchParams.set("limit", String(filters.limit));
  }
  return url.toString();
}

export function buildAgentIdentitySubmissionReviewUrl(
  controlPlaneUrl: string,
  submissionId: string
): string {
  return new URL(
    `/v1/identities/submissions/${encodeURIComponent(submissionId)}/review`,
    controlPlaneUrl
  ).toString();
}

function isSubmission(value: unknown): value is AgentIdentitySubmissionView {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const candidate = value as Partial<AgentIdentitySubmissionView>;
  return (
    typeof candidate.id === "string" &&
    typeof candidate.site_id === "string" &&
    isOptionalString(candidate.request_id) &&
    typeof candidate.purpose === "string" &&
    typeof candidate.requested_access_duration_seconds === "number" &&
    Number.isInteger(candidate.requested_access_duration_seconds) &&
    candidate.requested_access_duration_seconds >= 60 &&
    candidate.requested_access_duration_seconds <= 7_776_000 &&
    typeof candidate.requested_access_expires_at === "string" &&
    isOptionalString(candidate.purpose_rationale) &&
    typeof candidate.provider_name === "string" &&
    isOptionalString(candidate.operator_actor_id) &&
    typeof candidate.contact_url === "string" &&
    isOptionalString(candidate.jwks_url) &&
    isOptionalString(candidate.delegation_authority_jwk_thumbprint_sha256) &&
    Array.isArray(candidate.cascade_attestation) &&
    candidate.cascade_attestation.every((layer) => typeof layer === "string") &&
    isOptionalString(candidate.declaration) &&
    isAgentIdentitySubmissionStatus(candidate.status) &&
    typeof candidate.submitted_at === "string" &&
    isOptionalString(candidate.reviewed_at) &&
    (candidate.review_decision === undefined || isReviewAction(candidate.review_decision)) &&
    isOptionalString(candidate.reviewer_identity_hash_sha256) &&
    isOptionalString(candidate.review_reason) &&
    isOptionalString(candidate.approved_operator_actor_id) &&
    isOptionalString(candidate.operator_reputation_id) &&
    (candidate.assigned_trust_tier === undefined || isReviewTrustTier(candidate.assigned_trust_tier)) &&
    (candidate.assigned_operator_status === undefined || isReviewOperatorStatus(candidate.assigned_operator_status)) &&
    (candidate.assigned_reputation_score === undefined ||
      (typeof candidate.assigned_reputation_score === "number" &&
        Number.isInteger(candidate.assigned_reputation_score) &&
        candidate.assigned_reputation_score >= 0 &&
        candidate.assigned_reputation_score <= 100))
  );
}

function isReviewAction(value: unknown): value is AgentIdentityReviewAction {
  return typeof value === "string" && (REVIEW_ACTIONS as readonly string[]).includes(value);
}

function isReviewTrustTier(value: unknown): value is AgentIdentityReviewTrustTier {
  return typeof value === "string" && (REVIEW_TRUST_TIERS as readonly string[]).includes(value);
}

function isReviewOperatorStatus(value: unknown): value is AgentIdentityReviewOperatorStatus {
  return typeof value === "string" && (REVIEW_OPERATOR_STATUSES as readonly string[]).includes(value);
}

function isDecisionAction(value: unknown): value is AgentIdentityDefaultAction {
  return typeof value === "string" && (DECISION_ACTIONS as readonly string[]).includes(value);
}

function optionalTrimmed(value: unknown, max: number): string | undefined | false {
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== "string") {
    return false;
  }
  const trimmed = value.trim();
  return trimmed.length === 0 || trimmed.length > max ? false : trimmed;
}

function optionalScopeRoutes(value: unknown): readonly string[] | undefined | false {
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

export function parseAgentIdentitySubmissionList(value: unknown): readonly AgentIdentitySubmissionView[] | undefined {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return undefined;
  }
  const submissions = (value as { submissions?: unknown }).submissions;
  if (!Array.isArray(submissions)) {
    return undefined;
  }
  return submissions.filter(isSubmission);
}

export type AgentIdentityReviewValidationError =
  | "invalid_review_body"
  | "invalid_review_action"
  | "invalid_operator_actor_id"
  | "invalid_trust_tier"
  | "invalid_operator_status"
  | "invalid_reputation_score"
  | "invalid_default_action"
  | "invalid_default_scope_routes"
  | "invalid_default_scope_redirect_path"
  | "invalid_approval_expires_at"
  | "invalid_display_name"
  | "invalid_notes"
  | "invalid_review_reason";

export type AgentIdentityReviewParseResult =
  | {
      readonly ok: true;
      readonly payload: AgentIdentitySubmissionReviewRequest;
    }
  | {
      readonly ok: false;
      readonly error: AgentIdentityReviewValidationError;
    };

export function parseAgentIdentityReviewRequest(rawBody: unknown): AgentIdentityReviewParseResult {
  const body = rawBody !== null && typeof rawBody === "object" && !Array.isArray(rawBody)
    ? (rawBody as Readonly<Record<string, unknown>>)
    : undefined;
  if (body === undefined) {
    return { ok: false, error: "invalid_review_body" };
  }

  const action = body["action"];
  if (!isReviewAction(action)) {
    return { ok: false, error: "invalid_review_action" };
  }

  const operatorActorId = optionalTrimmed(body["operator_actor_id"], 128);
  if (operatorActorId === false || (typeof operatorActorId === "string" && !/^[A-Za-z0-9:_-]+$/.test(operatorActorId))) {
    return { ok: false, error: "invalid_operator_actor_id" };
  }

  const trustTierRaw = body["trust_tier"] ?? "restricted";
  if (!isReviewTrustTier(trustTierRaw)) {
    return { ok: false, error: "invalid_trust_tier" };
  }

  const operatorStatusRaw = body["operator_status"] ?? "active";
  if (!isReviewOperatorStatus(operatorStatusRaw)) {
    return { ok: false, error: "invalid_operator_status" };
  }

  const reputationScoreRaw = body["reputation_score"];
  let reputationScore: number | undefined;
  if (reputationScoreRaw !== undefined) {
    if (
      typeof reputationScoreRaw !== "number" ||
      !Number.isInteger(reputationScoreRaw) ||
      reputationScoreRaw < 0 ||
      reputationScoreRaw > 100
    ) {
      return { ok: false, error: "invalid_reputation_score" };
    }
    reputationScore = reputationScoreRaw;
  }

  const defaultActionRaw = body["default_action"] ?? "allow";
  if (!isDecisionAction(defaultActionRaw)) {
    return { ok: false, error: "invalid_default_action" };
  }
  const defaultScopeRoutes = optionalScopeRoutes(body["default_scope_routes"]);
  if (defaultScopeRoutes === false) {
    return { ok: false, error: "invalid_default_scope_routes" };
  }
  const defaultScopeRedirectPath = optionalTrimmed(body["default_scope_redirect_path"], 256);
  if (
    defaultScopeRedirectPath === false ||
    (typeof defaultScopeRedirectPath === "string" && !DEFAULT_SCOPE_REDIRECT_PATH_REGEX.test(defaultScopeRedirectPath))
  ) {
    return { ok: false, error: "invalid_default_scope_redirect_path" };
  }

  const approvalExpiresAtRaw = body["approval_expires_at"];
  let approvalExpiresAt: string | undefined;
  if (approvalExpiresAtRaw !== undefined) {
    if (typeof approvalExpiresAtRaw !== "string" || Number.isNaN(Date.parse(approvalExpiresAtRaw))) {
      return { ok: false, error: "invalid_approval_expires_at" };
    }
    approvalExpiresAt = new Date(Date.parse(approvalExpiresAtRaw)).toISOString();
  }

  const displayName = optionalTrimmed(body["display_name"], 128);
  if (displayName === false) {
    return { ok: false, error: "invalid_display_name" };
  }
  const notes = optionalTrimmed(body["notes"], 1024);
  if (notes === false) {
    return { ok: false, error: "invalid_notes" };
  }
  const reviewReason = optionalTrimmed(body["review_reason"], 1024);
  if (reviewReason === false || (action === "reject" && reviewReason === undefined)) {
    return { ok: false, error: "invalid_review_reason" };
  }

  return {
    ok: true,
    payload: {
      action,
      ...(operatorActorId === undefined ? {} : { operator_actor_id: operatorActorId }),
      trust_tier: trustTierRaw,
      operator_status: operatorStatusRaw,
      ...(reputationScore === undefined ? {} : { reputation_score: reputationScore }),
      default_action: defaultActionRaw,
      default_scope_routes: defaultScopeRoutes ?? [],
      ...(defaultScopeRedirectPath === undefined ? {} : { default_scope_redirect_path: defaultScopeRedirectPath }),
      ...(approvalExpiresAt === undefined ? {} : { approval_expires_at: approvalExpiresAt }),
      ...(displayName === undefined ? {} : { display_name: displayName }),
      ...(notes === undefined ? {} : { notes }),
      ...(reviewReason === undefined ? {} : { review_reason: reviewReason })
    }
  };
}

export function parseAgentIdentityReviewResponse(value: unknown): AgentIdentitySubmissionReviewResponse | undefined {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return undefined;
  }
  const submission = (value as { submission?: unknown }).submission;
  if (!isSubmission(submission)) {
    return undefined;
  }
  const operator = (value as { operator?: unknown }).operator;
  return operator === undefined ? { submission } : { submission, operator };
}
