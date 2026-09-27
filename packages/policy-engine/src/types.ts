export const ACTOR_CLASSES = [
  "verified_agent",
  "signed_agent",
  "likely_human",
  "suspicious_automation",
  "unknown"
] as const;

export type ActorClass = (typeof ACTOR_CLASSES)[number];

export const DECISION_ACTIONS = [
  "allow",
  "throttle",
  "queue",
  "sandbox",
  "deny",
  "price_required"
] as const;

export type DecisionAction = (typeof DECISION_ACTIONS)[number];

export const VERIFIER_MODES = ["observe", "recommend", "enforce"] as const;
export type VerifierMode = (typeof VERIFIER_MODES)[number];

export type DegradedAction = "queue" | "deny";
export type DegradedState = "healthy" | "redis_down" | "policy_stale" | "issuer_cache_stale" | "control_plane_down";

export type ReasonCode =
  | "matched_policy"
  | "missing_signature"
  | "bad_signature"
  | "unknown_issuer"
  | "issuer_key_rotation_pending"
  | "audience_mismatch"
  | "resource_mismatch"
  | "token_expired"
  | "revoked"
  | "rate_limited"
  | "strict_route_degraded"
  | "purpose_required"
  | "purpose_disallowed"
  | "permission_scope_mismatch"
  | "price_required"
  | "sandbox_policy"
  | "operator_override";

export interface RatePolicy {
  readonly capacity: number;
  readonly refillPerSec: number;
  readonly cost: number;
}

export interface PriceMetadata {
  readonly unit: string;
  readonly currency: "USD";
  readonly amountMicros: number;
}

export interface PolicyDefaults {
  readonly strict: boolean;
  readonly onDegraded: DegradedAction;
  readonly sandboxOrigin?: string | undefined;
  readonly suspicionThreshold: number;
  readonly rate: RatePolicy;
}

export interface ActorRoutePolicy {
  readonly actorClass: ActorClass | "*";
  readonly decision: DecisionAction | null;
  readonly rate: RatePolicy;
  readonly strict: boolean;
  readonly signatureRequired: readonly string[];
  readonly queueRetrySeconds: number;
  readonly retryAfterSeconds: number;
  readonly priceUsd?: number | undefined;
  readonly priceMetadata?: PriceMetadata | undefined;
  readonly sandboxOrigin?: string | undefined;
  readonly ruleId: string;
}

export interface CompiledRoutePolicy {
  readonly ruleId: string;
  readonly routeTemplate: string;
  readonly method: string;
  readonly allowedPurposes?: readonly string[] | undefined;
  readonly requiredPermissions?: readonly string[] | undefined;
  readonly routeBucket: string;
  readonly mode: VerifierMode;
  readonly strict: boolean;
  readonly onDegraded: DegradedAction;
  readonly signatureRequired: readonly string[];
  readonly rate: RatePolicy;
  readonly queueRetrySeconds: number;
  readonly retryAfterSeconds: number;
  readonly sandboxOrigin?: string | undefined;
  readonly defaultActorPolicy: ActorRoutePolicy;
  readonly perActorClass: ReadonlyMap<ActorClass, ActorRoutePolicy>;
}

export interface MatchedPolicy {
  readonly routePolicy: CompiledRoutePolicy;
  readonly actorPolicy: ActorRoutePolicy;
  readonly routeTemplate: string;
  readonly params: Readonly<Record<string, string>>;
  readonly matched: boolean;
}

export interface CompiledPolicyBundle {
  readonly version: string;
  readonly siteId: string;
  readonly mode: VerifierMode;
  readonly defaults: PolicyDefaults;
  readonly routes: readonly CompiledRoutePolicy[];
}

export interface RateOutcome {
  readonly allow: boolean;
  readonly remaining: number;
  readonly retryAfterSeconds?: number | undefined;
  readonly degraded?: Exclude<DegradedState, "healthy"> | undefined;
}

export interface DecisionEvaluation {
  readonly action: DecisionAction;
  readonly recommendedAction: DecisionAction;
  readonly httpStatus: number;
  readonly headers: Readonly<Record<string, string>>;
  readonly reasonCodes: readonly ReasonCode[];
  readonly route?: string | undefined;
  readonly annotations: readonly string[];
}

export function isActorClass(value: string): value is ActorClass {
  return ACTOR_CLASSES.includes(value as ActorClass);
}
