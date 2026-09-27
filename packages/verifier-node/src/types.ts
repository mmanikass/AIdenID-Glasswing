import type {
  AsyncTokenBucketStore,
  DegradedState,
  PolicyTrie,
  RedisTokenBucketScriptRunner,
  TokenBucketStore
} from "@aidenid/policy-engine";
import type { CascadeTrace } from "@aidenid/common-schemas";
import type { RedisReplayCacheScriptRunner, ReplayCacheLike } from "@aidenid/crypto";
import type { FingerprintEvidenceProvider } from "@aidenid/fingerprint-sidecar";
import type { QuarantinePinCacheLike } from "./quarantinePinCache.js";

export type ActorClass = "verified_agent" | "signed_agent" | "likely_human" | "suspicious_automation" | "unknown";

export type DecisionAction = "allow" | "throttle" | "queue" | "sandbox" | "deny" | "price_required";
export type OperatorAction = DecisionAction | "quarantine";
export type MaybePromise<T> = T | Promise<T>;

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
  | "fingerprint_risk"
  | "operator_reputation_suspended"
  | "operator_scope_mismatch"
  | "price_required"
  | "quarantine"
  | "operator_pinned"
  | "sandbox_policy"
  | "operator_override";

export type VerifierMode = "observe" | "recommend" | "enforce";
export type CryptoPathRolloutMode = "disabled" | "shadow" | "enforce";

export interface HeaderBag {
  readonly [name: string]: string | readonly string[] | undefined;
}

export interface HeaderReader {
  get(name: string): string | null;
}

export type RequestHeaders = HeaderBag | HeaderReader;

export interface AidenIdVerifierOptions {
  readonly siteId: string;
  readonly apiKey: string;
  readonly mode?: VerifierMode | undefined;
  readonly crypto?: VerifierCryptoOptions | undefined;
  readonly policy?: VerifierPolicyOptions | undefined;
  readonly fingerprint?: VerifierFingerprintOptions | undefined;
  readonly operatorReputation?: VerifierOperatorReputationOptions | undefined;
  readonly redis?: VerifierRedisOptions | undefined;
  readonly rollback?: VerifierRollbackControls | undefined;
  readonly quarantinePinCache?: QuarantinePinCacheLike | undefined;
  readonly metrics?: VerifierMetricsSink | undefined;
  readonly onDecision?: ((decision: DecisionResult) => void | Promise<void>) | undefined;
  readonly decisionOverride?: ((decision: DecisionResult) => DecisionResult | undefined | Promise<DecisionResult | undefined>) | undefined;
  readonly now?: (() => Date) | undefined;
}

export interface VerifierCryptoOptions {
  readonly sessionTokenPublicJwksByIssuer: Record<string, Record<string, unknown>>;
  readonly httpMessageSignaturePublicJwksByKeyId: Record<string, Record<string, unknown>>;
  readonly issuerKeyStatesByIssuer?:
    | Readonly<Record<string, Readonly<Record<string, "tofu_pending" | "trusted" | "rotation_pending" | "revoked">>>>
    | undefined;
  readonly minRevocationEpoch?: number | undefined;
  readonly replayCache?: ReplayCacheLike | undefined;
  readonly requireHttpSignatureNonce?: boolean | undefined;
}

export interface VerifierRedisOptions {
  readonly scriptRunner: RedisTokenBucketScriptRunner & RedisReplayCacheScriptRunner;
  readonly keyPrefix?: string | undefined;
  readonly tokenBucketKeyPrefix?: string | undefined;
  readonly replayKeyPrefix?: string | undefined;
  readonly quarantinePinKeyPrefix?: string | undefined;
}

export interface VerifierPolicyOptions {
  readonly trie: PolicyTrie;
  readonly tokenBucketStore?: TokenBucketStore | undefined;
  readonly asyncTokenBucketStore?: AsyncTokenBucketStore | undefined;
  readonly degraded?: DegradedState | boolean | undefined;
}

export interface VerifierFingerprintOptions {
  readonly provider?: FingerprintEvidenceProvider | undefined;
  readonly providerId?: string | undefined;
  readonly enabled?: boolean | undefined;
  readonly timeoutMs?: number | undefined;
  readonly suspiciousBotScoreThreshold?: number | undefined;
  readonly suspiciousDeltaThreshold?: number | undefined;
}

export type OperatorTrustTier = "unknown" | "trusted" | "restricted";
export type OperatorReputationStatus = "active" | "watchlist" | "suspended";

export interface OperatorReputationLookupInput {
  readonly siteId: string;
  readonly actorClass: ActorClass;
  readonly issuer?: string | undefined;
  readonly subjectHandle?: string | undefined;
  readonly llmBrand?: string | undefined;
  readonly method: string;
  readonly url: string;
  readonly routeTemplate: string;
  readonly occurredAt: Date;
}

export interface OperatorReputationResult {
  readonly operatorActorId: string;
  readonly trustTier: OperatorTrustTier;
  readonly status: OperatorReputationStatus;
  readonly reputationScore?: number | undefined;
  readonly defaultAction?: DecisionAction | undefined;
  readonly defaultScopeRoutes?: readonly string[] | undefined;
  readonly defaultScopeRedirectPath?: string | undefined;
  readonly evidence?: readonly string[] | undefined;
}

export interface OperatorReputationProvider {
  lookup(input: OperatorReputationLookupInput, signal: AbortSignal): MaybePromise<OperatorReputationResult | undefined>;
}

export interface VerifierOperatorReputationOptions {
  readonly provider?: OperatorReputationProvider | undefined;
  readonly providerId?: string | undefined;
  readonly enabled?: boolean | undefined;
  readonly timeoutMs?: number | undefined;
}

export interface VerifierRollbackControls {
  readonly globalEnforcementPause?: boolean | undefined;
  readonly routeModeOverrides?: Readonly<Record<string, VerifierMode>> | undefined;
  readonly globalRevocationEpoch?: number | undefined;
  readonly cryptoPathRollout?: CryptoPathRolloutMode | undefined;
}

export interface RequestInput {
  readonly method: string;
  readonly url: string;
  readonly headers?: RequestHeaders | undefined;
  readonly statusCode?: number | undefined;
  readonly remoteAddress?: string | undefined;
}

export interface RateLimitSignal {
  readonly status: "ok" | "warning" | "throttled";
  readonly retryAfterSeconds?: number;
  readonly remaining?: number;
  readonly resetAtEpochSeconds?: number;
}

export interface ClassificationResult {
  readonly actorClass: ActorClass;
  readonly evidence: readonly string[];
}

export interface DecisionResult {
  readonly requestId: string;
  readonly siteId: string;
  readonly mode: VerifierMode;
  readonly method: string;
  readonly path: string;
  readonly routeTemplate: string;
  readonly actorClass: ActorClass;
  readonly issuer?: string | undefined;
  readonly subjectHandle?: string | undefined;
  readonly llmBrand?: string | undefined;
  readonly purpose?: string | undefined;
  readonly priceUsd?: number | undefined;
  readonly decision: DecisionAction;
  readonly recommendedDecision: DecisionAction;
  readonly reasons: readonly ReasonCode[];
  readonly responseHeaders?: Readonly<Record<string, string>> | undefined;
  readonly observeOnly: boolean;
  readonly rateLimit: RateLimitSignal;
  readonly cascadeTrace?: CascadeTrace | undefined;
  readonly latencyUs: number;
}

export interface VerifierMetricsSink {
  recordDecision(decision: DecisionResult): void | Promise<void>;
}
