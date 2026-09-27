import { createHash, randomUUID } from "node:crypto";
import { performance } from "node:perf_hooks";

import { MemoryReplayCache, RedisReplayCache, isAsyncReplayCache } from "@aidenid/crypto";
import { getFingerprintEvidence, type FingerprintEvidence } from "@aidenid/fingerprint-sidecar";
import type { CascadeTrace, CascadeTraceEntry, CascadeTraceStatus } from "@aidenid/common-schemas";
import {
  MemoryTokenBucketStore,
  RedisTokenBucketStore,
  applyRatePolicy,
  applyRatePolicyAsync,
  evaluateDecision,
  type MatchedPolicy,
  type ReasonCode as PolicyReasonCode,
  type RateOutcome
} from "@aidenid/policy-engine";

import { classifyRequest } from "./classifier.js";
import { resolveRequestId } from "./correlation.js";
import { verifyCryptoPath, verifyCryptoPathAsync, type CryptoDelegationEvidence, type CryptoPathResult } from "./cryptoPath.js";
import { readHeader } from "./headers.js";
import { normalizePath } from "./pathNormalize.js";
import { RedisQuarantinePinCache, isAsyncQuarantinePinCache } from "./quarantinePinCache.js";
import { ingestUpstreamRateLimit } from "./upstreamLimits.js";
import type {
  AidenIdVerifierOptions,
  CryptoPathRolloutMode,
  DecisionAction,
  DecisionResult,
  OperatorReputationResult,
  RateLimitSignal,
  ReasonCode,
  RequestInput,
  VerifierCryptoOptions,
  VerifierMode,
  VerifierOperatorReputationOptions,
  VerifierPolicyOptions,
  VerifierRedisOptions,
  VerifierRollbackControls
} from "./types.js";

export interface ResolvedVerifierOptions {
  readonly siteId: string;
  readonly apiKey: string;
  readonly mode: VerifierMode;
  readonly crypto?: VerifierCryptoOptions | undefined;
  readonly policy?: VerifierPolicyOptions | undefined;
  readonly fingerprint?: AidenIdVerifierOptions["fingerprint"] | undefined;
  readonly operatorReputation?: VerifierOperatorReputationOptions | undefined;
  readonly rollback?: VerifierRollbackControls | undefined;
  readonly quarantinePinCache?: AidenIdVerifierOptions["quarantinePinCache"] | undefined;
  readonly metrics?: AidenIdVerifierOptions["metrics"] | undefined;
  readonly onDecision?: ((decision: DecisionResult) => void | Promise<void>) | undefined;
  readonly decisionOverride?: AidenIdVerifierOptions["decisionOverride"] | undefined;
  readonly now: () => Date;
}

const DEFAULT_TOKEN_BUCKET_STORE = new MemoryTokenBucketStore();
const DEFAULT_REPLAY_CACHES = new Map<string, MemoryReplayCache>();
const DEFAULT_REDIS_STORES = new WeakMap<object, Map<string, DefaultRedisStores>>();
const MAX_DEFAULT_REPLAY_CACHE_GROUPS = 1_024;

interface PreparedRequestEvaluation {
  readonly started: number;
  readonly resolved: ResolvedVerifierOptions;
  readonly normalized: ReturnType<typeof normalizePath>;
  readonly now: Date;
  readonly classification: ReturnType<typeof classifyRequest>;
  readonly issuer: string | undefined;
  readonly subjectHandle: string | undefined;
  readonly llmBrand: string | undefined;
  readonly delegation: CryptoDelegationEvidence | undefined;
  readonly signatureFailureReason: PolicyReasonCode | undefined;
  readonly quarantinePinned: boolean;
  readonly operatorReputationSuspended: boolean;
  readonly operatorReputationDefaultAction: DecisionAction | undefined;
  readonly operatorReputationDefaultScopeRoutes: readonly string[];
  readonly operatorReputationDefaultScopeRedirectPath: string | undefined;
  readonly cascadeTrace: CascadeTrace;
  readonly rateLimit: RateLimitSignal;
  readonly recommendation: { readonly decision: DecisionAction; readonly reasons: readonly ReasonCode[] };
}

interface InitialRequestEvaluation {
  readonly started: number;
  readonly resolved: ResolvedVerifierOptions;
  readonly normalized: ReturnType<typeof normalizePath>;
  readonly now: Date;
  readonly classification: ReturnType<typeof classifyRequest>;
  readonly rateLimit: RateLimitSignal;
  readonly recommendation: { readonly decision: DecisionAction; readonly reasons: readonly ReasonCode[] };
}

interface CryptoDecisionOutcome {
  readonly classification: ReturnType<typeof classifyRequest>;
  readonly issuer: string | undefined;
  readonly subjectHandle: string | undefined;
  readonly llmBrand: string | undefined;
  readonly delegation: CryptoDelegationEvidence | undefined;
  readonly signatureFailureReason: PolicyReasonCode | undefined;
  readonly quarantinePinned: boolean;
  readonly operatorReputationSuspended: boolean;
  readonly operatorReputationDefaultAction: DecisionAction | undefined;
  readonly operatorReputationDefaultScopeRoutes: readonly string[];
  readonly operatorReputationDefaultScopeRedirectPath: string | undefined;
  readonly cascadeTrace: CascadeTrace;
  readonly recommendation: { readonly decision: DecisionAction; readonly reasons: readonly ReasonCode[] };
}

interface DefaultRedisStores {
  readonly replayCache: RedisReplayCache;
  readonly tokenBucketStore: RedisTokenBucketStore;
  readonly quarantinePinCache: RedisQuarantinePinCache;
}

interface PurposeCheckResult {
  readonly ok: boolean;
  readonly purpose?: string | undefined;
  readonly reason?: Extract<ReasonCode, "purpose_required" | "purpose_disallowed"> | undefined;
}

interface DelegationScopeCheckResult {
  readonly ok: boolean;
  readonly cascadeTrace: CascadeTrace;
  readonly reason?: Extract<ReasonCode, "permission_scope_mismatch"> | undefined;
}

interface OperatorScopeCheckResult {
  readonly ok: boolean;
  readonly cascadeTrace: CascadeTrace;
  readonly reason?: Extract<ReasonCode, "operator_scope_mismatch"> | undefined;
}

const PURPOSE_SLUG_RE = /^[a-z][a-z0-9_-]{0,63}$/;
const DEFAULT_SCOPE_ROUTE_RE = /^\/[A-Za-z0-9._~!$&'()*+,;=:@/%-]*(?:\/\*)?$/u;
const DEFAULT_SCOPE_REDIRECT_PATH_RE = /^\/[A-Za-z0-9._~!$&'()*+,;=:@/%-]*$/u;
const DECISION_ACTIONS = ["allow", "throttle", "queue", "sandbox", "deny", "price_required"] as const;
const DEFAULT_FINGERPRINT_SUSPICIOUS_BOT_SCORE_THRESHOLD = 0.8;
const DEFAULT_FINGERPRINT_SUSPICIOUS_DELTA_THRESHOLD = 0.75;
const DEFAULT_OPERATOR_REPUTATION_TIMEOUT_MS = 10;
const PROVIDER_EVIDENCE_MAX = 16;

function createQueueRetryToken(): string {
  return `rty_${randomUUID().replaceAll("-", "")}`;
}

export function resolveVerifierOptions(options: AidenIdVerifierOptions): ResolvedVerifierOptions {
  if (!options.siteId.trim()) {
    throw new Error("siteId is required");
  }
  if (!options.apiKey.trim()) {
    throw new Error("apiKey is required");
  }

  const redisStores = options.redis === undefined ? undefined : defaultRedisStores(options.redis, options.siteId);
  const crypto = options.crypto === undefined ? undefined : withDefaultReplayCache(options.siteId, options.crypto, redisStores?.replayCache);
  const policy = options.policy === undefined ? undefined : withDefaultTokenBucketStore(options.policy, redisStores?.tokenBucketStore);
  const quarantinePinCache = options.quarantinePinCache ?? redisStores?.quarantinePinCache;
  enforceDistributedStoreRequirement(crypto, policy, quarantinePinCache);

  return {
    siteId: options.siteId,
    apiKey: options.apiKey,
    mode: options.mode ?? "observe",
    crypto,
    policy,
    fingerprint: options.fingerprint,
    operatorReputation: options.operatorReputation,
    rollback: options.rollback,
    quarantinePinCache,
    metrics: options.metrics,
    onDecision: options.onDecision,
    decisionOverride: options.decisionOverride,
    now: options.now ?? (() => new Date())
  };
}

function withDefaultReplayCache(
  siteId: string,
  crypto: VerifierCryptoOptions,
  redisReplayCache: RedisReplayCache | undefined
): VerifierCryptoOptions {
  if (crypto.replayCache !== undefined) {
    return crypto;
  }
  if (redisReplayCache !== undefined) {
    return { ...crypto, replayCache: redisReplayCache };
  }
  const cacheKey = replayCacheGroupKey(siteId, crypto);
  let replayCache = DEFAULT_REPLAY_CACHES.get(cacheKey);
  if (replayCache === undefined) {
    replayCache = new MemoryReplayCache({ maxEntries: 50_000 });
    if (DEFAULT_REPLAY_CACHES.size >= MAX_DEFAULT_REPLAY_CACHE_GROUPS) {
      const oldestKey = DEFAULT_REPLAY_CACHES.keys().next().value as string | undefined;
      if (oldestKey !== undefined) {
        DEFAULT_REPLAY_CACHES.delete(oldestKey);
      }
    }
    DEFAULT_REPLAY_CACHES.set(cacheKey, replayCache);
  }
  return { ...crypto, replayCache };
}

function withDefaultTokenBucketStore(
  policy: VerifierPolicyOptions,
  redisTokenBucketStore: RedisTokenBucketStore | undefined
): VerifierPolicyOptions {
  if (redisTokenBucketStore === undefined || policy.asyncTokenBucketStore !== undefined) {
    return policy;
  }
  return { ...policy, asyncTokenBucketStore: redisTokenBucketStore };
}

function defaultRedisStores(redis: VerifierRedisOptions, siteId: string): DefaultRedisStores {
  const runnerKey = redis.scriptRunner as object;
  const keyPrefix = redis.keyPrefix ?? "aidenid:";
  const tokenBucketKeyPrefix = redis.tokenBucketKeyPrefix ?? keyPrefix;
  const replayKeyPrefix = redis.replayKeyPrefix ?? `${keyPrefix}replay:${siteId}:`;
  const quarantinePinKeyPrefix = redis.quarantinePinKeyPrefix ?? `${keyPrefix}quarantine:`;
  const cacheKey = `${tokenBucketKeyPrefix}\n${replayKeyPrefix}\n${quarantinePinKeyPrefix}`;
  let storesByPrefix = DEFAULT_REDIS_STORES.get(runnerKey);
  if (storesByPrefix === undefined) {
    storesByPrefix = new Map<string, DefaultRedisStores>();
    DEFAULT_REDIS_STORES.set(runnerKey, storesByPrefix);
  }
  let stores = storesByPrefix.get(cacheKey);
  if (stores === undefined) {
    stores = {
      replayCache: new RedisReplayCache(redis.scriptRunner, { keyPrefix: replayKeyPrefix }),
      tokenBucketStore: new RedisTokenBucketStore(redis.scriptRunner, { keyPrefix: tokenBucketKeyPrefix }),
      quarantinePinCache: new RedisQuarantinePinCache(redis.scriptRunner, { keyPrefix: quarantinePinKeyPrefix })
    };
    storesByPrefix.set(cacheKey, stores);
  }
  return stores;
}

function stableJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableJson(item)).join(",")}]`;
  }
  return `{${Object.keys(value as Record<string, unknown>)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${stableJson((value as Record<string, unknown>)[key])}`)
    .join(",")}}`;
}

function replayCacheGroupKey(siteId: string, crypto: VerifierCryptoOptions): string {
  return createHash("sha256")
    .update(
      stableJson({
        siteId,
        sessionTokenPublicJwksByIssuer: crypto.sessionTokenPublicJwksByIssuer,
        httpMessageSignaturePublicJwksByKeyId: crypto.httpMessageSignaturePublicJwksByKeyId
      })
    )
    .digest("hex");
}

function distributedStoresRequired(): boolean {
  return /^(1|true|yes)$/i.test(process.env.AIDENID_REQUIRE_DISTRIBUTED_STORES ?? "");
}

function enforceDistributedStoreRequirement(
  crypto: VerifierCryptoOptions | undefined,
  policy: VerifierPolicyOptions | undefined,
  quarantinePinCache: AidenIdVerifierOptions["quarantinePinCache"] | undefined
): void {
  if (!distributedStoresRequired()) {
    return;
  }
  if (crypto !== undefined && !isAsyncReplayCache(crypto.replayCache)) {
    throw new Error("AIDENID_REQUIRE_DISTRIBUTED_STORES requires a Redis replay cache or top-level redis option");
  }
  if (policy !== undefined && policy.asyncTokenBucketStore === undefined) {
    throw new Error("AIDENID_REQUIRE_DISTRIBUTED_STORES requires a Redis token bucket store or top-level redis option");
  }
  if (quarantinePinCache !== undefined && !isAsyncQuarantinePinCache(quarantinePinCache)) {
    throw new Error("AIDENID_REQUIRE_DISTRIBUTED_STORES requires a Redis quarantine pin cache or top-level redis option");
  }
}

function recommendedDecision(actorClass: string, rateStatus: string): { decision: DecisionAction; reasons: ReasonCode[] } {
  if (rateStatus === "throttled") {
    return { decision: "throttle", reasons: ["rate_limited"] };
  }
  if (actorClass === "suspicious_automation") {
    return { decision: "throttle", reasons: ["matched_policy"] };
  }
  return { decision: "allow", reasons: ["matched_policy"] };
}

function policyRateSignal(rateOutcome: RateOutcome): RateLimitSignal {
  if (rateOutcome.allow) {
    return {
      status: rateOutcome.degraded === undefined ? "ok" : "warning",
      remaining: rateOutcome.remaining
    };
  }
  return {
    status: "throttled",
    remaining: rateOutcome.remaining,
    ...(rateOutcome.retryAfterSeconds === undefined ? {} : { retryAfterSeconds: rateOutcome.retryAfterSeconds })
  };
}

function elapsedUs(started: number): number {
  return Math.max(0, Math.round((performance.now() - started) * 1000));
}

function cascadeTraceEntry(
  ordinal: CascadeTraceEntry["ordinal"],
  layer: CascadeTraceEntry["layer"],
  status: CascadeTraceStatus,
  reason: string,
  latencyUs: number,
  evidence: readonly string[] = []
): CascadeTraceEntry {
  return {
    ordinal,
    layer,
    status,
    reason,
    latency_us: Math.max(0, Math.round(latencyUs)),
    ...(evidence.length === 0 ? {} : { evidence: [...evidence] })
  };
}

function isPromiseLike<T>(value: T | Promise<T>): value is Promise<T> {
  return typeof (value as Promise<T>)?.then === "function";
}

function isPositiveNumber(value: number | undefined): value is number {
  return value !== undefined && Number.isFinite(value) && value >= 0;
}

function boundedEvidence(items: readonly string[]): readonly string[] {
  return items
    .filter((item) => item.trim().length > 0)
    .map((item) => item.trim().slice(0, 128))
    .slice(0, PROVIDER_EVIDENCE_MAX);
}

function isDecisionAction(value: string): value is DecisionAction {
  return (DECISION_ACTIONS as readonly string[]).includes(value);
}

function normalizeDefaultAction(value: DecisionAction | undefined): DecisionAction {
  if (value === undefined) {
    return "allow";
  }
  if (!isDecisionAction(value)) {
    throw new Error("operator reputation provider returned an invalid defaultAction");
  }
  return value;
}

function normalizeDefaultScopeRoutes(value: readonly string[] | undefined): readonly string[] {
  if (value === undefined) {
    return [];
  }
  if (!Array.isArray(value) || value.length > 32) {
    throw new Error("operator reputation provider returned too many defaultScopeRoutes");
  }
  const routes = value.map((route) => {
    const trimmed = route.trim();
    if (trimmed.length === 0 || trimmed.length > 256 || !DEFAULT_SCOPE_ROUTE_RE.test(trimmed)) {
      throw new Error("operator reputation provider returned an invalid defaultScopeRoute");
    }
    return trimmed;
  });
  return [...new Set(routes)];
}

function normalizeDefaultScopeRedirectPath(value: string | undefined): string | undefined {
  if (value === undefined) {
    return undefined;
  }
  const trimmed = value.trim();
  if (trimmed.length === 0 || trimmed.length > 256 || !DEFAULT_SCOPE_REDIRECT_PATH_RE.test(trimmed)) {
    throw new Error("operator reputation provider returned an invalid defaultScopeRedirectPath");
  }
  return trimmed;
}

function configuredProviderEvidence(providerId: string | undefined): readonly string[] {
  const id = providerId?.trim();
  return id === undefined || id.length === 0 ? [] : [`provider:${id.slice(0, 64)}`];
}

function fingerprintConfigured(options: ResolvedVerifierOptions): boolean {
  return options.fingerprint?.enabled !== false && options.fingerprint?.provider !== undefined;
}

function operatorReputationConfigured(options: ResolvedVerifierOptions): boolean {
  return options.operatorReputation?.enabled !== false && options.operatorReputation?.provider !== undefined;
}

function fingerprintIsSuspicious(evidence: FingerprintEvidence, options: ResolvedVerifierOptions): boolean {
  const botScoreThreshold = options.fingerprint?.suspiciousBotScoreThreshold ?? DEFAULT_FINGERPRINT_SUSPICIOUS_BOT_SCORE_THRESHOLD;
  const deltaThreshold = options.fingerprint?.suspiciousDeltaThreshold ?? DEFAULT_FINGERPRINT_SUSPICIOUS_DELTA_THRESHOLD;
  return (
    (isPositiveNumber(evidence.botScore) && evidence.botScore >= botScoreThreshold) ||
    (isPositiveNumber(evidence.suspicionDelta) && evidence.suspicionDelta >= deltaThreshold)
  );
}

function fingerprintTraceEntry(evidence: FingerprintEvidence, suspicious: boolean, fallbackProviderId?: string | undefined): CascadeTraceEntry {
  const provider = fallbackProviderId ?? evidence.provider;
  if (!evidence.enabled) {
    return cascadeTraceEntry(3, "fingerprint_sidecar", "not_configured", "fingerprint_provider_missing", Math.round(evidence.providerLatencyMs * 1000));
  }
  if (!evidence.available) {
    const reason =
      evidence.error === "timeout"
        ? "fingerprint_timeout_bypassed"
        : evidence.error === "invalid_provider_result"
          ? "fingerprint_invalid_result_bypassed"
          : "fingerprint_provider_error_bypassed";
    return cascadeTraceEntry(
      3,
      "fingerprint_sidecar",
      "skipped",
      reason,
      Math.round(evidence.providerLatencyMs * 1000),
      boundedEvidence([...configuredProviderEvidence(provider), ...evidence.evidence])
    );
  }
  return cascadeTraceEntry(
    3,
    "fingerprint_sidecar",
    suspicious ? "fail" : "pass",
    suspicious ? "fingerprint_risk" : "fingerprint_evidence",
    Math.round(evidence.providerLatencyMs * 1000),
    boundedEvidence([
      ...configuredProviderEvidence(provider),
      ...(evidence.deviceId === undefined ? [] : [`device_id:${evidence.deviceId}`]),
      ...(evidence.botScore === undefined ? [] : [`bot_score:${evidence.botScore.toFixed(3)}`]),
      `suspicion_delta:${evidence.suspicionDelta.toFixed(3)}`,
      ...evidence.evidence
    ])
  );
}

function withFingerprintIdentityHints(cryptoDecision: CryptoDecisionOutcome, evidence: FingerprintEvidence): CryptoDecisionOutcome {
  if (cryptoDecision.llmBrand !== undefined || evidence.llmBrandHint === undefined) {
    return cryptoDecision;
  }
  return { ...cryptoDecision, llmBrand: evidence.llmBrandHint };
}

function operatorReputationTraceEntry(
  result: OperatorReputationResult | undefined,
  latencyUs: number,
  unavailableReason?: "operator_reputation_not_found" | "operator_reputation_timeout_bypassed" | "operator_reputation_provider_error_bypassed",
  providerId?: string | undefined
): CascadeTraceEntry {
  if (result === undefined) {
    return cascadeTraceEntry(
      4,
      "operator_reputation",
      "skipped",
      unavailableReason ?? "operator_reputation_not_found",
      latencyUs,
      boundedEvidence(configuredProviderEvidence(providerId))
    );
  }
  const suspended = result.status === "suspended";
  const restricted = result.trustTier === "restricted" || result.status === "watchlist";
  return cascadeTraceEntry(
    4,
    "operator_reputation",
    suspended ? "fail" : "pass",
    suspended ? "operator_reputation_suspended" : restricted ? "operator_reputation_restricted" : "operator_reputation_active",
    latencyUs,
    boundedEvidence([
      ...configuredProviderEvidence(providerId),
      `operator_actor_id:${result.operatorActorId}`,
      `status:${result.status}`,
      `trust_tier:${result.trustTier}`,
      `default_action:${result.defaultAction ?? "allow"}`,
      `default_scope_route_count:${result.defaultScopeRoutes?.length ?? 0}`,
      ...(result.reputationScore === undefined ? [] : [`reputation_score:${result.reputationScore}`]),
      ...(result.evidence ?? [])
    ])
  );
}

function normalizeOperatorReputationResult(result: OperatorReputationResult | undefined): OperatorReputationResult | undefined {
  if (result === undefined) {
    return undefined;
  }
  const operatorActorId = result.operatorActorId.trim();
  if (operatorActorId.length === 0 || operatorActorId.length > 128) {
    throw new Error("operator reputation provider returned an invalid operatorActorId");
  }
  if (!["unknown", "trusted", "restricted"].includes(result.trustTier)) {
    throw new Error("operator reputation provider returned an invalid trustTier");
  }
  if (!["active", "watchlist", "suspended"].includes(result.status)) {
    throw new Error("operator reputation provider returned an invalid status");
  }
  if (
    result.reputationScore !== undefined &&
    (!Number.isInteger(result.reputationScore) || result.reputationScore < 0 || result.reputationScore > 100)
  ) {
    throw new Error("operator reputation provider returned an invalid reputationScore");
  }
  const defaultAction = normalizeDefaultAction(result.defaultAction);
  const defaultScopeRoutes = normalizeDefaultScopeRoutes(result.defaultScopeRoutes);
  const defaultScopeRedirectPath = normalizeDefaultScopeRedirectPath(result.defaultScopeRedirectPath);
  return {
    operatorActorId,
    trustTier: result.trustTier,
    status: result.status,
    ...(result.reputationScore === undefined ? {} : { reputationScore: result.reputationScore }),
    defaultAction,
    ...(defaultScopeRoutes.length === 0 ? {} : { defaultScopeRoutes }),
    ...(defaultScopeRedirectPath === undefined ? {} : { defaultScopeRedirectPath }),
    evidence: boundedEvidence(result.evidence ?? [])
  };
}

function delegationEvidence(
  delegation: CryptoDelegationEvidence,
  extra: readonly string[] = [],
  scopeMatched = true
): readonly string[] {
  const base = [
    `grant_id:${delegation.grantId}`,
    `chain_id:${delegation.chainId}`,
    `site_id:${delegation.siteId}`,
    `scope_match:${scopeMatched ? "true" : "false"}`,
    `permission_count:${delegation.permissions.length}`,
    ...extra
  ];
  const permissionBudget = Math.max(0, 16 - base.length);
  return [
    ...base,
    ...delegation.permissions.slice(0, permissionBudget).map((permission) => `permission:${permission}`)
  ].slice(0, 16);
}

function replaceCascadeTraceEntry(trace: CascadeTrace, entry: CascadeTraceEntry): CascadeTrace {
  return trace.map((candidate) => (candidate.ordinal === entry.ordinal ? entry : candidate)) as CascadeTrace;
}

function cascadeTraceForCryptoPath(
  initial: InitialRequestEvaluation,
  cryptoPathRollout: CryptoPathRolloutMode,
  cryptoResult: CryptoPathResult | undefined,
  cryptoLatencyUs: number
): CascadeTrace {
  const actorClass = initial.classification.actorClass;
  let cryptoIdentity: CascadeTraceEntry;
  let delegationAuthorization: CascadeTraceEntry;

  if (actorClass !== "signed_agent") {
    cryptoIdentity = cascadeTraceEntry(1, "crypto_identity", "skipped", "actor_class_not_signed_agent", 0, [`actor_class:${actorClass}`]);
    delegationAuthorization = cascadeTraceEntry(2, "delegation_authorization", "skipped", "depends_on_crypto_identity", 0);
  } else if (initial.resolved.crypto === undefined) {
    cryptoIdentity = cascadeTraceEntry(1, "crypto_identity", "not_configured", "crypto_options_missing", 0);
    delegationAuthorization = cascadeTraceEntry(2, "delegation_authorization", "not_configured", "crypto_options_missing", 0);
  } else if (cryptoPathRollout === "disabled") {
    cryptoIdentity = cascadeTraceEntry(1, "crypto_identity", "skipped", "crypto_rollout_disabled", 0);
    delegationAuthorization = cascadeTraceEntry(2, "delegation_authorization", "skipped", "crypto_rollout_disabled", 0);
  } else if (cryptoResult?.verified === true) {
    const delegation = cryptoResult.delegation;
    cryptoIdentity = cascadeTraceEntry(1, "crypto_identity", "pass", "http_signature_dpop_verified", cryptoLatencyUs, [
      `rollout:${cryptoPathRollout}`
    ]);
    delegationAuthorization =
      delegation === undefined
        ? cascadeTraceEntry(2, "delegation_authorization", "pass", "proof_bound_session_verified", cryptoLatencyUs, [
            `rollout:${cryptoPathRollout}`,
            "scope_match:true"
          ])
        : cascadeTraceEntry(
            2,
            "delegation_authorization",
            "pass",
            "proof_bound_session_verified",
            cryptoLatencyUs,
            delegationEvidence(delegation, [`rollout:${cryptoPathRollout}`])
          );
  } else {
    const reason = cryptoResult?.reason ?? "bad_signature";
    cryptoIdentity = cascadeTraceEntry(1, "crypto_identity", "fail", reason, cryptoLatencyUs, [`rollout:${cryptoPathRollout}`]);
    delegationAuthorization = cascadeTraceEntry(2, "delegation_authorization", "fail", reason, cryptoLatencyUs, [
      `rollout:${cryptoPathRollout}`
    ]);
  }

  return [
    cryptoIdentity,
    delegationAuthorization,
    cascadeTraceEntry(3, "fingerprint_sidecar", "not_configured", "fingerprint_provider_missing", 0),
    cascadeTraceEntry(4, "operator_reputation", "not_configured", "operator_reputation_provider_missing", 0)
  ];
}

function checkDelegationScope(prepared: PreparedRequestEvaluation, match: MatchedPolicy): DelegationScopeCheckResult {
  const requiredPermissions = match.routePolicy.requiredPermissions ?? [];
  if (prepared.classification.actorClass !== "verified_agent" || requiredPermissions.length === 0) {
    return { ok: true, cascadeTrace: prepared.cascadeTrace };
  }

  const delegation = prepared.delegation;
  if (delegation === undefined) {
    return {
      ok: false,
      reason: "permission_scope_mismatch",
      cascadeTrace: replaceCascadeTraceEntry(
        prepared.cascadeTrace,
        cascadeTraceEntry(2, "delegation_authorization", "fail", "permission_scope_mismatch", 0, [
          "scope_match:false",
          ...requiredPermissions.slice(0, 8).map((permission) => `required_permission:${permission}`)
        ])
      )
    };
  }

  const grantedPermissions = new Set(delegation.permissions);
  const missingPermissions = requiredPermissions.filter((permission) => !grantedPermissions.has(permission));
  const ok = missingPermissions.length === 0;
  return {
    ok,
    ...(ok ? {} : { reason: "permission_scope_mismatch" as const }),
    cascadeTrace: replaceCascadeTraceEntry(
      prepared.cascadeTrace,
      cascadeTraceEntry(
        2,
        "delegation_authorization",
        ok ? "pass" : "fail",
        ok ? "scope_match" : "permission_scope_mismatch",
        prepared.cascadeTrace[1]?.latency_us ?? 0,
        delegationEvidence(delegation, [
          ...requiredPermissions.slice(0, 6).map((permission) => `required_permission:${permission}`),
          ...missingPermissions.slice(0, 4).map((permission) => `missing_permission:${permission}`)
        ], ok)
      )
    )
  };
}

function routePatternMatches(pattern: string, path: string): boolean {
  if (pattern.endsWith("/*")) {
    const prefix = pattern.slice(0, -2);
    return path === prefix || path.startsWith(`${prefix}/`);
  }
  return path === pattern;
}

function checkOperatorDefaultScope(prepared: PreparedRequestEvaluation, match?: MatchedPolicy | undefined): OperatorScopeCheckResult {
  const routes = prepared.operatorReputationDefaultScopeRoutes;
  if (routes.length === 0) {
    return { ok: true, cascadeTrace: prepared.cascadeTrace };
  }
  const routeTemplate = match?.routeTemplate ?? prepared.normalized.routeTemplate;
  const ok = routes.some((route) => routePatternMatches(route, prepared.normalized.path) || routePatternMatches(route, routeTemplate));
  if (ok) {
    return { ok: true, cascadeTrace: prepared.cascadeTrace };
  }
  return {
    ok: false,
    reason: "operator_scope_mismatch",
    cascadeTrace: replaceCascadeTraceEntry(
      prepared.cascadeTrace,
      cascadeTraceEntry(4, "operator_reputation", "fail", "operator_scope_mismatch", 0, [
        "scope_match:false",
        `scope_route_count:${routes.length}`,
        `route_template:${routeTemplate}`,
        ...routes.slice(0, 8).map((route) => `scope_route:${route}`)
      ])
    )
  };
}

function defaultActionReasons(action: DecisionAction): readonly ReasonCode[] {
  if (action === "price_required") {
    return ["price_required"];
  }
  if (action === "sandbox") {
    return ["sandbox_policy"];
  }
  return ["matched_policy"];
}

function operatorDefaultHeaders(action: DecisionAction, retryToken?: string | undefined): Record<string, string> {
  const headers: Record<string, string> = {
    "X-AIdenID-Operator-Default-Action": action
  };
  if (action === "queue") {
    headers["Retry-After"] = "30";
    headers["X-AIdenID-Retry-Token"] = retryToken ?? createQueueRetryToken();
  }
  if (action === "throttle") {
    headers["Retry-After"] = "30";
  }
  if (action === "sandbox") {
    headers["X-AIdenID-Sandbox"] = "true";
  }
  return headers;
}

function operatorDefaultRecommendation(
  result: OperatorReputationResult | undefined,
  current: { readonly decision: DecisionAction; readonly reasons: readonly ReasonCode[] }
): { readonly decision: DecisionAction; readonly reasons: readonly ReasonCode[] } {
  if (result === undefined || result.status === "suspended" || current.decision !== "allow") {
    return current;
  }
  const action = result.defaultAction ?? "allow";
  return action === "allow" ? current : { decision: action, reasons: defaultActionReasons(action) };
}

function checkPurpose(match: MatchedPolicy, headers: RequestInput["headers"]): PurposeCheckResult {
  const allowedPurposes = match.routePolicy.allowedPurposes;
  if (allowedPurposes === undefined || allowedPurposes.length === 0) {
    return { ok: true };
  }

  const raw = readHeader(headers, "x-aidenid-purpose")?.trim();
  if (raw === undefined || raw.length === 0) {
    return { ok: false, reason: "purpose_required" };
  }

  const purpose = raw.toLowerCase();
  if (!PURPOSE_SLUG_RE.test(purpose)) {
    return { ok: false, reason: "purpose_required" };
  }
  if (!allowedPurposes.includes(purpose)) {
    return { ok: false, reason: "purpose_disallowed" };
  }
  return { ok: true, purpose };
}

function withRollbackRevocationFloor(
  crypto: VerifierCryptoOptions,
  rollback: VerifierRollbackControls | undefined
): VerifierCryptoOptions {
  if (rollback?.globalRevocationEpoch === undefined) {
    return crypto;
  }
  return {
    ...crypto,
    minRevocationEpoch: Math.max(crypto.minRevocationEpoch ?? 0, rollback.globalRevocationEpoch)
  };
}

function isSubjectPinned(initial: InitialRequestEvaluation, subjectHandle: string | undefined): boolean {
  const cache = initial.resolved.quarantinePinCache;
  if (cache === undefined || subjectHandle === undefined) {
    return false;
  }
  if (isAsyncQuarantinePinCache(cache)) {
    throw new Error("evaluateRequest cannot use async quarantinePinCache; use evaluateRequestAsync or evaluateAndEmit");
  }
  return cache.isPinned({ siteId: initial.resolved.siteId, subjectHandle }, initial.now.getTime());
}

async function isSubjectPinnedAsync(initial: InitialRequestEvaluation, subjectHandle: string | undefined): Promise<boolean> {
  const cache = initial.resolved.quarantinePinCache;
  if (cache === undefined || subjectHandle === undefined) {
    return false;
  }
  return cache.isPinned({ siteId: initial.resolved.siteId, subjectHandle }, initial.now.getTime());
}

function withFingerprintEvidence(_input: RequestInput, initial: InitialRequestEvaluation, cryptoDecision: CryptoDecisionOutcome): CryptoDecisionOutcome {
  if (!fingerprintConfigured(initial.resolved)) {
    return cryptoDecision;
  }
  throw new Error("evaluateRequest cannot use fingerprint provider; use evaluateRequestAsync or evaluateAndEmit");
}

async function withFingerprintEvidenceAsync(
  input: RequestInput,
  initial: InitialRequestEvaluation,
  cryptoDecision: CryptoDecisionOutcome
): Promise<CryptoDecisionOutcome> {
  if (!fingerprintConfigured(initial.resolved)) {
    return cryptoDecision;
  }

  const evidence = await getFingerprintEvidence(
    {
      method: input.method,
      url: input.url,
      headers: input.headers,
      remoteAddress: input.remoteAddress,
      routeTemplate: initial.normalized.routeTemplate
    },
    {
      provider: initial.resolved.fingerprint?.provider,
      enabled: initial.resolved.fingerprint?.enabled,
      timeoutMs: initial.resolved.fingerprint?.timeoutMs
    }
  );
  const suspicious = fingerprintIsSuspicious(evidence, initial.resolved);
  const hintedDecision = withFingerprintIdentityHints(cryptoDecision, evidence);
  const cascadeTrace = replaceCascadeTraceEntry(
    hintedDecision.cascadeTrace,
    fingerprintTraceEntry(evidence, suspicious, initial.resolved.fingerprint?.providerId)
  );
  if (!suspicious || hintedDecision.classification.actorClass === "verified_agent") {
    return { ...hintedDecision, cascadeTrace };
  }
  return {
    ...hintedDecision,
    classification: {
      actorClass: "suspicious_automation",
      evidence: boundedEvidence([...hintedDecision.classification.evidence, "fingerprint-risk"])
    },
    recommendation: { decision: "throttle", reasons: ["fingerprint_risk"] },
    cascadeTrace
  };
}

function reputationLookupInput(
  input: RequestInput,
  initial: InitialRequestEvaluation,
  cryptoDecision: CryptoDecisionOutcome
) {
  return {
    siteId: initial.resolved.siteId,
    actorClass: cryptoDecision.classification.actorClass,
    issuer: cryptoDecision.issuer,
    subjectHandle: cryptoDecision.subjectHandle,
    llmBrand: cryptoDecision.llmBrand,
    method: input.method.toUpperCase(),
    url: input.url,
    routeTemplate: initial.normalized.routeTemplate,
    occurredAt: initial.now
  };
}

function withOperatorReputation(input: RequestInput, initial: InitialRequestEvaluation, cryptoDecision: CryptoDecisionOutcome): CryptoDecisionOutcome {
  if (!operatorReputationConfigured(initial.resolved)) {
    return cryptoDecision;
  }
  const provider = initial.resolved.operatorReputation?.provider;
  if (provider === undefined) {
    return cryptoDecision;
  }

  const controller = new AbortController();
  const reputationStarted = performance.now();
  const providerId = initial.resolved.operatorReputation?.providerId;
  try {
    const rawResult = provider.lookup(reputationLookupInput(input, initial, cryptoDecision), controller.signal);
    if (isPromiseLike(rawResult)) {
      controller.abort();
      throw new Error("evaluateRequest cannot use async operatorReputation provider; use evaluateRequestAsync or evaluateAndEmit");
    }
    const result = normalizeOperatorReputationResult(rawResult);
    const entry = operatorReputationTraceEntry(result, elapsedUs(reputationStarted), undefined, providerId);
    const suspended = result?.status === "suspended";
    return {
      ...cryptoDecision,
      operatorReputationSuspended: suspended,
      operatorReputationDefaultAction: suspended ? undefined : result?.defaultAction,
      operatorReputationDefaultScopeRoutes: suspended ? [] : (result?.defaultScopeRoutes ?? []),
      operatorReputationDefaultScopeRedirectPath: suspended ? undefined : result?.defaultScopeRedirectPath,
      recommendation: suspended
        ? { decision: "deny", reasons: ["operator_reputation_suspended"] }
        : operatorDefaultRecommendation(result, cryptoDecision.recommendation),
      cascadeTrace: replaceCascadeTraceEntry(cryptoDecision.cascadeTrace, entry)
    };
  } catch (error) {
    controller.abort();
    if (error instanceof Error && /async operatorReputation/.test(error.message)) {
      throw error;
    }
    const entry = operatorReputationTraceEntry(undefined, elapsedUs(reputationStarted), "operator_reputation_provider_error_bypassed", providerId);
    return { ...cryptoDecision, cascadeTrace: replaceCascadeTraceEntry(cryptoDecision.cascadeTrace, entry) };
  }
}

async function withOperatorReputationAsync(
  input: RequestInput,
  initial: InitialRequestEvaluation,
  cryptoDecision: CryptoDecisionOutcome
): Promise<CryptoDecisionOutcome> {
  if (!operatorReputationConfigured(initial.resolved)) {
    return cryptoDecision;
  }
  const provider = initial.resolved.operatorReputation?.provider;
  if (provider === undefined) {
    return cryptoDecision;
  }

  const configuredTimeoutMs = initial.resolved.operatorReputation?.timeoutMs ?? DEFAULT_OPERATOR_REPUTATION_TIMEOUT_MS;
  const timeoutMs = Number.isInteger(configuredTimeoutMs) && configuredTimeoutMs > 0 ? configuredTimeoutMs : DEFAULT_OPERATOR_REPUTATION_TIMEOUT_MS;
  const controller = new AbortController();
  let timeout: ReturnType<typeof setTimeout> | undefined;
  let timedOut = false;
  const reputationStarted = performance.now();
  const providerId = initial.resolved.operatorReputation?.providerId;
  const timeoutPromise = new Promise<undefined>((resolve) => {
    timeout = setTimeout(() => {
      timedOut = true;
      controller.abort();
      resolve(undefined);
    }, timeoutMs);
  });

  try {
    const lookupPromise = Promise.resolve(provider.lookup(reputationLookupInput(input, initial, cryptoDecision), controller.signal)).then((result) =>
      normalizeOperatorReputationResult(result)
    );
    lookupPromise.catch(() => undefined);
    const result = await Promise.race([lookupPromise, timeoutPromise]);
    const entry = operatorReputationTraceEntry(
      result,
      elapsedUs(reputationStarted),
      timedOut ? "operator_reputation_timeout_bypassed" : "operator_reputation_not_found",
      providerId
    );
    const suspended = result?.status === "suspended";
    return {
      ...cryptoDecision,
      operatorReputationSuspended: suspended,
      operatorReputationDefaultAction: suspended ? undefined : result?.defaultAction,
      operatorReputationDefaultScopeRoutes: suspended ? [] : (result?.defaultScopeRoutes ?? []),
      operatorReputationDefaultScopeRedirectPath: suspended ? undefined : result?.defaultScopeRedirectPath,
      recommendation: suspended
        ? { decision: "deny", reasons: ["operator_reputation_suspended"] }
        : operatorDefaultRecommendation(result, cryptoDecision.recommendation),
      cascadeTrace: replaceCascadeTraceEntry(cryptoDecision.cascadeTrace, entry)
    };
  } catch {
    const entry = operatorReputationTraceEntry(undefined, elapsedUs(reputationStarted), "operator_reputation_provider_error_bypassed", providerId);
    return { ...cryptoDecision, cascadeTrace: replaceCascadeTraceEntry(cryptoDecision.cascadeTrace, entry) };
  } finally {
    if (timeout !== undefined) {
      clearTimeout(timeout);
    }
  }
}

function modeWithRollback(
  routeTemplate: string,
  mode: VerifierMode,
  rollback: VerifierRollbackControls | undefined
): VerifierMode {
  const routeMode = rollback?.routeModeOverrides?.[routeTemplate] ?? mode;
  if (rollback?.globalEnforcementPause === true && routeMode === "enforce") {
    return "observe";
  }
  return routeMode;
}

export function evaluateRequest(input: RequestInput, options: AidenIdVerifierOptions): DecisionResult {
  const prepared = prepareRequestEvaluation(input, options);
  if (prepared.quarantinePinned) {
    return buildQuarantinePinnedDecision(input, prepared);
  }
  if (prepared.resolved.policy !== undefined) {
    const policy = prepared.resolved.policy;
    if (policy.tokenBucketStore === undefined && policy.asyncTokenBucketStore !== undefined) {
      throw new Error("evaluateRequest cannot use asyncTokenBucketStore; use evaluateRequestAsync or evaluateAndEmit");
    }
    const match = policy.trie.match(input.method, prepared.normalized.path, prepared.classification.actorClass);
    const scope = checkDelegationScope(prepared, match);
    const scopedPrepared = { ...prepared, cascadeTrace: scope.cascadeTrace };
    if (!scope.ok) {
      return buildDelegationScopeDeniedDecision(input, options, scopedPrepared, match);
    }
    if (scopedPrepared.operatorReputationSuspended) {
      return buildOperatorReputationSuspendedDecision(input, options, scopedPrepared, match);
    }
    const operatorScope = checkOperatorDefaultScope(scopedPrepared, match);
    const operatorScopedPrepared = { ...scopedPrepared, cascadeTrace: operatorScope.cascadeTrace };
    if (!operatorScope.ok) {
      return buildOperatorScopeDeniedDecision(input, options, operatorScopedPrepared, match);
    }
    const purpose = checkPurpose(match, input.headers);
    if (!purpose.ok) {
      return buildPurposeDeniedDecision(input, options, operatorScopedPrepared, match, purpose.reason ?? "purpose_required");
    }
    const rateOutcome = applyRatePolicy({
      siteId: operatorScopedPrepared.resolved.siteId,
      routeBucket: match.routePolicy.routeBucket,
      policy: match.actorPolicy.rate,
      strict: match.actorPolicy.strict,
      onDegraded: match.routePolicy.onDegraded,
      store: policy.tokenBucketStore ?? DEFAULT_TOKEN_BUCKET_STORE,
      remoteIp: input.remoteAddress,
      actorClass: operatorScopedPrepared.classification.actorClass,
      nowMs: operatorScopedPrepared.now.getTime()
    });
    return buildPolicyDecision(input, options, operatorScopedPrepared, match, rateOutcome, purpose.purpose);
  }

  if (prepared.operatorReputationSuspended) {
    return buildOperatorReputationSuspendedDecision(input, options, prepared);
  }
  const operatorScope = checkOperatorDefaultScope(prepared);
  const operatorScopedPrepared = { ...prepared, cascadeTrace: operatorScope.cascadeTrace };
  if (!operatorScope.ok) {
    return buildOperatorScopeDeniedDecision(input, options, operatorScopedPrepared);
  }
  return buildNonPolicyDecision(input, operatorScopedPrepared);
}

export async function evaluateRequestAsync(input: RequestInput, options: AidenIdVerifierOptions): Promise<DecisionResult> {
  const prepared = await prepareRequestEvaluationAsync(input, options);
  if (prepared.quarantinePinned) {
    return buildQuarantinePinnedDecision(input, prepared);
  }
  if (prepared.resolved.policy !== undefined) {
    const policy = prepared.resolved.policy;
    const match = policy.trie.match(input.method, prepared.normalized.path, prepared.classification.actorClass);
    const scope = checkDelegationScope(prepared, match);
    const scopedPrepared = { ...prepared, cascadeTrace: scope.cascadeTrace };
    if (!scope.ok) {
      return buildDelegationScopeDeniedDecision(input, options, scopedPrepared, match);
    }
    if (scopedPrepared.operatorReputationSuspended) {
      return buildOperatorReputationSuspendedDecision(input, options, scopedPrepared, match);
    }
    const operatorScope = checkOperatorDefaultScope(scopedPrepared, match);
    const operatorScopedPrepared = { ...scopedPrepared, cascadeTrace: operatorScope.cascadeTrace };
    if (!operatorScope.ok) {
      return buildOperatorScopeDeniedDecision(input, options, operatorScopedPrepared, match);
    }
    const purpose = checkPurpose(match, input.headers);
    if (!purpose.ok) {
      return buildPurposeDeniedDecision(input, options, operatorScopedPrepared, match, purpose.reason ?? "purpose_required");
    }
    const rateOutcome = await applyRatePolicyAsync({
      siteId: operatorScopedPrepared.resolved.siteId,
      routeBucket: match.routePolicy.routeBucket,
      policy: match.actorPolicy.rate,
      strict: match.actorPolicy.strict,
      onDegraded: match.routePolicy.onDegraded,
      store: policy.asyncTokenBucketStore ?? policy.tokenBucketStore ?? DEFAULT_TOKEN_BUCKET_STORE,
      remoteIp: input.remoteAddress,
      actorClass: operatorScopedPrepared.classification.actorClass,
      nowMs: operatorScopedPrepared.now.getTime()
    });
    return buildPolicyDecision(input, options, operatorScopedPrepared, match, rateOutcome, purpose.purpose);
  }

  if (prepared.operatorReputationSuspended) {
    return buildOperatorReputationSuspendedDecision(input, options, prepared);
  }
  const operatorScope = checkOperatorDefaultScope(prepared);
  const operatorScopedPrepared = { ...prepared, cascadeTrace: operatorScope.cascadeTrace };
  if (!operatorScope.ok) {
    return buildOperatorScopeDeniedDecision(input, options, operatorScopedPrepared);
  }
  return buildNonPolicyDecision(input, operatorScopedPrepared);
}

function startRequestEvaluation(input: RequestInput, options: AidenIdVerifierOptions): InitialRequestEvaluation {
  const started = performance.now();
  const resolved = resolveVerifierOptions(options);
  const normalized = normalizePath(input.url);
  const now = resolved.now();
  const classification = classifyRequest(input.headers);
  const rateLimit = ingestUpstreamRateLimit(input.headers, input.statusCode, now);
  const recommendation = recommendedDecision(classification.actorClass, rateLimit.status);
  return { started, resolved, normalized, now, classification, rateLimit, recommendation };
}

function applyCryptoDecision(input: RequestInput, initial: InitialRequestEvaluation): CryptoDecisionOutcome {
  if (isAsyncReplayCache(initial.resolved.crypto?.replayCache)) {
    throw new Error("evaluateRequest cannot use async replayCache; use evaluateRequestAsync or evaluateAndEmit");
  }
  let classification = initial.classification;
  let issuer: string | undefined;
  let subjectHandle: string | undefined;
  let llmBrand: string | undefined;
  let delegation: CryptoDelegationEvidence | undefined;
  let signatureFailureReason: PolicyReasonCode | undefined;
  let recommendation = initial.recommendation;
  const cryptoPathRollout = initial.resolved.rollback?.cryptoPathRollout ?? "enforce";
  let cryptoResult: CryptoPathResult | undefined;
  let cryptoLatencyUs = 0;
  if (classification.actorClass === "signed_agent" && initial.resolved.crypto !== undefined) {
    if (cryptoPathRollout !== "disabled") {
      const cryptoStarted = performance.now();
      cryptoResult = verifyCryptoPath(
        { method: input.method, url: input.url, headers: input.headers },
        initial.resolved.siteId,
        withRollbackRevocationFloor(initial.resolved.crypto, initial.resolved.rollback),
        initial.now
      );
      cryptoLatencyUs = elapsedUs(cryptoStarted);
    }
    if (cryptoResult?.verified === true && cryptoPathRollout === "enforce") {
      classification = { actorClass: "verified_agent", evidence: ["http-signature-dpop-session-verified"] };
      issuer = cryptoResult.issuer;
      subjectHandle = cryptoResult.subject;
      llmBrand = cryptoResult.llmBrand;
      delegation = cryptoResult.delegation;
      recommendation = { decision: "allow", reasons: ["matched_policy"] };
    } else if (cryptoResult !== undefined && !cryptoResult.verified && cryptoPathRollout === "enforce") {
      signatureFailureReason = cryptoResult.reason ?? "bad_signature";
      recommendation = {
        decision: "deny",
        reasons: [signatureFailureReason]
      };
    }
  }

  return {
    classification,
    issuer,
    subjectHandle,
    llmBrand,
    delegation,
    signatureFailureReason,
    quarantinePinned: isSubjectPinned(initial, subjectHandle),
    operatorReputationSuspended: false,
    operatorReputationDefaultAction: undefined,
    operatorReputationDefaultScopeRoutes: [],
    operatorReputationDefaultScopeRedirectPath: undefined,
    cascadeTrace: cascadeTraceForCryptoPath(initial, cryptoPathRollout, cryptoResult, cryptoLatencyUs),
    recommendation
  };
}

async function applyCryptoDecisionAsync(input: RequestInput, initial: InitialRequestEvaluation): Promise<CryptoDecisionOutcome> {
  let classification = initial.classification;
  let issuer: string | undefined;
  let subjectHandle: string | undefined;
  let llmBrand: string | undefined;
  let delegation: CryptoDelegationEvidence | undefined;
  let signatureFailureReason: PolicyReasonCode | undefined;
  let recommendation = initial.recommendation;
  const cryptoPathRollout = initial.resolved.rollback?.cryptoPathRollout ?? "enforce";
  let cryptoResult: CryptoPathResult | undefined;
  let cryptoLatencyUs = 0;
  if (classification.actorClass === "signed_agent" && initial.resolved.crypto !== undefined) {
    if (cryptoPathRollout !== "disabled") {
      const cryptoStarted = performance.now();
      cryptoResult = await verifyCryptoPathAsync(
        { method: input.method, url: input.url, headers: input.headers },
        initial.resolved.siteId,
        withRollbackRevocationFloor(initial.resolved.crypto, initial.resolved.rollback),
        initial.now
      );
      cryptoLatencyUs = elapsedUs(cryptoStarted);
    }
    if (cryptoResult?.verified === true && cryptoPathRollout === "enforce") {
      classification = { actorClass: "verified_agent", evidence: ["http-signature-dpop-session-verified"] };
      issuer = cryptoResult.issuer;
      subjectHandle = cryptoResult.subject;
      llmBrand = cryptoResult.llmBrand;
      delegation = cryptoResult.delegation;
      recommendation = { decision: "allow", reasons: ["matched_policy"] };
    } else if (cryptoResult !== undefined && !cryptoResult.verified && cryptoPathRollout === "enforce") {
      signatureFailureReason = cryptoResult.reason ?? "bad_signature";
      recommendation = {
        decision: "deny",
        reasons: [signatureFailureReason]
      };
    }
  }

  return {
    classification,
    issuer,
    subjectHandle,
    llmBrand,
    delegation,
    signatureFailureReason,
    quarantinePinned: await isSubjectPinnedAsync(initial, subjectHandle),
    operatorReputationSuspended: false,
    operatorReputationDefaultAction: undefined,
    operatorReputationDefaultScopeRoutes: [],
    operatorReputationDefaultScopeRedirectPath: undefined,
    cascadeTrace: cascadeTraceForCryptoPath(initial, cryptoPathRollout, cryptoResult, cryptoLatencyUs),
    recommendation
  };
}

function preparedFromInitial(initial: InitialRequestEvaluation, cryptoDecision: CryptoDecisionOutcome): PreparedRequestEvaluation {
  return {
    started: initial.started,
    resolved: initial.resolved,
    normalized: initial.normalized,
    now: initial.now,
    classification: cryptoDecision.classification,
    issuer: cryptoDecision.issuer,
    subjectHandle: cryptoDecision.subjectHandle,
    llmBrand: cryptoDecision.llmBrand,
    delegation: cryptoDecision.delegation,
    signatureFailureReason: cryptoDecision.signatureFailureReason,
    quarantinePinned: cryptoDecision.quarantinePinned,
    operatorReputationSuspended: cryptoDecision.operatorReputationSuspended,
    operatorReputationDefaultAction: cryptoDecision.operatorReputationDefaultAction,
    operatorReputationDefaultScopeRoutes: cryptoDecision.operatorReputationDefaultScopeRoutes,
    operatorReputationDefaultScopeRedirectPath: cryptoDecision.operatorReputationDefaultScopeRedirectPath,
    cascadeTrace: cryptoDecision.cascadeTrace,
    rateLimit: initial.rateLimit,
    recommendation: cryptoDecision.recommendation
  };
}

function prepareRequestEvaluation(input: RequestInput, options: AidenIdVerifierOptions): PreparedRequestEvaluation {
  const initial = startRequestEvaluation(input, options);
  const cryptoDecision = applyCryptoDecision(input, initial);
  return preparedFromInitial(initial, withOperatorReputation(input, initial, withFingerprintEvidence(input, initial, cryptoDecision)));
}

async function prepareRequestEvaluationAsync(input: RequestInput, options: AidenIdVerifierOptions): Promise<PreparedRequestEvaluation> {
  const initial = startRequestEvaluation(input, options);
  const cryptoDecision = await applyCryptoDecisionAsync(input, initial);
  const fingerprintDecision = await withFingerprintEvidenceAsync(input, initial, cryptoDecision);
  return preparedFromInitial(initial, await withOperatorReputationAsync(input, initial, fingerprintDecision));
}

function buildQuarantinePinnedDecision(input: RequestInput, prepared: PreparedRequestEvaluation): DecisionResult {
  return {
    requestId: resolveRequestId(input.headers),
    siteId: prepared.resolved.siteId,
    mode: "enforce",
    method: input.method.toUpperCase(),
    path: prepared.normalized.path,
    routeTemplate: prepared.normalized.routeTemplate,
    actorClass: prepared.classification.actorClass,
    issuer: prepared.issuer,
    subjectHandle: prepared.subjectHandle,
    llmBrand: prepared.llmBrand,
    decision: "deny",
    recommendedDecision: "deny",
    reasons: ["operator_pinned", "quarantine"],
    responseHeaders: {
      "X-AIdenID-Operator-Action": "quarantine",
      "X-AIdenID-Operator-Effective-Decision": "deny"
    },
    observeOnly: false,
    rateLimit: prepared.rateLimit,
    cascadeTrace: prepared.cascadeTrace,
    latencyUs: elapsedUs(prepared.started)
  };
}

function buildPurposeDeniedDecision(
  input: RequestInput,
  options: AidenIdVerifierOptions,
  prepared: PreparedRequestEvaluation,
  match: MatchedPolicy,
  reason: Extract<ReasonCode, "purpose_required" | "purpose_disallowed">
): DecisionResult {
  const mode = modeWithRollback(match.routePolicy.routeTemplate, options.mode ?? match.routePolicy.mode, prepared.resolved.rollback);
  return {
    requestId: resolveRequestId(input.headers),
    siteId: prepared.resolved.siteId,
    mode,
    method: input.method.toUpperCase(),
    path: prepared.normalized.path,
    routeTemplate: match.routeTemplate,
    actorClass: prepared.classification.actorClass,
    issuer: prepared.issuer,
    subjectHandle: prepared.subjectHandle,
    llmBrand: prepared.llmBrand,
    decision: "deny",
    recommendedDecision: "deny",
    reasons: [reason],
    observeOnly: false,
    rateLimit: prepared.rateLimit,
    cascadeTrace: prepared.cascadeTrace,
    latencyUs: elapsedUs(prepared.started)
  };
}

function buildDelegationScopeDeniedDecision(
  input: RequestInput,
  options: AidenIdVerifierOptions,
  prepared: PreparedRequestEvaluation,
  match: MatchedPolicy
): DecisionResult {
  const mode = modeWithRollback(match.routePolicy.routeTemplate, options.mode ?? match.routePolicy.mode, prepared.resolved.rollback);
  return {
    requestId: resolveRequestId(input.headers),
    siteId: prepared.resolved.siteId,
    mode,
    method: input.method.toUpperCase(),
    path: prepared.normalized.path,
    routeTemplate: match.routeTemplate,
    actorClass: prepared.classification.actorClass,
    issuer: prepared.issuer,
    subjectHandle: prepared.subjectHandle,
    llmBrand: prepared.llmBrand,
    decision: "deny",
    recommendedDecision: "deny",
    reasons: ["permission_scope_mismatch"],
    observeOnly: false,
    rateLimit: prepared.rateLimit,
    cascadeTrace: prepared.cascadeTrace,
    latencyUs: elapsedUs(prepared.started)
  };
}

function buildOperatorReputationSuspendedDecision(
  input: RequestInput,
  options: AidenIdVerifierOptions,
  prepared: PreparedRequestEvaluation,
  match?: MatchedPolicy
): DecisionResult {
  const routeTemplate = match?.routeTemplate ?? prepared.normalized.routeTemplate;
  const mode = modeWithRollback(routeTemplate, options.mode ?? match?.routePolicy.mode ?? prepared.resolved.mode, prepared.resolved.rollback);
  return {
    requestId: resolveRequestId(input.headers),
    siteId: prepared.resolved.siteId,
    mode,
    method: input.method.toUpperCase(),
    path: prepared.normalized.path,
    routeTemplate,
    actorClass: prepared.classification.actorClass,
    issuer: prepared.issuer,
    subjectHandle: prepared.subjectHandle,
    llmBrand: prepared.llmBrand,
    decision: "deny",
    recommendedDecision: "deny",
    reasons: ["operator_reputation_suspended"],
    responseHeaders: {
      "X-AIdenID-Operator-Reputation-Status": "suspended"
    },
    observeOnly: false,
    rateLimit: prepared.rateLimit,
    cascadeTrace: prepared.cascadeTrace,
    latencyUs: elapsedUs(prepared.started)
  };
}

function buildOperatorScopeDeniedDecision(
  input: RequestInput,
  options: AidenIdVerifierOptions,
  prepared: PreparedRequestEvaluation,
  match?: MatchedPolicy
): DecisionResult {
  const routeTemplate = match?.routeTemplate ?? prepared.normalized.routeTemplate;
  const mode = modeWithRollback(routeTemplate, options.mode ?? match?.routePolicy.mode ?? prepared.resolved.mode, prepared.resolved.rollback);
  return {
    requestId: resolveRequestId(input.headers),
    siteId: prepared.resolved.siteId,
    mode,
    method: input.method.toUpperCase(),
    path: prepared.normalized.path,
    routeTemplate,
    actorClass: prepared.classification.actorClass,
    issuer: prepared.issuer,
    subjectHandle: prepared.subjectHandle,
    llmBrand: prepared.llmBrand,
    decision: "deny",
    recommendedDecision: "deny",
    reasons: ["operator_scope_mismatch"],
    responseHeaders: {
      "X-AIdenID-Operator-Scope": "mismatch",
      ...(prepared.operatorReputationDefaultScopeRedirectPath === undefined
        ? {}
        : { "X-AIdenID-Scope-Redirect": prepared.operatorReputationDefaultScopeRedirectPath })
    },
    observeOnly: false,
    rateLimit: prepared.rateLimit,
    cascadeTrace: prepared.cascadeTrace,
    latencyUs: elapsedUs(prepared.started)
  };
}

function applyOperatorDefaultToPolicyEvaluation(
  prepared: PreparedRequestEvaluation,
  mode: VerifierMode,
  evaluation: {
    readonly action: DecisionAction;
    readonly recommendedAction: DecisionAction;
    readonly headers: Readonly<Record<string, string>>;
    readonly reasonCodes: readonly ReasonCode[];
  }
): {
  readonly action: DecisionAction;
  readonly recommendedAction: DecisionAction;
  readonly headers: Readonly<Record<string, string>>;
  readonly reasonCodes: readonly ReasonCode[];
} {
  const defaultAction = prepared.operatorReputationDefaultAction;
  if (
    defaultAction === undefined ||
    defaultAction === "allow" ||
    evaluation.action !== "allow" ||
    evaluation.recommendedAction !== "allow"
  ) {
    return evaluation;
  }
  const reasonCodes = defaultActionReasons(defaultAction);
  const headers = {
    ...evaluation.headers,
    ...operatorDefaultHeaders(defaultAction)
  };
  if (mode === "observe") {
    return {
      action: "allow",
      recommendedAction: defaultAction,
      reasonCodes,
      headers: {
        ...headers,
        "X-AIdenID-Observed-Decision": defaultAction
      }
    };
  }
  if (mode === "recommend") {
    return {
      action: "allow",
      recommendedAction: defaultAction,
      reasonCodes,
      headers: {
        ...headers,
        "X-AIdenID-Recommended-Decision": defaultAction
      }
    };
  }
  return {
    action: defaultAction,
    recommendedAction: defaultAction,
    reasonCodes,
    headers
  };
}

function buildPolicyDecision(
  input: RequestInput,
  options: AidenIdVerifierOptions,
  prepared: PreparedRequestEvaluation,
  match: MatchedPolicy,
  rateOutcome: RateOutcome,
  purpose?: string | undefined
): DecisionResult {
  if (prepared.resolved.policy === undefined) {
    throw new Error("policy decision requested without policy options");
  }
  const mode = modeWithRollback(match.routePolicy.routeTemplate, options.mode ?? match.routePolicy.mode, prepared.resolved.rollback);
  const evaluation = evaluateDecision({
    match,
    actorClass: prepared.classification.actorClass,
    mode,
    rateOutcome,
    degraded: prepared.resolved.policy.degraded,
    signatureFailureReason: prepared.signatureFailureReason,
    retryToken: createQueueRetryToken()
  });
  const operatorAdjusted = applyOperatorDefaultToPolicyEvaluation(prepared, mode, {
    action: evaluation.action,
    recommendedAction: evaluation.recommendedAction,
    headers: evaluation.headers,
    reasonCodes: evaluation.reasonCodes
  });

  return {
    requestId: resolveRequestId(input.headers),
    siteId: prepared.resolved.siteId,
    mode,
    method: input.method.toUpperCase(),
    path: prepared.normalized.path,
    routeTemplate: match.routeTemplate,
    actorClass: prepared.classification.actorClass,
    issuer: prepared.issuer,
    subjectHandle: prepared.subjectHandle,
    llmBrand: prepared.llmBrand,
    purpose,
    decision: operatorAdjusted.action,
    recommendedDecision: operatorAdjusted.recommendedAction,
    reasons: operatorAdjusted.reasonCodes,
    responseHeaders: {
      ...operatorAdjusted.headers,
      ...(purpose === undefined ? {} : { "X-AIdenID-Purpose": purpose })
    },
    observeOnly: mode === "observe",
    rateLimit: policyRateSignal(rateOutcome),
    cascadeTrace: prepared.cascadeTrace,
    latencyUs: elapsedUs(prepared.started)
  };
}

function buildNonPolicyDecision(input: RequestInput, prepared: PreparedRequestEvaluation): DecisionResult {
  const mode = modeWithRollback(prepared.normalized.routeTemplate, prepared.resolved.mode, prepared.resolved.rollback);
  const observeOnly = mode === "observe";
  const decision = observeOnly ? "allow" : prepared.recommendation.decision;
  const defaultHeaders =
    prepared.operatorReputationDefaultAction !== undefined &&
    prepared.operatorReputationDefaultAction !== "allow" &&
    prepared.recommendation.decision === prepared.operatorReputationDefaultAction
      ? operatorDefaultHeaders(prepared.operatorReputationDefaultAction)
      : {};

  return {
    requestId: resolveRequestId(input.headers),
    siteId: prepared.resolved.siteId,
    mode,
    method: input.method.toUpperCase(),
    path: prepared.normalized.path,
    routeTemplate: prepared.normalized.routeTemplate,
    actorClass: prepared.classification.actorClass,
    issuer: prepared.issuer,
    subjectHandle: prepared.subjectHandle,
    llmBrand: prepared.llmBrand,
    decision,
    recommendedDecision: prepared.recommendation.decision,
    reasons: prepared.recommendation.reasons,
    responseHeaders: {
      ...defaultHeaders,
      ...(observeOnly && prepared.recommendation.decision !== "allow" ? { "X-AIdenID-Observed-Decision": prepared.recommendation.decision } : {})
    },
    observeOnly,
    rateLimit: prepared.rateLimit,
    cascadeTrace: prepared.cascadeTrace,
    latencyUs: elapsedUs(prepared.started)
  };
}

export async function evaluateAndEmit(input: RequestInput, options: AidenIdVerifierOptions): Promise<DecisionResult> {
  const decision = await evaluateRequestAsync(input, options);
  await options.metrics?.recordDecision(decision);
  await options.onDecision?.(decision);
  return (await options.decisionOverride?.(decision)) ?? decision;
}
