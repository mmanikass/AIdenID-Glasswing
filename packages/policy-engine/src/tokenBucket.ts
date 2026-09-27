import { createHash } from "node:crypto";

import type { DegradedAction, RateOutcome, RatePolicy } from "./types.js";

export const TOKEN_BUCKET_LUA = `
local b = redis.call('HMGET', KEYS[1], 'tokens', 'last_ms')
local tokens = tonumber(b[1]) or tonumber(ARGV[2])
local last_ms = tonumber(b[2]) or tonumber(ARGV[1])
local elapsed = (tonumber(ARGV[1]) - last_ms) / 1000.0
tokens = math.min(tonumber(ARGV[2]), tokens + elapsed * tonumber(ARGV[3]))
local cost = tonumber(ARGV[4])
if tokens >= cost then
  tokens = tokens - cost
  redis.call('HMSET', KEYS[1], 'tokens', tokens, 'last_ms', ARGV[1])
  redis.call('PEXPIRE', KEYS[1], 3600000)
  return {1, tokens}
else
  redis.call('HMSET', KEYS[1], 'tokens', tokens, 'last_ms', ARGV[1])
  redis.call('PEXPIRE', KEYS[1], 3600000)
  return {0, tokens}
end
`.trim();

export interface TokenBucketTakeResult {
  readonly allow: boolean;
  readonly remaining: number;
}

export interface TokenBucketStore {
  take(key: string, policy: RatePolicy, nowMs: number): TokenBucketTakeResult;
}

export interface AsyncTokenBucketStore {
  take(key: string, policy: RatePolicy, nowMs: number): TokenBucketTakeResult | Promise<TokenBucketTakeResult>;
}

export interface RedisTokenBucketScriptRunner {
  run(script: string, options: { readonly keys: readonly string[]; readonly arguments: readonly string[] }): Promise<unknown>;
  load?(script: string): Promise<string>;
  runSha?(sha: string, options: { readonly keys: readonly string[]; readonly arguments: readonly string[] }): Promise<unknown>;
}

export interface RedisTokenBucketStoreOptions {
  readonly keyPrefix?: string | undefined;
}

interface BaseRatePolicyRequest {
  readonly siteId: string;
  readonly routeBucket: string;
  readonly policy: RatePolicy;
  readonly strict: boolean;
  readonly onDegraded: DegradedAction;
  readonly session?: { readonly chainId: string } | undefined;
  readonly remoteIp?: string | undefined;
  readonly actorClass?: string | undefined;
  readonly nowMs?: number | undefined;
}

export interface RatePolicyRequest extends BaseRatePolicyRequest {
  readonly store: TokenBucketStore;
}

export interface AsyncRatePolicyRequest extends BaseRatePolicyRequest {
  readonly store: AsyncTokenBucketStore;
}

interface BucketState {
  tokens: number;
  lastMs: number;
}

function retryAfterSeconds(remaining: number, policy: RatePolicy): number {
  if (policy.refillPerSec <= 0) {
    return 60;
  }
  const missing = Math.max(0, policy.cost - remaining);
  return Math.max(1, Math.ceil(missing / policy.refillPerSec));
}

function hashIp(remoteIp: string): string {
  return createHash("sha256").update(remoteIp).digest("hex").slice(0, 24);
}

export function tokenBucketKey(request: Omit<RatePolicyRequest, "policy" | "strict" | "onDegraded" | "store" | "nowMs">): string {
  if (request.session !== undefined) {
    return `bkt:${request.siteId}:chain:${request.session.chainId}:${request.routeBucket}`;
  }
  const fallback = request.remoteIp === undefined || request.remoteIp.trim() === "" ? "unknown" : hashIp(request.remoteIp);
  return `bkt:${request.siteId}:ip:${fallback}:${request.routeBucket}`;
}

export class MemoryTokenBucketStore implements TokenBucketStore {
  readonly #buckets = new Map<string, BucketState>();

  take(key: string, policy: RatePolicy, nowMs: number): TokenBucketTakeResult {
    const current = this.#buckets.get(key) ?? { tokens: policy.capacity, lastMs: nowMs };
    const elapsedSeconds = Math.max(0, nowMs - current.lastMs) / 1000;
    const filled = Math.min(policy.capacity, current.tokens + elapsedSeconds * policy.refillPerSec);

    if (filled >= policy.cost) {
      const remaining = filled - policy.cost;
      this.#buckets.set(key, { tokens: remaining, lastMs: nowMs });
      return { allow: true, remaining };
    }

    this.#buckets.set(key, { tokens: filled, lastMs: nowMs });
    return { allow: false, remaining: filled };
  }

  snapshot(key: string): BucketState | undefined {
    const state = this.#buckets.get(key);
    return state === undefined ? undefined : { ...state };
  }
}

function parseRedisTokenBucketResult(raw: unknown): TokenBucketTakeResult {
  if (!Array.isArray(raw) || raw.length < 2) {
    throw new Error("Redis token bucket script returned an invalid response");
  }
  const [allowRaw, remainingRaw] = raw as readonly unknown[];
  const allow = Number(allowRaw) === 1;
  const remaining = Number(remainingRaw);
  if (!Number.isFinite(remaining)) {
    throw new Error("Redis token bucket script returned an invalid remaining count");
  }
  return { allow, remaining };
}

export class RedisTokenBucketStore implements AsyncTokenBucketStore {
  readonly #scriptRunner: RedisTokenBucketScriptRunner;
  readonly #keyPrefix: string;
  #loadedSha: string | undefined;
  #loadPromise: Promise<string> | undefined;

  constructor(scriptRunner: RedisTokenBucketScriptRunner, options: RedisTokenBucketStoreOptions = {}) {
    this.#scriptRunner = scriptRunner;
    this.#keyPrefix = options.keyPrefix ?? "aidenid:";
  }

  async take(key: string, policy: RatePolicy, nowMs: number): Promise<TokenBucketTakeResult> {
    const raw = await this.runScript({
      keys: [`${this.#keyPrefix}${key}`],
      arguments: [String(nowMs), String(policy.capacity), String(policy.refillPerSec), String(policy.cost)]
    });
    return parseRedisTokenBucketResult(raw);
  }

  private async loadScript(): Promise<string> {
    if (this.#loadedSha !== undefined) {
      return this.#loadedSha;
    }
    if (this.#loadPromise === undefined) {
      this.#loadPromise =
        this.#scriptRunner.load?.(TOKEN_BUCKET_LUA) ?? Promise.resolve(createHash("sha1").update(TOKEN_BUCKET_LUA).digest("hex"));
    }
    this.#loadedSha = await this.#loadPromise;
    return this.#loadedSha;
  }

  private async runScript(options: { readonly keys: readonly string[]; readonly arguments: readonly string[] }): Promise<unknown> {
    if (this.#scriptRunner.runSha === undefined) {
      return this.#scriptRunner.run(TOKEN_BUCKET_LUA, options);
    }

    const sha = await this.loadScript();
    try {
      return await this.#scriptRunner.runSha(sha, options);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (!message.toUpperCase().includes("NOSCRIPT")) {
        throw error;
      }
      if (this.#scriptRunner.load === undefined) {
        return this.#scriptRunner.run(TOKEN_BUCKET_LUA, options);
      }
      this.#loadedSha = undefined;
      this.#loadPromise = undefined;
      return this.#scriptRunner.runSha(await this.loadScript(), options);
    }
  }
}

function rateOutcomeFromTakeResult(result: TokenBucketTakeResult, policy: RatePolicy): RateOutcome {
  if (result.allow) {
    return { allow: true, remaining: result.remaining };
  }
  return {
    allow: false,
    remaining: result.remaining,
    retryAfterSeconds: retryAfterSeconds(result.remaining, policy)
  };
}

function degradedRateOutcome(request: Pick<BaseRatePolicyRequest, "strict" | "onDegraded">): RateOutcome {
  if (request.strict) {
    return {
      allow: false,
      remaining: 0,
      retryAfterSeconds: request.onDegraded === "queue" ? 30 : 1,
      degraded: "redis_down"
    };
  }
  return {
    allow: true,
    remaining: 0,
    degraded: "redis_down"
  };
}

export function applyRatePolicy(request: RatePolicyRequest): RateOutcome {
  const key = tokenBucketKey(request);
  const nowMs = request.nowMs ?? Date.now();

  try {
    const result = request.store.take(key, request.policy, nowMs);
    return rateOutcomeFromTakeResult(result, request.policy);
  } catch {
    return degradedRateOutcome(request);
  }
}

export async function applyRatePolicyAsync(request: AsyncRatePolicyRequest): Promise<RateOutcome> {
  const key = tokenBucketKey(request);
  const nowMs = request.nowMs ?? Date.now();

  try {
    const result = await request.store.take(key, request.policy, nowMs);
    return rateOutcomeFromTakeResult(result, request.policy);
  } catch {
    return degradedRateOutcome(request);
  }
}
