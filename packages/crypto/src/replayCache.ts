import { createHash } from "node:crypto";

export interface ReplayCache {
  storeOnce(key: string, ttlMs: number, nowMs?: number): boolean;
}

export interface AsyncReplayCache {
  readonly asyncReplayCache: true;
  storeOnce(key: string, ttlMs: number, nowMs?: number): Promise<boolean>;
}

export type ReplayCacheLike = ReplayCache | AsyncReplayCache;

export interface MemoryReplayCacheOptions {
  readonly maxEntries?: number | undefined;
  readonly purgeIntervalMs?: number | undefined;
}

export interface RedisReplayCacheScriptOptions {
  readonly keys: readonly string[];
  readonly arguments: readonly string[];
}

export interface RedisReplayCacheScriptRunner {
  run(script: string, options: RedisReplayCacheScriptOptions): Promise<unknown>;
  load?(script: string): Promise<string>;
  runSha?(sha: string, options: RedisReplayCacheScriptOptions): Promise<unknown>;
}

export interface RedisReplayCacheOptions {
  readonly keyPrefix?: string | undefined;
}

const DEFAULT_MAX_ENTRIES = 50_000;
const DEFAULT_PURGE_INTERVAL_MS = 1_000;

export const REDIS_REPLAY_CACHE_LUA = `
local stored = redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2], 'NX')
if stored then
  return 1
end
return 0
`.trim();

export class MemoryReplayCache implements ReplayCache {
  readonly #entries = new Map<string, number>();
  readonly #maxEntries: number;
  readonly #purgeIntervalMs: number;
  #nextPurgeMs = 0;

  constructor(options: MemoryReplayCacheOptions = {}) {
    this.#maxEntries = Math.max(1, Math.trunc(options.maxEntries ?? DEFAULT_MAX_ENTRIES));
    this.#purgeIntervalMs = Math.max(1, Math.trunc(options.purgeIntervalMs ?? DEFAULT_PURGE_INTERVAL_MS));
  }

  storeOnce(key: string, ttlMs: number, nowMs = Date.now()): boolean {
    this.maybePurgeExpired(nowMs);
    const expiresAt = this.#entries.get(key);
    if (expiresAt !== undefined && expiresAt > nowMs) {
      return false;
    }
    if (!this.#entries.has(key) && this.#entries.size >= this.#maxEntries) {
      this.evictOldest(nowMs);
    }
    this.#entries.set(key, nowMs + Math.max(1, ttlMs));
    return true;
  }

  has(key: string, nowMs = Date.now()): boolean {
    const expiresAt = this.#entries.get(key);
    if (expiresAt === undefined) {
      return false;
    }
    if (expiresAt <= nowMs) {
      this.#entries.delete(key);
      return false;
    }
    return true;
  }

  snapshot(nowMs = Date.now()): Readonly<Record<string, number>> {
    this.purgeExpired(nowMs);
    return Object.fromEntries(this.#entries);
  }

  private maybePurgeExpired(nowMs: number): void {
    if (nowMs < this.#nextPurgeMs && this.#entries.size < this.#maxEntries) {
      return;
    }
    this.purgeExpired(nowMs);
    this.#nextPurgeMs = nowMs + this.#purgeIntervalMs;
  }

  private purgeExpired(nowMs: number): void {
    for (const [key, expiresAt] of this.#entries) {
      if (expiresAt <= nowMs) {
        this.#entries.delete(key);
      }
    }
  }

  private evictOldest(nowMs: number): void {
    this.purgeExpired(nowMs);
    if (this.#entries.size < this.#maxEntries) {
      return;
    }
    let oldestKey: string | undefined;
    let oldestExpiry = Number.POSITIVE_INFINITY;
    for (const [key, expiresAt] of this.#entries) {
      if (expiresAt < oldestExpiry) {
        oldestExpiry = expiresAt;
        oldestKey = key;
      }
    }
    if (oldestKey !== undefined) {
      this.#entries.delete(oldestKey);
    }
  }
}

function sha1(input: string): string {
  return createHash("sha1").update(input).digest("hex");
}

function isPromiseLike(value: unknown): value is Promise<unknown> {
  return value !== null && typeof value === "object" && typeof (value as { then?: unknown }).then === "function";
}

function isNoScriptError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return message.toUpperCase().includes("NOSCRIPT");
}

function parseRedisReplayResult(raw: unknown): boolean {
  if (raw === true || raw === "1" || raw === 1) {
    return true;
  }
  if (raw === false || raw === "0" || raw === 0 || raw === null) {
    return false;
  }
  throw new Error("Redis replay cache script returned an invalid response");
}

export class RedisReplayCache implements AsyncReplayCache {
  readonly asyncReplayCache = true;
  readonly #scriptRunner: RedisReplayCacheScriptRunner;
  readonly #keyPrefix: string;
  #loadedSha: string | undefined;
  #loadPromise: Promise<string> | undefined;

  constructor(scriptRunner: RedisReplayCacheScriptRunner, options: RedisReplayCacheOptions = {}) {
    this.#scriptRunner = scriptRunner;
    this.#keyPrefix = options.keyPrefix ?? "aidenid:replay:";
  }

  async storeOnce(key: string, ttlMs: number, nowMs = Date.now()): Promise<boolean> {
    const raw = await this.runScript({
      keys: [`${this.#keyPrefix}${key}`],
      arguments: [String(nowMs), String(Math.max(1, Math.trunc(ttlMs)))]
    });
    return parseRedisReplayResult(raw);
  }

  private async loadScript(): Promise<string> {
    if (this.#loadedSha !== undefined) {
      return this.#loadedSha;
    }
    if (this.#loadPromise === undefined) {
      this.#loadPromise =
        this.#scriptRunner.load?.(REDIS_REPLAY_CACHE_LUA) ?? Promise.resolve(sha1(REDIS_REPLAY_CACHE_LUA));
    }
    this.#loadedSha = await this.#loadPromise;
    return this.#loadedSha;
  }

  private async runScript(options: RedisReplayCacheScriptOptions): Promise<unknown> {
    if (this.#scriptRunner.runSha === undefined) {
      return this.#scriptRunner.run(REDIS_REPLAY_CACHE_LUA, options);
    }

    const sha = await this.loadScript();
    try {
      return await this.#scriptRunner.runSha(sha, options);
    } catch (error) {
      if (!isNoScriptError(error)) {
        throw error;
      }
      if (this.#scriptRunner.load === undefined) {
        return this.#scriptRunner.run(REDIS_REPLAY_CACHE_LUA, options);
      }
      this.#loadedSha = undefined;
      this.#loadPromise = undefined;
      return this.#scriptRunner.runSha(await this.loadScript(), options);
    }
  }
}

export function isAsyncReplayCache(cache: ReplayCacheLike | undefined): cache is AsyncReplayCache {
  return cache !== undefined && (cache as { readonly asyncReplayCache?: unknown }).asyncReplayCache === true;
}

export function requireFreshReplayKey(cache: ReplayCache, key: string, ttlMs: number, nowMs: number, label: string): void {
  const fresh = cache.storeOnce(key, ttlMs, nowMs);
  if (isPromiseLike(fresh)) {
    throw new Error(`${label} replay cache requires async verification`);
  }
  if (!fresh) {
    throw new Error(`${label} replay detected`);
  }
}

export async function requireFreshReplayKeyAsync(
  cache: ReplayCacheLike,
  key: string,
  ttlMs: number,
  nowMs: number,
  label: string
): Promise<void> {
  if (!(await cache.storeOnce(key, ttlMs, nowMs))) {
    throw new Error(`${label} replay detected`);
  }
}
