import { createHash } from "node:crypto";

import type { RedisTokenBucketScriptRunner } from "@aidenid/policy-engine";

export interface QuarantinePinQuery {
  readonly siteId: string;
  readonly subjectHandle: string | undefined;
}

export interface QuarantinePinInput extends QuarantinePinQuery {
  readonly expiresAt: string;
  readonly decisionId?: string | undefined;
  readonly reason?: string | undefined;
}

export interface QuarantinePinCache {
  pin(input: QuarantinePinInput, nowMs?: number): boolean;
  isPinned(input: QuarantinePinQuery, nowMs?: number): boolean;
}

export interface AsyncQuarantinePinCache {
  readonly asyncQuarantinePinCache: true;
  pin(input: QuarantinePinInput, nowMs?: number): Promise<boolean>;
  isPinned(input: QuarantinePinQuery, nowMs?: number): Promise<boolean>;
}

export type QuarantinePinCacheLike = QuarantinePinCache | AsyncQuarantinePinCache;

export interface RedisQuarantinePinCacheOptions {
  readonly keyPrefix?: string | undefined;
}

interface MemoryPin {
  readonly expiresAtMs: number;
  readonly decisionId?: string | undefined;
  readonly reason?: string | undefined;
}

export const REDIS_QUARANTINE_PIN_LUA = `
local action = ARGV[1]
if action == 'pin' then
  local ttl_ms = tonumber(ARGV[2])
  if ttl_ms == nil or ttl_ms <= 0 then
    redis.call('DEL', KEYS[1])
    return 0
  end
  redis.call('SET', KEYS[1], ARGV[3], 'PX', ttl_ms)
  return 1
end
if action == 'has' then
  return redis.call('EXISTS', KEYS[1])
end
return redis.error_reply('unsupported quarantine pin action')
`.trim();

function sha1(input: string): string {
  return createHash("sha1").update(input).digest("hex");
}

function sha256Prefix(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex").slice(0, 32);
}

function parseExpiresAt(expiresAt: string): number {
  const parsed = Date.parse(expiresAt);
  return Number.isFinite(parsed) ? parsed : Number.NaN;
}

function parseRedisBool(raw: unknown): boolean {
  if (raw === true || raw === "1" || raw === 1) {
    return true;
  }
  if (raw === false || raw === "0" || raw === 0 || raw === null) {
    return false;
  }
  throw new Error("Redis quarantine pin script returned an invalid boolean response");
}

function isNoScriptError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return message.toUpperCase().includes("NOSCRIPT");
}

export function quarantinePinKey(input: QuarantinePinQuery): string | undefined {
  const subjectHandle = input.subjectHandle?.trim();
  if (subjectHandle === undefined || subjectHandle.length === 0) {
    return undefined;
  }
  return `qpin:${input.siteId}:subject:${sha256Prefix(subjectHandle)}`;
}

export class MemoryQuarantinePinCache implements QuarantinePinCache {
  readonly #pins = new Map<string, MemoryPin>();

  pin(input: QuarantinePinInput, nowMs = Date.now()): boolean {
    const key = quarantinePinKey(input);
    if (key === undefined) {
      return false;
    }
    const expiresAtMs = parseExpiresAt(input.expiresAt);
    if (!Number.isFinite(expiresAtMs) || expiresAtMs <= nowMs) {
      this.#pins.delete(key);
      return false;
    }
    this.#pins.set(key, {
      expiresAtMs,
      ...(input.decisionId === undefined ? {} : { decisionId: input.decisionId }),
      ...(input.reason === undefined ? {} : { reason: input.reason })
    });
    return true;
  }

  isPinned(input: QuarantinePinQuery, nowMs = Date.now()): boolean {
    const key = quarantinePinKey(input);
    if (key === undefined) {
      return false;
    }
    const pin = this.#pins.get(key);
    if (pin === undefined) {
      return false;
    }
    if (pin.expiresAtMs <= nowMs) {
      this.#pins.delete(key);
      return false;
    }
    return true;
  }

  snapshot(nowMs = Date.now()): Readonly<Record<string, MemoryPin>> {
    for (const [key, pin] of this.#pins) {
      if (pin.expiresAtMs <= nowMs) {
        this.#pins.delete(key);
      }
    }
    return Object.fromEntries(this.#pins);
  }
}

export class RedisQuarantinePinCache implements AsyncQuarantinePinCache {
  readonly asyncQuarantinePinCache = true;
  readonly #scriptRunner: RedisTokenBucketScriptRunner;
  readonly #keyPrefix: string;
  #loadedSha: string | undefined;
  #loadPromise: Promise<string> | undefined;

  constructor(scriptRunner: RedisTokenBucketScriptRunner, options: RedisQuarantinePinCacheOptions = {}) {
    this.#scriptRunner = scriptRunner;
    this.#keyPrefix = options.keyPrefix ?? "aidenid:quarantine:";
  }

  async pin(input: QuarantinePinInput, nowMs = Date.now()): Promise<boolean> {
    const key = quarantinePinKey(input);
    if (key === undefined) {
      return false;
    }
    const expiresAtMs = parseExpiresAt(input.expiresAt);
    if (!Number.isFinite(expiresAtMs)) {
      return false;
    }
    const ttlMs = Math.max(0, Math.trunc(expiresAtMs - nowMs));
    const raw = await this.runScript({
      keys: [`${this.#keyPrefix}${key}`],
      arguments: [
        "pin",
        String(ttlMs),
        JSON.stringify({
          ...(input.decisionId === undefined ? {} : { decision_id: input.decisionId }),
          ...(input.reason === undefined ? {} : { reason: input.reason }),
          expires_at: input.expiresAt
        })
      ]
    });
    return parseRedisBool(raw);
  }

  async isPinned(input: QuarantinePinQuery, _nowMs = Date.now()): Promise<boolean> {
    const key = quarantinePinKey(input);
    if (key === undefined) {
      return false;
    }
    const raw = await this.runScript({
      keys: [`${this.#keyPrefix}${key}`],
      arguments: ["has"]
    });
    return parseRedisBool(raw);
  }

  private async loadScript(): Promise<string> {
    if (this.#loadedSha !== undefined) {
      return this.#loadedSha;
    }
    if (this.#loadPromise === undefined) {
      this.#loadPromise =
        this.#scriptRunner.load?.(REDIS_QUARANTINE_PIN_LUA) ?? Promise.resolve(sha1(REDIS_QUARANTINE_PIN_LUA));
    }
    this.#loadedSha = await this.#loadPromise;
    return this.#loadedSha;
  }

  private async runScript(options: { readonly keys: readonly string[]; readonly arguments: readonly string[] }): Promise<unknown> {
    if (this.#scriptRunner.runSha === undefined) {
      return this.#scriptRunner.run(REDIS_QUARANTINE_PIN_LUA, options);
    }

    const sha = await this.loadScript();
    try {
      return await this.#scriptRunner.runSha(sha, options);
    } catch (error) {
      if (!isNoScriptError(error)) {
        throw error;
      }
      if (this.#scriptRunner.load === undefined) {
        return this.#scriptRunner.run(REDIS_QUARANTINE_PIN_LUA, options);
      }
      this.#loadedSha = undefined;
      this.#loadPromise = undefined;
      return this.#scriptRunner.runSha(await this.loadScript(), options);
    }
  }
}

export function isAsyncQuarantinePinCache(cache: QuarantinePinCacheLike | undefined): cache is AsyncQuarantinePinCache {
  return cache !== undefined && (cache as { readonly asyncQuarantinePinCache?: unknown }).asyncQuarantinePinCache === true;
}
