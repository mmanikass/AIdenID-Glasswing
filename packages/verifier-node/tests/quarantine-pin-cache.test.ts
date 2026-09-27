import type { RedisTokenBucketScriptRunner } from "@aidenid/policy-engine";
import { describe, expect, it } from "vitest";

import {
  MemoryQuarantinePinCache,
  RedisQuarantinePinCache,
  REDIS_QUARANTINE_PIN_LUA,
  isAsyncQuarantinePinCache,
  resolveVerifierOptions,
  quarantinePinKey
} from "../src/index.js";

class FakeQuarantineRedisRunner implements RedisTokenBucketScriptRunner {
  readonly calls: string[] = [];
  nowMs = 0;
  throwNoScriptOnce = false;
  readonly #store = new Map<string, number>();

  async load(script: string): Promise<string> {
    this.calls.push(script === REDIS_QUARANTINE_PIN_LUA ? "load:qpin" : "load:other");
    return "sha-quarantine-pin";
  }

  async runSha(_sha: string, options: { readonly keys: readonly string[]; readonly arguments: readonly string[] }): Promise<unknown> {
    this.calls.push(`sha:${options.arguments[0] ?? ""}`);
    if (this.throwNoScriptOnce) {
      this.throwNoScriptOnce = false;
      throw new Error("NOSCRIPT No matching script");
    }
    return this.execute(options);
  }

  async run(_script: string, options: { readonly keys: readonly string[]; readonly arguments: readonly string[] }): Promise<unknown> {
    this.calls.push(`eval:${options.arguments[0] ?? ""}`);
    return this.execute(options);
  }

  private execute(options: { readonly keys: readonly string[]; readonly arguments: readonly string[] }): number {
    const key = options.keys[0];
    if (key === undefined) {
      throw new Error("missing Redis key");
    }

    const action = options.arguments[0];
    if (action === "pin") {
      const ttlMs = Number(options.arguments[1]);
      if (!Number.isFinite(ttlMs) || ttlMs <= 0) {
        this.#store.delete(key);
        return 0;
      }
      this.#store.set(key, this.nowMs + ttlMs);
      return 1;
    }

    if (action === "has") {
      const expiresAtMs = this.#store.get(key);
      if (expiresAtMs === undefined) {
        return 0;
      }
      if (expiresAtMs <= this.nowMs) {
        this.#store.delete(key);
        return 0;
      }
      return 1;
    }

    throw new Error(`unsupported action ${String(action)}`);
  }
}

describe("quarantine pin cache", () => {
  it("keeps subject pins in memory until their TTL expires", () => {
    const cache = new MemoryQuarantinePinCache();
    const expiresAt = new Date(2_000).toISOString();

    expect(cache.pin({ siteId: "sit_demo", subjectHandle: "sub_secret", expiresAt }, 1_000)).toBe(true);
    expect(cache.isPinned({ siteId: "sit_demo", subjectHandle: "sub_secret" }, 1_999)).toBe(true);
    expect(cache.isPinned({ siteId: "sit_demo", subjectHandle: "sub_secret" }, 2_000)).toBe(false);
  });

  it("hashes pin keys and ignores missing subject handles", () => {
    expect(quarantinePinKey({ siteId: "sit_demo", subjectHandle: undefined })).toBeUndefined();
    const key = quarantinePinKey({ siteId: "sit_demo", subjectHandle: "sub_secret" });

    expect(key).toMatch(/^qpin:sit_demo:subject:[a-f0-9]{32}$/);
    expect(key).not.toContain("sub_secret");
  });

  it("uses Redis SCRIPT LOAD/EVALSHA and retries NOSCRIPT once", async () => {
    const runner = new FakeQuarantineRedisRunner();
    runner.nowMs = 1_000;
    runner.throwNoScriptOnce = true;
    const cache = new RedisQuarantinePinCache(runner, { keyPrefix: "test:" });
    const expiresAt = new Date(2_500).toISOString();

    await expect(cache.pin({ siteId: "sit_demo", subjectHandle: "sub_secret", expiresAt }, runner.nowMs)).resolves.toBe(
      true
    );
    await expect(cache.isPinned({ siteId: "sit_demo", subjectHandle: "sub_secret" }, runner.nowMs)).resolves.toBe(true);
    runner.nowMs = 2_500;
    await expect(cache.isPinned({ siteId: "sit_demo", subjectHandle: "sub_secret" }, runner.nowMs)).resolves.toBe(false);
    await expect(cache.pin({ siteId: "sit_demo", subjectHandle: "sub_secret", expiresAt: "not-a-date" }, 1_000)).resolves.toBe(
      false
    );

    expect(runner.calls).toEqual(["load:qpin", "sha:pin", "load:qpin", "sha:pin", "sha:has", "sha:has"]);
  });

  it("auto-wires the Redis quarantine cache from top-level verifier redis options", () => {
    const runner = new FakeQuarantineRedisRunner();
    const resolved = resolveVerifierOptions({
      siteId: "sit_demo",
      apiKey: "key",
      redis: { scriptRunner: runner }
    });

    expect(isAsyncQuarantinePinCache(resolved.quarantinePinCache)).toBe(true);
  });
});
