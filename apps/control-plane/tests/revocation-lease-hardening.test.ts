import { InMemoryOutboxStore, StoreBackedOutboxPublisher } from "@aidenid/eventing";
import { afterEach, describe, expect, it } from "vitest";

import { sessionSignerFromOptions } from "../src/app.js";
import { LocalDecisionReceiptIssuer } from "../src/services/decisionReceipts.js";
import { InMemoryKillSwitchController } from "../src/services/killSwitch.js";
import { InMemoryPersonaAuditController } from "../src/services/personaAudit.js";
import { __resetRevocationLeasesForTests, revokeChain, withChainAuthority, type RevocationRedisClient } from "../src/services/revocation.js";
import { InMemoryControlPlaneStore } from "../src/services/store.js";
import { EnvironmentWebhookSecretResolver } from "../src/services/webhookSecrets.js";
import type { ControlPlaneServices } from "../src/types.js";

function servicesWithGrant(): { readonly services: ControlPlaneServices; readonly chainId: string } {
  const store = new InMemoryControlPlaneStore();
  const target = store.createTarget({ tenantId: "ten_demo", siteId: "sit_lease", name: "Lease Shop", origin: "https://lease.example.com" });
  const grant = store.createGrant({
    targetId: target.id,
    siteId: target.siteId,
    subject: "agent:gpt-luna-xh",
    resource: target.origin,
    permissions: ["catalog:read"],
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
    issuerActorId: "platform_admin"
  });
  const services: ControlPlaneServices = {
    store,
    outbox: new StoreBackedOutboxPublisher(new InMemoryOutboxStore()),
    killSwitch: new InMemoryKillSwitchController(),
    personaAudit: new InMemoryPersonaAuditController(),
    webhookSecrets: new EnvironmentWebhookSecretResolver(),
    decisionReceipts: new LocalDecisionReceiptIssuer({ issuer: "https://test.aidenid.local" }),
    issuer: "https://test.aidenid.local",
    sessionTtlSeconds: 60,
    sessionSigner: sessionSignerFromOptions({})
  };
  return { services, chainId: grant.chainId };
}

/** Redis stand-in that records commands and honours SET NX plus eval compare-and-delete. */
class FakeRedis implements RevocationRedisClient {
  readonly commands: string[] = [];
  readonly values = new Map<string, string>();
  constructor(private readonly withEval: boolean) {}
  async set(key: string, value: string, _mode: "PX", _ttlMs: number, _flag: "NX"): Promise<string | null> {
    this.commands.push(`SET ${key} ${value}`);
    if (this.values.has(key)) {
      return null;
    }
    this.values.set(key, value);
    return "OK";
  }
  async get(key: string): Promise<string | null> {
    this.commands.push(`GET ${key}`);
    return this.values.get(key) ?? null;
  }
  async del(key: string): Promise<number> {
    this.commands.push(`DEL ${key}`);
    return this.values.delete(key) ? 1 : 0;
  }
  eval?(script: string, _numKeys: number, ...args: string[]): Promise<unknown>;
}
function fakeRedis(withEval: boolean): FakeRedis {
  const redis = new FakeRedis(withEval);
  if (withEval) {
    redis.eval = async (script: string, _numKeys: number, ...args: string[]) => {
      const [key, owner] = args;
      redis.commands.push(`EVAL cad ${key} ${owner}`);
      if (!script.includes('redis.call("GET", KEYS[1]) == ARGV[1]')) {
        throw new Error("unexpected script");
      }
      if (redis.values.get(key!) === owner) {
        redis.values.delete(key!);
        return 1;
      }
      return 0;
    };
  }
  return redis;
}

describe("lease hardening", () => {
  afterEach(() => {
    __resetRevocationLeasesForTests();
  });

  it("refuses to gate an effect on the TTL-bound Redis lease and never runs the effect", async () => {
    const { services, chainId } = servicesWithGrant();
    let ran = false;
    const result = await withChainAuthority(services, { chainId, tokenRevocationEpoch: 0 }, () => {
      ran = true;
      return "effect";
    }, { redis: fakeRedis(true) });
    expect(result).toEqual({ ok: false, reason: "lease_backend_unsupported" });
    expect(ran).toBe(false);
    // The same call without Redis options runs under the in-process lease.
    expect(await withChainAuthority(services, { chainId, tokenRevocationEpoch: 0 }, () => "effect")).toEqual({ ok: true, epoch: 0, value: "effect" });
  });

  it("releases the Redis revocation lease with an atomic compare-and-delete when eval is available", async () => {
    const { services, chainId } = servicesWithGrant();
    const redis = fakeRedis(true);
    await revokeChain(services, { chainId, reason: "owner_revoked", actorId: "platform_admin" }, { redis });
    expect(redis.commands).toEqual([`SET lease:revoke:${chainId} platform_admin`, `EVAL cad lease:revoke:${chainId} platform_admin`]);
    expect(redis.values.size).toBe(0);

    // A lease that expired and was re-acquired by someone else is left alone.
    const stolen = fakeRedis(true);
    const original = revokeChain(services, { chainId, reason: "again", actorId: "platform_admin" }, { redis: stolen });
    // Let the in-process lease and the SET NX happen, then simulate expiry + re-acquisition by another holder.
    await new Promise((resolve) => setTimeout(resolve, 0));
    stolen.values.set(`lease:revoke:${chainId}`, "someone_else");
    await original;
    expect(stolen.values.get(`lease:revoke:${chainId}`)).toBe("someone_else");
  });

  it("falls back to GET then DEL for a Redis client without eval", async () => {
    const { services, chainId } = servicesWithGrant();
    const redis = fakeRedis(false);
    await revokeChain(services, { chainId, reason: "owner_revoked", actorId: "platform_admin" }, { redis });
    expect(redis.commands).toEqual([`SET lease:revoke:${chainId} platform_admin`, `GET lease:revoke:${chainId}`, `DEL lease:revoke:${chainId}`]);
  });

  it("serializes two concurrent in-process revokes by the same actor instead of letting the second pass through", async () => {
    const { services, chainId } = servicesWithGrant();
    const order: string[] = [];
    const slowStore = services.store;
    const originalBump = slowStore.bumpEpoch.bind(slowStore);
    let firstBumpStarted: (() => void) | undefined;
    let releaseFirst: (() => void) | undefined;
    const gate = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    const started = new Promise<void>((resolve) => {
      firstBumpStarted = resolve;
    });
    let calls = 0;
    Object.assign(slowStore, {
      bumpEpoch: async (input: Parameters<typeof originalBump>[0], occurredAt: string) => {
        calls += 1;
        if (calls === 1) {
          firstBumpStarted?.();
          await gate;
          order.push("first_bumped");
        } else {
          order.push("second_bumped");
        }
        return originalBump(input, occurredAt);
      }
    });

    const first = revokeChain(services, { chainId, reason: "r1", actorId: "platform_admin" });
    await started;
    const second = revokeChain(services, { chainId, reason: "r2", actorId: "platform_admin" });
    await new Promise((resolve) => setTimeout(resolve, 40));
    expect(order).toEqual([]);
    releaseFirst?.();
    const [a, b] = await Promise.all([first, second]);
    expect(order).toEqual(["first_bumped", "second_bumped"]);
    expect([a.epoch, b.epoch].sort()).toEqual([1, 2]);
  });
});
