import { describe, expect, it } from "vitest";

import { createControlPlaneRuntime } from "../src/index.js";
import { revokeChain, withChainAuthority } from "../src/services/revocation.js";

const ADMIN_TOKEN = "test_operator_token_admin_123456";
const OPERATOR_AUTH = {
  entries: [{ actorId: "platform_admin", token: ADMIN_TOKEN, roles: ["admin"] }]
} as const;
const ADMIN_HEADERS = { Authorization: `Bearer ${ADMIN_TOKEN}` };

type Runtime = Awaited<ReturnType<typeof createControlPlaneRuntime>>;

interface Issued {
  readonly siteId: string;
  readonly origin: string;
  readonly grantId: string;
  readonly chainId: string;
}

async function issueGrant(runtime: Runtime): Promise<Issued> {
  const targetResponse = await runtime.app.inject({
    method: "POST",
    url: "/v1/targets",
    headers: ADMIN_HEADERS,
    payload: { tenant_id: "ten_demo", site_id: "sit_boundary", name: "Boundary Shop", origin: "https://boundary.example.com" }
  });
  expect(targetResponse.statusCode).toBe(201);
  const target = targetResponse.json<{ id: string; site_id: string; origin: string }>();
  const grantResponse = await runtime.app.inject({
    method: "POST",
    url: "/v1/grants",
    headers: ADMIN_HEADERS,
    payload: { target_id: target.id, subject: "agent:gpt-luna-xh", resource: target.origin, permissions: ["catalog:read"], expires_in_seconds: 600 }
  });
  expect(grantResponse.statusCode).toBe(201);
  const grant = grantResponse.json<{ id: string; chain_id: string }>();
  return { siteId: target.site_id, origin: target.origin, grantId: grant.id, chainId: grant.chain_id };
}

async function exchange(runtime: Runtime, issued: Issued) {
  return runtime.app.inject({
    method: "POST",
    url: "/v1/sessions/exchange",
    payload: { grant_id: issued.grantId, audience: issued.siteId, resource: issued.origin, proof_jkt: "proof-thumbprint-boundary", requested_permissions: ["catalog:read"] }
  });
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}

describe("revocation fails closed when the outbox is unavailable", () => {
  it("marks the grant revoked and bumps the epoch before any publish, so exchange is refused even though the revoke request errored", async () => {
    const runtime = await createControlPlaneRuntime({ sessionTtlSeconds: 60, operatorAuth: OPERATOR_AUTH });
    try {
      const issued = await issueGrant(runtime);
      expect((await exchange(runtime, issued)).statusCode).toBe(201);

      // Injected bus failure: every publish rejects from now on.
      const publishedAfterFailure: string[] = [];
      Object.assign(runtime.services, {
        outbox: {
          publish: async (event: { type: string }) => {
            publishedAfterFailure.push(event.type);
            throw new Error("bus down");
          }
        }
      });

      const revoke = await runtime.app.inject({
        method: "POST",
        url: "/v1/revoke",
        headers: ADMIN_HEADERS,
        payload: { chain_id: issued.chainId, reason: "owner_revoked", actor_id: "platform_admin" }
      });
      expect(revoke.statusCode).toBe(500);
      expect(publishedAfterFailure).toEqual(["REVOCATION_EPOCH_BUMP"]);

      // The authoritative transition already happened: exchange is refused and the epoch moved.
      expect((await exchange(runtime, issued)).statusCode).toBe(403);
      expect((await runtime.services.store.getGrant(issued.grantId))?.revokedAt).toBeTypeOf("string");
      expect(await runtime.services.store.currentEpoch(issued.chainId)).toBe(1);
    } finally {
      await runtime.app.close();
    }
  });
});

describe("withChainAuthority: the co-located effect boundary", () => {
  it("runs the effect under the chain lease; a concurrent revoke waits and lands after the effect committed", async () => {
    const runtime = await createControlPlaneRuntime({ sessionTtlSeconds: 60, operatorAuth: OPERATOR_AUTH });
    try {
      const issued = await issueGrant(runtime);
      const order: string[] = [];
      const gate = deferred<void>();
      const effectStarted = deferred<void>();

      const effect = withChainAuthority(runtime.services, { chainId: issued.chainId, tokenRevocationEpoch: 0 }, async () => {
        effectStarted.resolve();
        await gate.promise;
        order.push("effect_committed");
        return "catalog-bytes";
      });
      await effectStarted.promise;

      const revoke = revokeChain(runtime.services, { chainId: issued.chainId, reason: "owner_revoked", actorId: "platform_admin" }).then((record) => {
        order.push("revoked");
        return record;
      });
      // Give the revoke a chance to run: it must be blocked on the lease, not interleave.
      await new Promise((resolve) => setTimeout(resolve, 50));
      expect(order).toEqual([]);

      gate.resolve();
      const result = await effect;
      const revocation = await revoke;
      expect(result).toEqual({ ok: true, epoch: 0, value: "catalog-bytes" });
      expect(revocation.epoch).toBe(1);
      expect(order).toEqual(["effect_committed", "revoked"]);

      // After the revoke, the next effect is refused before it runs.
      let ran = false;
      const refused = await withChainAuthority(runtime.services, { chainId: issued.chainId, tokenRevocationEpoch: 0 }, async () => {
        ran = true;
        return "should-not-run";
      });
      expect(refused).toEqual({ ok: false, reason: "grant_revoked" });
      expect(ran).toBe(false);
    } finally {
      await runtime.app.close();
    }
  });

  it("refuses an effect whose token epoch is stale and never invokes it", async () => {
    const runtime = await createControlPlaneRuntime({ sessionTtlSeconds: 60, operatorAuth: OPERATOR_AUTH });
    try {
      const issued = await issueGrant(runtime);
      await runtime.services.store.bumpEpoch({ chainId: issued.chainId, reason: "rotation", actorId: "platform_admin" }, new Date().toISOString());
      let ran = false;
      const result = await withChainAuthority(runtime.services, { chainId: issued.chainId, tokenRevocationEpoch: 0 }, () => {
        ran = true;
        return 1;
      });
      expect(result).toEqual({ ok: false, reason: "epoch_stale" });
      expect(ran).toBe(false);
      expect(await withChainAuthority(runtime.services, { chainId: issued.chainId, tokenRevocationEpoch: 1 }, () => 2)).toEqual({ ok: true, epoch: 1, value: 2 });
    } finally {
      await runtime.app.close();
    }
  });

  it("serializes two effects on the same chain and fails closed when the lease wait is exhausted", async () => {
    const runtime = await createControlPlaneRuntime({ sessionTtlSeconds: 60, operatorAuth: OPERATOR_AUTH });
    try {
      const issued = await issueGrant(runtime);
      const order: string[] = [];
      const firstGate = deferred<void>();
      const firstStarted = deferred<void>();
      const first = withChainAuthority(runtime.services, { chainId: issued.chainId, tokenRevocationEpoch: 0 }, async () => {
        firstStarted.resolve();
        await firstGate.promise;
        order.push("first_done");
        return 1;
      });
      await firstStarted.promise;
      const second = withChainAuthority(runtime.services, { chainId: issued.chainId, tokenRevocationEpoch: 0 }, () => {
        order.push("second_ran");
        return 2;
      });
      // A third caller that will not wait sees the chain busy and gets no effect.
      const impatient = await withChainAuthority(runtime.services, { chainId: issued.chainId, tokenRevocationEpoch: 0 }, () => 3, { leaseWaitMs: 0 });
      expect(impatient).toEqual({ ok: false, reason: "chain_busy" });

      firstGate.resolve();
      expect(await first).toEqual({ ok: true, epoch: 0, value: 1 });
      expect(await second).toEqual({ ok: true, epoch: 0, value: 2 });
      expect(order).toEqual(["first_done", "second_ran"]);
    } finally {
      await runtime.app.close();
    }
  });
});
