import { describe, expect, it } from "vitest";

import { createControlPlaneRuntime } from "../src/index.js";
import { checkChainAuthority } from "../src/services/revocation.js";

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

async function issueGrant(runtime: Runtime, expiresInSeconds = 600): Promise<Issued> {
  const targetResponse = await runtime.app.inject({
    method: "POST",
    url: "/v1/targets",
    headers: ADMIN_HEADERS,
    payload: {
      tenant_id: "ten_demo",
      site_id: "sit_terminal",
      name: "Terminal Shop",
      origin: "https://terminal.example.com"
    }
  });
  expect(targetResponse.statusCode).toBe(201);
  const target = targetResponse.json<{ id: string; site_id: string; origin: string }>();
  const grantResponse = await runtime.app.inject({
    method: "POST",
    url: "/v1/grants",
    headers: ADMIN_HEADERS,
    payload: {
      target_id: target.id,
      subject: "agent:gpt-luna-xh",
      resource: target.origin,
      permissions: ["catalog:read"],
      expires_in_seconds: expiresInSeconds
    }
  });
  expect(grantResponse.statusCode).toBe(201);
  const grant = grantResponse.json<{ id: string; chain_id: string }>();
  return { siteId: target.site_id, origin: target.origin, grantId: grant.id, chainId: grant.chain_id };
}

async function exchange(runtime: Runtime, issued: Issued) {
  return runtime.app.inject({
    method: "POST",
    url: "/v1/sessions/exchange",
    payload: {
      grant_id: issued.grantId,
      audience: issued.siteId,
      resource: issued.origin,
      proof_jkt: "proof-thumbprint-terminal",
      requested_permissions: ["catalog:read"]
    }
  });
}

async function revoke(runtime: Runtime, chainId: string) {
  return runtime.app.inject({
    method: "POST",
    url: "/v1/revoke",
    headers: ADMIN_HEADERS,
    payload: { chain_id: chainId, reason: "owner_revoked", actor_id: "platform_admin" }
  });
}

describe("revocation is terminal for the grant (F-01)", () => {
  it("refuses a session exchange after the chain is revoked and records the grant revocation", async () => {
    const runtime = await createControlPlaneRuntime({ sessionTtlSeconds: 60, operatorAuth: OPERATOR_AUTH });
    try {
      const issued = await issueGrant(runtime);

      const before = await exchange(runtime, issued);
      expect(before.statusCode).toBe(201);
      expect(before.json<{ revocation_epoch: number }>().revocation_epoch).toBe(0);

      const revoked = await revoke(runtime, issued.chainId);
      expect(revoked.statusCode).toBe(202);
      expect(revoked.json()).toMatchObject({ chain_id: issued.chainId, revocation_epoch: 1 });

      const after = await exchange(runtime, issued);
      expect(after.statusCode).toBe(403);
      expect(after.json()).toMatchObject({ error: "grant_not_active" });

      const grant = await runtime.services.store.getGrant(issued.grantId);
      expect(grant?.revokedAt).toBeTypeOf("string");

      const outboxTypes = runtime.outboxStore.all().map((event) => event.type);
      expect(outboxTypes).toEqual(expect.arrayContaining(["REVOCATION_EPOCH_BUMP", "GRANT_REVOKED_HASH"]));
      const grantRevoked = runtime.outboxStore.all().find((event) => event.type === "GRANT_REVOKED_HASH");
      expect(grantRevoked?.payload).toMatchObject({
        grant_id: issued.grantId,
        chain_id: issued.chainId,
        epoch: 1,
        actor_id: "platform_admin"
      });
    } finally {
      await runtime.app.close();
    }
  });

  it("keeps the first revocation time on a repeated revoke and still refuses exchange", async () => {
    const runtime = await createControlPlaneRuntime({ sessionTtlSeconds: 60, operatorAuth: OPERATOR_AUTH });
    try {
      const issued = await issueGrant(runtime);
      expect((await revoke(runtime, issued.chainId)).statusCode).toBe(202);
      const firstRevokedAt = (await runtime.services.store.getGrant(issued.grantId))?.revokedAt;
      expect(firstRevokedAt).toBeTypeOf("string");

      const again = await revoke(runtime, issued.chainId);
      expect(again.statusCode).toBe(202);
      expect(again.json()).toMatchObject({ chain_id: issued.chainId, revocation_epoch: 2 });
      expect((await runtime.services.store.getGrant(issued.grantId))?.revokedAt).toBe(firstRevokedAt);
      expect(runtime.outboxStore.all().filter((event) => event.type === "GRANT_REVOKED_HASH")).toHaveLength(1);

      expect((await exchange(runtime, issued)).statusCode).toBe(403);
    } finally {
      await runtime.app.close();
    }
  });
});

describe("per-chain authority check at the effect boundary (F-02)", () => {
  it("is current for a live chain, revoked after revocation, and unknown for a missing chain", async () => {
    const runtime = await createControlPlaneRuntime({ sessionTtlSeconds: 60, operatorAuth: OPERATOR_AUTH });
    try {
      const issued = await issueGrant(runtime);
      await expect(
        checkChainAuthority(runtime.services, { chainId: issued.chainId, tokenRevocationEpoch: 0 })
      ).resolves.toEqual({ current: true, epoch: 0 });

      expect((await revoke(runtime, issued.chainId)).statusCode).toBe(202);
      // The token issued before revocation carries epoch 0; the revoked grant wins over the stale epoch.
      await expect(
        checkChainAuthority(runtime.services, { chainId: issued.chainId, tokenRevocationEpoch: 0 })
      ).resolves.toEqual({ current: false, reason: "grant_revoked", epoch: 1 });
      // Even a token that somehow carries the bumped epoch is refused once the grant is revoked.
      await expect(
        checkChainAuthority(runtime.services, { chainId: issued.chainId, tokenRevocationEpoch: 1 })
      ).resolves.toMatchObject({ current: false, reason: "grant_revoked" });

      await expect(
        checkChainAuthority(runtime.services, { chainId: "chn_does_not_exist", tokenRevocationEpoch: 0 })
      ).resolves.toEqual({ current: false, reason: "unknown_chain", epoch: 0 });
    } finally {
      await runtime.app.close();
    }
  });

  it("reports a stale token epoch when the epoch moved without a grant revocation, and an expired grant", async () => {
    const runtime = await createControlPlaneRuntime({ sessionTtlSeconds: 60, operatorAuth: OPERATOR_AUTH });
    try {
      const issued = await issueGrant(runtime, 30);
      await runtime.services.store.bumpEpoch(
        { chainId: issued.chainId, reason: "key_rotation", actorId: "platform_admin" },
        new Date().toISOString()
      );
      await expect(
        checkChainAuthority(runtime.services, { chainId: issued.chainId, tokenRevocationEpoch: 0 })
      ).resolves.toEqual({ current: false, reason: "epoch_stale", epoch: 1 });
      await expect(
        checkChainAuthority(runtime.services, { chainId: issued.chainId, tokenRevocationEpoch: 1 })
      ).resolves.toEqual({ current: true, epoch: 1 });

      const later = new Date(Date.now() + 31_000);
      await expect(
        checkChainAuthority(runtime.services, { chainId: issued.chainId, tokenRevocationEpoch: 1, now: later })
      ).resolves.toEqual({ current: false, reason: "grant_expired", epoch: 1 });
    } finally {
      await runtime.app.close();
    }
  });
});
