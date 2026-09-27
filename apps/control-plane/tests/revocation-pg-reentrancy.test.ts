import { InMemoryOutboxStore, StoreBackedOutboxPublisher } from "@aidenid/eventing";
import { afterEach, describe, expect, it } from "vitest";

import { sessionSignerFromOptions } from "../src/app.js";
import { LocalDecisionReceiptIssuer } from "../src/services/decisionReceipts.js";
import { InMemoryKillSwitchController } from "../src/services/killSwitch.js";
import { InMemoryPersonaAuditController } from "../src/services/personaAudit.js";
import { __resetRevocationLeasesForTests, revokeChain, withChainAuthority, type RevocationPgClient } from "../src/services/revocation.js";
import { InMemoryControlPlaneStore } from "../src/services/store.js";
import { EnvironmentWebhookSecretResolver } from "../src/services/webhookSecrets.js";
import type { ControlPlaneServices } from "../src/types.js";

function servicesWithGrant(): { readonly services: ControlPlaneServices; readonly chainId: string } {
  const store = new InMemoryControlPlaneStore();
  const target = store.createTarget({ tenantId: "ten_demo", siteId: "sit_pg", name: "PG Shop", origin: "https://pg.example.com" });
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

/**
 * A PostgreSQL session stand-in with the documented re-entrant behaviour: the owning
 * session may acquire its own advisory lock again while a waiter exists.
 */
class ReentrantPgSession implements RevocationPgClient {
  readonly held = new Map<string, number>();
  readonly queries: string[] = [];
  async query<T = unknown>(text: string, values?: readonly unknown[]): Promise<{ readonly rows: readonly T[] }> {
    this.queries.push(text);
    const key = String(values?.[0]);
    if (text.includes("pg_try_advisory_lock")) {
      this.held.set(key, (this.held.get(key) ?? 0) + 1);
      return { rows: [{ locked: true } as unknown as T] };
    }
    if (text.includes("pg_advisory_unlock")) {
      const remaining = (this.held.get(key) ?? 0) - 1;
      if (remaining <= 0) {
        this.held.delete(key);
      } else {
        this.held.set(key, remaining);
      }
      return { rows: [] };
    }
    return { rows: [] };
  }
}

describe("same-session PostgreSQL re-entrancy", () => {
  afterEach(() => {
    __resetRevocationLeasesForTests();
  });

  it("a revoke sharing the pg client of a pending effect waits for it instead of re-entering the session lock", async () => {
    const { services, chainId } = servicesWithGrant();
    const pgClient = new ReentrantPgSession();
    const order: string[] = [];
    let releaseEffect!: () => void;
    const gate = new Promise<void>((resolve) => {
      releaseEffect = resolve;
    });
    let started!: () => void;
    const effectStarted = new Promise<void>((resolve) => {
      started = resolve;
    });

    const effect = withChainAuthority(
      services,
      { chainId, tokenRevocationEpoch: 0 },
      async () => {
        started();
        await gate;
        order.push("effect_committed");
        return "bytes";
      },
      { pgClient }
    );
    await effectStarted;

    const revoke = revokeChain(services, { chainId, reason: "owner_revoked", actorId: "platform_admin" }, { pgClient }).then((record) => {
      order.push("revoked");
      return record;
    });
    await new Promise((resolve) => setTimeout(resolve, 50));
    // The re-entrant session lock alone would have let the revoke through; the in-process lease holds it.
    expect(order).toEqual([]);
    expect((await services.store.getGrantByChainId(chainId))?.revokedAt).toBeUndefined();

    releaseEffect();
    expect(await effect).toEqual({ ok: true, epoch: 0, value: "bytes" });
    expect((await revoke).epoch).toBe(1);
    expect(order).toEqual(["effect_committed", "revoked"]);
    expect(pgClient.held.size).toBe(0);

    // After the revoke, an effect on the same shared client is refused before it runs.
    let ran = false;
    const refused = await withChainAuthority(
      services,
      { chainId, tokenRevocationEpoch: 0 },
      () => {
        ran = true;
        return 1;
      },
      { pgClient }
    );
    expect(refused).toEqual({ ok: false, reason: "grant_revoked" });
    expect(ran).toBe(false);
  });

  it("releases the in-process lease when the cross-replica lock cannot be taken", async () => {
    const { services, chainId } = servicesWithGrant();
    const busy: RevocationPgClient = {
      async query<T = unknown>(text: string): Promise<{ readonly rows: readonly T[] }> {
        if (text.includes("pg_try_advisory_lock")) {
          return { rows: [{ locked: false } as unknown as T] };
        }
        return { rows: [] };
      }
    };
    await expect(revokeChain(services, { chainId, reason: "r", actorId: "platform_admin" }, { pgClient: busy })).rejects.toThrow(/concurrent revocation in flight/);
    // The local lease was released on failure, so the in-process gate still works afterwards.
    expect(await withChainAuthority(services, { chainId, tokenRevocationEpoch: 0 }, () => "ok")).toEqual({ ok: true, epoch: 0, value: "ok" });
  });
});
