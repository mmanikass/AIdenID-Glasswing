import { randomUUID } from "node:crypto";

import { makeOutboxEvent } from "@aidenid/eventing";

import { prefixedId } from "../ids.js";
import { enqueuePersonaAudit } from "./personaAudit.js";
import type { ControlPlaneServices, RevocationRecord } from "../types.js";

/**
 * Minimal Redis client surface required for cross-replica leases.
 *
 * `set(key, value, "PX", ms, "NX")` MUST atomically set the key with the
 * supplied TTL only when the key does not already exist, returning a truthy
 * value on success and `null` on contention. `get` returns the lease owner
 * (used for idempotent retries) and `del` releases the lease.
 *
 * Mirrors the `redis` v4 / `ioredis` shape used elsewhere in the verifier hot
 * path (see `packages/verifier-node/src/hotpath.ts` `options.redis`).
 */
export interface RevocationRedisClient {
  set(
    key: string,
    value: string,
    mode: "PX",
    ttlMs: number,
    flag: "NX"
  ): Promise<string | null | undefined>;
  get(key: string): Promise<string | null | undefined>;
  del(key: string): Promise<number | unknown>;
}

/**
 * Minimal Postgres client surface required for advisory-lock based leases.
 * Compatible with `pg.Pool` and `pg.Client` from the `pg` package.
 */
export interface RevocationPgClient {
  query<T = unknown>(
    text: string,
    values?: readonly unknown[]
  ): Promise<{ readonly rows: readonly T[] }>;
}

export interface RevokeChainOptions {
  readonly redis?: RevocationRedisClient | undefined;
  readonly pgClient?: RevocationPgClient | undefined;
  /** Lease TTL in milliseconds. Spec mandates ≤ 5_000ms. */
  readonly leaseTtlMs?: number | undefined;
  /** How long an in-process lease waits for a competing holder before failing closed. Default 2_000ms. */
  readonly leaseWaitMs?: number | undefined;
}

const MAX_LEASE_TTL_MS = 5_000;
const DEFAULT_LEASE_TTL_MS = 5_000;
const DEFAULT_LEASE_WAIT_MS = 2_000;
const LEASE_POLL_MS = 5;

/** In-process leases — only used as a last-resort fallback. */
const inMemoryLeases = new Map<string, string>();
let inMemoryWarningEmitted = false;

interface AcquiredLease {
  readonly mode: "redis" | "pg" | "memory";
  readonly key: string;
  readonly chainId: string;
  release(): Promise<void>;
}

function clampTtl(input: number | undefined): number {
  if (typeof input !== "number" || !Number.isFinite(input) || input <= 0) {
    return DEFAULT_LEASE_TTL_MS;
  }
  return Math.min(Math.floor(input), MAX_LEASE_TTL_MS);
}

async function acquireRedisLease(
  redis: RevocationRedisClient,
  leaseKey: string,
  chainId: string,
  ownerId: string,
  ttlMs: number
): Promise<AcquiredLease> {
  const set = await redis.set(leaseKey, ownerId, "PX", ttlMs, "NX");
  if (set) {
    return {
      mode: "redis",
      key: leaseKey,
      chainId,
      release: async () => {
        try {
          // Best-effort owner check before delete to avoid releasing a lease
          // we no longer own (e.g. after TTL expiry & re-acquisition).
          const current = await redis.get(leaseKey);
          if (current === ownerId) {
            await redis.del(leaseKey);
          }
        } catch {
          // swallow — lease will expire via TTL.
        }
      }
    };
  }
  // Idempotent path: if the existing lease holder is the same actor.id,
  // proper-lockfile-style semantics treat this as a benign retry.
  const existing = await redis.get(leaseKey);
  if (existing === ownerId) {
    return {
      mode: "redis",
      key: leaseKey,
      chainId,
      // Do not delete — the original holder will release on completion.
      release: async () => {
        /* no-op: not the original lease holder */
      }
    };
  }
  throw new Error("concurrent revocation in flight");
}

/**
 * 64-bit signed advisory lock key derived from the chainId via FNV-1a.
 * Postgres `pg_try_advisory_lock(bigint)` requires a numeric key.
 */
function pgAdvisoryKeyFromChainId(chainId: string): string {
  // FNV-1a 64-bit
  let hash = 0xcbf29ce484222325n;
  const prime = 0x100000001b3n;
  const mask = 0xffffffffffffffffn;
  for (let i = 0; i < chainId.length; i++) {
    hash = (hash ^ BigInt(chainId.charCodeAt(i))) & mask;
    hash = (hash * prime) & mask;
  }
  // Map unsigned 64-bit hash into signed bigint range that Postgres accepts.
  if (hash >= 0x8000000000000000n) {
    hash = hash - 0x10000000000000000n;
  }
  return hash.toString();
}

async function acquirePgLease(
  pgClient: RevocationPgClient,
  leaseKey: string,
  chainId: string,
  ownerId: string
): Promise<AcquiredLease> {
  const advisoryKey = pgAdvisoryKeyFromChainId(leaseKey);
  const result = await pgClient.query<{ readonly locked: boolean }>(
    "SELECT pg_try_advisory_lock($1::bigint) AS locked",
    [advisoryKey]
  );
  const acquired = Boolean(result.rows[0]?.locked);
  if (acquired) {
    return {
      mode: "pg",
      key: leaseKey,
      chainId,
      release: async () => {
        try {
          await pgClient.query("SELECT pg_advisory_unlock($1::bigint)", [advisoryKey]);
        } catch {
          // swallow — session-level locks release on disconnect.
        }
      }
    };
  }
  // Idempotent path for PG: we can't introspect lock holder identity from
  // pg_try_advisory_lock, so we use an in-memory map of advisory key → owner
  // to provide same-process idempotency semantics. Cross-process concurrent
  // revocations are correctly rejected.
  const existingOwner = inMemoryLeases.get(`pg:${advisoryKey}`);
  if (existingOwner === ownerId) {
    return {
      mode: "pg",
      key: leaseKey,
      chainId,
      release: async () => {
        /* no-op: not the original lease holder */
      }
    };
  }
  throw new Error("concurrent revocation in flight");
}

async function acquireMemoryLease(
  leaseKey: string,
  chainId: string,
  ownerId: string,
  waitMs: number
): Promise<AcquiredLease> {
  if (!inMemoryWarningEmitted) {
    inMemoryWarningEmitted = true;
    console.warn(
      "[control-plane] revocation lease falling back to in-memory Set; " +
        "single-process lease; not safe for multi-replica deployments."
    );
  }
  // The in-process lease is the co-located linearization point between a revocation and a
  // protected effect on the same chain: whichever holds it first commits first and the other
  // WAITS (bounded) instead of interleaving. When the wait is exhausted it fails closed.
  const deadline = Date.now() + Math.max(0, waitMs);
  for (;;) {
    const existing = inMemoryLeases.get(leaseKey);
    if (existing === undefined) {
      inMemoryLeases.set(leaseKey, ownerId);
      return {
        mode: "memory",
        key: leaseKey,
        chainId,
        release: async () => {
          if (inMemoryLeases.get(leaseKey) === ownerId) {
            inMemoryLeases.delete(leaseKey);
          }
        }
      };
    }
    if (existing === ownerId) {
      // Idempotent retry: same owner gets through; do not double-release.
      return {
        mode: "memory",
        key: leaseKey,
        chainId,
        release: async () => {
          /* no-op: not the original lease holder */
        }
      };
    }
    if (Date.now() >= deadline) {
      throw new Error("concurrent revocation in flight");
    }
    await new Promise<void>((resolve) => setTimeout(resolve, LEASE_POLL_MS));
  }
}

async function acquireLease(
  leaseKey: string,
  chainId: string,
  ownerId: string,
  options: RevokeChainOptions | undefined
): Promise<AcquiredLease> {
  const ttlMs = clampTtl(options?.leaseTtlMs);
  if (options?.redis) {
    return acquireRedisLease(options.redis, leaseKey, chainId, ownerId, ttlMs);
  }
  if (options?.pgClient) {
    const lease = await acquirePgLease(options.pgClient, leaseKey, chainId, ownerId);
    // Track owner so same-actor retries inside this process are idempotent.
    inMemoryLeases.set(`pg:${pgAdvisoryKeyFromChainId(leaseKey)}`, ownerId);
    const release = lease.release;
    return {
      ...lease,
      release: async () => {
        try {
          await release();
        } finally {
          inMemoryLeases.delete(`pg:${pgAdvisoryKeyFromChainId(leaseKey)}`);
        }
      }
    };
  }
  return acquireMemoryLease(leaseKey, chainId, ownerId, options?.leaseWaitMs ?? DEFAULT_LEASE_WAIT_MS);
}

export async function revokeChain(
  services: ControlPlaneServices,
  input: { readonly chainId: string; readonly reason: string; readonly actorId: string },
  options?: RevokeChainOptions
): Promise<RevocationRecord> {
  const leaseKey = `lease:revoke:${input.chainId}`;
  const lease = await acquireLease(leaseKey, input.chainId, input.actorId, options);

  try {
    const occurredAt = new Date().toISOString();
    const revocation = await services.store.bumpEpoch(
      {
        chainId: input.chainId,
        reason: input.reason,
        actorId: input.actorId
      },
      occurredAt
    );
    // Revocation is terminal for the delegation itself, not only for tokens already issued.
    // Bumping the epoch invalidates outstanding session tokens at the verifier, but
    // /v1/sessions/exchange refuses only on grant.revokedAt, which nothing used to set: a
    // revoked chain could mint a fresh session stamped with the new epoch immediately.
    // Both authoritative state transitions (epoch, grant) happen BEFORE any fallible
    // publication, so a bus failure leaves the chain revoked, never half-revoked.
    // Idempotent: a second revoke bumps the epoch again but keeps the first revokedAt.
    const grant = await services.store.getGrantByChainId(revocation.chainId);
    const newlyRevoked = grant !== undefined && grant.revokedAt === undefined;
    if (newlyRevoked) {
      await services.store.revokeGrant(grant.id, occurredAt);
    }
    await services.outbox.publish(
      makeOutboxEvent(prefixedId("evt"), "REVOCATION_EPOCH_BUMP", {
        chain_id: revocation.chainId,
        epoch: revocation.epoch,
        reason: revocation.reason,
        actor_id: revocation.actorId
      })
    );
    if (newlyRevoked) {
      await services.outbox.publish(
        makeOutboxEvent(prefixedId("evt"), "GRANT_REVOKED_HASH", {
          grant_id: grant.id,
          chain_id: revocation.chainId,
          site_id: grant.siteId,
          epoch: revocation.epoch,
          actor_id: revocation.actorId
        })
      );
    }
    await enqueuePersonaAudit(services, {
      triggerType: "revocation_epoch",
      siteId: grant?.siteId,
      chainId: revocation.chainId,
      revocationEpoch: revocation.epoch,
      reason: revocation.reason,
      actorId: revocation.actorId,
      occurredAt
    });
    return revocation;
  } finally {
    await lease.release();
  }
}

export type ChainAuthorityStatus =
  | { readonly current: true; readonly epoch: number }
  | {
      readonly current: false;
      readonly reason: "unknown_chain" | "grant_revoked" | "grant_expired" | "epoch_stale";
      readonly epoch: number;
    };

/**
 * Per-chain authority SNAPSHOT: store reads only, no lock. Use it for display and for
 * pre-checks; it is NOT the effect gate, because a revoke can land between this read and
 * the effect. The gate is `withChainAuthority`, which takes the same per-chain lease that
 * `revokeChain` holds.
 *
 * Why a per-chain check exists at all: the verifier hot path compares a session token's
 * revocation_epoch against ONE global minimum (AIDENID_VERIFIER_MIN_REVOCATION_EPOCH /
 * rollback.globalRevocationEpoch), so a per-chain revocation is invisible to it unless the
 * global floor is raised for every chain.
 */
export async function checkChainAuthority(
  services: Pick<ControlPlaneServices, "store">,
  input: { readonly chainId: string; readonly tokenRevocationEpoch: number; readonly now?: Date | undefined }
): Promise<ChainAuthorityStatus> {
  const grant = await services.store.getGrantByChainId(input.chainId);
  const epoch = await services.store.currentEpoch(input.chainId);
  if (grant === undefined) {
    return { current: false, reason: "unknown_chain", epoch };
  }
  if (grant.revokedAt !== undefined) {
    return { current: false, reason: "grant_revoked", epoch };
  }
  const nowMs = (input.now ?? new Date()).getTime();
  if (Date.parse(grant.expiresAt) <= nowMs) {
    return { current: false, reason: "grant_expired", epoch };
  }
  if (input.tokenRevocationEpoch !== epoch) {
    return { current: false, reason: "epoch_stale", epoch };
  }
  return { current: true, epoch };
}

export type ChainEffectResult<T> =
  | { readonly ok: true; readonly epoch: number; readonly value: T }
  | {
      readonly ok: false;
      readonly reason: Extract<ChainAuthorityStatus, { current: false }>["reason"] | "chain_busy";
    };

/**
 * The co-located effect boundary. Acquires the same per-chain lease `revokeChain` uses,
 * re-reads authority under it, and runs the effect while holding it. That makes the lease
 * the linearization point the contract requires: an effect that wins the lease commits
 * before a concurrent revoke; a revoke that wins it makes the effect refuse before it runs.
 * If the lease cannot be obtained within the bounded wait the effect is refused
 * (`chain_busy`) rather than run unchecked. Nothing here touches the network or a model.
 *
 * Deployment note: with the in-memory lease this is a single-process guarantee, exactly
 * like the in-memory revocation lease it shares. Multi-replica deployments pass the same
 * Redis/Postgres lease options to both callers.
 */
export async function withChainAuthority<T>(
  services: Pick<ControlPlaneServices, "store">,
  input: {
    readonly chainId: string;
    readonly tokenRevocationEpoch: number;
    readonly now?: Date | undefined;
    /** Lease owner id; defaults to a unique id per effect so two effects never share a lease. */
    readonly ownerId?: string | undefined;
  },
  effect: (authority: { readonly epoch: number }) => Promise<T> | T,
  options?: RevokeChainOptions
): Promise<ChainEffectResult<T>> {
  const leaseKey = `lease:revoke:${input.chainId}`;
  let lease: AcquiredLease;
  try {
    lease = await acquireLease(leaseKey, input.chainId, input.ownerId ?? `effect:${randomUUID()}`, options);
  } catch {
    return { ok: false, reason: "chain_busy" };
  }
  try {
    const status = await checkChainAuthority(services, input);
    if (!status.current) {
      return { ok: false, reason: status.reason };
    }
    const value = await effect({ epoch: status.epoch });
    return { ok: true, epoch: status.epoch, value };
  } finally {
    await lease.release();
  }
}

/** Internal test seam: reset module-level state. */
export function __resetRevocationLeasesForTests(): void {
  inMemoryLeases.clear();
  inMemoryWarningEmitted = false;
}
