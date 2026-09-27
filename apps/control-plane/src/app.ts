import { createPrivateKey, createPublicKey, generateKeyPairSync, type KeyObject } from "node:crypto";

import {
  InMemoryOutboxStore,
  RedisStreamsOutboxPublisher,
  StoreBackedOutboxPublisher,
  type RedisStreamsClient
} from "@aidenid/eventing";
import fastify, { type FastifyInstance } from "fastify";

import { registerAdoptionRoutes } from "./routes/adoption.js";
import { registerCorrelationPlugin } from "./plugins/correlation.js";
import { registerOperatorAuthPlugin, type RegisterOperatorAuthOptions } from "./plugins/operatorAuth.js";
import { assertRouteAccessManifestCoverage, registerRouteAccessGuard } from "./plugins/routeAccessGuard.js";
import { registerDecisionRoutes } from "./routes/decisions.js";
import { registerGrantRoutes } from "./routes/grants.js";
import { registerIdentityRoutes } from "./routes/identities.js";
import { registerKillSwitchRoutes } from "./routes/killSwitch.js";
import { registerOperatorRoutes } from "./routes/operators.js";
import { registerPersonaAuditRoutes } from "./routes/personaAudits.js";
import { registerPolicyCopilotRoutes } from "./routes/policyCopilot.js";
import { registerRevokeRoutes } from "./routes/revoke.js";
import { registerSessionRoutes } from "./routes/sessions.js";
import { registerTargetRoutes } from "./routes/targets.js";
import { InMemoryKillSwitchController } from "./services/killSwitch.js";
import { InMemoryPersonaAuditController } from "./services/personaAudit.js";
import { InMemoryControlPlaneStore, PostgresControlPlaneStore, type SqlClient } from "./services/store.js";
import { localDecisionReceiptIssuerFromEnvironment, RegistryBackedDecisionReceiptIssuer } from "./services/decisionReceipts.js";
import { EnvironmentWebhookSecretResolver } from "./services/webhookSecrets.js";
import { ControlPlaneRedisStreamsClient } from "./redisStreamsClient.js";
import type {
  ControlPlaneServices,
  ControlPlaneStore,
  DecisionReceiptIssuer,
  KillSwitchController,
  PersonaAuditController,
  SessionSigner,
  WebhookSecretResolver
} from "./types.js";

export interface ControlPlaneRuntime {
  readonly app: FastifyInstance;
  readonly services: ControlPlaneServices;
  readonly outboxStore: InMemoryOutboxStore;
}

export interface CreateControlPlaneOptions {
  readonly store?: ControlPlaneStore | undefined;
  readonly pgClient?: SqlClient | undefined;
  readonly databaseUrl?: string | undefined;
  readonly logger?: boolean | undefined;
  readonly decisionOutboxRetentionDays?: number | undefined;
  readonly decisionOutboxRetentionIntervalMs?: number | undefined;
  readonly killSwitch?: KillSwitchController | undefined;
  readonly personaAudit?: PersonaAuditController | undefined;
  readonly decisionReceipts?: DecisionReceiptIssuer | undefined;
  readonly webhookSecrets?: WebhookSecretResolver | undefined;
  readonly operatorAuth?: RegisterOperatorAuthOptions | undefined;
  readonly outboxRedisClient?: RedisStreamsClient | undefined;
  readonly outboxRedisStreamName?: string | undefined;
  readonly issuer?: string | undefined;
  readonly sessionTtlSeconds?: number | undefined;
  /**
   * Session-token signing key. Precedence: this option, then the
   * AIDENID_CONTROL_PLANE_SESSION_SIGNING_JWK environment variable (a private Ed25519 JWK
   * as JSON, `kid` inside it), then a fresh per-process key. A per-process key means every
   * restart invalidates outstanding sessions and no other process can verify them; fine for
   * an explicit local/demo run, never for a deployment.
   */
  readonly sessionSigningKey?: { readonly kid: string; readonly privateKey: KeyObject } | undefined;
}

const DEFAULT_SESSION_KEY_ID = "cpk_local_ed25519";
const SESSION_SIGNING_JWK_ENV = "AIDENID_CONTROL_PLANE_SESSION_SIGNING_JWK";

function publicJwkOf(privateKey: KeyObject): Readonly<Record<string, unknown>> {
  const exported = createPublicKey(privateKey).export({ format: "jwk" }) as Record<string, unknown>;
  if (exported.kty !== "OKP" || exported.crv !== "Ed25519") {
    throw new Error("session signing key must be an Ed25519 (OKP) key");
  }
  return { kty: exported.kty, crv: exported.crv, x: exported.x };
}

function sessionSignerFromEnvironment(raw: string | undefined): SessionSigner | undefined {
  if (raw === undefined || raw.trim().length === 0) {
    return undefined;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error(`${SESSION_SIGNING_JWK_ENV} must be a JSON private JWK`);
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`${SESSION_SIGNING_JWK_ENV} must be a JSON private JWK`);
  }
  const jwk = parsed as Record<string, unknown>;
  const kid = typeof jwk.kid === "string" && jwk.kid.trim().length > 0 ? jwk.kid.trim() : undefined;
  if (kid === undefined) {
    throw new Error(`${SESSION_SIGNING_JWK_ENV} must carry a non-empty kid`);
  }
  const { kid: _kid, ...keyMaterial } = jwk;
  const privateKey = createPrivateKey({ key: keyMaterial, format: "jwk" } as never);
  return { kid, alg: "EdDSA", privateKey, publicJwk: publicJwkOf(privateKey) };
}

export function sessionSignerFromOptions(options: CreateControlPlaneOptions, env: NodeJS.ProcessEnv = process.env): SessionSigner {
  if (options.sessionSigningKey !== undefined) {
    const { kid, privateKey } = options.sessionSigningKey;
    return { kid, alg: "EdDSA", privateKey, publicJwk: publicJwkOf(privateKey) };
  }
  const fromEnv = sessionSignerFromEnvironment(env[SESSION_SIGNING_JWK_ENV]);
  if (fromEnv !== undefined) {
    return fromEnv;
  }
  const { privateKey } = generateKeyPairSync("ed25519");
  return { kid: DEFAULT_SESSION_KEY_ID, alg: "EdDSA", privateKey, publicJwk: publicJwkOf(privateKey) };
}

async function createDefaultStore(app: FastifyInstance, options: CreateControlPlaneOptions): Promise<ControlPlaneStore> {
  if (options.store !== undefined) {
    return options.store;
  }
  if (options.pgClient !== undefined) {
    return new PostgresControlPlaneStore(options.pgClient);
  }

  const databaseUrl = options.databaseUrl ?? controlPlaneDatabaseUrlFromEnvironment(process.env);
  if (databaseUrl === undefined || databaseUrl.trim().length === 0) {
    if (requiresPersistentControlPlaneStore()) {
      throw new Error(
        "AIDENID_CONTROL_PLANE_DATABASE_URL, DATABASE_URL, or split AIDENID_CONTROL_PLANE_DATABASE_* settings are required in production; set AIDENID_ALLOW_EPHEMERAL_CONTROL_PLANE_STORE=true only for explicit local/demo runs"
      );
    }
    return new InMemoryControlPlaneStore();
  }

  const { Pool } = await import("pg");
  const pool = new Pool({ connectionString: databaseUrl });
  app.addHook("onClose", async () => {
    await pool.end();
  });
  return new PostgresControlPlaneStore(pool);
}

function requiresPersistentControlPlaneStore(): boolean {
  if (/^(1|true|yes)$/i.test(process.env.AIDENID_ALLOW_EPHEMERAL_CONTROL_PLANE_STORE ?? "")) {
    return false;
  }
  return process.env.NODE_ENV?.trim().toLowerCase() === "production";
}

function requiresPersistentControlPlaneOutbox(): boolean {
  if (/^(1|true|yes)$/i.test(process.env.AIDENID_ALLOW_IN_MEMORY_CONTROL_PLANE_OUTBOX ?? "")) {
    return false;
  }
  return process.env.NODE_ENV?.trim().toLowerCase() === "production";
}

function controlPlaneLoggerEnabled(): boolean {
  const configured = trimmed(process.env.AIDENID_CONTROL_PLANE_LOGGER);
  if (configured === undefined) {
    return process.env.NODE_ENV?.trim().toLowerCase() === "production";
  }
  return booleanEnv(process.env, "AIDENID_CONTROL_PLANE_LOGGER", false);
}

export interface ControlPlaneDatabaseEnvironment {
  readonly AIDENID_CONTROL_PLANE_DATABASE_URL?: string | undefined;
  readonly DATABASE_URL?: string | undefined;
  readonly AIDENID_CONTROL_PLANE_DATABASE_HOST?: string | undefined;
  readonly AIDENID_CONTROL_PLANE_DATABASE_PORT?: string | undefined;
  readonly AIDENID_CONTROL_PLANE_DATABASE_NAME?: string | undefined;
  readonly AIDENID_CONTROL_PLANE_DATABASE_USER?: string | undefined;
  readonly AIDENID_CONTROL_PLANE_DATABASE_PASSWORD?: string | undefined;
  readonly AIDENID_CONTROL_PLANE_DATABASE_SSLMODE?: string | undefined;
  readonly AIDENID_CONTROL_PLANE_DATABASE_SSLROOTCERT?: string | undefined;
}

export interface ControlPlaneOutboxEnvironment {
  readonly AIDENID_REDIS_HOST?: string | undefined;
  readonly AIDENID_REDIS_PORT?: string | undefined;
  readonly AIDENID_REDIS_TLS?: string | undefined;
  readonly AIDENID_REDIS_AUTH_TOKEN?: string | undefined;
  readonly AIDENID_REDIS_CONNECT_TIMEOUT_MS?: string | undefined;
  readonly AIDENID_REDIS_COMMAND_TIMEOUT_MS?: string | undefined;
  readonly AIDENID_CONTROL_PLANE_OUTBOX_REDIS_STREAM?: string | undefined;
}

function trimmed(value: string | undefined): string | undefined {
  if (value === undefined) {
    return undefined;
  }
  const result = value.trim();
  return result.length === 0 ? undefined : result;
}

export function controlPlaneDatabaseUrlFromEnvironment(env: ControlPlaneDatabaseEnvironment): string | undefined {
  const explicit = trimmed(env.AIDENID_CONTROL_PLANE_DATABASE_URL) ?? trimmed(env.DATABASE_URL);
  if (explicit !== undefined) {
    return explicit;
  }

  const host = trimmed(env.AIDENID_CONTROL_PLANE_DATABASE_HOST);
  const password = trimmed(env.AIDENID_CONTROL_PLANE_DATABASE_PASSWORD);
  const splitValues = [
    host,
    trimmed(env.AIDENID_CONTROL_PLANE_DATABASE_PORT),
    trimmed(env.AIDENID_CONTROL_PLANE_DATABASE_NAME),
    trimmed(env.AIDENID_CONTROL_PLANE_DATABASE_USER),
    password,
    trimmed(env.AIDENID_CONTROL_PLANE_DATABASE_SSLMODE),
    trimmed(env.AIDENID_CONTROL_PLANE_DATABASE_SSLROOTCERT)
  ];
  if (splitValues.every((value) => value === undefined)) {
    return undefined;
  }
  if (host === undefined || password === undefined) {
    throw new Error("split control-plane database configuration requires AIDENID_CONTROL_PLANE_DATABASE_HOST and _PASSWORD");
  }

  const url = new URL("postgresql://aidenid@localhost/postgres");
  url.hostname = host;
  url.port = trimmed(env.AIDENID_CONTROL_PLANE_DATABASE_PORT) ?? "5432";
  url.username = trimmed(env.AIDENID_CONTROL_PLANE_DATABASE_USER) ?? "aidenid";
  url.password = password;
  url.pathname = `/${trimmed(env.AIDENID_CONTROL_PLANE_DATABASE_NAME) ?? "postgres"}`;
  url.searchParams.set("sslmode", trimmed(env.AIDENID_CONTROL_PLANE_DATABASE_SSLMODE) ?? "require");
  const sslRootCert = trimmed(env.AIDENID_CONTROL_PLANE_DATABASE_SSLROOTCERT);
  if (sslRootCert !== undefined) {
    url.searchParams.set("sslrootcert", sslRootCert);
  }
  return url.toString();
}

function integerEnv(env: Record<string, string | undefined>, name: string, fallback: number, min: number, max: number): number {
  const value = trimmed(env[name]);
  if (value === undefined) {
    return fallback;
  }
  const parsed = Number.parseInt(value, 10);
  if (!Number.isInteger(parsed) || parsed < min || parsed > max) {
    throw new Error(`${name} must be an integer between ${min} and ${max}`);
  }
  return parsed;
}

function booleanEnv(env: Record<string, string | undefined>, name: string, fallback: boolean): boolean {
  const value = trimmed(env[name]);
  if (value === undefined) {
    return fallback;
  }
  if (/^(1|true|yes)$/i.test(value)) {
    return true;
  }
  if (/^(0|false|no)$/i.test(value)) {
    return false;
  }
  throw new Error(`${name} must be true or false`);
}

async function createOutboxPublisher(
  app: FastifyInstance,
  outboxStore: InMemoryOutboxStore,
  options: CreateControlPlaneOptions
): Promise<StoreBackedOutboxPublisher> {
  const streamName = options.outboxRedisStreamName ?? trimmed(process.env.AIDENID_CONTROL_PLANE_OUTBOX_REDIS_STREAM) ?? "aidenid:outbox";
  if (options.outboxRedisClient !== undefined) {
    return new StoreBackedOutboxPublisher(outboxStore, new RedisStreamsOutboxPublisher(options.outboxRedisClient, streamName));
  }

  const redisHost = trimmed(process.env.AIDENID_REDIS_HOST);
  if (redisHost === undefined) {
    if (requiresPersistentControlPlaneOutbox()) {
      throw new Error(
        "AIDENID_REDIS_HOST is required for the production control-plane outbox; set AIDENID_ALLOW_IN_MEMORY_CONTROL_PLANE_OUTBOX=true only for explicit local/demo runs"
      );
    }
    return new StoreBackedOutboxPublisher(outboxStore);
  }

  const authToken = trimmed(process.env.AIDENID_REDIS_AUTH_TOKEN);
  if (authToken === undefined && process.env.NODE_ENV?.trim().toLowerCase() === "production") {
    throw new Error("AIDENID_REDIS_AUTH_TOKEN is required with AIDENID_REDIS_HOST in production");
  }

  const client = new ControlPlaneRedisStreamsClient({
    host: redisHost,
    port: integerEnv(process.env, "AIDENID_REDIS_PORT", 6379, 1, 65_535),
    tls: booleanEnv(process.env, "AIDENID_REDIS_TLS", process.env.NODE_ENV?.trim().toLowerCase() === "production"),
    authToken,
    connectTimeoutMs: integerEnv(process.env, "AIDENID_REDIS_CONNECT_TIMEOUT_MS", 1_000, 1, 60_000),
    commandTimeoutMs: integerEnv(process.env, "AIDENID_REDIS_COMMAND_TIMEOUT_MS", 1_000, 1, 60_000)
  });
  try {
    await client.ping();
  } catch (error) {
    await client.close().catch(() => undefined);
    throw new Error(`control-plane Redis outbox unavailable: ${error instanceof Error ? error.message : String(error)}`);
  }
  app.addHook("onClose", async () => {
    await client.close();
  });
  return new StoreBackedOutboxPublisher(outboxStore, new RedisStreamsOutboxPublisher(client, streamName));
}

function startDecisionOutboxRetention(app: FastifyInstance, store: ControlPlaneStore, options: CreateControlPlaneOptions): void {
  const retentionDays = options.decisionOutboxRetentionDays ?? 7;
  const intervalMs = options.decisionOutboxRetentionIntervalMs ?? 24 * 60 * 60 * 1000;
  if (retentionDays <= 0 || intervalMs <= 0) {
    return;
  }
  const prune = () => {
    const cutoff = new Date(Date.now() - retentionDays * 24 * 60 * 60 * 1000).toISOString();
    void Promise.resolve(store.pruneDecisionOutboxBefore(cutoff)).catch((error: unknown) => {
      app.log.warn({ error }, "decision outbox retention prune failed");
    });
  };
  prune();
  const timer = setInterval(prune, intervalMs);
  timer.unref?.();
  app.addHook("onClose", async () => {
    clearInterval(timer);
  });
}

export async function createControlPlaneRuntime(options: CreateControlPlaneOptions = {}): Promise<ControlPlaneRuntime> {
  const app = fastify({ logger: options.logger ?? controlPlaneLoggerEnabled() });
  const outboxStore = new InMemoryOutboxStore();
  const store = await createDefaultStore(app, options);
  const outbox = await createOutboxPublisher(app, outboxStore, options);
  const issuer = options.issuer ?? "https://api.aidenid.local";
  const services: ControlPlaneServices = {
    store,
    outbox,
    killSwitch: options.killSwitch ?? new InMemoryKillSwitchController(),
    personaAudit: options.personaAudit ?? new InMemoryPersonaAuditController(),
    webhookSecrets: options.webhookSecrets ?? new EnvironmentWebhookSecretResolver(),
    decisionReceipts:
      options.decisionReceipts ??
      new RegistryBackedDecisionReceiptIssuer({
        signer: localDecisionReceiptIssuerFromEnvironment({ issuer }),
        store,
        allowActiveKeyRotation: booleanEnv(process.env, "AIDENID_DECISION_RECEIPT_ALLOW_ACTIVE_KEY_ROTATION", false)
      }),
    issuer,
    sessionTtlSeconds: options.sessionTtlSeconds ?? 90,
    sessionSigner: sessionSignerFromOptions(options)
  };
  startDecisionOutboxRetention(app, services.store, options);

  // Registered before ANY route so its onRoute collector observes every route
  // (onRoute is not retroactive), then asserts manifest<->route coverage at
  // onReady. Gated with the guard so it only fails startup where enforcement runs.
  if (process.env.AIDENID_ROUTE_ACCESS_GUARD_ENABLED === "true") {
    assertRouteAccessManifestCoverage(app);
  }

  app.get("/healthz", async () => ({ ok: true, service: "aidenid-control-plane" }));
  app.get("/readyz", async (_request, reply) => {
    try {
      await services.store.latestDecisionOutboxSeq();
      await services.store.listDecisionOutboxAfter(0, 1);
    } catch (error) {
      app.log.error({ error }, "control-plane readiness decision outbox check failed");
      return reply.code(503).send({
        ok: false,
        service: "aidenid-control-plane",
        error: "decision_outbox_unavailable"
      });
    }
    return {
      ok: true,
      service: "aidenid-control-plane",
      decisionOutboxAvailable: true
    };
  });

  await registerCorrelationPlugin(app);
  await registerOperatorAuthPlugin(app, {
    entries: options.operatorAuth?.entries,
    env: options.operatorAuth?.env ?? process.env.AIDENID_OPERATOR_TOKENS,
    servicePrincipalOverrides:
      options.operatorAuth?.servicePrincipalOverrides ?? process.env.AIDENID_OPERATOR_SERVICE_PRINCIPALS
  });
  // Deny-by-default route authorization. Registered AFTER the operator-auth
  // annotation hook so request.operatorAuth is already populated. Flag-gated for
  // the WAF-containment migration: the WAF fail-closes the /v1 surface until this
  // guard is enabled atomically with the verifier service-principal re-scope and
  // before WAF removal (see routeAccessManifest.ts / AUTH-1 sequencing).
  if (process.env.AIDENID_ROUTE_ACCESS_GUARD_ENABLED === "true") {
    registerRouteAccessGuard(app, {
      allowTransitional: process.env.AIDENID_ROUTE_ACCESS_ALLOW_TRANSITIONAL === "true"
    });
  }
  await registerTargetRoutes(app, services);
  await registerGrantRoutes(app, services);
  await registerKillSwitchRoutes(app, services);
  await registerSessionRoutes(app, services);
  await registerRevokeRoutes(app, services);
  await registerDecisionRoutes(app, services);
  await registerOperatorRoutes(app, services);
  await registerIdentityRoutes(app, services);
  await registerPersonaAuditRoutes(app, services);
  await registerPolicyCopilotRoutes(app);
  await registerAdoptionRoutes(app, services);

  return { app, services, outboxStore };
}

export async function createControlPlaneApp(options: CreateControlPlaneOptions = {}): Promise<FastifyInstance> {
  return (await createControlPlaneRuntime(options)).app;
}
