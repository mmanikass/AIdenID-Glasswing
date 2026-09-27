import { createControlPlaneRuntime, type ControlPlaneRuntime } from "../app.js";
import type { DecisionRecord } from "../types.js";

const REQUIRED_SERVICE_ROLES = ["decision_ingest", "decision_status"] as const;
const DEFAULT_TIMEOUT_MS = 90_000;
const DEFAULT_POLL_INTERVAL_MS = 500;

export interface AuthActivationCanaryOptions {
  readonly requestId: string;
  readonly siteId: string;
  readonly serviceActorId: string;
  readonly timeoutMs?: number | undefined;
  readonly pollIntervalMs?: number | undefined;
  readonly env?: NodeJS.ProcessEnv | undefined;
  readonly createRuntime?: (() => Promise<ControlPlaneRuntime>) | undefined;
  readonly now?: (() => number) | undefined;
  readonly sleep?: ((ms: number) => Promise<void>) | undefined;
}

export interface AuthActivationCanaryResult {
  readonly event: "control_plane_auth_activation_canary_pass";
  readonly request_id: string;
  readonly site_id: string;
  readonly decision_id: string;
  readonly decision: string;
  readonly actor_class: string;
  readonly route_template: string;
  readonly anonymous_status: 401;
  readonly service_status: 200 | 202;
  readonly operator_read_status: 403;
  readonly public_metadata_status: 200;
  readonly guard_enabled: true;
  readonly transitional_access_enabled: false;
  readonly service_roles: readonly ["decision_ingest", "decision_status"];
}

function objectRecord(
  value: unknown,
  name: string,
): Readonly<Record<string, unknown>> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${name} must be a JSON object`);
  }
  return value as Readonly<Record<string, unknown>>;
}

function parseJsonObject(
  raw: string | undefined,
  name: string,
): Readonly<Record<string, unknown>> {
  if (raw === undefined || raw.trim().length === 0) {
    throw new Error(`${name} is required`);
  }
  try {
    return objectRecord(JSON.parse(raw) as unknown, name);
  } catch (error) {
    if (error instanceof SyntaxError) {
      throw new Error(`${name} must contain valid JSON`, { cause: error });
    }
    throw error;
  }
}

function boundedIdentifier(
  value: string,
  name: string,
  pattern: RegExp,
): string {
  const normalized = value.trim();
  if (!pattern.test(normalized)) {
    throw new Error(`${name} has an invalid format`);
  }
  return normalized;
}

function integerOption(
  value: number | undefined,
  fallback: number,
  name: string,
  min: number,
  max: number,
): number {
  const resolved = value ?? fallback;
  if (!Number.isInteger(resolved) || resolved < min || resolved > max) {
    throw new Error(`${name} must be an integer between ${min} and ${max}`);
  }
  return resolved;
}

function exactServiceRoles(
  value: unknown,
): readonly ["decision_ingest", "decision_status"] {
  if (!Array.isArray(value) || value.some((role) => typeof role !== "string")) {
    throw new Error("verifier service-principal roles must be an array");
  }
  const unique = [...new Set(value as readonly string[])].sort();
  if (
    unique.length !== 2 ||
    unique[0] !== "decision_ingest" ||
    unique[1] !== "decision_status"
  ) {
    throw new Error(
      "verifier service principal must have exactly decision_ingest and decision_status roles",
    );
  }
  return REQUIRED_SERVICE_ROLES;
}

function activationServiceToken(
  env: NodeJS.ProcessEnv,
  serviceActorId: string,
): string {
  const registry = parseJsonObject(
    env.AIDENID_OPERATOR_TOKENS,
    "AIDENID_OPERATOR_TOKENS",
  );
  const candidate = registry[serviceActorId];
  if (
    typeof candidate !== "string" ||
    candidate.trim().length < 16 ||
    /\s/.test(candidate)
  ) {
    throw new Error(
      `AIDENID_OPERATOR_TOKENS must contain one bounded bare token for ${serviceActorId}`,
    );
  }
  return candidate.trim();
}

function assertActivationPolicy(
  env: NodeJS.ProcessEnv,
  serviceActorId: string,
): string {
  if (env.AIDENID_ROUTE_ACCESS_GUARD_ENABLED !== "true") {
    throw new Error("AIDENID_ROUTE_ACCESS_GUARD_ENABLED must be exactly true");
  }
  if (env.AIDENID_ROUTE_ACCESS_ALLOW_TRANSITIONAL !== "false") {
    throw new Error(
      "AIDENID_ROUTE_ACCESS_ALLOW_TRANSITIONAL must be exactly false",
    );
  }

  const overrides = parseJsonObject(
    env.AIDENID_OPERATOR_SERVICE_PRINCIPALS,
    "AIDENID_OPERATOR_SERVICE_PRINCIPALS",
  );
  const override = objectRecord(
    overrides[serviceActorId],
    `service-principal override for ${serviceActorId}`,
  );
  if ((override.principal_kind ?? override.principalKind) !== "service") {
    throw new Error(
      `service-principal override for ${serviceActorId} must set principal_kind to service`,
    );
  }
  exactServiceRoles(override.service_roles ?? override.serviceRoles);
  return activationServiceToken(env, serviceActorId);
}

async function waitForDecision(
  runtime: ControlPlaneRuntime,
  siteId: string,
  requestId: string,
  timeoutMs: number,
  pollIntervalMs: number,
  now: () => number,
  sleep: (ms: number) => Promise<void>,
): Promise<DecisionRecord> {
  const deadline = now() + timeoutMs;
  while (true) {
    const decision = await runtime.services.store.findDecisionByRequestId(
      siteId,
      requestId,
    );
    if (decision !== undefined) {
      return decision;
    }
    const remaining = deadline - now();
    if (remaining <= 0) {
      throw new Error(`timed out waiting for persisted decision ${requestId}`);
    }
    await sleep(Math.min(pollIntervalMs, remaining));
  }
}

function responseError(
  response: { readonly statusCode: number },
  expected: string,
): Error {
  return new Error(`${expected}; got HTTP ${response.statusCode}`);
}

export async function runControlPlaneAuthActivationCanary(
  options: AuthActivationCanaryOptions,
): Promise<AuthActivationCanaryResult> {
  const env = options.env ?? process.env;
  const requestId = boundedIdentifier(
    options.requestId,
    "requestId",
    /^[A-Za-z0-9_][A-Za-z0-9_.:-]{0,127}$/,
  );
  const siteId = boundedIdentifier(
    options.siteId,
    "siteId",
    /^sit_[A-Za-z0-9_-]{1,124}$/,
  );
  const serviceActorId = boundedIdentifier(
    options.serviceActorId,
    "serviceActorId",
    /^[A-Za-z0-9_.:-]{1,128}$/,
  );
  const timeoutMs = integerOption(
    options.timeoutMs,
    DEFAULT_TIMEOUT_MS,
    "timeoutMs",
    1_000,
    120_000,
  );
  const pollIntervalMs = integerOption(
    options.pollIntervalMs,
    DEFAULT_POLL_INTERVAL_MS,
    "pollIntervalMs",
    10,
    5_000,
  );
  const serviceToken = assertActivationPolicy(env, serviceActorId);
  const runtime = await (
    options.createRuntime ??
    (() =>
      createControlPlaneRuntime({
        logger: false,
        decisionOutboxRetentionDays: 0,
      }))
  )();

  try {
    await runtime.app.ready();
    const decision = await waitForDecision(
      runtime,
      siteId,
      requestId,
      timeoutMs,
      pollIntervalMs,
      options.now ?? Date.now,
      options.sleep ??
        ((ms) => new Promise((resolve) => setTimeout(resolve, ms))),
    );
    const awaitUrl = `/v1/decisions/${encodeURIComponent(decision.id)}/await?timeout_ms=1`;

    const anonymous = await runtime.app.inject({
      method: "GET",
      url: awaitUrl,
    });
    if (
      anonymous.statusCode !== 401 ||
      anonymous.json<{ error?: string }>().error !== "operator_auth_required"
    ) {
      throw responseError(
        anonymous,
        "anonymous decision-status access must fail with operator_auth_required/401",
      );
    }

    const service = await runtime.app.inject({
      method: "GET",
      url: awaitUrl,
      headers: { authorization: `Bearer ${serviceToken}` },
    });
    if (service.statusCode !== 200 && service.statusCode !== 202) {
      throw responseError(
        service,
        "verifier service principal must have decision_status access",
      );
    }
    const serviceBody = service.json<{
      decision?: { request_id?: string; site_id?: string };
    }>();
    if (
      serviceBody.decision?.request_id !== requestId ||
      serviceBody.decision.site_id !== siteId
    ) {
      throw new Error(
        "decision-status response did not match the exact persisted verifier request",
      );
    }

    const operatorRead = await runtime.app.inject({
      method: "GET",
      url: `/v1/decisions?site_id=${encodeURIComponent(siteId)}&limit=1`,
      headers: { authorization: `Bearer ${serviceToken}` },
    });
    if (
      operatorRead.statusCode !== 403 ||
      operatorRead.json<{ error?: string }>().error !== "operator_forbidden"
    ) {
      throw responseError(
        operatorRead,
        "verifier service principal must be forbidden from operator decision reads",
      );
    }

    const publicMetadata = await runtime.app.inject({
      method: "GET",
      url: "/v1/mcp/protected-resource-metadata",
    });
    if (publicMetadata.statusCode !== 200) {
      throw responseError(
        publicMetadata,
        "public MCP metadata must remain public at the application guard",
      );
    }

    return {
      event: "control_plane_auth_activation_canary_pass",
      request_id: requestId,
      site_id: siteId,
      decision_id: decision.id,
      decision: decision.decision,
      actor_class: decision.actorClass,
      route_template: decision.routeTemplate,
      anonymous_status: 401,
      service_status: service.statusCode,
      operator_read_status: 403,
      public_metadata_status: 200,
      guard_enabled: true,
      transitional_access_enabled: false,
      service_roles: REQUIRED_SERVICE_ROLES,
    };
  } finally {
    await runtime.app.close();
  }
}
