import { randomBytes, randomUUID, createHash } from "node:crypto";

import { exchangeSession, mintAgentKey, type AgentKeyMaterial, type ExchangedSession, type FetchLike } from "@aidenid/agent-client";
import { createControlPlaneRuntime, withChainAuthority } from "@aidenid/control-plane";
import { decodeCompactJwt, MemoryReplayCache } from "@aidenid/crypto";
import {
  assess,
  composeWithJev,
  createAnthropicJevProvider,
  PURPOSE_FIT_RUBRIC_V1,
  type JevProvider
} from "@aidenid/jev";
import { parsePolicyYaml } from "@aidenid/policy-engine";
import {
  aidenidFastifyPlugin,
  createControlPlaneDecisionOverride,
  type DecisionEmitterFetch,
  type DecisionResult,
  type ReasonCode
} from "@aidenid/verifier-node";
import fastify, { type FastifyInstance, type FastifyRequest } from "fastify";

const DEMO_SITE_ID = "sit_glasswing_demo";
const DEMO_TENANT_ID = "ten_glasswing_demo";
const DEMO_SUBJECT = "agent:gpt-luna-xh";
const DEMO_ORIGIN = "https://aidenid.local";
const CONTROL_PLANE_URL = "https://control-plane.aidenid.local";
const DEMO_ITEM_ID = "demo-item";
const DEMO_OPERATOR_ACTOR_ID = "glasswing_demo_operator";

const ROUTES = {
  catalog: { path: "/catalog", method: "GET", permissions: ["catalog:read"] },
  reserve: { path: `/items/${DEMO_ITEM_ID}/reserve`, method: "POST", permissions: ["items:reserve"] },
  customerExport: { path: "/customers/export", method: "GET", permissions: ["customers:export"] },
  reports: { path: "/reports/bulk", method: "GET", permissions: ["reports:bulk"] }
} as const;

export type DemoGrantName = keyof typeof ROUTES;

export interface ProtectedSiteOptions {
  readonly siteId?: string | undefined;
  readonly operatorToken?: string | undefined;
  readonly jevProvider?: JevProvider | null | undefined;
  readonly logger?: boolean | undefined;
  readonly sessionTtlSeconds?: number | undefined;
}

export interface DemoGrant {
  readonly id: string;
  readonly chain_id: string;
  readonly site_id: string;
  readonly resource: string;
  readonly permissions: readonly string[];
}

export interface ProtectedSiteDemoAgent {
  readonly key: AgentKeyMaterial;
  readonly sessions: Readonly<Record<DemoGrantName, ExchangedSession>>;
  readonly grants: Readonly<Record<DemoGrantName, DemoGrant>>;
}

export interface ProtectedSiteRuntime {
  readonly app: FastifyInstance;
  readonly siteId: string;
  readonly origin: string;
  /** Server-side credential for scoped control-plane setup and dashboard integration. */
  readonly operatorToken: string;
  readonly controlPlane: Awaited<ReturnType<typeof createControlPlaneRuntime>>;
  /** Local demo credentials are returned to the host process; the site never serves them. */
  readonly demoAgent: ProtectedSiteDemoAgent;
  close(): Promise<void>;
}

declare module "fastify" {
  interface FastifyRequest {
    aidenid?: DecisionResult | undefined;
  }
}

function policyFor(siteId: string): string {
  return `
version: 1
site_id: ${siteId}
mode: enforce
defaults:
  strict: true
  on_degraded: deny
  rate: { capacity: 100, refill_per_sec: 10, cost: 1 }
routes:
  - template: /healthz
    method: GET
    per_actor_class:
      verified_agent: { decision: allow }
      signed_agent: { decision: allow }
      likely_human: { decision: allow }
      suspicious_automation: { decision: allow }
      unknown: { decision: allow }
  - template: /catalog
    method: GET
    strict: true
    on_degraded: deny
    signature_required: ["@method", "@target-uri", "authorization", "dpop"]
    required_permissions: ["catalog:read"]
    per_actor_class:
      verified_agent: { decision: allow }
      signed_agent: { decision: deny }
      likely_human: { decision: deny }
      suspicious_automation: { decision: deny }
      unknown: { decision: deny }
  - template: /items/:id/reserve
    method: POST
    strict: true
    on_degraded: deny
    signature_required: ["@method", "@target-uri", "authorization", "dpop"]
    required_permissions: ["items:reserve"]
    per_actor_class:
      verified_agent: { decision: allow }
      signed_agent: { decision: deny }
      likely_human: { decision: deny }
      suspicious_automation: { decision: deny }
      unknown: { decision: deny }
  - template: /customers/export
    method: GET
    strict: true
    on_degraded: deny
    per_actor_class:
      verified_agent: { decision: deny }
      signed_agent: { decision: deny }
      likely_human: { decision: deny }
      suspicious_automation: { decision: deny }
      unknown: { decision: deny }
  - template: /reports/bulk
    method: GET
    strict: true
    on_degraded: deny
    signature_required: ["@method", "@target-uri", "authorization", "dpop"]
    required_permissions: ["reports:bulk"]
    allowed_purposes: [research, compare]
    per_actor_class:
      verified_agent: { decision: allow }
      signed_agent: { decision: deny }
      likely_human: { decision: deny }
      suspicious_automation: { decision: deny }
      unknown: { decision: deny }
  - template: /**
    method: "*"
    strict: true
    on_degraded: deny
    per_actor_class:
      verified_agent: { decision: deny }
      signed_agent: { decision: deny }
      likely_human: { decision: deny }
      suspicious_automation: { decision: deny }
      unknown: { decision: deny }
`;
}

function headerObject(headers: RequestInit["headers"]): Record<string, string> {
  const result: Record<string, string> = {};
  new Headers(headers).forEach((value, key) => {
    result[key] = value;
  });
  return result;
}

function responseHeaders(headers: Readonly<Record<string, string | number | readonly string[] | undefined>>): Headers {
  const result = new Headers();
  for (const [name, value] of Object.entries(headers)) {
    if (value === undefined) {
      continue;
    }
    for (const item of Array.isArray(value) ? value : [value]) {
      result.append(name, String(item));
    }
  }
  return result;
}

async function fastifyFetch(app: FastifyInstance, input: string, init: RequestInit = {}): Promise<Response> {
  const url = new URL(input);
  const result = await app.inject({
    method: (init.method ?? "GET") as "GET" | "POST",
    url: `${url.pathname}${url.search}`,
    headers: headerObject(init.headers),
    ...(typeof init.body === "string" ? { payload: init.body } : {})
  });
  return new Response(result.statusCode === 204 || result.statusCode === 304 ? null : result.body, {
    status: result.statusCode,
    headers: responseHeaders(result.headers)
  });
}

function decisionEmitterFetch(app: FastifyInstance): DecisionEmitterFetch {
  return async (input, init) => {
    const requestInit: RequestInit = {
      method: init.method,
      headers: init.headers,
      signal: init.signal,
      ...(init.body === undefined ? {} : { body: init.body })
    };
    const response = await fastifyFetch(app, input, requestInit);
    return { ok: response.ok, status: response.status, text: () => response.text() };
  };
}

function requireJson<T>(response: Response, action: string): Promise<T> {
  if (!response.ok) {
    return response.text().then((body) => {
      throw new Error(`${action} failed with HTTP ${response.status}: ${body.slice(0, 240)}`);
    });
  }
  return response.json() as Promise<T>;
}

function bearer(token: string): string {
  return `Bearer ${token}`;
}

function actionDigest(decision: DecisionResult, resource: string, permissions: readonly string[]): string {
  const action = JSON.stringify({
    method: decision.method,
    route_template: decision.routeTemplate,
    resource,
    permissions
  });
  return createHash("sha256").update(action, "utf8").digest("hex");
}

function authorityReason(reason: string): ReasonCode {
  if (reason === "epoch_stale") {
    return "epoch_stale";
  }
  if (reason === "grant_expired") {
    return "token_expired";
  }
  if (reason === "chain_busy" || reason === "lease_backend_unsupported") {
    return "strict_route_degraded";
  }
  return "revoked";
}

function sessionAuthority(request: FastifyRequest, grant: DemoGrant): { readonly chainId: string; readonly tokenRevocationEpoch: number } | undefined {
  const authorization = request.headers.authorization;
  if (typeof authorization !== "string") {
    return undefined;
  }
  const match = authorization.match(/^DPoP\s+(.+)$/i);
  if (match?.[1] === undefined) {
    return undefined;
  }
  try {
    const payload = decodeCompactJwt(match[1]).payload;
    const chainId = payload.chain_id;
    const epoch = payload.revocation_epoch;
    if (
      payload.grant_id !== grant.id ||
      payload.site_id !== grant.site_id ||
      payload.aud !== grant.site_id ||
      payload.resource !== grant.resource ||
      typeof chainId !== "string" ||
      chainId !== grant.chain_id ||
      typeof epoch !== "number" ||
      !Number.isSafeInteger(epoch)
    ) {
      return undefined;
    }
    return { chainId, tokenRevocationEpoch: epoch };
  } catch {
    return undefined;
  }
}

function jsonStringHeader(request: FastifyRequest, name: string): string | undefined {
  const value = request.headers[name.toLowerCase()];
  if (typeof value === "string") {
    return value;
  }
  return Array.isArray(value) && typeof value[0] === "string" ? value[0] : undefined;
}

export async function createProtectedSiteRuntime(options: ProtectedSiteOptions = {}): Promise<ProtectedSiteRuntime> {
  const siteId = options.siteId ?? DEMO_SITE_ID;
  if (!/^sit_[A-Za-z0-9_-]+$/.test(siteId)) {
    throw new Error("protected-site siteId must be a valid sit_ identifier");
  }
  const operatorToken = options.operatorToken ?? randomBytes(32).toString("base64url");
  const controlPlane = await createControlPlaneRuntime({
    issuer: CONTROL_PLANE_URL,
    sessionTtlSeconds: options.sessionTtlSeconds ?? 600,
    operatorAuth: {
      entries: [
        {
          actorId: DEMO_OPERATOR_ACTOR_ID,
          token: operatorToken,
          roles: ["admin", "decision_operator", "decision_search"],
          sites: [siteId]
        }
      ]
    }
  });

  try {
    const app = fastify({
      logger: options.logger ?? false,
      genReqId: () => `req_${randomUUID()}`
    });
    const cpFetch: FetchLike = (input, init) => fastifyFetch(controlPlane.app, input, init);
    const operatorHeaders = { authorization: bearer(operatorToken) };
    const target = await requireJson<{ id: string }>(
      await cpFetch(`${CONTROL_PLANE_URL}/v1/targets`, {
        method: "POST",
        headers: { ...operatorHeaders, "content-type": "application/json" },
        body: JSON.stringify({ tenant_id: DEMO_TENANT_ID, site_id: siteId, name: "Glasswing Demo Shop", origin: DEMO_ORIGIN })
      }),
      "demo target creation"
    );

    const grants = {} as Record<DemoGrantName, DemoGrant>;
    for (const [name, route] of Object.entries(ROUTES) as Array<[DemoGrantName, (typeof ROUTES)[DemoGrantName]]>) {
      grants[name] = await requireJson<DemoGrant>(
        await cpFetch(`${CONTROL_PLANE_URL}/v1/grants`, {
          method: "POST",
          headers: { ...operatorHeaders, "content-type": "application/json" },
          body: JSON.stringify({
            target_id: target.id,
            subject: DEMO_SUBJECT,
            resource: `${DEMO_ORIGIN}${route.path}`,
            permissions: route.permissions,
            expires_in_seconds: 3_600
          })
        }),
        `demo ${name} grant creation`
      );
    }

    const agentKey = mintAgentKey("agk_glasswing_demo");
    const sessions = {} as Record<DemoGrantName, ExchangedSession>;
    for (const name of Object.keys(ROUTES) as DemoGrantName[]) {
      const grant = grants[name];
      sessions[name] = await exchangeSession(agentKey, {
        controlPlaneUrl: CONTROL_PLANE_URL,
        grantId: grant.id,
        audience: siteId,
        resource: grant.resource,
        requestedPermissions: grant.permissions,
        llmBrand: "openai",
        fetchImpl: cpFetch
      });
    }

    const policy = parsePolicyYaml(policyFor(siteId));
    const replayCache = new MemoryReplayCache({ maxEntries: 10_000 });
    const jevProvider = options.jevProvider === null ? undefined : (options.jevProvider ?? createAnthropicJevProvider());
    const jevCache = new Map();
    const purposeTextByRequestId = new Map<string, string>();
    const emitter = createControlPlaneDecisionOverride({
      controlPlaneUrl: CONTROL_PLANE_URL,
      apiKey: operatorToken,
      fetcher: decisionEmitterFetch(controlPlane.app),
      awaitTimeoutMs: 100,
      failClosed: true
    });

    app.addHook("onRequest", async (request) => {
      // Decision correlation is generated by the server. The agent's optional request id is
      // not signed and must not let one request borrow another request's Jev input.
      request.headers["x-request-id"] = request.id;
      if (request.url.split("?", 1)[0] === ROUTES.reports.path) {
        purposeTextByRequestId.set(request.id, jsonStringHeader(request, "x-aidenid-purpose-text") ?? "");
      }
    });
    app.addHook("onResponse", async (request) => {
      purposeTextByRequestId.delete(request.id);
    });

    const decisionOverride = async (decision: DecisionResult): Promise<DecisionResult | undefined> => {
      let composedDecision = decision;
      if (decision.routeTemplate === ROUTES.reports.path && decision.actorClass === "verified_agent" && decision.decision === "allow") {
        const grant = grants.reports;
        const assessment = await assess(
          {
            rubric: PURPOSE_FIT_RUBRIC_V1,
            scope: {
              tenantId: DEMO_TENANT_ID,
              siteId,
              subject: decision.subjectHandle ?? DEMO_SUBJECT,
              grantId: grant.id,
              policyVersion: "glasswing-demo-v1",
              action: `${decision.method} ${decision.routeTemplate}`,
              resource: grant.resource,
              permissions: grant.permissions
            },
            purposeText:
              purposeTextByRequestId.get(decision.requestId)?.trim() || decision.purpose || "",
            actionDigest: actionDigest(decision, grant.resource, grant.permissions),
            mandatory: true
          },
          { provider: jevProvider, cache: jevCache }
        );
        const composed = composeWithJev({ action: decision.decision, reasonCodes: decision.reasons }, assessment);
        composedDecision = {
          ...decision,
          decision: composed.action,
          // Preserve the deterministic policy result so the dashboard can show why a queue
          // was added on top of the policy allow.
          recommendedDecision: decision.recommendedDecision,
          reasons: composed.reasonCodes as ReasonCode[],
          responseHeaders: {
            ...decision.responseHeaders,
            "X-AIdenID-JEV-Status": assessment.verificationStatus,
            "X-AIdenID-JEV-Obligation": assessment.obligation
          }
        };
      }
      return (await emitter(composedDecision)) ?? composedDecision;
    };

    const verifier = aidenidFastifyPlugin({
      siteId,
      apiKey: operatorToken,
      mode: "enforce",
      crypto: {
        sessionTokenPublicJwksByIssuer: {
          [controlPlane.services.issuer]: controlPlane.services.sessionSigner.publicJwk
        },
        httpMessageSignaturePublicJwksByKeyId: { [agentKey.keyId]: agentKey.publicJwk },
        issuerKeyStatesByIssuer: {
          [controlPlane.services.issuer]: { [controlPlane.services.sessionSigner.kid]: "trusted" }
        },
        replayCache,
        requireHttpSignatureNonce: true
      },
      policy: { trie: policy.trie },
      decisionOverride
    });
    await verifier(app);

    const reservations = new Set<string>();
    app.get("/healthz", async () => ({ status: "ok", site_id: siteId }));
    app.get("/catalog", async (_request, reply) => {
      return reply.send({ items: [{ id: DEMO_ITEM_ID, name: "Glasswing Widget", available: !reservations.has(DEMO_ITEM_ID) }] });
    });
    app.post<{ Params: { id: string } }>("/items/:id/reserve", async (request, reply) => {
      const decision = request.aidenid;
      const authority = sessionAuthority(request, grants.reserve);
      if (decision === undefined || authority === undefined) {
        return reply.code(403).send({ error: "session_authority_invalid" });
      }

      const gated = await withChainAuthority(
        controlPlane.services,
        { chainId: authority.chainId, tokenRevocationEpoch: authority.tokenRevocationEpoch },
        async () => {
          if (request.params.id !== DEMO_ITEM_ID) {
            return { statusCode: 404 as const, body: { error: "item_not_found" } };
          }
          if (reservations.has(request.params.id)) {
            return { statusCode: 409 as const, body: { error: "item_already_reserved" } };
          }
          reservations.add(request.params.id);
          return { statusCode: 201 as const, body: { item_id: request.params.id, status: "reserved" } };
        }
      );

      if (!gated.ok) {
        const reason = authorityReason(gated.reason);
        await decisionOverride({
          ...decision,
          decision: "deny",
          reasons: [reason],
          responseHeaders: { ...decision.responseHeaders, "X-AIdenID-Decision": "deny" }
        });
        const statusCode = gated.reason === "chain_busy" ? 503 : 403;
        return reply.code(statusCode).send({ error: reason, request_id: decision.requestId });
      }
      return reply.code(gated.value.statusCode).send(gated.value.body);
    });
    app.get<{ Params: { id: string } }>("/items/:id/reserve", async (_request, reply) => {
      return reply.code(500).send({ error: "method_substitution_handler_should_not_run" });
    });
    app.get("/customers/export", async (_request, reply) => {
      return reply.code(500).send({ error: "denied_route_handler_should_not_run" });
    });
    app.get("/reports/bulk", async (_request, reply) => {
      return reply.send({ rows: [{ day: "2026-09-27", orders: 3 }] });
    });

    app.addHook("onClose", async () => {
      await controlPlane.app.close();
    });

    return {
      app,
      siteId,
      origin: DEMO_ORIGIN,
      operatorToken,
      controlPlane,
      demoAgent: { key: agentKey, sessions, grants },
      close: () => app.close()
    };
  } catch (error) {
    await controlPlane.app.close();
    throw error;
  }
}

export const protectedSiteDemo = {
  siteId: DEMO_SITE_ID,
  tenantId: DEMO_TENANT_ID,
  subject: DEMO_SUBJECT,
  origin: DEMO_ORIGIN,
  controlPlaneUrl: CONTROL_PLANE_URL,
  itemId: DEMO_ITEM_ID
} as const;
