import { randomBytes, randomUUID, createHash, timingSafeEqual } from "node:crypto";

import { exchangeSession, mintAgentKey, signedFetch, type AgentKeyMaterial, type ExchangedSession, type FetchLike } from "@aidenid/agent-client";
import { createControlPlaneRuntime, withChainAuthority } from "@aidenid/control-plane";
import { decodeCompactJwt, MemoryReplayCache } from "@aidenid/crypto";
import {
  assess,
  composeWithJev,
  createAnthropicJevProvider,
  PURPOSE_FIT_RUBRIC_V1,
  type JevAssessment,
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
import fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from "fastify";

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

const TASKS: Readonly<Record<GlasswingTask, { readonly path: string; readonly method: "GET" | "POST"; readonly permission: string }>> = {
  catalog: { path: ROUTES.catalog.path, method: "GET", permission: ROUTES.catalog.permissions[0] },
  reserve: { path: ROUTES.reserve.path, method: "POST", permission: ROUTES.reserve.permissions[0] },
  export: { path: ROUTES.customerExport.path, method: "GET", permission: ROUTES.customerExport.permissions[0] },
  "bulk-report": { path: ROUTES.reports.path, method: "GET", permission: ROUTES.reports.permissions[0] }
};

const REPORT_ROWS = [{ day: "2026-09-27", orders: 3 }] as const;

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
  readonly expires_at: string;
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
  /** In-memory report jobs released by human approval; exposed only to the local host/test process. */
  readonly releasedReports: readonly ReleasedReport[];
  close(): Promise<void>;
}

export type GlasswingTask = "catalog" | "reserve" | "export" | "bulk-report";

export interface PublicAgent {
  readonly id: string;
  readonly keyId: string;
  readonly thumbprint: string;
  readonly publicJwk: AgentKeyMaterial["publicJwk"];
  readonly createdAt: string;
}

export interface PublicReview {
  readonly id: string;
  readonly requestId: string;
  readonly agentId: string;
  readonly task: GlasswingTask;
  readonly purpose: string;
  readonly assessment: JevAssessment;
  readonly status: "pending" | "approved" | "denied";
}

export interface ReleasedReport {
  readonly id: string;
  readonly reviewId: string;
  readonly agentId: string;
  readonly grantId: string;
  readonly createdAt: string;
  readonly rows: readonly { readonly day: string; readonly orders: number }[];
}

interface ManagedAgent {
  readonly id: string;
  readonly subject: string;
  readonly key: AgentKeyMaterial;
  readonly createdAt: string;
}

interface ManagedGrant extends DemoGrant {
  readonly ownerAgentId: string;
}

interface RequestAuthorityContext {
  readonly agentId: string;
  readonly grant: ManagedGrant;
  readonly chainId: string;
  readonly tokenRevocationEpoch: number;
}

interface PendingReview extends Omit<PublicReview, "status"> {
  status: "pending" | "approved" | "denied";
  readonly context: RequestAuthorityContext;
  readonly originalDecision: DecisionResult;
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
  - template: /glasswing/**
    method: "*"
    strict: true
    on_degraded: deny
    per_actor_class:
      verified_agent: { decision: allow }
      signed_agent: { decision: allow }
      likely_human: { decision: allow }
      suspicious_automation: { decision: allow }
      unknown: { decision: allow }
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

/**
 * Route templates served to operators and probes rather than agents. They pass the policy
 * allow-all entry and are authenticated by the operator token in their handlers, so recording
 * them would bury the agent decisions the dashboard feed exists to show.
 */
function isOperatorSurface(routeTemplate: string): boolean {
  return routeTemplate === "/healthz" || routeTemplate === "/glasswing" || routeTemplate.startsWith("/glasswing/");
}

function bodyRecord(value: unknown): Readonly<Record<string, unknown>> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? (value as Readonly<Record<string, unknown>>) : undefined;
}

function isGlasswingTask(value: unknown): value is GlasswingTask {
  return typeof value === "string" && Object.hasOwn(TASKS, value);
}

function publicAgent(agent: ManagedAgent): PublicAgent {
  return {
    id: agent.id,
    keyId: agent.key.keyId,
    thumbprint: agent.key.thumbprint,
    publicJwk: agent.key.publicJwk,
    createdAt: agent.createdAt
  };
}

function publicGrant(grant: ManagedGrant) {
  return {
    id: grant.id,
    chainId: grant.chain_id,
    siteId: grant.site_id,
    resource: grant.resource,
    permissions: grant.permissions,
    expiresAt: grant.expires_at
  };
}

function publicReview(review: PendingReview): PublicReview {
  return {
    id: review.id,
    requestId: review.requestId,
    agentId: review.agentId,
    task: review.task,
    purpose: review.purpose,
    assessment: review.assessment,
    status: review.status
  };
}

function permissionRoute(permissions: readonly string[]): (typeof ROUTES)[DemoGrantName] | undefined {
  if (permissions.length === 0 || new Set(permissions).size !== permissions.length) {
    return undefined;
  }
  return Object.values(ROUTES).find(
    (route) => route.permissions.length === permissions.length && route.permissions.every((permission) => permissions.includes(permission))
  );
}

function authorizedOperator(request: FastifyRequest, expectedToken: string): boolean {
  const authorization = request.headers.authorization;
  if (typeof authorization !== "string") {
    return false;
  }
  const match = authorization.match(/^Bearer\s+(.+)$/i);
  if (match?.[1] === undefined) {
    return false;
  }
  const provided = Buffer.from(match[1], "utf8");
  const expected = Buffer.from(expectedToken, "utf8");
  return provided.length === expected.length && timingSafeEqual(provided, expected);
}

function requireOperator(request: FastifyRequest, reply: FastifyReply, expectedToken: string): boolean {
  if (authorizedOperator(request, expectedToken)) {
    return true;
  }
  reply.code(401).send({ error: { code: "operator_unauthorized", message: "A valid server-side operator token is required." } });
  return false;
}

function sendRunError(
  reply: FastifyReply,
  statusCode: number,
  request: { readonly method: string; readonly url: string },
  code: string,
  message: string
): void {
  reply.code(statusCode).send({
    request,
    session: null,
    decision: null,
    effect: null,
    jev: null,
    error: { code, message }
  });
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

    const demoAgentId = "glasswing_demo";
    const agentKey = mintAgentKey("agk_glasswing_demo");
    const demoAgent: ManagedAgent = { id: demoAgentId, subject: DEMO_SUBJECT, key: agentKey, createdAt: new Date().toISOString() };
    const agents = new Map<string, ManagedAgent>([[demoAgent.id, demoAgent]]);
    const managedGrants = new Map<string, ManagedGrant>();
    const grantOwners = new Map<string, string>();
    const httpPublicJwksByKeyId: Record<string, Record<string, unknown>> = { [agentKey.keyId]: agentKey.publicJwk };
    const createGrantForAgent = async (
      agent: ManagedAgent,
      resource: string,
      permissions: readonly string[],
      expiresInSeconds: number
    ): Promise<DemoGrant> => {
      const created = await requireJson<DemoGrant>(
        await cpFetch(`${CONTROL_PLANE_URL}/v1/grants`, {
          method: "POST",
          headers: { ...operatorHeaders, "content-type": "application/json" },
          body: JSON.stringify({
            target_id: target.id,
            subject: agent.subject,
            resource,
            permissions,
            expires_in_seconds: expiresInSeconds
          })
        }),
        "grant creation"
      );
      const managed = { ...created, ownerAgentId: agent.id };
      managedGrants.set(managed.id, managed);
      grantOwners.set(managed.id, agent.id);
      return created;
    };

    const grants = {} as Record<DemoGrantName, DemoGrant>;
    for (const [name, route] of Object.entries(ROUTES) as Array<[DemoGrantName, (typeof ROUTES)[DemoGrantName]]>) {
      grants[name] = await createGrantForAgent(demoAgent, `${DEMO_ORIGIN}${route.path}`, route.permissions, 3_600);
    }

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
    const requestAuthorities = new Map<string, RequestAuthorityContext>();
    const jevByRequestId = new Map<string, JevAssessment>();
    const reviews = new Map<string, PendingReview>();
    const releasedReports: ReleasedReport[] = [];
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
      const authorization = request.headers.authorization;
      if (typeof authorization === "string") {
        const match = authorization.match(/^DPoP\s+(.+)$/i);
        if (match?.[1] !== undefined) {
          try {
            const grantId = decodeCompactJwt(match[1]).payload.grant_id;
            const grant = typeof grantId === "string" ? managedGrants.get(grantId) : undefined;
            const authority = grant === undefined ? undefined : sessionAuthority(request, grant);
            const agentId = grant === undefined ? undefined : grantOwners.get(grant.id);
            if (grant !== undefined && authority !== undefined && agentId !== undefined) {
              requestAuthorities.set(request.id, { agentId, grant, ...authority });
            }
          } catch {
            // The verifier owns token validation; this map is only for site-side effect gating.
          }
        }
      }
      if (request.url.split("?", 1)[0] === ROUTES.reports.path) {
        purposeTextByRequestId.set(request.id, jsonStringHeader(request, "x-aidenid-purpose-text") ?? "");
      }
    });
    app.addHook("onResponse", async (request) => {
      purposeTextByRequestId.delete(request.id);
      requestAuthorities.delete(request.id);
    });
    app.addHook("onSend", async (request, reply, payload) => {
      if (request.aidenid !== undefined) {
        reply.header("X-AIdenID-Request-Id", request.aidenid.requestId);
      }
      return payload;
    });

    const decisionOverride = async (decision: DecisionResult): Promise<DecisionResult | undefined> => {
      if (isOperatorSurface(decision.routeTemplate)) {
        return decision;
      }
      let composedDecision = decision;
      const context = requestAuthorities.get(decision.requestId);
      if (
        decision.routeTemplate === ROUTES.reports.path &&
        decision.actorClass === "verified_agent" &&
        decision.decision === "allow" &&
        context !== undefined
      ) {
        const grant = context.grant;
        const purposeText = purposeTextByRequestId.get(decision.requestId)?.trim() || decision.purpose || "";
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
            purposeText,
            actionDigest: actionDigest(decision, grant.resource, grant.permissions),
            mandatory: true
          },
          { provider: jevProvider, cache: jevCache }
        );
        jevByRequestId.set(decision.requestId, assessment);
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
        if (composed.action === "queue") {
          const review: PendingReview = {
            id: `rev_${randomUUID().replaceAll("-", "")}`,
            requestId: decision.requestId,
            agentId: context.agentId,
            task: "bulk-report",
            purpose: purposeText,
            assessment,
            status: "pending",
            context,
            originalDecision: composedDecision
          };
          reviews.set(review.id, review);
        }
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
        httpMessageSignaturePublicJwksByKeyId: httpPublicJwksByKeyId,
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

    const reviewTransitions = new Set<string>();
    const emitReviewDecision = async (review: PendingReview, action: "allow" | "deny"): Promise<void> => {
      const decision: DecisionResult = {
        ...review.originalDecision,
        requestId: `${review.requestId}:review:${review.id}`,
        decision: action,
        recommendedDecision: action,
        reasons: action === "allow" ? ["operator_override"] : ["semantic_review_required", "operator_override"]
      };
      await emitter(decision);
    };

    app.post("/glasswing/agents", async (request, reply) => {
      if (!requireOperator(request, reply, operatorToken)) {
        return;
      }
      const id = `agt_${randomUUID().replaceAll("-", "")}`;
      const agent: ManagedAgent = {
        id,
        subject: `agent:${id}`,
        key: mintAgentKey(`agk_${randomUUID().replaceAll("-", "")}`),
        createdAt: new Date().toISOString()
      };
      agents.set(id, agent);
      httpPublicJwksByKeyId[agent.key.keyId] = agent.key.publicJwk;
      return reply.code(201).send({ agent: publicAgent(agent) });
    });

    app.get("/glasswing/agents", async (request, reply) => {
      if (!requireOperator(request, reply, operatorToken)) {
        return;
      }
      return { agents: [...agents.values()].map(publicAgent) };
    });

    app.post("/glasswing/grants", async (request, reply) => {
      if (!requireOperator(request, reply, operatorToken)) {
        return;
      }
      const body = bodyRecord(request.body);
      const agentId = body?.agentId;
      const rawPermissions = body?.permissions;
      const expiresInSeconds = body?.expiresInSeconds ?? 3_600;
      if (
        typeof agentId !== "string" ||
        !Array.isArray(rawPermissions) ||
        rawPermissions.some((permission) => typeof permission !== "string" || permission.trim().length === 0) ||
        !Number.isSafeInteger(expiresInSeconds) ||
        (expiresInSeconds as number) < 1 ||
        (expiresInSeconds as number) > 86_400
      ) {
        return reply.code(400).send({ error: { code: "invalid_grant_request", message: "agentId, permissions, and a valid expiresInSeconds are required." } });
      }
      const agent = agents.get(agentId);
      if (agent === undefined) {
        return reply.code(404).send({ error: { code: "agent_not_found", message: "The requested agent does not exist." } });
      }
      const permissions = (rawPermissions as string[]).map((permission) => permission.trim());
      const route = permissionRoute(permissions);
      if (route === undefined) {
        return reply.code(400).send({
          error: {
            code: "unsupported_permission_scope",
            message: "A demo grant must contain exactly one supported permission for one protected route."
          }
        });
      }
      const grant = await createGrantForAgent(agent, `${DEMO_ORIGIN}${route.path}`, permissions, expiresInSeconds as number);
      const managed = managedGrants.get(grant.id);
      if (managed === undefined) {
        throw new Error("new grant was not registered in the local grant index");
      }
      return reply.code(201).send({ grant: publicGrant(managed) });
    });

    app.post<{ Params: { id: string } }>("/glasswing/agents/:id/run", async (request, reply) => {
      if (!requireOperator(request, reply, operatorToken)) {
        return;
      }
      const body = bodyRecord(request.body);
      const task = body?.task;
      const grantId = body?.grantId;
      const purpose = typeof body?.purpose === "string" ? body.purpose.trim().slice(0, 1_024) : "";
      if (!isGlasswingTask(task) || typeof grantId !== "string") {
        return sendRunError(reply, 400, { method: "", url: "" }, "invalid_run_request", "A known task and grantId are required.");
      }
      const taskSpec = TASKS[task];
      const resource = `${DEMO_ORIGIN}${taskSpec.path}`;
      const requestSummary = { method: taskSpec.method, url: resource };
      const agent = agents.get(request.params.id);
      if (agent === undefined) {
        return sendRunError(reply, 404, requestSummary, "agent_not_found", "The requested agent does not exist.");
      }
      const grant = managedGrants.get(grantId);
      if (grant === undefined || grant.ownerAgentId !== agent.id) {
        return sendRunError(reply, 403, requestSummary, "grant_forbidden", "The grant is not owned by this agent.");
      }
      if (grant.resource !== resource || !grant.permissions.includes(taskSpec.permission)) {
        return sendRunError(reply, 403, requestSummary, "permission_scope_mismatch", "The grant does not authorize this task resource and permission.");
      }

      let session: ExchangedSession;
      try {
        session = await exchangeSession(agent.key, {
          controlPlaneUrl: CONTROL_PLANE_URL,
          grantId: grant.id,
          audience: siteId,
          resource: grant.resource,
          requestedPermissions: grant.permissions,
          llmBrand: "openai",
          fetchImpl: cpFetch
        });
      } catch {
        return sendRunError(reply, 403, requestSummary, "session_exchange_failed", "The grant is no longer active or could not be exchanged.");
      }

      const headers: Record<string, string> = {};
      if (task === "bulk-report") {
        const purposeSlug = purpose.toLowerCase() === "compare" ? "compare" : "research";
        headers["x-aidenid-purpose"] = purposeSlug;
        if (purpose.length > 0) {
          headers["x-aidenid-purpose-text"] = purpose;
        }
      }
      const response = await signedFetch(agent.key, resource, {
        method: taskSpec.method,
        sessionToken: session.accessToken,
        headers,
        fetchImpl: (input, init) => fastifyFetch(app, input, init)
      });
      const requestId = response.headers.get("x-aidenid-request-id") ?? "";
      const decisionRecord = requestId.length > 0 ? await controlPlane.services.store.findDecisionByRequestId(siteId, requestId) : undefined;
      const assessment = requestId.length > 0 ? (jevByRequestId.get(requestId) ?? null) : null;
      if (requestId.length > 0) {
        jevByRequestId.delete(requestId);
      }
      const responseText = await response.text();
      let responseValue: unknown;
      try {
        responseValue = responseText.length === 0 ? undefined : (JSON.parse(responseText) as unknown);
      } catch {
        responseValue = undefined;
      }
      const summary = decisionRecord === undefined
        ? null
        : {
            requestId: decisionRecord.requestId,
            decisionId: decisionRecord.id,
            action: decisionRecord.decision,
            reasonCodes: decisionRecord.reasonCodes ?? [],
            actorClass: decisionRecord.actorClass
          };
      // When the verifier allowed the request but the handler refused (effect gate or shop
      // state), the handler's error code is the reason the operator needs to see, not the
      // policy reason that let the request through.
      const handlerError = bodyRecord(responseValue)?.error;
      const handlerReason = typeof handlerError === "string" ? handlerError : `http_${response.status}`;
      const effect = decisionRecord?.decision === "queue"
        ? null
        : decisionRecord?.decision === "allow" && response.ok
          ? { ok: true, ...(responseValue === undefined ? {} : { value: responseValue }) }
          : decisionRecord?.decision === "allow"
            ? { ok: false, reason: handlerReason }
            : { ok: false, reason: decisionRecord?.reasonCodes?.[0] ?? handlerReason };

      return {
        request: requestSummary,
        session: { sessionId: session.sessionId, revocationEpoch: session.revocationEpoch },
        decision: summary,
        effect,
        jev: assessment
      };
    });

    app.post("/glasswing/revoke", async (request, reply) => {
      if (!requireOperator(request, reply, operatorToken)) {
        return;
      }
      const body = bodyRecord(request.body);
      if (typeof body?.chainId !== "string" || typeof body.reason !== "string" || body.reason.trim().length === 0) {
        return reply.code(400).send({ error: { code: "invalid_revocation_request", message: "chainId and reason are required." } });
      }
      const response = await cpFetch(`${CONTROL_PLANE_URL}/v1/revoke`, {
        method: "POST",
        headers: { ...operatorHeaders, "content-type": "application/json" },
        body: JSON.stringify({ chain_id: body.chainId, reason: body.reason.trim(), actor_id: DEMO_OPERATOR_ACTOR_ID })
      });
      if (!response.ok) {
        return reply.code(response.status).send({ error: { code: "revocation_failed", message: "The control plane refused the chain revocation." } });
      }
      const revocation = (await response.json()) as { id: string; chain_id: string; revocation_epoch: number };
      return reply.code(202).send({ revocation: { id: revocation.id, chainId: revocation.chain_id, epoch: revocation.revocation_epoch } });
    });

    app.get("/glasswing/reviews", async (request, reply) => {
      if (!requireOperator(request, reply, operatorToken)) {
        return;
      }
      return { reviews: [...reviews.values()].map(publicReview) };
    });

    app.post<{ Params: { id: string } }>("/glasswing/reviews/:id", async (request, reply) => {
      if (!requireOperator(request, reply, operatorToken)) {
        return;
      }
      const body = bodyRecord(request.body);
      const action = body?.decision;
      if (action !== "approve" && action !== "deny") {
        return reply.code(400).send({ error: { code: "invalid_review_decision", message: "decision must be approve or deny." } });
      }
      const review = reviews.get(request.params.id);
      if (review === undefined) {
        return reply.code(404).send({ error: { code: "review_not_found", message: "The requested review does not exist." } });
      }
      if (review.status !== "pending") {
        return { review: publicReview(review) };
      }
      if (reviewTransitions.has(review.id)) {
        return reply.code(409).send({ error: { code: "review_transition_in_progress", message: "A decision is already being applied to this review." } });
      }

      reviewTransitions.add(review.id);
      try {
        if (action === "deny") {
          await emitReviewDecision(review, "deny");
          review.status = "denied";
          return { review: publicReview(review) };
        }

        const gated = await withChainAuthority(
          controlPlane.services,
          { chainId: review.context.chainId, tokenRevocationEpoch: review.context.tokenRevocationEpoch },
          async () => {
            const job: ReleasedReport = {
              id: `job_${randomUUID().replaceAll("-", "")}`,
              reviewId: review.id,
              agentId: review.agentId,
              grantId: review.context.grant.id,
              createdAt: new Date().toISOString(),
              rows: REPORT_ROWS
            };
            releasedReports.push(job);
            return job;
          }
        );
        if (!gated.ok) {
          review.status = "denied";
          await emitReviewDecision(review, "deny");
          return { review: publicReview(review) };
        }
        review.status = "approved";
        await emitReviewDecision(review, "allow");
        return { review: publicReview(review) };
      } finally {
        reviewTransitions.delete(review.id);
      }
    });

    const reservations = new Set<string>();
    app.get("/healthz", async () => ({ status: "ok", site_id: siteId }));
    app.get("/catalog", async (_request, reply) => {
      return reply.send({ items: [{ id: DEMO_ITEM_ID, name: "Glasswing Widget", available: !reservations.has(DEMO_ITEM_ID) }] });
    });
    app.post<{ Params: { id: string } }>("/items/:id/reserve", async (request, reply) => {
      const decision = request.aidenid;
      const authority = decision === undefined ? undefined : requestAuthorities.get(decision.requestId);
      if (decision?.decision !== "allow" || authority === undefined || authority.grant.resource !== `${DEMO_ORIGIN}${ROUTES.reserve.path}`) {
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
      return reply.send({ rows: REPORT_ROWS });
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
      releasedReports,
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
