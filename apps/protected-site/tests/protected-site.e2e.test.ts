import { buildSignedHeaders, signedFetch } from "@aidenid/agent-client";
import { decodeCompactJwt, signCompactJws } from "@aidenid/crypto";
import type { JevAssessment, JevProvider } from "@aidenid/jev";
import { afterEach, describe, expect, it } from "vitest";

import { createProtectedSiteRuntime } from "../src/index.js";
import type { ProtectedSiteRuntime } from "../src/index.js";

const runtimes: ProtectedSiteRuntime[] = [];

afterEach(async () => {
  await Promise.all(runtimes.splice(0).map((runtime) => runtime.close()));
});

function clearJevProvider(coverage: "none" | "partial" | "full" = "full"): JevProvider {
  return {
    modelVersion: "test-jeV-v1",
    async assess() {
      return {
        risk_class: "low",
        confidence: 0.95,
        evidence_coverage: coverage,
        rationale: "test fixture"
      };
    }
  };
}

async function createRuntime(jevProvider?: JevProvider | null): Promise<ProtectedSiteRuntime> {
  const runtime = await createProtectedSiteRuntime({ jevProvider });
  runtimes.push(runtime);
  return runtime;
}

function operatorHeaders(runtime: ProtectedSiteRuntime): Record<string, string> {
  return { authorization: `Bearer ${runtime.operatorToken}`, "content-type": "application/json" };
}

async function createManagedAgent(runtime: ProtectedSiteRuntime): Promise<{ id: string; keyId: string }> {
  const response = await runtime.app.inject({ method: "POST", url: "/glasswing/agents", headers: operatorHeaders(runtime), payload: "{}" });
  expect(response.statusCode).toBe(201);
  const body = response.json() as { agent: { id: string; keyId: string } };
  return { id: body.agent.id, keyId: body.agent.keyId };
}

async function createManagedGrant(runtime: ProtectedSiteRuntime, agentId: string, permission: string) {
  const response = await runtime.app.inject({
    method: "POST",
    url: "/glasswing/grants",
    headers: operatorHeaders(runtime),
    payload: JSON.stringify({ agentId, permissions: [permission], expiresInSeconds: 3_600 })
  });
  expect(response.statusCode).toBe(201);
  return (response.json() as { grant: { id: string; chainId: string; resource: string; permissions: string[] } }).grant;
}

function fetchFrom(app: ProtectedSiteRuntime["app"]) {
  return async (input: string, init?: RequestInit): Promise<Response> => {
    const url = new URL(input);
    const response = await app.inject({
      method: (init?.method ?? "GET") as "GET" | "POST",
      url: `${url.pathname}${url.search}`,
      headers: Object.fromEntries(new Headers(init?.headers).entries()),
      ...(typeof init?.body === "string" ? { payload: init.body } : {})
    });
    return new Response(response.body, { status: response.statusCode, headers: response.headers as Record<string, string> });
  };
}

describe("protected-site verifier integration", () => {
  it("manages server-held agent keys and runs scoped tasks without returning session tokens", async () => {
    const runtime = await createRuntime(clearJevProvider());
    const unauthorized = await runtime.app.inject({ method: "GET", url: "/glasswing/agents" });
    expect(unauthorized.statusCode).toBe(401);

    const created = await runtime.app.inject({ method: "POST", url: "/glasswing/agents", headers: operatorHeaders(runtime), payload: "{}" });
    expect(created.statusCode).toBe(201);
    const createdBody = created.json() as { agent: { id: string; keyId: string; thumbprint: string; publicJwk: Record<string, unknown>; createdAt: string } };
    expect(createdBody.agent).toMatchObject({ keyId: expect.stringMatching(/^agk_/), publicJwk: { kty: "OKP", crv: "Ed25519" } });
    expect(createdBody.agent).not.toHaveProperty("privateKey");
    const agentList = await runtime.app.inject({ method: "GET", url: "/glasswing/agents", headers: operatorHeaders(runtime) });
    expect((agentList.json() as { agents: unknown[] }).agents).toEqual(
      expect.arrayContaining([expect.objectContaining({ id: createdBody.agent.id, keyId: createdBody.agent.keyId })])
    );

    const grant = await createManagedGrant(runtime, createdBody.agent.id, "catalog:read");
    expect(grant).toMatchObject({
      siteId: runtime.siteId,
      resource: "https://aidenid.local/catalog",
      permissions: ["catalog:read"]
    });
    const otherAgent = await createManagedAgent(runtime);
    const otherGrant = await createManagedGrant(runtime, otherAgent.id, "catalog:read");
    const crossAgentRun = await runtime.app.inject({
      method: "POST",
      url: `/glasswing/agents/${createdBody.agent.id}/run`,
      headers: operatorHeaders(runtime),
      payload: JSON.stringify({ grantId: otherGrant.id, task: "catalog" })
    });
    expect(crossAgentRun.statusCode).toBe(403);
    expect(crossAgentRun.json()).toMatchObject({ error: { code: "grant_forbidden" }, session: null, decision: null, effect: null, jev: null });
    const mixedScope = await runtime.app.inject({
      method: "POST",
      url: "/glasswing/grants",
      headers: operatorHeaders(runtime),
      payload: JSON.stringify({ agentId: createdBody.agent.id, permissions: ["catalog:read", "items:reserve"] })
    });
    expect(mixedScope.statusCode).toBe(400);

    const run = await runtime.app.inject({
      method: "POST",
      url: `/glasswing/agents/${createdBody.agent.id}/run`,
      headers: operatorHeaders(runtime),
      payload: JSON.stringify({ grantId: grant.id, task: "catalog" })
    });
    expect(run.statusCode).toBe(200);
    const result = run.json() as {
      request: { method: string; url: string };
      session: { sessionId: string; revocationEpoch: number };
      decision: { requestId: string; decisionId: string; action: string; reasonCodes: string[]; actorClass: string };
      effect: { ok: boolean; value: { items: Array<{ id: string }> } };
      jev: unknown;
    };
    expect(result).toMatchObject({
      request: { method: "GET", url: grant.resource },
      session: { sessionId: expect.any(String), revocationEpoch: 0 },
      decision: { action: "allow", actorClass: "verified_agent" },
      effect: { ok: true, value: { items: [{ id: "demo-item" }] } },
      jev: null
    });
    expect(result.decision.requestId).not.toBe("");
    expect(result.decision.decisionId).not.toBe("");
    expect(JSON.stringify(result)).not.toContain("accessToken");
    expect(JSON.stringify(result)).not.toContain("privateKey");

    const reserveGrant = await createManagedGrant(runtime, createdBody.agent.id, "items:reserve");
    const reserve = await runtime.app.inject({
      method: "POST",
      url: `/glasswing/agents/${createdBody.agent.id}/run`,
      headers: operatorHeaders(runtime),
      payload: JSON.stringify({ grantId: reserveGrant.id, task: "reserve" })
    });
    expect(reserve.json()).toMatchObject({
      decision: { action: "allow", actorClass: "verified_agent" },
      effect: { ok: true, value: { item_id: "demo-item", status: "reserved" } }
    });

    const missingExportPermission = await runtime.app.inject({
      method: "POST",
      url: `/glasswing/agents/${createdBody.agent.id}/run`,
      headers: operatorHeaders(runtime),
      payload: JSON.stringify({ grantId: grant.id, task: "export" })
    });
    expect(missingExportPermission.statusCode).toBe(403);
    expect(missingExportPermission.json()).toMatchObject({ error: { code: "permission_scope_mismatch" } });

    const exportGrant = await createManagedGrant(runtime, createdBody.agent.id, "customers:export");
    const exported = await runtime.app.inject({
      method: "POST",
      url: `/glasswing/agents/${createdBody.agent.id}/run`,
      headers: operatorHeaders(runtime),
      payload: JSON.stringify({ grantId: exportGrant.id, task: "export" })
    });
    expect(exported.json()).toMatchObject({ decision: { action: "deny" }, effect: { ok: false } });
  });

  it("serves the same session keys and recorded decisions from the embedded control-plane listener", async () => {
    const runtime = await createRuntime(clearJevProvider());
    await runtime.controlPlane.app.listen({ host: "127.0.0.1", port: 0 });
    const address = runtime.controlPlane.app.server.address();
    if (address === null || typeof address === "string") {
      throw new Error("embedded control-plane listener did not bind a TCP port");
    }
    const controlPlaneUrl = `http://127.0.0.1:${address.port}`;

    const response = await signedFetch(runtime.demoAgent.key, runtime.demoAgent.grants.catalog.resource, {
      method: "GET",
      sessionToken: runtime.demoAgent.sessions.catalog.accessToken,
      fetchImpl: fetchFrom(runtime.app)
    });
    expect(response.status).toBe(200);

    const jwks = await fetch(`${controlPlaneUrl}/.well-known/aidenid-session-jwks.json`);
    expect(jwks.status).toBe(200);
    expect(await jwks.json()).toMatchObject({ issuer: "https://control-plane.aidenid.local", keys: [expect.objectContaining({ kid: expect.any(String) })] });

    const decisions = await fetch(`${controlPlaneUrl}/v1/decisions?site_id=${encodeURIComponent(runtime.siteId)}&limit=10`, {
      headers: { authorization: `Bearer ${runtime.operatorToken}` }
    });
    expect(decisions.status).toBe(200);
    expect(await decisions.json()).toMatchObject({ decisions: [expect.objectContaining({ site_id: runtime.siteId, decision: "allow" })] });
  });

  it("queues bulk reports, releases approval once under chain authority, and records review denial", async () => {
    const runtime = await createRuntime(null);
    const agent = await createManagedAgent(runtime);
    const grant = await createManagedGrant(runtime, agent.id, "reports:bulk");
    const runBulkReport = async () => runtime.app.inject({
      method: "POST",
      url: `/glasswing/agents/${agent.id}/run`,
      headers: operatorHeaders(runtime),
      payload: JSON.stringify({ grantId: grant.id, task: "bulk-report", purpose: "Compare order totals for the current quarter." })
    });

    const firstRun = await runBulkReport();
    expect(firstRun.statusCode).toBe(200);
    const firstResult = firstRun.json() as { decision: { action: string }; jev: JevAssessment; effect: unknown };
    expect(firstResult.decision.action).toBe("queue");
    expect(firstResult.jev).toMatchObject({ verificationStatus: "unavailable", obligation: "review_required" });
    expect(firstResult.effect).toBeNull();

    const pending = await runtime.app.inject({ method: "GET", url: "/glasswing/reviews", headers: operatorHeaders(runtime) });
    const reviews = (pending.json() as { reviews: Array<{ id: string; status: string; agentId: string; task: string; purpose: string }> }).reviews;
    expect(reviews).toHaveLength(1);
    expect(reviews[0]).toMatchObject({ status: "pending", agentId: agent.id, task: "bulk-report", purpose: "Compare order totals for the current quarter." });

    const approve = async (id: string) => runtime.app.inject({
      method: "POST",
      url: `/glasswing/reviews/${id}`,
      headers: operatorHeaders(runtime),
      payload: JSON.stringify({ decision: "approve" })
    });
    const approved = await approve(reviews[0]!.id);
    expect(approved.json()).toMatchObject({ review: { id: reviews[0]!.id, status: "approved" } });
    await approve(reviews[0]!.id);
    expect(runtime.releasedReports).toHaveLength(1);
    expect(runtime.releasedReports[0]).toMatchObject({ reviewId: reviews[0]!.id, grantId: grant.id, rows: [{ orders: 3 }] });

    await runBulkReport();
    const allPending = (await runtime.app.inject({ method: "GET", url: "/glasswing/reviews", headers: operatorHeaders(runtime) })).json() as {
      reviews: Array<{ id: string; status: string }>;
    };
    const secondReview = allPending.reviews.find((review) => review.status === "pending");
    expect(secondReview).toBeDefined();
    const denied = await runtime.app.inject({
      method: "POST",
      url: `/glasswing/reviews/${secondReview!.id}`,
      headers: operatorHeaders(runtime),
      payload: JSON.stringify({ decision: "deny" })
    });
    expect(denied.json()).toMatchObject({ review: { id: secondReview!.id, status: "denied" } });
    expect(runtime.releasedReports).toHaveLength(1);

    await runBulkReport();
    const thirdPending = (await runtime.app.inject({ method: "GET", url: "/glasswing/reviews", headers: operatorHeaders(runtime) })).json() as {
      reviews: Array<{ id: string; status: string }>;
    };
    const thirdReview = thirdPending.reviews.find((review) => review.status === "pending");
    expect(thirdReview).toBeDefined();
    const revoke = await runtime.app.inject({
      method: "POST",
      url: "/glasswing/revoke",
      headers: operatorHeaders(runtime),
      payload: JSON.stringify({ chainId: grant.chainId, reason: "review_authority_revoked" })
    });
    expect(revoke.statusCode).toBe(202);
    const refusedApproval = await runtime.app.inject({
      method: "POST",
      url: `/glasswing/reviews/${thirdReview!.id}`,
      headers: operatorHeaders(runtime),
      payload: JSON.stringify({ decision: "approve" })
    });
    expect(refusedApproval.json()).toMatchObject({ review: { id: thirdReview!.id, status: "denied" } });
    expect(runtime.releasedReports).toHaveLength(1);
    const decisions = await runtime.controlPlane.services.store.listDecisions(runtime.siteId, 100);
    expect(decisions).toEqual(expect.arrayContaining([expect.objectContaining({ decision: "deny", reasonCodes: expect.arrayContaining(["operator_override"]) })]));
  });

  it("verifies signed routes, denies exports, and records Jev's composed report decision", async () => {
    const runtime = await createRuntime(clearJevProvider());
    const { key, sessions, grants } = runtime.demoAgent;
    const send = fetchFrom(runtime.app);

    const catalog = await signedFetch(key, grants.catalog.resource, {
      sessionToken: sessions.catalog.accessToken,
      fetchImpl: send
    });
    expect(catalog.status).toBe(200);
    expect(await catalog.json()).toMatchObject({ items: [{ id: "demo-item", available: true }] });

    const report = await signedFetch(key, grants.reports.resource, {
      sessionToken: sessions.reports.accessToken,
      headers: {
        "x-aidenid-purpose": "compare",
        "x-aidenid-purpose-text": "Compare this week's order totals with last week."
      },
      fetchImpl: send
    });
    expect(report.status).toBe(200);
    expect(await report.json()).toMatchObject({ rows: [{ orders: 3 }] });

    const exported = await signedFetch(key, grants.customerExport.resource, {
      sessionToken: sessions.customerExport.accessToken,
      fetchImpl: send
    });
    expect(exported.status).toBe(403);
    expect(await exported.json()).toMatchObject({ decision: "deny" });

    const decisions = await runtime.controlPlane.services.store.listDecisions(runtime.siteId, 100);
    expect(decisions).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ routeTemplate: "/catalog", decision: "allow", subjectHandle: "agent:gpt-luna-xh" }),
        expect.objectContaining({
          routeTemplate: "/reports/bulk",
          decision: "allow",
          recommendedDecision: "allow",
          purpose: "compare"
        }),
        expect.objectContaining({ routeTemplate: "/customers/export", decision: "deny" })
      ])
    );
  });

  it("queues the mandatory report check when Jev is unavailable or reports no evidence", async () => {
    const unavailable = await createRuntime(null);
    const credentials = unavailable.demoAgent;
    const response = await signedFetch(credentials.key, credentials.grants.reports.resource, {
      sessionToken: credentials.sessions.reports.accessToken,
      headers: { "x-aidenid-purpose": "research", "x-aidenid-purpose-text": "Research order totals." },
      fetchImpl: fetchFrom(unavailable.app)
    });
    expect(response.status).toBe(202);
    expect(response.headers.get("x-aidenid-jev-status")).toBe("unavailable");
    expect(unavailable.controlPlane.services.store.listDecisions(unavailable.siteId, 100)).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          routeTemplate: "/reports/bulk",
          decision: "queue",
          reasonCodes: expect.arrayContaining(["semantic_review_required", "jev_unavailable"])
        })
      ])
    );

    const noEvidence = await createRuntime(clearJevProvider("none"));
    const noEvidenceCredentials = noEvidence.demoAgent;
    const noEvidenceResponse = await signedFetch(noEvidenceCredentials.key, noEvidenceCredentials.grants.reports.resource, {
      sessionToken: noEvidenceCredentials.sessions.reports.accessToken,
      headers: { "x-aidenid-purpose": "compare", "x-aidenid-purpose-text": "Compare order totals." },
      fetchImpl: fetchFrom(noEvidence.app)
    });
    expect(noEvidenceResponse.status).toBe(202);
    expect(noEvidence.controlPlane.services.store.listDecisions(noEvidence.siteId, 100)).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          routeTemplate: "/reports/bulk",
          decision: "queue",
          reasonCodes: expect.arrayContaining(["semantic_review_required"])
        })
      ])
    );
  });

  it("fails closed on purpose allowlist violations, audience mismatch, replay, and method substitution", async () => {
    const runtime = await createRuntime(clearJevProvider());
    const { key, sessions, grants } = runtime.demoAgent;
    const fetchImpl = fetchFrom(runtime.app);

    const purposeDenied = await signedFetch(key, grants.reports.resource, {
      sessionToken: sessions.reports.accessToken,
      headers: { "x-aidenid-purpose": "export", "x-aidenid-purpose-text": "Export customer records." },
      fetchImpl
    });
    expect(purposeDenied.status).toBe(403);
    expect(purposeDenied.headers.get("x-aidenid-decision")).toBe("deny");

    const nowSeconds = Math.floor(Date.now() / 1000);
    const claims = decodeCompactJwt(sessions.catalog.accessToken).payload;
    const wrongAudienceToken = signCompactJws(
      { ...claims, aud: "sit_another_site", site_id: "sit_another_site", iat: nowSeconds, nbf: nowSeconds, exp: nowSeconds + 600 },
      runtime.controlPlane.services.sessionSigner.privateKey,
      runtime.controlPlane.services.sessionSigner.alg,
      { kid: runtime.controlPlane.services.sessionSigner.kid }
    );
    const wrongAudience = await signedFetch(key, grants.catalog.resource, {
      sessionToken: wrongAudienceToken,
      fetchImpl
    });
    expect(wrongAudience.status).toBe(403);
    expect(wrongAudience.headers.get("x-aidenid-decision")).toBe("deny");

    const catalogHeaders = buildSignedHeaders(key, {
      method: "GET",
      url: grants.catalog.resource,
      sessionToken: sessions.catalog.accessToken
    });
    const first = await runtime.app.inject({ method: "GET", url: "/catalog", headers: catalogHeaders });
    const replay = await runtime.app.inject({ method: "GET", url: "/catalog", headers: catalogHeaders });
    expect(first.statusCode).toBe(200);
    expect(replay.statusCode).toBe(403);

    const reserveHeaders = buildSignedHeaders(key, {
      method: "POST",
      url: grants.reserve.resource,
      sessionToken: sessions.reserve.accessToken
    });
    const methodSwap = await runtime.app.inject({ method: "GET", url: "/items/demo-item/reserve", headers: reserveHeaders });
    expect(methodSwap.statusCode).toBe(403);

    const postCatalogHeaders = buildSignedHeaders(key, {
      method: "POST",
      url: grants.catalog.resource,
      sessionToken: sessions.catalog.accessToken
    });
    const catalogMethodSwap = await runtime.app.inject({ method: "GET", url: "/catalog", headers: postCatalogHeaders });
    expect(catalogMethodSwap.statusCode).toBe(403);

    const unknownRoute = await runtime.app.inject({ method: "GET", url: "/not-a-demo-route" });
    expect(unknownRoute.statusCode).toBe(403);

    const catalogAfterMethodSwap = await signedFetch(key, grants.catalog.resource, {
      sessionToken: sessions.catalog.accessToken,
      fetchImpl
    });
    expect(catalogAfterMethodSwap.status).toBe(200);
    expect(await catalogAfterMethodSwap.json()).toMatchObject({ items: [{ id: "demo-item", available: true }] });
  });

  it("holds the real reserve effect behind the chain authority check and emits a revoke denial", async () => {
    const runtime = await createRuntime(clearJevProvider());
    const { key, sessions, grants } = runtime.demoAgent;
    const reserve = await signedFetch(key, grants.reserve.resource, {
      method: "POST",
      sessionToken: sessions.reserve.accessToken,
      fetchImpl: fetchFrom(runtime.app)
    });
    expect(reserve.status).toBe(201);

    const revoked = await runtime.controlPlane.app.inject({
      method: "POST",
      url: "/v1/revoke",
      headers: { authorization: `Bearer ${runtime.operatorToken}` },
      payload: { chain_id: grants.reserve.chain_id, reason: "demo_revocation", actor_id: "glasswing_demo_operator" }
    });
    expect(revoked.statusCode).toBe(202);

    const refused = await signedFetch(key, grants.reserve.resource, {
      method: "POST",
      sessionToken: sessions.reserve.accessToken,
      fetchImpl: fetchFrom(runtime.app)
    });
    expect(refused.status).toBe(403);
    const decisions = await runtime.controlPlane.services.store.listDecisions(runtime.siteId, 100);
    expect(decisions).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ routeTemplate: "/items/:id/reserve", decision: "deny", reasonCodes: ["revoked"] })
      ])
    );
  });
});
