import { buildSignedHeaders, signedFetch } from "@aidenid/agent-client";
import { decodeCompactJwt, signCompactJws } from "@aidenid/crypto";
import type { JevProvider } from "@aidenid/jev";
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
