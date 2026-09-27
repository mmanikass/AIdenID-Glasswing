import { describe, expect, it } from "vitest";

import { proxyGlasswingRequest, resolveGlasswingUpstreamPath } from "../src/glasswing/proxy.js";
import { issueDevOperatorSession } from "../src/glasswing/session.js";

const ENV = {
  AIDENID_PROTECTED_SITE_URL: "http://127.0.0.1:4100",
  AIDENID_OPERATOR_TOKEN: "upstream_operator_token_0123456789",
  AIDENID_DASHBOARD_OPERATOR_REQUEST_TOKEN: "dashboard_client_token_0123456789"
} as const;
const CLIENT = { cookie: "aidenid_operator_token=dashboard_client_token_0123456789" };

function recordingFetch(status = 200, body: unknown = { ok: true }) {
  const calls: Array<{ url: string; init: RequestInit & { timeoutMs: number } }> = [];
  const fetchImpl = (async (url: string, init: RequestInit & { timeoutMs: number }) => {
    calls.push({ url, init });
    return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  }) as unknown as Parameters<typeof proxyGlasswingRequest>[0]["fetchImpl"];
  return { calls, fetchImpl };
}

describe("resolveGlasswingUpstreamPath", () => {
  it("maps exactly the contract routes and nothing else", () => {
    expect(resolveGlasswingUpstreamPath("GET", ["agents"])).toBe("/glasswing/agents");
    expect(resolveGlasswingUpstreamPath("POST", ["agents"])).toBe("/glasswing/agents");
    expect(resolveGlasswingUpstreamPath("POST", ["agents", "agt_1", "run"])).toBe("/glasswing/agents/agt_1/run");
    expect(resolveGlasswingUpstreamPath("POST", ["grants"])).toBe("/glasswing/grants");
    expect(resolveGlasswingUpstreamPath("POST", ["revoke"])).toBe("/glasswing/revoke");
    expect(resolveGlasswingUpstreamPath("GET", ["reviews"])).toBe("/glasswing/reviews");
    expect(resolveGlasswingUpstreamPath("POST", ["reviews", "rev_1"])).toBe("/glasswing/reviews/rev_1");
    // Not allowed: wrong method, traversal, control-plane paths, extra segments.
    expect(resolveGlasswingUpstreamPath("DELETE", ["agents"])).toBeUndefined();
    expect(resolveGlasswingUpstreamPath("GET", ["agents", "agt_1", "run"])).toBeUndefined();
    expect(resolveGlasswingUpstreamPath("POST", ["agents", "../v1", "run"])).toBeUndefined();
    expect(resolveGlasswingUpstreamPath("GET", ["v1", "decisions"])).toBeUndefined();
    expect(resolveGlasswingUpstreamPath("POST", ["reviews"])).toBeUndefined();
    expect(resolveGlasswingUpstreamPath("GET", [])).toBeUndefined();
  });
});

describe("proxyGlasswingRequest", () => {
  it("requires the dashboard client credential and never forwards it upstream", async () => {
    const { calls, fetchImpl } = recordingFetch();
    const anonymous = await proxyGlasswingRequest({ request: new Request("http://localhost:3000/api/glasswing/agents"), segments: ["agents"], env: ENV, fetchImpl });
    expect(anonymous.status).toBe(401);
    expect(calls).toHaveLength(0);

    const authed = await proxyGlasswingRequest({ request: new Request("http://localhost:3000/api/glasswing/agents", { headers: CLIENT }), segments: ["agents"], env: ENV, fetchImpl });
    expect(authed.status).toBe(200);
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe("http://127.0.0.1:4100/glasswing/agents");
    const headers = calls[0]!.init.headers as Record<string, string>;
    expect(headers.Authorization).toBe(`Bearer ${ENV.AIDENID_OPERATOR_TOKEN}`);
    expect(JSON.stringify(headers)).not.toContain("dashboard_client_token");
    expect(JSON.stringify(headers)).not.toContain("cookie");
    expect(authed.headers.get("X-AIdenID-Dashboard-Data-Source")).toBe("live");
  });

  it("forwards a JSON body on POST, refuses non-JSON and oversized bodies, and passes upstream status through", async () => {
    const { calls, fetchImpl } = recordingFetch(403, { error: "grant_not_active" });
    const response = await proxyGlasswingRequest({
      request: new Request("http://localhost:3000/api/glasswing/agents/agt_1/run", { method: "POST", headers: { ...CLIENT, "content-type": "application/json" }, body: JSON.stringify({ grantId: "grt_1", task: "catalog" }) }),
      segments: ["agents", "agt_1", "run"],
      env: ENV,
      fetchImpl
    });
    expect(response.status).toBe(403);
    expect(await response.json()).toEqual({ error: "grant_not_active" });
    expect(calls[0]!.init.method).toBe("POST");
    expect(calls[0]!.init.body).toBe(JSON.stringify({ grantId: "grt_1", task: "catalog" }));

    const notJson = await proxyGlasswingRequest({ request: new Request("http://localhost:3000/api/glasswing/grants", { method: "POST", headers: CLIENT, body: "not json" }), segments: ["grants"], env: ENV, fetchImpl });
    expect(notJson.status).toBe(400);
    const huge = await proxyGlasswingRequest({ request: new Request("http://localhost:3000/api/glasswing/grants", { method: "POST", headers: CLIENT, body: JSON.stringify({ x: "y".repeat(20_000) }) }), segments: ["grants"], env: ENV, fetchImpl });
    expect(huge.status).toBe(413);
    expect(calls).toHaveLength(1);
  });

  it("refuses unknown routes and missing configuration before any network call", async () => {
    const { calls, fetchImpl } = recordingFetch();
    expect((await proxyGlasswingRequest({ request: new Request("http://localhost:3000/api/glasswing/v1/decisions", { headers: CLIENT }), segments: ["v1", "decisions"], env: ENV, fetchImpl })).status).toBe(404);
    expect((await proxyGlasswingRequest({ request: new Request("http://localhost:3000/api/glasswing/agents", { headers: CLIENT }), segments: ["agents"], env: { ...ENV, AIDENID_PROTECTED_SITE_URL: "ftp://x" }, fetchImpl })).status).toBe(503);
    expect((await proxyGlasswingRequest({ request: new Request("http://localhost:3000/api/glasswing/agents", { headers: CLIENT }), segments: ["agents"], env: { ...ENV, AIDENID_OPERATOR_TOKEN: "" }, fetchImpl })).status).toBe(503);
    expect(calls).toHaveLength(0);
  });

  it("maps an unreachable protected site to a gateway error", async () => {
    const failing = (async () => {
      throw new Error("connect ECONNREFUSED");
    }) as unknown as Parameters<typeof proxyGlasswingRequest>[0]["fetchImpl"];
    const response = await proxyGlasswingRequest({ request: new Request("http://localhost:3000/api/glasswing/agents", { headers: CLIENT }), segments: ["agents"], env: ENV, fetchImpl: failing });
    expect([502, 504]).toContain(response.status);
    expect(await response.json()).toEqual({ error: "protected_site_unavailable" });
  });
});

describe("issueDevOperatorSession", () => {
  it("issues the cookie only with login off, a configured token, and a loopback request", () => {
    expect(issueDevOperatorSession(ENV, { loginRequired: false, requestUrl: "http://127.0.0.1:3000/api/glasswing/session" })).toEqual({
      ok: true,
      cookie: { name: "aidenid_operator_token", value: ENV.AIDENID_DASHBOARD_OPERATOR_REQUEST_TOKEN, secure: false, maxAgeSeconds: 8 * 60 * 60 }
    });
    expect(issueDevOperatorSession(ENV, { loginRequired: true, requestUrl: "http://127.0.0.1:3000/x" })).toEqual({ ok: false, status: 403, error: "login_required" });
    expect(issueDevOperatorSession({}, { loginRequired: false, requestUrl: "http://127.0.0.1:3000/x" })).toEqual({ ok: false, status: 503, error: "operator_auth_not_configured" });
    expect(issueDevOperatorSession(ENV, { loginRequired: false, requestUrl: "http://dashboard.example.com/x" })).toEqual({ ok: false, status: 403, error: "loopback_only" });
  });
});
