import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { POST as postOperatorAction } from "../src/app/api/decisions/[decisionId]/operator-action/route.js";
import { GET as getDecisionSearch } from "../src/app/api/decisions/search/route.js";
import { GET as getDecisionStream } from "../src/app/api/decisions/stream/route.js";
import {
  DASHBOARD_VIEWS,
  authorizeDashboardOperatorRequest,
  buildDecisionOperatorActionProxyRequest,
  buildDecisionSearchProxyRequest,
  buildDecisionStreamProxyRequest,
  cascadeTelemetryFromBenchmarkArtifact,
  counterfactualImpactFromEvents,
  dashboardDecisionEventFromPayload,
  dashboardLayoutForWidth,
  dashboardRuntimeStatusFromEnv,
  dashboardStreamErrorFromPayload,
  filterDecisionEvents,
  personaAuditSeverityCounts,
  priceRequiredBillingFromEvents,
  providerReputationFromEvents,
  sampleCascadeTelemetry,
  routeMetricsFromEvents,
  sampleDecisionEvents,
  samplePersonaAuditIncidents,
  samplePolicyCopilotSuggestions,
  samplePolicyYaml,
  dashboardControlPlaneTimeoutMs,
  dashboardOperatorRequestAuthConfigured,
  fetchDashboardControlPlaneWithTimeout,
  fetchLiveOperatorAction,
  LiveOperatorActionCircuitBreaker,
  trafficClassificationFromEvents,
  validatePolicyText,
  type CascadeLatencyBenchmarkArtifact,
} from "../src/index.js";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../..",
);

function bearerHeader(value: string): string {
  return ["Bearer", value].join(" ");
}

async function withDashboardEnv<T>(
  updates: Readonly<Record<string, string | undefined>>,
  callback: () => Promise<T>,
): Promise<T> {
  const previous = new Map<string, string | undefined>();
  for (const key of Object.keys(updates)) {
    previous.set(key, process.env[key]);
    const value = updates[key];
    if (value === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = value;
    }
  }
  try {
    return await callback();
  } finally {
    for (const [key, value] of previous.entries()) {
      if (value === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }
  }
}

function replaceFetch(implementation: typeof fetch): () => void {
  const previous = globalThis.fetch;
  globalThis.fetch = implementation;
  return () => {
    globalThis.fetch = previous;
  };
}

describe("dashboard scaffold", () => {
  it("includes the MVP operator surfaces", () => {
    expect(DASHBOARD_VIEWS).toContain("live_stream");
    expect(DASHBOARD_VIEWS).toContain("policy_editor");
    expect(DASHBOARD_VIEWS).toContain("policy_diff_preview");
    expect(DASHBOARD_VIEWS).toContain("policy_copilot");
    expect(DASHBOARD_VIEWS).toContain("counterfactual_impact");
    expect(DASHBOARD_VIEWS).toContain("cascade_telemetry");
    expect(DASHBOARD_VIEWS).toContain("price_required_billing");
    expect(DASHBOARD_VIEWS).toContain("persona_audit");
    expect(DASHBOARD_VIEWS).toContain("identity_challenges");
    expect(DASHBOARD_VIEWS).toContain("revocation_center");
  });

  it("keeps the dashboard shell runtime-rendered so live mode cannot freeze as seeded demo at build time", () => {
    const dashboardPageSource = readFileSync(
      path.join(repoRoot, "apps/dashboard/src/app/page.tsx"),
      "utf8",
    );

    expect(dashboardPageSource).toContain('export const dynamic = "force-dynamic";');
    expect(dashboardPageSource).toContain("Live required");
    expect(dashboardPageSource).toContain(
      "Live evidence mode is required, but no control plane is configured. Seeded decision samples are disabled.",
    );
  });

  it("keeps a route-level dashboard error boundary with retry", () => {
    const dashboardErrorSource = readFileSync(
      path.join(repoRoot, "apps/dashboard/src/app/error.tsx"),
      "utf8",
    );

    expect(dashboardErrorSource).toContain('"use client"');
    expect(dashboardErrorSource).toContain('role="alert"');
    expect(dashboardErrorSource).toContain("Live dashboard unavailable");
    expect(dashboardErrorSource).toContain("onClick={reset}");
  });

  it("filters live traffic without collapsing actor class and decision", () => {
    const results = filterDecisionEvents(
      sampleDecisionEvents,
      "verified_agent price_required",
    );

    expect(results).toHaveLength(1);
    expect(results[0]).toMatchObject({
      actorClass: "verified_agent",
      decision: "price_required",
      routeTemplate: "/premium-content/*",
    });
  });

  it("filters live traffic by cascade layer status and reason", () => {
    const results = filterDecisionEvents(
      sampleDecisionEvents,
      "fingerprint_sidecar pass",
    );

    expect(results.length).toBeGreaterThan(0);
    expect(
      results.every((event) =>
        event.cascadeTrace?.some(
          (entry) => entry.layer === "fingerprint_sidecar",
        ),
      ),
    ).toBe(true);
  });

  it("filters live traffic by declared agent purpose", () => {
    const results = filterDecisionEvents(sampleDecisionEvents, "research");

    expect(results).toHaveLength(1);
    expect(results[0]).toMatchObject({
      requestId: "req_931",
      purpose: "research",
      llmBrand: "openai",
    });
  });

  it("keeps demo traffic visually classified across bots and humans", () => {
    expect(trafficClassificationFromEvents(sampleDecisionEvents)).toEqual([
      { key: "agents", label: "Agents", count: 4, percentage: 44 },
      { key: "humans", label: "Humans", count: 1, percentage: 11 },
      { key: "automation", label: "Automation", count: 2, percentage: 22 },
      { key: "unknown", label: "Unknown", count: 2, percentage: 22 },
    ]);
  });

  it("keeps the fallback demo covering all six decisions and the four-layer pass path", () => {
    expect(new Set(sampleDecisionEvents.map((event) => event.decision))).toEqual(
      new Set(["allow", "throttle", "queue", "sandbox", "deny", "price_required"]),
    );
    expect(sampleDecisionEvents[0]?.cascadeTrace).toEqual([
      expect.objectContaining({ layer: "crypto_identity", status: "pass" }),
      expect.objectContaining({ layer: "delegation_authorization", status: "pass" }),
      expect.objectContaining({ layer: "fingerprint_sidecar", status: "pass" }),
      expect.objectContaining({ layer: "operator_reputation", status: "pass" }),
    ]);
  });

  it("summarizes ChatGPT provider reputation from live decision evidence", () => {
    const summaries = providerReputationFromEvents(sampleDecisionEvents);

    expect(summaries[0]).toMatchObject({
      providerId: "openai",
      displayName: "ChatGPT / OpenAI",
      eventCount: 3,
      passCount: 3,
      latestScore: 92,
      latestStatus: "pass",
      latestDecisionId: "dec_live_1",
      latestRouteTemplate: "/dashboard/ai/assistant",
      recommendedAction: "allow",
      risk: "trusted",
    });
    expect(summaries).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          providerId: "anthropic",
          displayName: "Claude / Anthropic",
          latestScore: 54,
          latestStatus: "fail",
          recommendedAction: "queue",
          risk: "review",
        }),
        expect.objectContaining({
          providerId: "unknown",
          latestScore: 18,
          latestStatus: "fail",
          recommendedAction: "deny",
          risk: "restricted",
        }),
      ]),
    );
  });

  it("normalizes control-plane stream payloads into live dashboard events", () => {
    expect(
      dashboardDecisionEventFromPayload({
        id: "dec_live_1",
        site_id: "sit_demo",
        request_id: "req_live_1",
        actor_class: "verified_agent",
        decision: "allow",
        recommended_decision: "allow",
        route_template: "/benefits/PHI/*",
        method: "get",
        occurred_at: "2026-04-29T01:00:00.000Z",
        latency_us: 2450,
        reason_codes: ["matched_policy"],
        issuer: "https://partner-broker.example",
        llm_brand: "openai",
        purpose: "research",
        operator_action: "quarantine",
        operator_action_actor_id: "ciso_demo",
        operator_action_reason: "manual override",
        operator_action_at: "2026-04-29T01:00:01.000Z",
        operator_action_effective_decision: "deny",
        operator_action_expires_at: "2026-04-29T02:00:01.000Z",
        operator_action_effects: [
          "deny",
          "actor_pin",
          "ocsf_emit",
          "webhook_emit",
        ],
        cascade_trace: [
          {
            ordinal: 1,
            layer: "crypto_identity",
            status: "pass",
            reason: "http_signature_dpop_verified",
            latency_us: 410,
          },
          {
            ordinal: 2,
            layer: "delegation_authorization",
            status: "pass",
            reason: "proof_bound_session_verified",
            latency_us: 410,
          },
          {
            ordinal: 3,
            layer: "fingerprint_sidecar",
            status: "not_configured",
            reason: "fingerprint_provider_missing",
            latency_us: 0,
          },
          {
            ordinal: 4,
            layer: "operator_reputation",
            status: "not_configured",
            reason: "operator_reputation_provider_missing",
            latency_us: 0,
          },
        ],
      }),
    ).toEqual({
      id: "dec_live_1",
      siteId: "sit_demo",
      requestId: "req_live_1",
      actorClass: "verified_agent",
      issuer: "https://partner-broker.example",
      llmBrand: "openai",
      purpose: "research",
      decision: "allow",
      recommendedDecision: "allow",
      routeTemplate: "/benefits/PHI/*",
      method: "GET",
      occurredAt: "2026-04-29T01:00:00.000Z",
      latencyMs: 2.45,
      reasonCodes: ["matched_policy"],
      operatorAction: "quarantine",
      operatorActionActorId: "ciso_demo",
      operatorActionReason: "manual override",
      operatorActionAt: "2026-04-29T01:00:01.000Z",
      operatorActionEffectiveDecision: "deny",
      operatorActionExpiresAt: "2026-04-29T02:00:01.000Z",
      operatorActionEffects: ["deny", "actor_pin", "ocsf_emit", "webhook_emit"],
      cascadeTrace: [
        {
          ordinal: 1,
          layer: "crypto_identity",
          status: "pass",
          reason: "http_signature_dpop_verified",
          latencyUs: 410,
          evidence: [],
        },
        {
          ordinal: 2,
          layer: "delegation_authorization",
          status: "pass",
          reason: "proof_bound_session_verified",
          latencyUs: 410,
          evidence: [],
        },
        {
          ordinal: 3,
          layer: "fingerprint_sidecar",
          status: "not_configured",
          reason: "fingerprint_provider_missing",
          latencyUs: 0,
          evidence: [],
        },
        {
          ordinal: 4,
          layer: "operator_reputation",
          status: "not_configured",
          reason: "operator_reputation_provider_missing",
          latencyUs: 0,
          evidence: [],
        },
      ],
    });
    expect(dashboardDecisionEventFromPayload({ id: "bad" })).toBeUndefined();
  });

  it("normalizes explicit dashboard stream error payloads", () => {
    expect(
      dashboardStreamErrorFromPayload({
        error: "control_plane_stream_unavailable",
        status: 504,
      }),
    ).toEqual({
      error: "control_plane_stream_unavailable",
      status: 504,
    });
    expect(
      dashboardStreamErrorFromPayload({
        error: "live_control_plane_required",
      }),
    ).toEqual({ error: "live_control_plane_required" });
    expect(dashboardStreamErrorFromPayload({ status: 504 })).toBeUndefined();
    expect(dashboardStreamErrorFromPayload("stream down")).toBeUndefined();
  });

  it("keeps live stream empty and error states visible to operators", () => {
    const liveStreamSource = readFileSync(
      path.join(repoRoot, "apps/dashboard/src/components/LiveStream.tsx"),
      "utf8",
    );

    expect(liveStreamSource).toContain(
      'className={`stream-status ${streamStatus}`} role="status"',
    );
    expect(liveStreamSource).toContain("Connecting to live decision stream");
    expect(liveStreamSource).toContain("Decision stream reconnecting");
    expect(liveStreamSource).toContain("stream-notice");
    expect(liveStreamSource).toContain(
      'streamError === undefined ? "stream-notice" : "stream-error"',
    );
    expect(liveStreamSource).toContain('role="status"');
    expect(liveStreamSource).toContain('role="log"');
    expect(liveStreamSource).toContain('aria-live="polite"');
    expect(liveStreamSource).toContain('aria-relevant="additions text"');
    expect(liveStreamSource).toContain(
      "Waiting for live control-plane decisions",
    );
  });

  it("builds a control-plane SSE proxy request that preserves cursor + operator auth and forces the server-owned site scope", () => {
    expect(
      buildDecisionStreamProxyRequest({
        requestUrl:
          "https://dashboard.example.com/api/decisions/stream?once=true&site_id=sit_browser_supplied",
        controlPlaneUrl: "https://control.example.com/",
        operatorToken: "cp_key",
        serverSiteId: "sit_server_owned",
        lastEventId: "41",
      }),
    ).toEqual({
      url: "https://control.example.com/v1/decisions/stream?once=true&site_id=sit_server_owned",
      headers: {
        Accept: "text/event-stream",
        Authorization: bearerHeader("cp_key"),
        "Last-Event-ID": "41",
      },
    });
    expect(
      buildDecisionStreamProxyRequest({
        requestUrl: "https://dashboard.example.com/api/decisions/stream",
        controlPlaneUrl: "",
      }),
    ).toBeUndefined();
  });

  it("closes the sample SSE fallback for once=true canaries", async () => {
    const previous = {
      controlPlaneUrl: process.env.AIDENID_CONTROL_PLANE_URL,
      controlPlaneApiKey: process.env.AIDENID_CONTROL_PLANE_API_KEY,
      requireLiveData: process.env.AIDENID_DASHBOARD_REQUIRE_LIVE_DATA,
    };
    try {
      delete process.env.AIDENID_CONTROL_PLANE_URL;
      delete process.env.AIDENID_CONTROL_PLANE_API_KEY;
      delete process.env.AIDENID_DASHBOARD_REQUIRE_LIVE_DATA;
      const response = await getDecisionStream(
        new Request(
          "https://dashboard.example.com/api/decisions/stream?once=true",
        ),
      );
      const body = await response.text();

      expect(response.headers.get("content-type")).toBe("text/event-stream");
      expect(response.headers.get("x-aidenid-dashboard-data-source")).toBe(
        "sample",
      );
      expect(body).toContain("event: recorded");
      expect(body).not.toContain("heartbeat");
    } finally {
      if (previous.controlPlaneUrl === undefined) {
        delete process.env.AIDENID_CONTROL_PLANE_URL;
      } else {
        process.env.AIDENID_CONTROL_PLANE_URL = previous.controlPlaneUrl;
      }
      if (previous.controlPlaneApiKey === undefined) {
        delete process.env.AIDENID_CONTROL_PLANE_API_KEY;
      } else {
        process.env.AIDENID_CONTROL_PLANE_API_KEY = previous.controlPlaneApiKey;
      }
      if (previous.requireLiveData === undefined) {
        delete process.env.AIDENID_DASHBOARD_REQUIRE_LIVE_DATA;
      } else {
        process.env.AIDENID_DASHBOARD_REQUIRE_LIVE_DATA =
          previous.requireLiveData;
      }
    }
  });

  it("fails closed for once=true stream canaries when live dashboard evidence is required", async () => {
    const response = await withDashboardEnv(
      {
        AIDENID_CONTROL_PLANE_URL: undefined,
        AIDENID_CONTROL_PLANE_API_KEY: undefined,
        AIDENID_DASHBOARD_REQUIRE_LIVE_DATA: "true",
      },
      async () =>
        getDecisionStream(
          new Request(
            "https://dashboard.example.com/api/decisions/stream?once=true",
          ),
        ),
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(response.headers.get("x-aidenid-dashboard-data-source")).toBe(
      "live",
    );
    expect(body).toContain("event: stream_error");
    expect(body).toContain('"error":"live_control_plane_required"');
    expect(body).not.toContain("event: recorded");
  });

  it("fails closed when live dashboard evidence is required but no control plane is configured", async () => {
    const response = await withDashboardEnv(
      {
        AIDENID_CONTROL_PLANE_URL: undefined,
        AIDENID_CONTROL_PLANE_API_KEY: undefined,
        AIDENID_OPERATOR_TOKEN: undefined,
        AIDENID_DASHBOARD_REQUIRE_LIVE_DATA: "true",
      },
      async () =>
        getDecisionSearch(
          new Request("https://dashboard.example.com/api/decisions/search"),
        ),
    );

    expect(response.status).toBe(503);
    expect(response.headers.get("x-aidenid-dashboard-data-source")).toBe(
      "live",
    );
    await expect(response.json()).resolves.toEqual({
      error: "live_control_plane_required",
    });
  });

  it("builds a control-plane operator action proxy request with auth", () => {
    expect(
      buildDecisionOperatorActionProxyRequest({
        controlPlaneUrl: "https://control.example.com/",
        operatorToken: "operator_token_123456",
        decisionId: "dec_live_1",
        operatorAction: "deny",
        operatorReason: "manual override",
      }),
    ).toEqual({
      url: "https://control.example.com/v1/decisions/dec_live_1/operator-action",
      headers: {
        "Content-Type": "application/json",
        Authorization: bearerHeader("operator_token_123456"),
      },
      body: JSON.stringify({
        operator_action: "deny",
        operator_reason: "manual override",
      }),
    });
    expect(
      buildDecisionOperatorActionProxyRequest({
        controlPlaneUrl: "",
        decisionId: "dec_live_1",
        operatorAction: "deny",
      }),
    ).toBeUndefined();
  });

  it("never accepts the upstream control-plane credential as the inbound dashboard credential", () => {
    // Previously AIDENID_DASHBOARD_OPERATOR_REQUEST_TOKEN fell back to AIDENID_OPERATOR_TOKEN,
    // so every dashboard client held the raw upstream operator credential and could bypass this
    // dashboard entirely by calling the control plane directly.
    const upstreamOnly = {
      AIDENID_OPERATOR_TOKEN: "upstream_control_plane_token_123456",
      AIDENID_DASHBOARD_OPERATOR_ACTOR_ID: "ops_alice",
    };
    expect(dashboardOperatorRequestAuthConfigured(upstreamOnly)).toBe(false);
    expect(
      authorizeDashboardOperatorRequest(
        new Request("https://dashboard.example.com/api/decisions/dec_1/operator-action", {
          headers: {
            Authorization: bearerHeader("upstream_control_plane_token_123456"),
          },
        }),
        upstreamOnly,
      ),
    ).toEqual({ ok: false, status: 503, error: "operator_auth_not_configured" });

    // Provisioning a distinct VARIABLE is not the same property as a distinct SECRET. Setting it
    // to the upstream value looks configured but recreates the defect, so it fails closed too.
    const sameSecret = {
      AIDENID_OPERATOR_TOKEN: "shared_secret_value_123456",
      AIDENID_DASHBOARD_OPERATOR_REQUEST_TOKEN: "shared_secret_value_123456",
      AIDENID_DASHBOARD_OPERATOR_ACTOR_ID: "ops_alice",
    };
    expect(
      authorizeDashboardOperatorRequest(
        new Request("https://dashboard.example.com/api/decisions/dec_1/operator-action", {
          headers: { Authorization: bearerHeader("shared_secret_value_123456") },
        }),
        sameSecret,
      ),
    ).toEqual({
      ok: false,
      status: 503,
      error: "operator_auth_shares_upstream_credential",
    });

    // Distinct secrets: the inbound credential authorizes, the upstream one does not.
    const distinct = {
      AIDENID_OPERATOR_TOKEN: "upstream_control_plane_token_123456",
      AIDENID_DASHBOARD_OPERATOR_REQUEST_TOKEN: "dashboard_inbound_token_123456",
      AIDENID_DASHBOARD_OPERATOR_ACTOR_ID: "ops_alice",
    };
    expect(
      authorizeDashboardOperatorRequest(
        new Request("https://dashboard.example.com/api/decisions/dec_1/operator-action", {
          headers: { Authorization: bearerHeader("dashboard_inbound_token_123456") },
        }),
        distinct,
      ),
    ).toEqual({ ok: true, actorId: "ops_alice" });
    expect(
      authorizeDashboardOperatorRequest(
        new Request("https://dashboard.example.com/api/decisions/dec_1/operator-action", {
          headers: {
            Authorization: bearerHeader("upstream_control_plane_token_123456"),
          },
        }),
        distinct,
      ),
    ).toEqual({ ok: false, status: 401, error: "invalid_operator_token" });
  });

  it("requires inbound operator credentials for live dashboard operator requests", () => {
    const env = {
      AIDENID_OPERATOR_TOKEN: "upstream_control_plane_token_123456",
          AIDENID_DASHBOARD_OPERATOR_REQUEST_TOKEN: "operator_token_123456",
      AIDENID_DASHBOARD_OPERATOR_ACTOR_ID: "ops_alice",
    };

    expect(dashboardOperatorRequestAuthConfigured({})).toBe(false);
    expect(dashboardOperatorRequestAuthConfigured(env)).toBe(true);
    expect(
      authorizeDashboardOperatorRequest(
        new Request(
          "https://dashboard.example.com/api/decisions/dec_live_1/operator-action",
        ),
        env,
      ),
    ).toEqual({ ok: false, status: 401, error: "operator_auth_required" });
    expect(
      authorizeDashboardOperatorRequest(
        new Request(
          "https://dashboard.example.com/api/decisions/dec_live_1/operator-action",
          {
            headers: { Authorization: bearerHeader("operator_token_123456") },
          },
        ),
        env,
      ),
    ).toEqual({ ok: true, actorId: "ops_alice" });
    expect(
      authorizeDashboardOperatorRequest(
        new Request(
          "https://dashboard.example.com/api/decisions/dec_live_1/operator-action",
          {
            headers: { cookie: "aidenid_operator_token=operator_token_123456" },
          },
        ),
        env,
      ),
    ).toEqual({ ok: true, actorId: "ops_alice" });
    expect(
      authorizeDashboardOperatorRequest(
        new Request(
          "https://dashboard.example.com/api/decisions/dec_live_1/operator-action",
          {
            headers: { "x-aidenid-operator-token": "wrong_token" },
          },
        ),
        env,
      ),
    ).toEqual({ ok: false, status: 401, error: "invalid_operator_token" });
  });

  it("fails closed instead of applying a local operator-action fallback", async () => {
    let fetchCalled = false;
    const restoreFetch = replaceFetch(async () => {
      fetchCalled = true;
      return Response.json({});
    });
    try {
      const response = await withDashboardEnv(
        {
          AIDENID_CONTROL_PLANE_URL: undefined,
          AIDENID_OPERATOR_TOKEN: "upstream_control_plane_token_123456",
          AIDENID_DASHBOARD_OPERATOR_REQUEST_TOKEN: "operator_token_123456",
        },
        async () =>
          postOperatorAction(
            new Request(
              "https://dashboard.example.com/api/decisions/dec_live_1/operator-action",
              {
                method: "POST",
                headers: {
                  "Content-Type": "application/json",
                  Authorization: bearerHeader("operator_token_123456"),
                },
                body: JSON.stringify({ operator_action: "deny" }),
              },
            ),
            { params: Promise.resolve({ decisionId: "dec_live_1" }) },
          ),
      );
      const body = (await response.json()) as Readonly<Record<string, unknown>>;

      expect(response.status).toBe(503);
      expect(body.error).toBe("control_plane_operator_action_unavailable");
      expect(fetchCalled).toBe(false);
    } finally {
      restoreFetch();
    }
  });

  it("denies unauthenticated live operator actions before proxying upstream", async () => {
    let fetchCalled = false;
    const restoreFetch = replaceFetch(async () => {
      fetchCalled = true;
      return Response.json({});
    });
    try {
      const response = await withDashboardEnv(
        {
          AIDENID_CONTROL_PLANE_URL: "https://control.example.com/",
          AIDENID_OPERATOR_TOKEN: "upstream_control_plane_token_123456",
          AIDENID_DASHBOARD_OPERATOR_REQUEST_TOKEN: "operator_token_123456",
        },
        async () =>
          postOperatorAction(
            new Request(
              "https://dashboard.example.com/api/decisions/dec_live_1/operator-action",
              {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ operator_action: "deny" }),
              },
            ),
            { params: Promise.resolve({ decisionId: "dec_live_1" }) },
          ),
      );
      const body = (await response.json()) as Readonly<Record<string, unknown>>;

      expect(response.status).toBe(401);
      expect(body.error).toBe("operator_auth_required");
      expect(fetchCalled).toBe(false);
    } finally {
      restoreFetch();
    }
  });

  it("uses bounded AbortSignal fetches for operator actions and decision search", async () => {
    const calls: RequestInit[] = [];
    const restoreFetch = replaceFetch(
      async (_input: Parameters<typeof fetch>[0], init?: RequestInit) => {
        calls.push(init ?? {});
        return Response.json({
          decision: { id: "dec_live_1", operator_action: "deny" },
        });
      },
    );
    try {
      const operatorResponse = await withDashboardEnv(
        {
          AIDENID_CONTROL_PLANE_URL: "https://control.example.com/",
          AIDENID_OPERATOR_TOKEN: "upstream_control_plane_token_123456",
          AIDENID_DASHBOARD_OPERATOR_REQUEST_TOKEN: "operator_token_123456",
          AIDENID_DASHBOARD_CONTROL_PLANE_TIMEOUT_MS: "1200",
        },
        async () =>
          postOperatorAction(
            new Request(
              "https://dashboard.example.com/api/decisions/dec_live_1/operator-action",
              {
                method: "POST",
                headers: {
                  "Content-Type": "application/json",
                  Authorization: bearerHeader("operator_token_123456"),
                },
                body: JSON.stringify({ operator_action: "deny" }),
              },
            ),
            { params: Promise.resolve({ decisionId: "dec_live_1" }) },
          ),
      );
      expect(operatorResponse.status).toBe(200);
      expect(calls[0]?.signal).toBeInstanceOf(AbortSignal);
      expect(
        dashboardControlPlaneTimeoutMs({
          AIDENID_DASHBOARD_CONTROL_PLANE_TIMEOUT_MS: "1200",
        }),
      ).toBe(1200);

      const searchResponse = await withDashboardEnv(
        {
          AIDENID_CONTROL_PLANE_URL: "https://control.example.com/",
          AIDENID_OPERATOR_TOKEN: "upstream_control_plane_token_123456",
          AIDENID_DASHBOARD_OPERATOR_REQUEST_TOKEN: "operator_token_123456",
        },
        async () =>
          getDecisionSearch(
            new Request(
              "https://dashboard.example.com/api/decisions/search?decision=deny",
              {
                headers: {
                  Authorization: bearerHeader("operator_token_123456"),
                },
              },
            ),
          ),
      );
      expect(searchResponse.status).toBe(200);
      expect(calls[1]?.signal).toBeInstanceOf(AbortSignal);
    } finally {
      restoreFetch();
    }
  });

  it("centralizes bounded dashboard control-plane fetches", async () => {
    const restoreFetch = replaceFetch(
      async (_input: Parameters<typeof fetch>[0], init?: RequestInit) => {
        expect(init?.signal).toBeInstanceOf(AbortSignal);
        return Response.json({ ok: true });
      },
    );
    try {
      const response = await fetchDashboardControlPlaneWithTimeout(
        "https://control.example.com/v1/decisions",
        { timeoutMs: 500, cache: "no-store" },
      );
      expect(response.status).toBe(200);
    } finally {
      restoreFetch();
    }
  });

  it("bounds live operator action calls and opens a local fallback circuit", async () => {
    let now = 25_000;
    let calls = 0;
    const circuitBreaker = new LiveOperatorActionCircuitBreaker({
      failureThreshold: 1,
      openMs: 2_000,
      now: () => now,
    });
    const failingFetch: typeof fetch = async (_input, init) => {
      calls += 1;
      expect(init?.signal).toBeInstanceOf(AbortSignal);
      return new Response("origin unavailable", { status: 503 });
    };

    const first = await fetchLiveOperatorAction(
      "/api/decisions/dec_live_1/operator-action",
      { method: "POST" },
      { circuitBreaker, fetchImpl: failingFetch, timeoutMs: 250 },
    );
    expect(first.status).toBe(503);

    await expect(
      fetchLiveOperatorAction(
        "/api/decisions/dec_live_1/operator-action",
        { method: "POST" },
        { circuitBreaker, fetchImpl: failingFetch, timeoutMs: 250 },
      ),
    ).rejects.toThrow("operator action circuit open until 27000");
    expect(calls).toBe(1);

    now = 27_001;
    const recovered = await fetchLiveOperatorAction(
      "/api/decisions/dec_live_1/operator-action",
      { method: "POST" },
      {
        circuitBreaker,
        fetchImpl: async (_input, init) => {
          calls += 1;
          expect(init?.signal).toBeInstanceOf(AbortSignal);
          return Response.json({ decision: { id: "dec_live_1" } });
        },
      },
    );
    expect(recovered.status).toBe(200);
    expect(calls).toBe(2);
  });

  it("returns bounded timeout failures for live search and stream proxies", async () => {
    const restoreFetch = replaceFetch(async () => {
      throw new DOMException("aborted", "AbortError");
    });
    try {
      const searchResponse = await withDashboardEnv(
        {
          AIDENID_CONTROL_PLANE_URL: "https://control.example.com/",
          AIDENID_OPERATOR_TOKEN: "upstream_control_plane_token_123456",
          AIDENID_DASHBOARD_OPERATOR_REQUEST_TOKEN: "operator_token_123456",
        },
        async () =>
          getDecisionSearch(
            new Request(
              "https://dashboard.example.com/api/decisions/search?decision=deny",
              {
                headers: {
                  Authorization: bearerHeader("operator_token_123456"),
                },
              },
            ),
          ),
      );
      expect(searchResponse.status).toBe(504);
      await expect(searchResponse.json()).resolves.toMatchObject({
        error: "control_plane_search_unavailable",
        status: 504,
      });

      const streamResponse = await withDashboardEnv(
        {
          AIDENID_CONTROL_PLANE_URL: "https://control.example.com/",
          AIDENID_OPERATOR_TOKEN: "upstream_control_plane_token_123456",
          AIDENID_DASHBOARD_OPERATOR_REQUEST_TOKEN: "operator_token_123456",
          AIDENID_DASHBOARD_SITE_ID: "sit_server_owned",
        },
        async () =>
          getDecisionStream(
            new Request(
              "https://dashboard.example.com/api/decisions/stream?once=true",
              {
                headers: {
                  Authorization: bearerHeader("operator_token_123456"),
                },
              },
            ),
          ),
      );
      expect(streamResponse.status).toBe(200);
      const streamBody = await streamResponse.text();
      expect(streamBody).toContain("event: stream_error");
      expect(streamBody).toContain('"error":"control_plane_stream_unavailable"');
      expect(streamBody).toContain('"status":504');
    } finally {
      restoreFetch();
    }
  });

  it("builds a control-plane decision-search proxy request that forwards filters and auth", () => {
    expect(
      buildDecisionSearchProxyRequest({
        requestUrl:
          "https://dashboard.example.com/api/decisions/search?site_id=sit_demo&decision=deny&operator_actor_id=ops_alice&limit=50",
        controlPlaneUrl: "https://control.example.com/",
        operatorToken: "search_token",
      }),
    ).toEqual({
      url: "https://control.example.com/v1/decisions/search?site_id=sit_demo&decision=deny&operator_actor_id=ops_alice&limit=50",
      headers: {
        Accept: "application/json",
        Authorization: bearerHeader("search_token"),
      },
    });
    expect(
      buildDecisionSearchProxyRequest({
        requestUrl:
          "https://dashboard.example.com/api/decisions/search?site_id=sit_demo",
        controlPlaneUrl: "",
      }),
    ).toBeUndefined();
  });

  it("reports sample and live runtime status without exposing secrets", () => {
    expect(dashboardRuntimeStatusFromEnv({})).toEqual({
      service: "aidenid-clearance-dashboard",
      mode: "sample_data",
      controlPlaneStreamConfigured: false,
      operatorActionsConfigured: false,
      policyPreviewConfigured: false,
      fallbackDataEnabled: true,
      liveDataRequired: false,
    });
    expect(
      dashboardRuntimeStatusFromEnv({
        AIDENID_DASHBOARD_REQUIRE_LIVE_DATA: "true",
      }),
    ).toEqual({
      service: "aidenid-clearance-dashboard",
      mode: "live_control_plane_required",
      controlPlaneStreamConfigured: false,
      operatorActionsConfigured: false,
      policyPreviewConfigured: false,
      fallbackDataEnabled: false,
      liveDataRequired: true,
    });
    expect(
      dashboardRuntimeStatusFromEnv({
        AIDENID_CONTROL_PLANE_URL:
          "http://control-plane.aidenid-clearance-demo.local:3000",
        AIDENID_CONTROL_PLANE_API_KEY: "cp_secret",
        AIDENID_DASHBOARD_REQUIRE_LIVE_DATA: "true",
        AIDENID_OPERATOR_TOKEN: "operator_secret",
        // Distinct from the upstream credential above: operator actions are only "configured"
        // when the dashboard has its own inbound token, not when it can borrow the upstream one.
        AIDENID_DASHBOARD_OPERATOR_REQUEST_TOKEN: "dashboard_inbound_secret",
      }),
    ).toEqual({
      service: "aidenid-clearance-dashboard",
      mode: "live_control_plane",
      controlPlaneStreamConfigured: true,
      operatorActionsConfigured: true,
      policyPreviewConfigured: true,
      fallbackDataEnabled: false,
      liveDataRequired: true,
    });
  });

  it("aggregates analytics by route template", () => {
    const metrics = routeMetricsFromEvents(sampleDecisionEvents);

    expect(metrics[0]).toMatchObject({ routeTemplate: "/checkout", count: 2 });
    expect(
      metrics.every((metric) => metric.routeTemplate.startsWith("/")),
    ).toBe(true);
  });

  it("computes counterfactual enforcement impact from observe-mode recommendations", () => {
    const impacts = counterfactualImpactFromEvents(sampleDecisionEvents);

    expect(impacts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          routeTemplate: "/comments/:id",
          newlyBlockedIfEnforced: 1,
          wouldBlockIfEnforced: 1,
        }),
        expect.objectContaining({
          routeTemplate: "/checkout",
          newlyBlockedIfEnforced: 1,
        }),
      ]),
    );
  });

  it("aggregates price_required billing by issuer", () => {
    expect(priceRequiredBillingFromEvents(sampleDecisionEvents)).toEqual([
      expect.objectContaining({
        issuer: "https://partner-broker.example",
        decisionCount: 1,
        pricedDecisionCount: 1,
        estimatedGrossUsd: 0.01,
      }),
    ]);
  });

  it("builds cascade telemetry from the benchmark artifact", () => {
    const artifact = JSON.parse(
      readFileSync(
        path.join(
          repoRoot,
          "docs/dd/artifacts/cascade-latency-2026-05-02.json",
        ),
        "utf8",
      ),
    ) as CascadeLatencyBenchmarkArtifact;
    const telemetry = cascadeTelemetryFromBenchmarkArtifact(artifact);

    expect(telemetry).toMatchObject({
      decisions: 1000,
      concurrency: 50,
      seed: 20260502,
      shortCircuiting: false,
      sloBudgetMs: 200,
      sloStatus: "within_budget",
      overall: {
        p50Ms: 122.496,
        p95Ms: 154.777,
        p99Ms: 184.667,
      },
    });
    expect(telemetry.layers.map((layer) => layer.label)).toEqual([
      "Web Bot Auth",
      "Delegation",
      "Fingerprint",
      "Reputation",
    ]);
    expect(telemetry.slowestLayer).toMatchObject({
      name: "fingerprint_stub",
      p95Ms: 62.173,
    });
  });

  it("exposes dashboard sample cascade telemetry with the quoteable worst-case p95", () => {
    expect(sampleCascadeTelemetry).toMatchObject({
      mode: "all_layers_worst_case",
      sloStatus: "within_budget",
      overall: {
        p95Ms: 154.777,
        p99Ms: 184.667,
      },
    });
  });

  it("validates policy YAML and exposes mobile/tablet layout smoke checks", () => {
    expect(validatePolicyText(samplePolicyYaml)).toMatchObject({
      ok: true,
      routeCount: 2,
    });
    expect(dashboardLayoutForWidth(390)).toBe("mobile");
    expect(dashboardLayoutForWidth(900)).toBe("tablet");
    expect(dashboardLayoutForWidth(1280)).toBe("desktop");
  });

  it("shows offline Policy Copilot suggestions as pending ai_proposed review items", () => {
    expect(samplePolicyCopilotSuggestions[0]).toMatchObject({
      label: "ai_proposed",
      approvalStatus: "pending",
      metadata: {
        model: "offline-policy-copilot-rules-v1",
        tool: "aidenid-policy-copilot",
      },
    });
  });

  it("shows persona audit incidents by severity", () => {
    expect(personaAuditSeverityCounts(samplePersonaAuditIncidents)).toEqual({
      high: 1,
      medium: 1,
    });
    expect(samplePersonaAuditIncidents[0]).toMatchObject({
      triggerType: "revocation_epoch",
      tool: "create-sentinelayer",
      status: "queued",
    });
  });
});
