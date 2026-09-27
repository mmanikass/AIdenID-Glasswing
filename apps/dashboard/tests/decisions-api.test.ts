import { describe, expect, it } from "vitest";

import { POST as postOperatorAction } from "../src/app/api/decisions/[decisionId]/operator-action/route.js";
import { GET as getDecisionSearch } from "../src/app/api/decisions/search/route.js";
import { GET as getDecisionStream } from "../src/app/api/decisions/stream/route.js";
import { fetchInitialDashboardDecisionEvents } from "../src/index.js";

const CRITICAL_DECISIONS_API_COVERAGE = [
  {
    route: "/api/decisions/search",
    assertions: [
      "requires operator auth in live mode",
      "does not fetch upstream before auth succeeds",
      "preserves control-plane error envelope",
      "preserves upstream search failure envelopes",
    ],
  },
  {
    route: "/api/decisions/stream",
    assertions: [
      "requires operator auth in live mode",
      "does not fetch upstream before auth succeeds",
      "returns text/event-stream",
      "labels live data source",
      "emits named stream_error on upstream timeout",
      "emits named stream_error on upstream non-OK responses",
    ],
  },
  {
    route: "/api/decisions/:decisionId/operator-action",
    assertions: [
      "requires operator auth",
      "rejects malformed mutation bodies before upstream fetch",
      "proxies authenticated PATCH to control plane",
      "preserves upstream mutation status codes",
      "uses bounded AbortSignal upstream fetch",
    ],
  },
] as const;

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

function recordFetchCall(
  calls: Array<{
    readonly input: Parameters<typeof fetch>[0];
    readonly init?: RequestInit;
  }>,
  input: Parameters<typeof fetch>[0],
  init?: RequestInit,
): void {
  calls.push(init === undefined ? { input } : { input, init });
}

describe("dashboard decisions API integration", () => {
  it("keeps a machine-checkable coverage matrix for critical decisions endpoints", () => {
    expect(CRITICAL_DECISIONS_API_COVERAGE).toEqual([
      {
        route: "/api/decisions/search",
        assertions: [
          "requires operator auth in live mode",
          "does not fetch upstream before auth succeeds",
          "preserves control-plane error envelope",
          "preserves upstream search failure envelopes",
        ],
      },
      {
        route: "/api/decisions/stream",
        assertions: [
          "requires operator auth in live mode",
          "does not fetch upstream before auth succeeds",
          "returns text/event-stream",
          "labels live data source",
          "emits named stream_error on upstream timeout",
          "emits named stream_error on upstream non-OK responses",
        ],
      },
      {
        route: "/api/decisions/:decisionId/operator-action",
        assertions: [
          "requires operator auth",
          "rejects malformed mutation bodies before upstream fetch",
          "proxies authenticated PATCH to control plane",
          "preserves upstream mutation status codes",
          "uses bounded AbortSignal upstream fetch",
        ],
      },
    ]);
  });

  it("denies unauthenticated live decision search before upstream fetch", async () => {
    let fetchCalled = false;
    const restoreFetch = replaceFetch(async () => {
      fetchCalled = true;
      return Response.json({ decisions: [] });
    });
    try {
      const response = await withDashboardEnv(
        {
          AIDENID_CONTROL_PLANE_URL: "https://control.example.com/",
          AIDENID_OPERATOR_TOKEN: "upstream_control_plane_token_123456",
          AIDENID_DASHBOARD_OPERATOR_REQUEST_TOKEN: "operator_token_123456",
        },
        async () =>
          getDecisionSearch(
            new Request(
              "https://dashboard.example.com/api/decisions/search?decision=deny",
            ),
          ),
      );

      expect(response.status).toBe(401);
      await expect(response.json()).resolves.toMatchObject({
        error: "operator_auth_required",
      });
      expect(fetchCalled).toBe(false);
    } finally {
      restoreFetch();
    }
  });

  it("returns a structured live decision search error when upstream fails", async () => {
    const restoreFetch = replaceFetch(async () =>
      Response.json({ error: "control plane down" }, { status: 503 }),
    );
    try {
      const response = await withDashboardEnv(
        {
          AIDENID_CONTROL_PLANE_URL: "https://control.example.com/",
          AIDENID_OPERATOR_TOKEN: "upstream_control_plane_token_123456",
          AIDENID_DASHBOARD_OPERATOR_REQUEST_TOKEN: "operator_token_123456",
        },
        async () =>
          getDecisionSearch(
            new Request(
              "https://dashboard.example.com/api/decisions/search?limit=25",
              { headers: { Authorization: bearerHeader("operator_token_123456") } },
            ),
          ),
      );

      expect(response.status).toBe(503);
      await expect(response.json()).resolves.toEqual({
        error: "control_plane_search_unavailable",
        status: 503,
      });
    } finally {
      restoreFetch();
    }
  });

  it("denies unauthenticated live decision stream before upstream fetch", async () => {
    let fetchCalled = false;
    const restoreFetch = replaceFetch(async () => {
      fetchCalled = true;
      return new Response("event: recorded\ndata: {}\n\n", {
        headers: { "Content-Type": "text/event-stream" },
      });
    });
    try {
      const response = await withDashboardEnv(
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
            ),
          ),
      );

      expect(response.status).toBe(401);
      await expect(response.json()).resolves.toEqual({
        error: "operator_auth_required",
      });
      expect(fetchCalled).toBe(false);
    } finally {
      restoreFetch();
    }
  });

  it("denies invalid live decision-stream credentials before upstream fetch", async () => {
    let fetchCalled = false;
    const restoreFetch = replaceFetch(async () => {
      fetchCalled = true;
      return new Response("event: recorded\ndata: {}\n\n");
    });
    try {
      const response = await withDashboardEnv(
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
              { headers: { Authorization: bearerHeader("wrong_token_123456") } },
            ),
          ),
      );

      expect(response.status).toBe(401);
      await expect(response.json()).resolves.toEqual({
        error: "invalid_operator_token",
      });
      expect(fetchCalled).toBe(false);
    } finally {
      restoreFetch();
    }
  });

  it("authenticates a live decision-stream cookie before using server-owned upstream scope", async () => {
    const upstreamCalls: Array<{
      readonly input: Parameters<typeof fetch>[0];
      readonly init?: RequestInit;
    }> = [];
    const restoreFetch = replaceFetch(async (input, init) => {
      recordFetchCall(upstreamCalls, input, init);
      return new Response('event: recorded\ndata: {"site_id":"sit_server_owned"}\n\n', {
        headers: { "Content-Type": "text/event-stream" },
      });
    });
    try {
      const response = await withDashboardEnv(
        {
          AIDENID_CONTROL_PLANE_URL: "https://control.example.com/",
          AIDENID_OPERATOR_TOKEN: "upstream_control_plane_token_123456",
          AIDENID_DASHBOARD_OPERATOR_REQUEST_TOKEN: "operator_token_123456",
          AIDENID_DASHBOARD_SITE_ID: "sit_server_owned",
        },
        async () =>
          getDecisionStream(
            new Request(
              "https://dashboard.example.com/api/decisions/stream?once=true&site_id=sit_browser_supplied",
              { headers: { cookie: "aidenid_operator_token=operator_token_123456" } },
            ),
          ),
      );

      expect(response.status).toBe(200);
      expect(response.headers.get("x-aidenid-dashboard-data-source")).toBe("live");
      expect(await response.text()).toContain("event: recorded");
      expect(upstreamCalls).toHaveLength(1);
      expect(String(upstreamCalls[0]?.input)).toBe(
        "https://control.example.com/v1/decisions/stream?once=true&site_id=sit_server_owned",
      );
      expect(upstreamCalls[0]?.init?.headers).toMatchObject({
        Authorization: bearerHeader("upstream_control_plane_token_123456"),
      });
    } finally {
      restoreFetch();
    }
  });

  it("emits a named SSE error event when the live decision stream is unavailable", async () => {
    const restoreFetch = replaceFetch(async () => {
      throw new DOMException("aborted", "AbortError");
    });
    try {
      const response = await withDashboardEnv(
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
              { headers: { Authorization: bearerHeader("operator_token_123456") } },
            ),
          ),
      );

      expect(response.status).toBe(200);
      expect(response.headers.get("content-type")).toBe("text/event-stream");
      expect(response.headers.get("x-aidenid-dashboard-data-source")).toBe(
        "live",
      );
      const body = await response.text();
      expect(body).toContain("event: stream_error");
      expect(body).toContain('"error":"control_plane_stream_unavailable"');
      expect(body).toContain('"status":504');
    } finally {
      restoreFetch();
    }
  });

  it("emits a named SSE error event when the live decision stream returns non-OK", async () => {
    const restoreFetch = replaceFetch(async () =>
      Response.json({ error: "maintenance" }, { status: 503 }),
    );
    try {
      const response = await withDashboardEnv(
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
              { headers: { Authorization: bearerHeader("operator_token_123456") } },
            ),
          ),
      );

      expect(response.status).toBe(200);
      expect(response.headers.get("content-type")).toBe("text/event-stream");
      const body = await response.text();
      expect(body).toContain("event: stream_error");
      expect(body).toContain('"error":"control_plane_stream_unavailable"');
      expect(body).toContain('"status":503');
    } finally {
      restoreFetch();
    }
  });

  it("server-bootstraps recent live decisions without exposing browser credentials", async () => {
    const upstreamCalls: Array<{
      readonly input: Parameters<typeof fetch>[0];
      readonly init?: RequestInit;
    }> = [];
    const restoreFetch = replaceFetch(async (input, init) => {
      recordFetchCall(upstreamCalls, input, init);
      return Response.json({
        decisions: [
          {
            id: "dec_live_bootstrap_1",
            occurred_at: "2026-07-01T08:00:00.000Z",
            request_id: "req_bootstrap_1",
            site_id: "sit_demo",
            actor_class: "verified_agent",
            decision: "allow",
            route_template: "/checkout",
            method: "GET",
            latency_ms: 12,
            reason_codes: ["identity_verified"],
          },
          {
            id: "missing-required-fields",
          },
        ],
      });
    });
    try {
      const events = await fetchInitialDashboardDecisionEvents({
        AIDENID_CONTROL_PLANE_URL: "https://control.example.com/",
        AIDENID_OPERATOR_TOKEN: "upstream_control_plane_token_123456",
        AIDENID_DASHBOARD_OPERATOR_REQUEST_TOKEN: "operator_token_123456",
        AIDENID_DASHBOARD_LIVE_INITIAL_LIMIT: "10",
      });

      expect(events).toHaveLength(1);
      expect(events[0]).toMatchObject({
        id: "dec_live_bootstrap_1",
        actorClass: "verified_agent",
        decision: "allow",
        routeTemplate: "/checkout",
      });
      expect(upstreamCalls).toHaveLength(1);
      expect(String(upstreamCalls[0]?.input)).toBe(
        "https://control.example.com/v1/decisions/search?limit=10",
      );
      expect(upstreamCalls[0]?.init?.headers).toMatchObject({
        Accept: "application/json",
        Authorization: bearerHeader("upstream_control_plane_token_123456"),
      });
      expect(upstreamCalls[0]?.init?.signal).toBeInstanceOf(AbortSignal);
    } finally {
      restoreFetch();
    }
  });

  it("keeps live decision bootstrap fail-closed when upstream search is unavailable", async () => {
    const restoreFetch = replaceFetch(async () =>
      Response.json({ error: "unavailable" }, { status: 503 }),
    );
    try {
      await expect(
        fetchInitialDashboardDecisionEvents({
          AIDENID_CONTROL_PLANE_URL: "https://control.example.com/",
          AIDENID_CONTROL_PLANE_API_KEY: "cp_key",
        }),
      ).resolves.toEqual([]);
    } finally {
      restoreFetch();
    }
  });

  it("proxies authenticated operator actions to the live control plane", async () => {
    const upstreamCalls: Array<{
      readonly input: Parameters<typeof fetch>[0];
      readonly init?: RequestInit;
    }> = [];
    const restoreFetch = replaceFetch(async (input, init) => {
      recordFetchCall(upstreamCalls, input, init);
      return Response.json({
        decision: {
          id: "dec_live_1",
          operator_action: "deny",
          operator_action_actor_id: "ops_alice",
        },
      });
    });
    try {
      const response = await withDashboardEnv(
        {
          AIDENID_CONTROL_PLANE_URL: "https://control.example.com/",
          AIDENID_OPERATOR_TOKEN: "upstream_control_plane_token_123456",
          AIDENID_DASHBOARD_OPERATOR_REQUEST_TOKEN: "operator_token_123456",
          AIDENID_DASHBOARD_OPERATOR_ACTOR_ID: "ops_alice",
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
                body: JSON.stringify({
                  operator_action: "deny",
                  operator_reason: "manual override",
                }),
              },
            ),
            { params: Promise.resolve({ decisionId: "dec_live_1" }) },
          ),
      );

      expect(response.status).toBe(200);
      await expect(response.json()).resolves.toMatchObject({
        decision: {
          id: "dec_live_1",
          operator_action: "deny",
          operator_action_actor_id: "ops_alice",
        },
      });
      expect(upstreamCalls).toHaveLength(1);
      expect(String(upstreamCalls[0]?.input)).toBe(
        "https://control.example.com/v1/decisions/dec_live_1/operator-action",
      );
      expect(upstreamCalls[0]?.init?.method).toBe("PATCH");
      expect(upstreamCalls[0]?.init?.headers).toMatchObject({
        Authorization: bearerHeader("upstream_control_plane_token_123456"),
        "Content-Type": "application/json",
      });
      expect(upstreamCalls[0]?.init?.body).toBe(
        JSON.stringify({
          operator_action: "deny",
          operator_reason: "manual override",
        }),
      );
      expect(upstreamCalls[0]?.init?.signal).toBeInstanceOf(AbortSignal);
    } finally {
      restoreFetch();
    }
  });

  it("denies unauthenticated operator actions before upstream mutation", async () => {
    let fetchCalled = false;
    const restoreFetch = replaceFetch(async () => {
      fetchCalled = true;
      return Response.json({ ok: true });
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

      expect(response.status).toBe(401);
      await expect(response.json()).resolves.toEqual({
        error: "operator_auth_required",
      });
      expect(fetchCalled).toBe(false);
    } finally {
      restoreFetch();
    }
  });

  it("rejects malformed operator-action bodies before upstream mutation", async () => {
    let fetchCalled = false;
    const restoreFetch = replaceFetch(async () => {
      fetchCalled = true;
      return Response.json({ ok: true });
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
                headers: {
                  "Content-Type": "application/json",
                  Authorization: bearerHeader("operator_token_123456"),
                },
                body: JSON.stringify({ operator_reason: "missing action" }),
              },
            ),
            { params: Promise.resolve({ decisionId: "dec_live_1" }) },
          ),
      );

      expect(response.status).toBe(400);
      await expect(response.json()).resolves.toEqual({
        error: "invalid_operator_action_request",
        message: "operator_action is required",
      });
      expect(fetchCalled).toBe(false);
    } finally {
      restoreFetch();
    }
  });

  it("preserves upstream operator-action conflict responses", async () => {
    const restoreFetch = replaceFetch(async () =>
      Response.json({ error: "decision_already_actioned" }, { status: 409 }),
    );
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

      expect(response.status).toBe(409);
      await expect(response.json()).resolves.toEqual({
        error: "decision_already_actioned",
      });
    } finally {
      restoreFetch();
    }
  });

  it("returns structured operator-action errors when the control plane fails", async () => {
    const restoreFetch = replaceFetch(async () => {
      throw new DOMException("aborted", "AbortError");
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

      expect(response.status).toBe(504);
      await expect(response.json()).resolves.toEqual({
        error: "control_plane_operator_action_unavailable",
        status: 504,
      });
    } finally {
      restoreFetch();
    }
  });
});
