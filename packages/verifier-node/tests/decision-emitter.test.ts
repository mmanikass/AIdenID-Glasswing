import { describe, expect, it } from "vitest";

import {
  controlPlaneDecisionPayloadFromResult,
  createControlPlaneDecisionEmitter,
  createControlPlaneDecisionOverride,
  type DecisionEmitterFetch,
  type DecisionResult
} from "../src/index.js";

const DECISION: DecisionResult = {
  requestId: "req_emit_1",
  siteId: "sit_emit",
  mode: "enforce",
  method: "get",
  path: "/benefits/PHI/member-123",
  routeTemplate: "/benefits/PHI/*",
  actorClass: "verified_agent",
  decision: "allow",
  recommendedDecision: "allow",
  reasons: ["matched_policy"],
  observeOnly: false,
  rateLimit: { status: "ok", remaining: 9 },
  cascadeTrace: [
    { ordinal: 1, layer: "crypto_identity", status: "pass", reason: "http_signature_dpop_verified", latency_us: 410 },
    { ordinal: 2, layer: "delegation_authorization", status: "pass", reason: "proof_bound_session_verified", latency_us: 410 },
    { ordinal: 3, layer: "fingerprint_sidecar", status: "not_configured", reason: "fingerprint_provider_missing", latency_us: 0 },
    { ordinal: 4, layer: "operator_reputation", status: "not_configured", reason: "operator_reputation_provider_missing", latency_us: 0 }
  ],
  latencyUs: 1725
};

async function waitFor(condition: () => boolean, timeoutMs = 250): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!condition()) {
    if (Date.now() >= deadline) {
      throw new Error("timed out waiting for condition");
    }
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

describe("control-plane decision emitter", () => {
  it("maps verifier decisions into the control-plane ingest contract", () => {
    expect(
      controlPlaneDecisionPayloadFromResult(
        {
          ...DECISION,
          issuer: "https://partner-broker.example",
          subjectHandle: "subh_demo",
          llmBrand: "openai",
          purpose: "research",
          decision: "price_required",
          responseHeaders: { "X-AIdenID-Price-USD": "0.01" }
        },
        { now: () => new Date("2026-04-29T01:00:00.000Z") }
      )
    ).toEqual({
      site_id: "sit_emit",
      request_id: "req_emit_1",
      actor_class: "verified_agent",
      issuer: "https://partner-broker.example",
      subject_handle: "subh_demo",
      llm_brand: "openai",
      purpose: "research",
      decision: "price_required",
      recommended_decision: "allow",
      route_template: "/benefits/PHI/*",
      method: "GET",
      occurred_at: "2026-04-29T01:00:00.000Z",
      latency_us: 1725,
      price_usd: 0.01,
      cascade_trace: [
        { ordinal: 1, layer: "crypto_identity", status: "pass", reason: "http_signature_dpop_verified", latency_us: 410 },
        { ordinal: 2, layer: "delegation_authorization", status: "pass", reason: "proof_bound_session_verified", latency_us: 410 },
        { ordinal: 3, layer: "fingerprint_sidecar", status: "not_configured", reason: "fingerprint_provider_missing", latency_us: 0 },
        { ordinal: 4, layer: "operator_reputation", status: "not_configured", reason: "operator_reputation_provider_missing", latency_us: 0 }
      ],
      reason_codes: ["matched_policy"]
    });
  });

  it("queues decisions without blocking the caller and posts them to /v1/decisions", async () => {
    const calls: Array<{ readonly input: string; readonly body: unknown; readonly authorization?: string | undefined }> = [];
    const fetcher: DecisionEmitterFetch = async (input, init) => {
      calls.push({
        input,
        body: JSON.parse(init.body ?? "{}") as unknown,
        authorization: init.headers.Authorization
      });
      return {
        ok: true,
        status: 201,
        text: async () => ""
      };
    };

    await createControlPlaneDecisionEmitter({
        controlPlaneUrl: "https://control.example.com/base/../",
        apiKey: "cp_demo_key",
        fetcher,
        flushIntervalMs: 10,
        now: () => new Date("2026-04-29T01:00:00.000Z")
      })(DECISION);

    expect(calls).toEqual([]);
    await waitFor(() => calls.length === 1);
    expect(calls).toEqual([
      {
        input: "https://control.example.com/v1/decisions",
        authorization: "Bearer cp_demo_key",
        body: expect.objectContaining({
          site_id: "sit_emit",
          request_id: "req_emit_1",
          cascade_trace: DECISION.cascadeTrace,
          reason_codes: ["matched_policy"]
        })
      }
    ]);
  });

  it("reports emit failures without throwing unless failClosed is enabled", async () => {
    const errors: string[] = [];
    const fetcher: DecisionEmitterFetch = async () => ({
      ok: false,
      status: 503,
      text: async () => "maintenance"
    });
    await createControlPlaneDecisionEmitter({
      controlPlaneUrl: "https://control.example.com",
      fetcher,
      flushIntervalMs: 1,
      onError: (error) => {
        errors.push(error.message);
      }
    })(DECISION);
    await waitFor(() => errors.length === 1);
    expect(errors).toEqual(["control-plane decision emit failed with HTTP 503: maintenance"]);

    await expect(
      createControlPlaneDecisionEmitter({
        controlPlaneUrl: "https://control.example.com",
        fetcher,
        failClosed: true
      })(DECISION)
    ).rejects.toThrow(/HTTP 503/);
  });

  it("bounds queued decision emission and drops the oldest decision on overflow", async () => {
    const calls: string[] = [];
    const errors: string[] = [];
    const fetcher: DecisionEmitterFetch = async (_input, init) => {
      const payload = JSON.parse(init.body ?? "{}") as { readonly request_id?: string };
      calls.push(payload.request_id ?? "");
      return {
        ok: true,
        status: 201,
        text: async () => ""
      };
    };
    const emit = createControlPlaneDecisionEmitter({
      controlPlaneUrl: "https://control.example.com",
      fetcher,
      flushIntervalMs: 10,
      maxQueueSize: 1,
      onError: (error) => {
        errors.push(error.message);
      }
    });

    await emit({ ...DECISION, requestId: "req_oldest" });
    await emit({ ...DECISION, requestId: "req_newest" });

    await waitFor(() => errors.length === 1 && calls.length === 1);
    expect(errors[0]).toContain("control-plane decision emitter queue full");
    expect(calls).toEqual(["req_newest"]);
  });

  it("emits a decision, awaits an operator action, and returns the overridden decision", async () => {
    const calls: Array<{ readonly input: string; readonly method: string }> = [];
    const fetcher: DecisionEmitterFetch = async (input, init) => {
      calls.push({ input, method: init.method });
      if (init.method === "POST") {
        return {
          ok: true,
          status: 201,
          text: async () => JSON.stringify({ decision: { id: "dec_override_1" } })
        };
      }
      return {
        ok: true,
        status: 200,
        text: async () =>
          JSON.stringify({
            status: "resolved",
            decision: {
              id: "dec_override_1",
              operator_action: "deny",
              operator_action_actor_id: "ciso_demo"
            }
          })
      };
    };

    await expect(
      createControlPlaneDecisionOverride({
        controlPlaneUrl: "https://control.example.com",
        fetcher,
        awaitTimeoutMs: 125
      })(DECISION)
    ).resolves.toMatchObject({
      decision: "deny",
      reasons: ["matched_policy", "operator_override"],
      responseHeaders: { "X-AIdenID-Operator-Action": "deny", "X-AIdenID-Operator-Effective-Decision": "deny" }
    });
    expect(calls).toEqual([
      { input: "https://control.example.com/v1/decisions", method: "POST" },
      { input: "https://control.example.com/v1/decisions/dec_override_1/await?timeout_ms=125", method: "GET" }
    ]);
  });

  it("maps a quarantine operator action to a deny response while preserving the operator label", async () => {
    const fetcher: DecisionEmitterFetch = async (_input, init) =>
      init.method === "POST"
        ? {
            ok: true,
            status: 201,
            text: async () => JSON.stringify({ decision: { id: "dec_quarantine_1" } })
          }
        : {
            ok: true,
            status: 200,
            text: async () =>
              JSON.stringify({
                status: "resolved",
                decision: {
                  id: "dec_quarantine_1",
                  operator_action: "quarantine",
                  operator_action_effective_decision: "deny"
                }
              })
          };

    await expect(
      createControlPlaneDecisionOverride({
        controlPlaneUrl: "https://control.example.com",
        fetcher,
        awaitTimeoutMs: 125
      })(DECISION)
    ).resolves.toMatchObject({
      decision: "deny",
      reasons: ["matched_policy", "operator_override", "quarantine"],
      responseHeaders: {
        "X-AIdenID-Operator-Action": "quarantine",
        "X-AIdenID-Operator-Effective-Decision": "deny"
      }
    });
  });

  it("keeps the original decision when the operator await times out", async () => {
    const fetcher: DecisionEmitterFetch = async (_input, init) =>
      init.method === "POST"
        ? {
            ok: true,
            status: 201,
            text: async () => JSON.stringify({ decision: { id: "dec_pending_1" } })
          }
        : {
            ok: true,
            status: 202,
            text: async () => JSON.stringify({ status: "pending", decision: { id: "dec_pending_1" } })
          };

    await expect(
      createControlPlaneDecisionOverride({
        controlPlaneUrl: "https://control.example.com",
        fetcher,
        awaitTimeoutMs: 5
      })(DECISION)
    ).resolves.toBeUndefined();
  });
});
