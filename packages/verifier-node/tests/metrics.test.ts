import { describe, expect, it } from "vitest";

import { evaluateAndEmit, InMemoryVerifierMetricsSink, type DecisionResult } from "../src/index.js";

describe("verifier metrics", () => {
  it("records Prometheus-shaped decision counters and latency gauges", async () => {
    const metrics = new InMemoryVerifierMetricsSink();

    await evaluateAndEmit(
      {
        method: "GET",
        url: "https://shop.example.com/catalog",
        headers: { "user-agent": "Mozilla/5.0", accept: "text/html", "x-request-id": "req_metrics" }
      },
      {
        siteId: "sit_metrics",
        apiKey: "key",
        mode: "observe",
        metrics,
        now: () => new Date("2026-04-25T00:00:00.000Z")
      }
    );

    expect(metrics.snapshot()).toEqual([
      expect.objectContaining({
        siteId: "sit_metrics",
        action: "allow",
        actorClass: "likely_human",
        mode: "observe",
        routeTemplate: "/catalog",
        count: 1
      })
    ]);
    expect(metrics.renderPrometheus()).toContain('aidenid_decision_total{site_id="sit_metrics",action="allow"');
  });

  it("records provider-layer counters and latency gauges by provider id", async () => {
    const metrics = new InMemoryVerifierMetricsSink();

    await evaluateAndEmit(
      {
        method: "GET",
        url: "https://shop.example.com/catalog",
        headers: { "user-agent": "Mozilla/5.0", accept: "text/html", "x-request-id": "req_provider_metrics" }
      },
      {
        siteId: "sit_metrics",
        apiKey: "key",
        mode: "observe",
        metrics,
        fingerprint: {
          providerId: "fingerprint-demo",
          provider: {
            async lookup() {
              return {
                provider: "fingerprint-runtime-instance",
                botScore: 0.1,
                suspicionDelta: 0.05,
                evidence: ["low-risk-device"]
              };
            }
          }
        },
        operatorReputation: {
          providerId: "operator-cache",
          provider: {
            lookup() {
              return {
                operatorActorId: "op_demo",
                trustTier: "trusted",
                status: "active",
                reputationScore: 91
              };
            }
          }
        },
        now: () => new Date("2026-04-25T00:00:00.000Z")
      }
    );

    expect(metrics.providerSnapshot()).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          siteId: "sit_metrics",
          layer: "fingerprint_sidecar",
          provider: "fingerprint-demo",
          status: "pass",
          reason: "fingerprint_evidence",
          routeTemplate: "/catalog",
          count: 1
        }),
        expect.objectContaining({
          siteId: "sit_metrics",
          layer: "operator_reputation",
          provider: "operator-cache",
          status: "pass",
          reason: "operator_reputation_active",
          routeTemplate: "/catalog",
          count: 1
        })
      ])
    );
    const prometheus = metrics.renderPrometheus();
    expect(prometheus).toContain(
      'aidenid_provider_layer_total{site_id="sit_metrics",layer="fingerprint_sidecar",provider="fingerprint-demo",status="pass",reason="fingerprint_evidence",route_template="/catalog"} 1'
    );
    expect(prometheus).toContain(
      'aidenid_provider_layer_total{site_id="sit_metrics",layer="operator_reputation",provider="operator-cache",status="pass",reason="operator_reputation_active",route_template="/catalog"} 1'
    );
  });

  it("records dedicated low-cardinality operator scope mismatch counters", () => {
    const metrics = new InMemoryVerifierMetricsSink();
    const decision: DecisionResult = {
      requestId: "req_scope_metrics",
      siteId: "sit_metrics",
      mode: "enforce",
      method: "GET",
      path: "/private/report",
      routeTemplate: "/private/:id",
      actorClass: "verified_agent",
      decision: "deny",
      recommendedDecision: "deny",
      reasons: ["operator_scope_mismatch"],
      observeOnly: false,
      rateLimit: { status: "ok" },
      cascadeTrace: [
        {
          ordinal: 4,
          layer: "operator_reputation",
          status: "fail",
          reason: "operator_scope_mismatch",
          latency_us: 0,
          evidence: ["scope_match:false", "provider:operator-cache"]
        }
      ],
      latencyUs: 42
    };

    metrics.recordDecision(decision);
    metrics.recordDecision(decision);

    expect(metrics.scopeMismatchSnapshot()).toEqual([
      {
        siteId: "sit_metrics",
        actorClass: "verified_agent",
        mode: "enforce",
        routeTemplate: "/private/:id",
        count: 2
      }
    ]);
    const prometheus = metrics.renderPrometheus();
    expect(prometheus).toContain(
      'aidenid_operator_scope_mismatch_total{site_id="sit_metrics",actor_class="verified_agent",mode="enforce",route_template="/private/:id"} 2'
    );
    expect(prometheus).toContain(
      'aidenid_provider_layer_total{site_id="sit_metrics",layer="operator_reputation",provider="operator-cache",status="fail",reason="operator_scope_mismatch",route_template="/private/:id"} 2'
    );
  });

  it("records dedicated low-cardinality sandbox route counters", () => {
    const metrics = new InMemoryVerifierMetricsSink();
    const decision: DecisionResult = {
      requestId: "req_sandbox_metrics",
      siteId: "sit_metrics",
      mode: "enforce",
      method: "GET",
      path: "/comments/123",
      routeTemplate: "/comments/:id",
      actorClass: "suspicious_automation",
      decision: "sandbox",
      recommendedDecision: "sandbox",
      reasons: ["sandbox_policy"],
      observeOnly: false,
      rateLimit: { status: "ok" },
      latencyUs: 64
    };

    metrics.recordDecision(decision);
    metrics.recordDecision(decision);

    expect(metrics.sandboxRouteSnapshot()).toEqual([
      {
        siteId: "sit_metrics",
        actorClass: "suspicious_automation",
        mode: "enforce",
        routeTemplate: "/comments/:id",
        count: 2
      }
    ]);
    expect(metrics.renderPrometheus()).toContain(
      'aidenid_sandbox_route_total{site_id="sit_metrics",actor_class="suspicious_automation",mode="enforce",route_template="/comments/:id"} 2'
    );
  });
});
