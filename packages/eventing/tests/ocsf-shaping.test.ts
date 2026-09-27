import { describe, expect, it } from "vitest";

import { severityFromDecision, toOcsfApiActivity } from "../src/index.js";

describe("OCSF API activity shaping", () => {
  it("maps decision events into OCSF api_activity records", () => {
    const ocsf = toOcsfApiActivity({
      id: "dec_1",
      requestId: "req_1",
      traceId: "trace_1",
      siteId: "sit_demo",
      occurredAt: "2026-04-24T10:00:00.000Z",
      actorClass: "verified_agent",
      decision: "deny",
      reasonCodes: ["matched_policy", "strict_route_degraded"],
      routeTemplate: "/checkout/:id",
      method: "POST",
      subjectHandle: "sub_pairwise",
      issuer: "agent.example.com",
      llmBrand: "openai",
      purpose: "research",
      priceUsd: 0.01,
      clientIp: "203.0.113.10"
    });

    expect(ocsf).toMatchObject({
      class_name: "API Activity",
      class_uid: 6003,
      category_uid: 6,
      activity_id: 2,
      severity_id: 4,
      metadata: {
        correlation_uid: "trace_1",
        product: { name: "AIdenID Clearance Layer", vendor_name: "PlexAura" }
      },
      actor: {
        user: { uid: "sub_pairwise" },
        invoked_by: "agent.example.com",
        process: { name: "verified_agent" }
      },
      dst_endpoint: { svc_name: "sit_demo", path: "/checkout/:id" },
      http_response: { code: 403 }
    });
    expect(ocsf.observables).toContainEqual({ name: "decision", type: "Other", value: "deny" });
    expect(ocsf.observables).toContainEqual({
      name: "reason_codes",
      type: "Other",
      value: "matched_policy,strict_route_degraded"
    });
    expect(ocsf.observables).toContainEqual({ name: "llm_brand", type: "Other", value: "openai" });
    expect(ocsf.observables).toContainEqual({ name: "purpose", type: "Other", value: "research" });
    expect(ocsf.observables).toContainEqual({ name: "price_usd", type: "Other", value: 0.01 });
  });

  it("assigns increasing severity for stricter decisions", () => {
    expect(severityFromDecision("allow")).toBeLessThan(severityFromDecision("sandbox"));
    expect(severityFromDecision("sandbox")).toBeLessThan(severityFromDecision("deny"));
  });

  it("uses operator effective decision for quarantine severity and status", () => {
    const ocsf = toOcsfApiActivity({
      id: "dec_2",
      requestId: "req_2",
      siteId: "sit_demo",
      occurredAt: "2026-04-24T10:00:00.000Z",
      actorClass: "verified_agent",
      decision: "allow",
      operatorAction: "quarantine",
      operatorEffectiveDecision: "deny",
      reasonCodes: ["matched_policy", "operator_override", "quarantine"],
      routeTemplate: "/benefits/PHI/*",
      method: "GET"
    });

    expect(ocsf).toMatchObject({ severity_id: 4, http_response: { code: 403 } });
    expect(ocsf.observables).toContainEqual({ name: "operator_action", type: "Other", value: "quarantine" });
    expect(ocsf.observables).toContainEqual({ name: "operator_effective_decision", type: "Other", value: "deny" });
  });
});
