import { describe, expect, it } from "vitest";

import {
  approvePolicySuggestion,
  rejectPolicySuggestion,
  suggestPolicyDiffs,
  verifyPolicySuggestionAgainstGoldenVectors,
  type PolicyCopilotDecisionSample
} from "../src/index.js";

const policyYaml = `version: 1
site_id: sit_copilot
mode: enforce
defaults:
  strict: false
  on_degraded: queue
  rate: { capacity: 100, refill_per_sec: 10, cost: 1 }
routes:
  - template: /checkout
    method: POST
    signature_required: [http-message-signature, dpop]
    per_actor_class:
      verified_agent: { decision: allow }
  - template: /comments/:id
    method: POST
    per_actor_class:
      likely_human: { decision: allow }
`;

const suspiciousSamples: readonly PolicyCopilotDecisionSample[] = [
  {
    routeTemplate: "/comments/:id",
    method: "POST",
    actorClass: "suspicious_automation",
    decision: "allow",
    reasonCodes: ["matched_policy"]
  },
  {
    routeTemplate: "/comments/:id",
    method: "POST",
    actorClass: "suspicious_automation",
    decision: "allow",
    reasonCodes: ["matched_policy"]
  },
  {
    routeTemplate: "/comments/:id",
    method: "POST",
    actorClass: "suspicious_automation",
    decision: "allow",
    reasonCodes: ["matched_policy"]
  }
];

describe("offline policy copilot", () => {
  it("proposes ai-labeled fail-closed diffs with audit metadata", () => {
    const suggestions = suggestPolicyDiffs({
      policyYaml,
      decisionSamples: [],
      prompt: "tighten strict signed routes",
      inputRefs: ["decision_stream:sit_copilot"],
      generatedAt: "2026-04-24T13:30:00.000Z"
    });

    expect(suggestions[0]).toMatchObject({
      label: "ai_proposed",
      approvalStatus: "pending",
      riskLevel: "medium",
      metadata: {
        model: "offline-policy-copilot-rules-v1",
        tool: "aidenid-policy-copilot",
        inputRefs: ["decision_stream:sit_copilot"],
        generatedAt: "2026-04-24T13:30:00.000Z"
      }
    });
    expect(suggestions[0]?.metadata.promptDigestSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(suggestions[0]?.outputDiff.operations).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ path: "/routes/0/strict", after: true }),
        expect.objectContaining({ path: "/routes/0/on_degraded", after: "deny" })
      ])
    );
    expect(suggestions[0]?.proposedPolicyYaml).toContain("on_degraded: deny");
  });

  it("suggests suspicious automation throttles from offline samples without approval", () => {
    const suggestions = suggestPolicyDiffs({
      policyYaml,
      decisionSamples: suspiciousSamples,
      suspiciousAutomationThreshold: 3,
      generatedAt: "2026-04-24T13:30:00.000Z"
    });
    const throttleSuggestion = suggestions.find((suggestion) =>
      suggestion.outputDiff.operations.some((operation) => operation.path === "/routes/1/per_actor_class/suspicious_automation")
    );

    expect(throttleSuggestion).toBeDefined();
    expect(throttleSuggestion).toMatchObject({
      label: "ai_proposed",
      approvalStatus: "pending",
      riskLevel: "low"
    });
    expect(throttleSuggestion?.proposedPolicyYaml).toContain("suspicious_automation:");
    expect(throttleSuggestion?.proposedPolicyYaml).toContain("decision: throttle");
  });

  it("requires human review records before approval or rejection", () => {
    const suggestion = suggestPolicyDiffs({
      policyYaml,
      decisionSamples: [],
      generatedAt: "2026-04-24T13:30:00.000Z"
    })[0];
    if (suggestion === undefined) {
      throw new Error("expected policy copilot suggestion");
    }

    expect(() => approvePolicySuggestion(suggestion, { reviewer: " ", reviewedAt: "2026-04-24T13:40:00.000Z" })).toThrow(
      /human reviewer/
    );
    expect(approvePolicySuggestion(suggestion, { reviewer: "policy_admin", reviewedAt: "2026-04-24T13:40:00.000Z" })).toMatchObject({
      label: "ai_proposed",
      approvalStatus: "approved",
      reviewer: "policy_admin"
    });
    expect(
      rejectPolicySuggestion(suggestion, {
        reviewer: "policy_admin",
        reviewedAt: "2026-04-24T13:41:00.000Z",
        comment: "too broad"
      })
    ).toMatchObject({ approvalStatus: "rejected", reviewComment: "too broad" });
  });

  it("checks proposed policies against golden vectors before deployment", () => {
    const suggestion = suggestPolicyDiffs({
      policyYaml,
      decisionSamples: suspiciousSamples,
      suspiciousAutomationThreshold: 3,
      generatedAt: "2026-04-24T13:30:00.000Z"
    }).find((candidate) => candidate.outputDiff.operations.some((operation) => operation.path.includes("suspicious_automation")));
    if (suggestion === undefined) {
      throw new Error("expected suspicious automation suggestion");
    }

    expect(
      verifyPolicySuggestionAgainstGoldenVectors(suggestion, [
        { method: "POST", path: "/comments/123", actorClass: "suspicious_automation", expectedDecision: "throttle" }
      ])
    ).toEqual({ ok: true, failures: [] });

    expect(
      verifyPolicySuggestionAgainstGoldenVectors(suggestion, [
        { method: "POST", path: "/comments/123", actorClass: "suspicious_automation", expectedDecision: "deny" }
      ])
    ).toMatchObject({ ok: false, failures: [expect.objectContaining({ actualDecision: "throttle" })] });
  });
});
