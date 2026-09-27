import { describe, expect, it } from "vitest";

import { ACTOR_CLASSES, DECISION_ACTIONS, OPERATOR_ACTIONS, isDecisionAction, isOperatorAction } from "../src/enums.js";
import { decisionFromHttpStatus, httpStatusForDecision } from "../src/httpDecision.js";

describe("common schema enums", () => {
  it("uses humble actor labels only", () => {
    expect(ACTOR_CLASSES).toEqual([
      "verified_agent",
      "signed_agent",
      "likely_human",
      "suspicious_automation",
      "unknown"
    ]);
  });

  it("exposes all six decision outcomes", () => {
    expect(DECISION_ACTIONS).toEqual([
      "allow",
      "throttle",
      "queue",
      "sandbox",
      "deny",
      "price_required"
    ]);
    expect(isDecisionAction("sandbox")).toBe(true);
    expect(isDecisionAction("block")).toBe(false);
  });

  it("keeps quarantine as an operator action instead of a seventh verifier decision", () => {
    expect(DECISION_ACTIONS).not.toContain("quarantine");
    expect(OPERATOR_ACTIONS).toEqual([...DECISION_ACTIONS, "quarantine"]);
    expect(isOperatorAction("quarantine")).toBe(true);
    expect(isDecisionAction("quarantine")).toBe(false);
  });

  it("centralizes verifier HTTP status semantics", () => {
    expect(DECISION_ACTIONS.map((decision) => [decision, httpStatusForDecision(decision)])).toEqual([
      ["allow", 200],
      ["throttle", 429],
      ["queue", 202],
      ["sandbox", 200],
      ["deny", 403],
      ["price_required", 402]
    ]);
    expect(decisionFromHttpStatus(200)).toBe("allow");
    expect(decisionFromHttpStatus(202)).toBe("queue");
    expect(decisionFromHttpStatus(401)).toBe("deny");
    expect(decisionFromHttpStatus(402)).toBe("price_required");
    expect(decisionFromHttpStatus(403)).toBe("deny");
    expect(decisionFromHttpStatus(429)).toBe("throttle");
    expect(decisionFromHttpStatus(500)).toBe("deny");
  });
});
