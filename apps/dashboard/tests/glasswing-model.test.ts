import { describe, expect, it } from "vitest";

import { describeJev, expiryLabel, summarizeRun } from "../src/glasswing/model.js";
import type { GlasswingJevAssessment, GlasswingRunResult } from "../src/glasswing/types.js";

const jevClear: GlasswingJevAssessment = {
  verificationStatus: "evaluated",
  riskClass: "low",
  modelConfidence: 0.92,
  evidenceCoverage: "full",
  rationale: "fits the purpose",
  obligation: "none",
  unavailableReason: null,
  modelVersion: "claude-opus-5",
  latencyMs: 800
};

function run(overrides: Partial<GlasswingRunResult>): GlasswingRunResult {
  return {
    request: { method: "GET", url: "https://shop.test/api/catalog" },
    session: { sessionId: "ses_1", revocationEpoch: 0 },
    decision: { requestId: "req_1", decisionId: "dec_1", action: "allow", reasonCodes: ["matched_policy"], actorClass: "verified_agent" },
    effect: { ok: true, value: { items: 3 } },
    jev: null,
    ...overrides
  };
}

describe("summarizeRun", () => {
  it("reports allow + executed, policy deny, and effect-boundary refusal as distinct outcomes", () => {
    expect(summarizeRun(run({}))).toMatchObject({ tone: "allowed", headline: "Allowed and executed" });
    expect(summarizeRun(run({ decision: { requestId: "r", decisionId: null, action: "deny", reasonCodes: ["permission_scope_mismatch"], actorClass: "verified_agent" }, effect: null }))).toMatchObject({ tone: "refused", headline: "Denied by policy", detail: "permission_scope_mismatch" });
    expect(summarizeRun(run({ effect: { ok: false, reason: "grant_revoked" } }))).toMatchObject({ tone: "refused", headline: "Refused at the effect boundary (grant_revoked)" });
  });

  it("never shows an allow as executed when the effect did not run, and surfaces refused sessions and errors", () => {
    expect(summarizeRun(run({ session: null, decision: null, effect: null }))).toMatchObject({ tone: "refused", headline: "Session refused" });
    expect(summarizeRun(run({ effect: null, jev: { ...jevClear, obligation: "review_required", riskClass: "high" } }))).toMatchObject({ tone: "queued", headline: "Queued for human review" });
    expect(summarizeRun(run({ error: { code: "protected_site_unavailable", message: "down" } }))).toMatchObject({ tone: "error", headline: "Error: protected_site_unavailable" });
    expect(summarizeRun(run({ session: null, decision: null, effect: null, jev: null, error: { code: "permission_scope_mismatch", message: "The grant does not authorize this task resource and permission." } }))).toMatchObject({
      tone: "refused",
      headline: "Refused before signing (permission_scope_mismatch)",
      detail: "The grant does not authorize this task resource and permission."
    });
    expect(summarizeRun(run({ session: null, decision: null, effect: null, jev: null, error: { code: "session_exchange_failed", message: "The grant is no longer active or could not be exchanged." } }))).toMatchObject({
      tone: "refused",
      headline: "Session refused"
    });
  });
});

describe("describeJev", () => {
  it("states unavailable and inconclusive explicitly instead of implying a verdict", () => {
    expect(describeJev(jevClear)).toContain("low risk, confidence 92%, evidence full");
    expect(describeJev({ ...jevClear, verificationStatus: "unavailable", riskClass: null, modelConfidence: null, unavailableReason: "timeout", obligation: "review_required" })).toContain("unavailable (timeout)");
    expect(describeJev({ ...jevClear, verificationStatus: "inconclusive", riskClass: null, obligation: "review_required" })).toContain("inconclusive");
  });
});

describe("expiryLabel", () => {
  it("reports minutes remaining or expired", () => {
    const now = new Date("2026-09-27T12:00:00Z");
    expect(expiryLabel("2026-09-27T12:10:30Z", now)).toBe("expires in 10 min");
    expect(expiryLabel("2026-09-27T12:00:20Z", now)).toBe("expires in under a minute");
    expect(expiryLabel("2026-09-27T11:59:00Z", now)).toBe("expired");
    expect(expiryLabel("garbage", now)).toBe("unknown expiry");
  });
});
