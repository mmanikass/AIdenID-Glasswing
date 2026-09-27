import type { JevAssessment } from "./types.js";

/** The six deterministic outcomes of the clearance kernel. Mirrors @aidenid/policy-engine DecisionAction. */
export type DeterministicAction = "allow" | "throttle" | "queue" | "sandbox" | "deny" | "price_required";

export interface DeterministicDecision {
  readonly action: DeterministicAction;
  readonly reasonCodes: readonly string[];
}

export interface ComposedDecision {
  /** Display outcome. `deny` is never changed; `allow` becomes `queue` while review is pending. */
  readonly action: DeterministicAction;
  /** True only when nothing stands between the decision and execution. */
  readonly dispatchEligible: boolean;
  readonly obligations: readonly "review_required"[];
  readonly reasonCodes: readonly string[];
}

/**
 * Combine a deterministic decision with a Jev assessment.
 *
 * Invariants (tested):
 * - A deterministic `deny` stays `deny` whatever Jev says, including a confident `low`.
 * - Jev can only add a `review_required` obligation; it cannot remove one or add authority.
 * - An `allow` with a pending obligation is displayed as `queue` and is not dispatch-eligible.
 * - Non-allow outcomes keep their label and are never dispatch-eligible here.
 */
export function composeWithJev(deterministic: DeterministicDecision, assessment: JevAssessment): ComposedDecision {
  if (deterministic.action === "deny") {
    return { action: "deny", dispatchEligible: false, obligations: [], reasonCodes: deterministic.reasonCodes };
  }
  if (assessment.obligation === "review_required") {
    const reasonCodes = [...deterministic.reasonCodes, "semantic_review_required"];
    if (assessment.verificationStatus === "unavailable") {
      reasonCodes.push("jev_unavailable");
    } else if (assessment.verificationStatus === "inconclusive") {
      reasonCodes.push("jev_inconclusive");
    }
    return {
      action: deterministic.action === "allow" ? "queue" : deterministic.action,
      dispatchEligible: false,
      obligations: ["review_required"],
      reasonCodes
    };
  }
  return {
    action: deterministic.action,
    dispatchEligible: deterministic.action === "allow",
    obligations: [],
    reasonCodes: deterministic.reasonCodes
  };
}
