import type { GlasswingJevAssessment, GlasswingRunResult } from "./types.js";

export type RunOutcomeTone = "allowed" | "refused" | "queued" | "error";

export interface RunOutcomeSummary {
  readonly tone: RunOutcomeTone;
  readonly headline: string;
  readonly detail: string;
}

/**
 * One truthful sentence per run, derived only from what the server recorded. The decision and
 * the effect are reported separately: an allow with a refused effect is shown as refused,
 * because the effect boundary is what actually protects the resource.
 */
export function summarizeRun(run: GlasswingRunResult): RunOutcomeSummary {
  if (run.error !== undefined) {
    // Two refusals the site reports as errors because no decision exists yet: the grant did
    // not cover the task (nothing was signed), or the control plane refused to mint a session.
    if (run.error.code === "permission_scope_mismatch") {
      return { tone: "refused", headline: "Refused before signing (permission_scope_mismatch)", detail: run.error.message };
    }
    if (run.error.code === "session_exchange_failed") {
      return { tone: "refused", headline: "Session refused", detail: run.error.message };
    }
    return { tone: "error", headline: `Error: ${run.error.code}`, detail: run.error.message };
  }
  if (run.session === null) {
    return { tone: "refused", headline: "Session refused", detail: "The control plane refused to exchange the grant (revoked, expired, or out of scope)." };
  }
  if (run.decision === null) {
    return { tone: "error", headline: "No decision recorded", detail: "The protected site returned no decision for this request." };
  }
  const reasons = run.decision.reasonCodes.length > 0 ? run.decision.reasonCodes.join(", ") : "no reason codes";
  if (run.decision.action === "deny") {
    return { tone: "refused", headline: "Denied by policy", detail: reasons };
  }
  if (run.effect !== null && run.effect.ok === false) {
    return { tone: "refused", headline: `Refused at the effect boundary (${run.effect.reason ?? "unknown"})`, detail: reasons };
  }
  if (run.jev !== null && run.jev.obligation === "review_required") {
    return { tone: "queued", headline: "Queued for human review", detail: describeJev(run.jev) };
  }
  if (run.decision.action === "allow" && run.effect !== null && run.effect.ok) {
    return { tone: "allowed", headline: "Allowed and executed", detail: reasons };
  }
  return { tone: "queued", headline: `Decision: ${run.decision.action}`, detail: reasons };
}

export function describeJev(jev: GlasswingJevAssessment): string {
  if (jev.verificationStatus === "evaluated") {
    const confidence = jev.modelConfidence === null ? "n/a" : `${Math.round(jev.modelConfidence * 100)}%`;
    return `Jev ${jev.riskClass ?? "unknown"} risk, confidence ${confidence}, evidence ${jev.evidenceCoverage}${jev.rationale ? `: ${jev.rationale}` : ""}`;
  }
  if (jev.verificationStatus === "unavailable") {
    return `Jev unavailable (${jev.unavailableReason ?? "unknown"}); the check did not run and nothing was inferred`;
  }
  if (jev.verificationStatus === "inconclusive") {
    return "Jev answered outside the contract (inconclusive); treated as needing review";
  }
  return "Jev not evaluated for this action";
}

export function expiryLabel(expiresAt: string, now: Date = new Date()): string {
  const ms = Date.parse(expiresAt) - now.getTime();
  if (!Number.isFinite(ms)) return "unknown expiry";
  if (ms <= 0) return "expired";
  const minutes = Math.floor(ms / 60_000);
  if (minutes < 1) return "expires in under a minute";
  return `expires in ${minutes} min`;
}

export function reviewStatusLabel(status: "pending" | "approved" | "denied"): string {
  return status === "pending" ? "Awaiting operator" : status === "approved" ? "Approved, released once" : "Denied";
}
