import { z } from "zod";

export const ACTOR_CLASSES = [
  "verified_agent",
  "signed_agent",
  "likely_human",
  "suspicious_automation",
  "unknown"
] as const;

export const ActorClassSchema = z.enum(ACTOR_CLASSES);
export type ActorClass = z.infer<typeof ActorClassSchema>;

export const DECISION_ACTIONS = [
  "allow",
  "throttle",
  "queue",
  "sandbox",
  "deny",
  "price_required"
] as const;

export const DecisionActionSchema = z.enum(DECISION_ACTIONS);
export type DecisionAction = z.infer<typeof DecisionActionSchema>;

export const OPERATOR_ACTIONS = [...DECISION_ACTIONS, "quarantine"] as const;
export const OperatorActionSchema = z.enum(OPERATOR_ACTIONS);
export type OperatorAction = z.infer<typeof OperatorActionSchema>;

export const REASON_CODES = [
  "matched_policy",
  "missing_signature",
  "bad_signature",
  "unknown_issuer",
  "issuer_key_rotation_pending",
  "audience_mismatch",
  "resource_mismatch",
  "token_expired",
  "revoked",
  "rate_limited",
  "strict_route_degraded",
  "purpose_required",
  "purpose_disallowed",
  "permission_scope_mismatch",
  "fingerprint_risk",
  "operator_reputation_suspended",
  "operator_scope_mismatch",
  "price_required",
  "quarantine",
  "operator_pinned",
  "sandbox_policy",
  "operator_override",
  "semantic_review_required",
  "jev_unavailable",
  "jev_inconclusive",
  "epoch_stale"
] as const;

export const ReasonCodeSchema = z.enum(REASON_CODES);
export type ReasonCode = z.infer<typeof ReasonCodeSchema>;

export const VERIFIER_MODES = ["observe", "recommend", "enforce"] as const;
export const VerifierModeSchema = z.enum(VERIFIER_MODES);
export type VerifierMode = z.infer<typeof VerifierModeSchema>;

export const QUOTA_STATUSES = ["ok", "warning", "throttled", "exhausted"] as const;
export const QuotaStatusSchema = z.enum(QUOTA_STATUSES);
export type QuotaStatus = z.infer<typeof QuotaStatusSchema>;

export const TOFU_STATES = ["tofu_pending", "trusted", "rotation_pending", "revoked"] as const;
export const TofuStateSchema = z.enum(TOFU_STATES);
export type TofuState = z.infer<typeof TofuStateSchema>;

export function isDecisionAction(value: string): value is DecisionAction {
  return DECISION_ACTIONS.includes(value as DecisionAction);
}

export function isOperatorAction(value: string): value is OperatorAction {
  return OPERATOR_ACTIONS.includes(value as OperatorAction);
}
