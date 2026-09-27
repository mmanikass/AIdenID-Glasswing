import type { DecisionAction } from "./enums.js";

export const DECISION_HTTP_STATUS = {
  allow: 200,
  throttle: 429,
  queue: 202,
  sandbox: 200,
  deny: 403,
  price_required: 402
} as const satisfies Readonly<Record<DecisionAction, number>>;

export function httpStatusForDecision(decision: DecisionAction): number {
  return DECISION_HTTP_STATUS[decision];
}

export function decisionFromHttpStatus(status: number): DecisionAction {
  if (status === DECISION_HTTP_STATUS.price_required) {
    return "price_required";
  }
  if (status === DECISION_HTTP_STATUS.throttle) {
    return "throttle";
  }
  if (status === DECISION_HTTP_STATUS.queue) {
    return "queue";
  }
  if (status === 401 || status === DECISION_HTTP_STATUS.deny) {
    return "deny";
  }
  return status >= 200 && status < 300 ? "allow" : "deny";
}
