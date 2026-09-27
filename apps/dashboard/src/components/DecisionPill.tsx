import type { DecisionAction, OperatorAction } from "../dashboardModel.js";

export function DecisionPill({ decision }: { readonly decision: DecisionAction | OperatorAction }) {
  return <span className={`decision-pill decision-${decision}`}>{decision}</span>;
}
