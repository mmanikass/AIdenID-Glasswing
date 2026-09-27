export const DASHBOARD_VIEWS = [
  "live_stream",
  "policy_editor",
  "policy_diff_preview",
  "policy_copilot",
  "counterfactual_impact",
  "cascade_telemetry",
  "price_required_billing",
  "persona_audit",
  "identity_challenges",
  "identity_review_notifications",
  "route_analytics",
  "revocation_center",
  "usage_meter",
] as const;

export type DashboardView = (typeof DASHBOARD_VIEWS)[number];

export * from "./dashboardData.js";
export * from "./dashboardApi.js";
export * from "./dashboardInitialEvents.js";
export * from "./dashboardLiveActions.js";
export * from "./dashboardIdentityChallenges.js";
export * from "./dashboardIdentityReviewNotifications.js";
export * from "./dashboardModel.js";
export * from "./dashboardStatus.js";
export * from "./decisionStream.js";
export * from "./policyPreview.js";
