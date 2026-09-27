import { dashboardOperatorRequestAuthConfigured } from "./dashboardApi.js";

export type DashboardRuntimeMode =
  | "live_control_plane"
  | "live_control_plane_required"
  | "sample_data";

export interface DashboardRuntimeStatus {
  readonly service: "aidenid-clearance-dashboard";
  readonly mode: DashboardRuntimeMode;
  readonly controlPlaneStreamConfigured: boolean;
  readonly operatorActionsConfigured: boolean;
  readonly policyPreviewConfigured: boolean;
  readonly fallbackDataEnabled: boolean;
  readonly liveDataRequired: boolean;
}

export interface DashboardRuntimeEnvironment extends Readonly<
  Record<string, string | undefined>
> {
  readonly AIDENID_CONTROL_PLANE_URL?: string | undefined;
  readonly AIDENID_CONTROL_PLANE_API_KEY?: string | undefined;
  readonly AIDENID_DASHBOARD_REQUIRE_LIVE_DATA?: string | undefined;
  readonly AIDENID_DASHBOARD_OPERATOR_REQUEST_TOKEN?: string | undefined;
  readonly AIDENID_OPERATOR_TOKEN?: string | undefined;
}

function configured(value: string | undefined): boolean {
  return value !== undefined && value.trim().length > 0;
}

export function dashboardRuntimeStatusFromEnv(
  env: DashboardRuntimeEnvironment,
): DashboardRuntimeStatus {
  const controlPlaneConfigured = configured(env.AIDENID_CONTROL_PLANE_URL);
  const liveDataRequired = env.AIDENID_DASHBOARD_REQUIRE_LIVE_DATA === "true";
  const controlPlaneApiKeyConfigured = configured(
    env.AIDENID_CONTROL_PLANE_API_KEY,
  );
  const operatorTokenConfigured = configured(env.AIDENID_OPERATOR_TOKEN);
  const operatorRequestAuthConfigured =
    dashboardOperatorRequestAuthConfigured(env);

  return {
    service: "aidenid-clearance-dashboard",
    mode: controlPlaneConfigured
      ? "live_control_plane"
      : liveDataRequired
        ? "live_control_plane_required"
        : "sample_data",
    controlPlaneStreamConfigured: controlPlaneConfigured,
    operatorActionsConfigured:
      controlPlaneConfigured &&
      operatorTokenConfigured &&
      operatorRequestAuthConfigured,
    policyPreviewConfigured:
      controlPlaneConfigured &&
      controlPlaneApiKeyConfigured &&
      operatorRequestAuthConfigured,
    fallbackDataEnabled: !controlPlaneConfigured && !liveDataRequired,
    liveDataRequired,
  };
}
