import {
  authorizeDashboardOperatorRequest,
  dashboardControlPlaneTimeoutMs,
  dashboardUpstreamStatusForError,
  fetchDashboardControlPlaneWithTimeout,
  operatorAuthFailureResponse
} from "../../../../dashboardApi.js";
import {
  buildOperatorReputationListUrl,
  dashboardSiteId,
  isValidSiteId
} from "../../../../dashboardOperatorRegistry.js";

export const dynamic = "force-dynamic";

const LIVE_HEADER = {
  "Cache-Control": "no-cache, no-transform",
  "Content-Type": "application/json",
  "X-AIdenID-Dashboard-Data-Source": "live"
} as const;

function jsonError(status: number, error: string, message?: string): Response {
  return Response.json(
    message === undefined ? { error } : { error, message },
    { status, headers: LIVE_HEADER }
  );
}

export async function GET(request: Request): Promise<Response> {
  const auth = authorizeDashboardOperatorRequest(request, process.env);
  if (!auth.ok) {
    return operatorAuthFailureResponse(auth);
  }

  const controlPlaneUrl = process.env.AIDENID_CONTROL_PLANE_URL?.trim();
  if (controlPlaneUrl === undefined || controlPlaneUrl.length === 0) {
    return jsonError(
      503,
      "live_control_plane_required",
      "operator registry is operator-edited live data and does not fall back to sample data"
    );
  }

  const siteId = dashboardSiteId(process.env);
  if (!isValidSiteId(siteId)) {
    return jsonError(500, "invalid_dashboard_site_id", "AIDENID_DASHBOARD_SITE_ID must match /^sit_[A-Za-z0-9_-]+$/");
  }

  const operatorToken = process.env.AIDENID_OPERATOR_TOKEN?.trim();
  if (operatorToken === undefined || operatorToken.length === 0) {
    return jsonError(503, "operator_token_unavailable", "AIDENID_OPERATOR_TOKEN must be set to call the operator registry");
  }

  const upstreamUrl = buildOperatorReputationListUrl(controlPlaneUrl, siteId);

  try {
    const upstream = await fetchDashboardControlPlaneWithTimeout(upstreamUrl, {
      method: "GET",
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${operatorToken}`
      },
      cache: "no-store",
      timeoutMs: dashboardControlPlaneTimeoutMs(process.env)
    });
    const body = await upstream.text();
    return new Response(body, {
      status: upstream.status,
      headers: {
        ...LIVE_HEADER,
        "Content-Type": upstream.headers.get("content-type") ?? "application/json"
      }
    });
  } catch (error) {
    const status = dashboardUpstreamStatusForError(error);
    return jsonError(status, "control_plane_operator_registry_unavailable");
  }
}
