import {
  authorizeDashboardOperatorRequest,
  dashboardControlPlaneTimeoutMs,
  dashboardUpstreamStatusForError,
  fetchDashboardControlPlaneWithTimeout,
  operatorAuthFailureResponse,
} from "../../../../dashboardApi.js";
import { sampleDecisionEvents } from "../../../../dashboardData.js";
import { buildDecisionSearchProxyRequest } from "../../../../decisionStream.js";

export const dynamic = "force-dynamic";

function requireLiveData(): boolean {
  return process.env.AIDENID_DASHBOARD_REQUIRE_LIVE_DATA === "true";
}

function jsonHeaders(dataSource: "live" | "sample"): Readonly<Record<string, string>> {
  return {
    "Cache-Control": "no-cache, no-transform",
    "Content-Type": "application/json",
    "X-AIdenID-Dashboard-Data-Source": dataSource,
  };
}

function sampleSearchResponse(requestUrl: string): Response {
  const params = new URL(requestUrl).searchParams;
  const decisionFilter = params.get("decision");
  const operatorActorIdFilter = params.get("operator_actor_id");
  const filtered = sampleDecisionEvents.filter((event) => {
    if (decisionFilter !== null && event.decision !== decisionFilter)
      return false;
    if (
      operatorActorIdFilter !== null &&
      event.operatorActionActorId !== operatorActorIdFilter
    )
      return false;
    return true;
  });
  const limit = Number(params.get("limit") ?? "100");
  return Response.json(
    {
      decisions: filtered.slice(
        0,
        Number.isFinite(limit) && limit > 0 ? limit : 100,
      ),
    },
    { headers: jsonHeaders("sample") },
  );
}

export async function GET(request: Request): Promise<Response> {
  const auth = authorizeDashboardOperatorRequest(request, process.env);
  if (
    !auth.ok &&
    process.env.AIDENID_CONTROL_PLANE_URL !== undefined &&
    process.env.AIDENID_CONTROL_PLANE_URL.trim().length > 0
  ) {
    return operatorAuthFailureResponse(auth);
  }

  const proxy = buildDecisionSearchProxyRequest({
    requestUrl: request.url,
    controlPlaneUrl: process.env.AIDENID_CONTROL_PLANE_URL,
    operatorToken:
      process.env.AIDENID_OPERATOR_TOKEN ??
      process.env.AIDENID_CONTROL_PLANE_API_KEY,
  });
  if (proxy === undefined) {
    if (requireLiveData()) {
      return Response.json(
        { error: "live_control_plane_required" },
        { headers: jsonHeaders("live"), status: 503 },
      );
    }
    return sampleSearchResponse(request.url);
  }

  try {
    const response = await fetchDashboardControlPlaneWithTimeout(proxy.url, {
      headers: proxy.headers,
      cache: "no-store",
      timeoutMs: dashboardControlPlaneTimeoutMs(process.env),
    });
    const body = await response.text();
    if (!response.ok) {
      return Response.json(
        { error: "control_plane_search_unavailable", status: response.status },
        {
          headers: jsonHeaders("live"),
          status:
            response.status >= 400 && response.status < 600
              ? response.status
              : 502,
        },
      );
    }
    return new Response(body, {
      headers: jsonHeaders("live"),
    });
  } catch (error) {
    return Response.json(
      {
        error: "control_plane_search_unavailable",
        status: dashboardUpstreamStatusForError(error),
      },
      { headers: jsonHeaders("live"), status: dashboardUpstreamStatusForError(error) },
    );
  }
}
