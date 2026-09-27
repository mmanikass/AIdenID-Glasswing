import {
  authorizeDashboardOperatorRequest,
  dashboardControlPlaneTimeoutMs,
  dashboardUpstreamStatusForError,
  fetchDashboardControlPlaneWithTimeout,
  operatorAuthFailureResponse
} from "../../../../../dashboardApi.js";
import {
  buildOperatorReputationDetailUrl,
  dashboardSiteId,
  isValidOperatorActorId,
  isValidSiteId,
  parseOperatorReputationUpsert
} from "../../../../../dashboardOperatorRegistry.js";

export const dynamic = "force-dynamic";

type RouteParams = { readonly operatorActorId: string };
type RouteContext = { readonly params: Promise<RouteParams> };

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

interface UpstreamPrep {
  readonly url: string;
  readonly siteId: string;
  readonly operatorToken: string;
  readonly operatorActorId: string;
}

function prepareUpstream(operatorActorId: string): UpstreamPrep | Response {
  const controlPlaneUrl = process.env.AIDENID_CONTROL_PLANE_URL?.trim();
  if (controlPlaneUrl === undefined || controlPlaneUrl.length === 0) {
    return jsonError(503, "live_control_plane_required");
  }
  const siteId = dashboardSiteId(process.env);
  if (!isValidSiteId(siteId)) {
    return jsonError(500, "invalid_dashboard_site_id");
  }
  if (!isValidOperatorActorId(operatorActorId)) {
    return jsonError(400, "invalid_operator_actor_id");
  }
  const operatorToken = process.env.AIDENID_OPERATOR_TOKEN?.trim();
  if (operatorToken === undefined || operatorToken.length === 0) {
    return jsonError(503, "operator_token_unavailable");
  }
  return {
    url: buildOperatorReputationDetailUrl(controlPlaneUrl, siteId, operatorActorId),
    siteId,
    operatorToken,
    operatorActorId
  };
}

async function forwardJson(
  upstream: Response,
  fallbackContentType = "application/json"
): Promise<Response> {
  const body = await upstream.text();
  return new Response(body, {
    status: upstream.status,
    headers: {
      ...LIVE_HEADER,
      "Content-Type": upstream.headers.get("content-type") ?? fallbackContentType
    }
  });
}

export async function GET(request: Request, context: RouteContext): Promise<Response> {
  const auth = authorizeDashboardOperatorRequest(request, process.env);
  if (!auth.ok) {
    return operatorAuthFailureResponse(auth);
  }
  const params = await context.params;
  const prep = prepareUpstream(params.operatorActorId);
  if (prep instanceof Response) {
    return prep;
  }

  try {
    const upstream = await fetchDashboardControlPlaneWithTimeout(prep.url, {
      method: "GET",
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${prep.operatorToken}`
      },
      cache: "no-store",
      timeoutMs: dashboardControlPlaneTimeoutMs(process.env)
    });
    return forwardJson(upstream);
  } catch (error) {
    return jsonError(dashboardUpstreamStatusForError(error), "control_plane_operator_registry_unavailable");
  }
}

export async function PUT(request: Request, context: RouteContext): Promise<Response> {
  const auth = authorizeDashboardOperatorRequest(request, process.env);
  if (!auth.ok) {
    return operatorAuthFailureResponse(auth);
  }
  const params = await context.params;
  const prep = prepareUpstream(params.operatorActorId);
  if (prep instanceof Response) {
    return prep;
  }

  let rawBody: unknown;
  try {
    rawBody = (await request.json()) as unknown;
  } catch (error) {
    return jsonError(
      400,
      "invalid_operator_reputation_body",
      error instanceof Error ? error.message : "request body must be valid JSON"
    );
  }

  const parsed = parseOperatorReputationUpsert(rawBody, prep.siteId);
  if (!parsed.ok) {
    return jsonError(400, parsed.error);
  }

  try {
    const upstream = await fetchDashboardControlPlaneWithTimeout(prep.url, {
      method: "PUT",
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${prep.operatorToken}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify(parsed.payload),
      cache: "no-store",
      timeoutMs: dashboardControlPlaneTimeoutMs(process.env)
    });
    return forwardJson(upstream);
  } catch (error) {
    return jsonError(dashboardUpstreamStatusForError(error), "control_plane_operator_registry_unavailable");
  }
}
