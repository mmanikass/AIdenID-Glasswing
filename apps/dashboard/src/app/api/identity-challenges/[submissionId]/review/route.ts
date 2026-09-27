import {
  authorizeDashboardOperatorRequest,
  dashboardControlPlaneTimeoutMs,
  dashboardUpstreamStatusForError,
  fetchDashboardControlPlaneWithTimeout,
  operatorAuthFailureResponse
} from "../../../../../dashboardApi.js";
import {
  buildAgentIdentitySubmissionReviewUrl,
  parseAgentIdentityReviewRequest
} from "../../../../../dashboardIdentityChallenges.js";

export const dynamic = "force-dynamic";

type RouteParams = { readonly submissionId: string };
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

function isValidSubmissionId(value: string): boolean {
  return /^ais_[A-Za-z0-9_-]+$/.test(value);
}

async function forwardJson(upstream: Response): Promise<Response> {
  const body = await upstream.text();
  return new Response(body, {
    status: upstream.status,
    headers: {
      ...LIVE_HEADER,
      "Content-Type": upstream.headers.get("content-type") ?? "application/json"
    }
  });
}

export async function POST(request: Request, context: RouteContext): Promise<Response> {
  const auth = authorizeDashboardOperatorRequest(request, process.env);
  if (!auth.ok) {
    return operatorAuthFailureResponse(auth);
  }

  const { submissionId } = await context.params;
  if (!isValidSubmissionId(submissionId)) {
    return jsonError(400, "invalid_identity_submission_id");
  }

  const controlPlaneUrl = process.env.AIDENID_CONTROL_PLANE_URL?.trim();
  if (controlPlaneUrl === undefined || controlPlaneUrl.length === 0) {
    return jsonError(503, "live_control_plane_required");
  }
  const operatorToken = process.env.AIDENID_OPERATOR_TOKEN?.trim();
  if (operatorToken === undefined || operatorToken.length === 0) {
    return jsonError(503, "operator_token_unavailable");
  }

  let rawBody: unknown;
  try {
    rawBody = (await request.json()) as unknown;
  } catch (error) {
    return jsonError(
      400,
      "invalid_identity_review_body",
      error instanceof Error ? error.message : "request body must be valid JSON"
    );
  }

  const parsed = parseAgentIdentityReviewRequest(rawBody);
  if (!parsed.ok) {
    return jsonError(400, parsed.error);
  }

  try {
    const upstream = await fetchDashboardControlPlaneWithTimeout(
      buildAgentIdentitySubmissionReviewUrl(controlPlaneUrl, submissionId),
      {
        method: "PATCH",
        headers: {
          Accept: "application/json",
          Authorization: `Bearer ${operatorToken}`,
          "Content-Type": "application/json",
          "X-AIdenID-Reviewer-Id": auth.actorId
        },
        body: JSON.stringify(parsed.payload),
        cache: "no-store",
        timeoutMs: dashboardControlPlaneTimeoutMs(process.env)
      }
    );
    return forwardJson(upstream);
  } catch (error) {
    return jsonError(dashboardUpstreamStatusForError(error), "control_plane_identity_review_unavailable");
  }
}
