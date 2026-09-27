import {
  authorizeDashboardOperatorRequest,
  dashboardControlPlaneTimeoutMs,
  dashboardUpstreamStatusForError,
  fetchDashboardControlPlaneWithTimeout,
  operatorAuthFailureResponse,
} from "../../../../../dashboardApi.js";
import { buildDecisionOperatorActionProxyRequest } from "../../../../../decisionStream.js";

export const dynamic = "force-dynamic";

type RouteParams = { readonly decisionId: string };
type RouteContext = { readonly params: Promise<RouteParams> };

function recordFromUnknown(
  value: unknown,
): Readonly<Record<string, unknown>> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Readonly<Record<string, unknown>>)
    : undefined;
}

function stringField(
  source: Readonly<Record<string, unknown>>,
  key: string,
): string | undefined {
  const value = source[key];
  return typeof value === "string" && value.trim().length > 0
    ? value.trim()
    : undefined;
}

export async function POST(
  request: Request,
  context: RouteContext,
): Promise<Response> {
  const auth = authorizeDashboardOperatorRequest(request, process.env);
  if (!auth.ok) {
    return operatorAuthFailureResponse(auth);
  }

  let rawPayload: unknown;
  try {
    rawPayload = (await request.json()) as unknown;
  } catch (error) {
    return Response.json(
      {
        error: "invalid_operator_action_request",
        message:
          error instanceof Error
            ? error.message
            : "request body must be valid JSON",
      },
      { status: 400 },
    );
  }
  const payload = recordFromUnknown(rawPayload);
  if (payload === undefined) {
    return Response.json(
      {
        error: "invalid_operator_action_request",
        message: "request body must be an object",
      },
      { status: 400 },
    );
  }

  const operatorAction = stringField(payload, "operator_action");
  if (operatorAction === undefined) {
    return Response.json(
      {
        error: "invalid_operator_action_request",
        message: "operator_action is required",
      },
      { status: 400 },
    );
  }

  const params = await context.params;
  const operatorToken = process.env.AIDENID_OPERATOR_TOKEN;
  const proxy = buildDecisionOperatorActionProxyRequest({
    decisionId: params.decisionId,
    controlPlaneUrl: process.env.AIDENID_CONTROL_PLANE_URL,
    operatorToken,
    operatorAction,
    operatorReason: stringField(payload, "operator_reason"),
  });

  if (proxy === undefined) {
    return Response.json(
      {
        error: "control_plane_operator_action_unavailable",
        message:
          "operator actions require live control-plane URL and operator token",
      },
      { status: 503 },
    );
  }

  try {
    const response = await fetchDashboardControlPlaneWithTimeout(proxy.url, {
      method: "PATCH",
      headers: proxy.headers,
      body: proxy.body,
      cache: "no-store",
      timeoutMs: dashboardControlPlaneTimeoutMs(process.env),
    });
    const body = await response.text();
    return new Response(body, {
      status: response.status,
      headers: {
        "Content-Type":
          response.headers.get("content-type") ?? "application/json",
      },
    });
  } catch (error) {
    return Response.json(
      {
        error: "control_plane_operator_action_unavailable",
        status: dashboardUpstreamStatusForError(error),
      },
      { status: dashboardUpstreamStatusForError(error) },
    );
  }
}
