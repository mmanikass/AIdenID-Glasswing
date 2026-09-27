import {
  authorizeDashboardOperatorRequest,
  dashboardControlPlaneTimeoutMs,
  dashboardUpstreamStatusForError,
  fetchDashboardControlPlaneWithTimeout,
  operatorAuthFailureResponse,
} from "../../../../dashboardApi.js";
import { sampleDecisionEvents } from "../../../../dashboardData.js";
import { buildDecisionStreamProxyRequest } from "../../../../decisionStream.js";

export const dynamic = "force-dynamic";

function requireLiveData(): boolean {
  return process.env.AIDENID_DASHBOARD_REQUIRE_LIVE_DATA === "true";
}

function streamHeaders(dataSource: "live" | "sample"): Readonly<Record<string, string>> {
  return {
    "Cache-Control": "no-cache, no-transform",
    "Content-Type": "text/event-stream",
    "X-AIdenID-Dashboard-Data-Source": dataSource,
  };
}

function sampleStream(requestUrl: string): Response {
  const encoder = new TextEncoder();
  const once = new URL(requestUrl).searchParams.get("once");
  const closeAfterInitialEvents =
    once === "1" || once === "true" || once === "yes";
  let heartbeat: ReturnType<typeof setInterval> | undefined;
  const stream = new ReadableStream({
    start(controller) {
      for (const event of sampleDecisionEvents.slice(0, 3)) {
        controller.enqueue(
          encoder.encode(`event: recorded\ndata: ${JSON.stringify(event)}\n\n`),
        );
      }
      if (closeAfterInitialEvents) {
        controller.close();
        return;
      }
      heartbeat = setInterval(
        () => controller.enqueue(encoder.encode(": heartbeat\n\n")),
        15_000,
      );
    },
    cancel() {
      if (heartbeat !== undefined) {
        clearInterval(heartbeat);
      }
    },
  });

  return new Response(stream, {
    headers: streamHeaders("sample"),
  });
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

  const proxy = buildDecisionStreamProxyRequest({
    requestUrl: request.url,
    controlPlaneUrl: process.env.AIDENID_CONTROL_PLANE_URL,
    operatorToken: process.env.AIDENID_OPERATOR_TOKEN,
    serverSiteId: process.env.AIDENID_DASHBOARD_SITE_ID,
    lastEventId: request.headers.get("last-event-id"),
  });
  if (proxy === undefined) {
    if (requireLiveData()) {
      return new Response(
        `event: stream_error\ndata: ${JSON.stringify({ error: "live_control_plane_required" })}\n\n`,
        {
          headers: streamHeaders("live"),
          status: 200,
        },
      );
    }
    return sampleStream(request.url);
  }

  let response: Response;
  try {
    response = await fetchDashboardControlPlaneWithTimeout(proxy.url, {
      headers: proxy.headers,
      cache: "no-store",
      timeoutMs: dashboardControlPlaneTimeoutMs(process.env),
    });
  } catch (error) {
    const status = dashboardUpstreamStatusForError(error);
    return new Response(
      `event: stream_error\ndata: ${JSON.stringify({ error: "control_plane_stream_unavailable", status })}\n\n`,
      {
        headers: streamHeaders("live"),
        status: 200,
      },
    );
  }

  if (!response.ok || response.body === null) {
    return new Response(
      `event: stream_error\ndata: ${JSON.stringify({ error: "control_plane_stream_unavailable", status: response.status })}\n\n`,
      {
        headers: streamHeaders("live"),
        status: 200,
      },
    );
  }

  return new Response(response.body, {
    headers: streamHeaders("live"),
  });
}
