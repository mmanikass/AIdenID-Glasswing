import {
  authorizeDashboardOperatorRequest,
  dashboardControlPlaneTimeoutMs,
  dashboardUpstreamStatusForError,
  fetchDashboardControlPlaneWithTimeout,
  operatorAuthFailureResponse,
  type DashboardApiEnvironment
} from "../dashboardApi.js";

export interface GlasswingProxyEnvironment extends DashboardApiEnvironment {
  readonly AIDENID_PROTECTED_SITE_URL?: string | undefined;
}

const LIVE_HEADER = {
  "Cache-Control": "no-store",
  "Content-Type": "application/json",
  "X-AIdenID-Dashboard-Data-Source": "live"
} as const;

const ID_SEGMENT = /^[A-Za-z0-9_-]{1,128}$/;
const MAX_BODY_BYTES = 16_384;

/**
 * Allow-listed upstream routes. Anything else is refused before any network call, so the
 * proxy cannot be used to reach arbitrary protected-site or control-plane paths.
 */
export function resolveGlasswingUpstreamPath(method: string, segments: readonly string[]): string | undefined {
  const m = method.toUpperCase();
  const [a, b, c] = segments;
  if (segments.length === 1 && a === "agents" && (m === "GET" || m === "POST")) return "/glasswing/agents";
  if (segments.length === 3 && a === "agents" && b !== undefined && ID_SEGMENT.test(b) && c === "run" && m === "POST") return `/glasswing/agents/${b}/run`;
  if (segments.length === 1 && a === "grants" && m === "POST") return "/glasswing/grants";
  if (segments.length === 1 && a === "revoke" && m === "POST") return "/glasswing/revoke";
  if (segments.length === 1 && a === "reviews" && m === "GET") return "/glasswing/reviews";
  if (segments.length === 2 && a === "reviews" && b !== undefined && ID_SEGMENT.test(b) && m === "POST") return `/glasswing/reviews/${b}`;
  return undefined;
}

function jsonError(status: number, error: string, message?: string): Response {
  return Response.json(message === undefined ? { error } : { error, message }, { status, headers: LIVE_HEADER });
}

function protectedSiteUrl(env: GlasswingProxyEnvironment): URL | undefined {
  const raw = env.AIDENID_PROTECTED_SITE_URL?.trim();
  if (!raw) return undefined;
  try {
    const url = new URL(raw);
    if ((url.protocol !== "http:" && url.protocol !== "https:") || url.username || url.password || url.search || url.hash) {
      return undefined;
    }
    return url;
  } catch {
    return undefined;
  }
}

export interface ProxyGlasswingInput {
  readonly request: Request;
  readonly segments: readonly string[];
  readonly env: GlasswingProxyEnvironment;
  readonly fetchImpl?: typeof fetchDashboardControlPlaneWithTimeout | undefined;
}

/**
 * Forward one allow-listed Glasswing call to the protected site with the SERVER-held
 * operator token. The browser never sees that token; it authenticates to this dashboard with
 * its own request credential, exactly like the other operator routes. Client cookies and
 * headers are not forwarded upstream.
 */
export async function proxyGlasswingRequest(input: ProxyGlasswingInput): Promise<Response> {
  const { request, segments, env } = input;
  const auth = authorizeDashboardOperatorRequest(request, env);
  if (!auth.ok) {
    return operatorAuthFailureResponse(auth);
  }
  const upstreamPath = resolveGlasswingUpstreamPath(request.method, segments);
  if (upstreamPath === undefined) {
    return jsonError(404, "glasswing_route_not_allowed");
  }
  const site = protectedSiteUrl(env);
  if (site === undefined) {
    return jsonError(503, "protected_site_not_configured", "AIDENID_PROTECTED_SITE_URL must be an http(s) origin");
  }
  const operatorToken = env.AIDENID_OPERATOR_TOKEN?.trim();
  if (!operatorToken) {
    return jsonError(503, "operator_token_unavailable", "AIDENID_OPERATOR_TOKEN must be set to call the protected site");
  }

  let body: string | undefined;
  if (request.method.toUpperCase() === "POST") {
    const declared = Number(request.headers.get("content-length") ?? "0");
    if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) {
      return jsonError(413, "glasswing_body_too_large");
    }
    body = await request.text();
    if (Buffer.byteLength(body, "utf8") > MAX_BODY_BYTES) {
      return jsonError(413, "glasswing_body_too_large");
    }
    if (body.length > 0) {
      try {
        JSON.parse(body);
      } catch {
        return jsonError(400, "glasswing_body_not_json");
      }
    }
  }

  const fetchImpl = input.fetchImpl ?? fetchDashboardControlPlaneWithTimeout;
  try {
    const upstream = await fetchImpl(new URL(upstreamPath, site).toString(), {
      method: request.method.toUpperCase(),
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${operatorToken}`,
        ...(body === undefined ? {} : { "Content-Type": "application/json" })
      },
      ...(body === undefined ? {} : { body }),
      cache: "no-store",
      timeoutMs: dashboardControlPlaneTimeoutMs(env)
    });
    const text = await upstream.text();
    return new Response(text, {
      status: upstream.status,
      headers: { ...LIVE_HEADER, "Content-Type": upstream.headers.get("content-type") ?? "application/json" }
    });
  } catch (error) {
    return jsonError(dashboardUpstreamStatusForError(error), "protected_site_unavailable");
  }
}
