import { NextResponse } from "next/server.js";

import {
  dashboardPublicOrigin,
  SESSION_COOKIE,
  sentinelayerApiUrl,
  SSO_STATE_COOKIE,
} from "../../../auth/constants.js";
import { matchesSsoState } from "../../../auth/ssoState.js";
import { fetchDashboardAuthJson } from "../../../auth/upstreamFetch.js";

export const dynamic = "force-dynamic";

const SESSION_MAX_AGE_SECONDS = 60 * 60 * 24 * 7;
const SSO_HANDOFF_CODE_PATTERN = /^[A-Za-z0-9_-]{43}$/;

function clearSsoState(response: NextResponse): NextResponse {
  response.cookies.set(SSO_STATE_COOKIE, "", {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    path: "/",
    maxAge: 0,
  });
  response.headers.set("Cache-Control", "no-store");
  return response;
}

function failureResponse(dashboardOrigin: string): NextResponse {
  return clearSsoState(
    NextResponse.redirect(new URL("/login?error=sso", dashboardOrigin)),
  );
}

/**
 * SSO callback: exchange the single-use handoff code (minted by sentinelayer)
 * for a session JWT, store it in an httpOnly cookie, and land in the dashboard.
 * The JWT only ever arrives via this server-side exchange, never in a URL.
 */
export async function GET(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const dashboardOrigin = dashboardPublicOrigin(request.url);
  const code = url.searchParams.get("code");
  const callbackState = url.searchParams.get("state");
  const cookieState = request.headers
    .get("cookie")
    ?.split(";")
    .map((part) => part.trim())
    .find((part) => part.startsWith(`${SSO_STATE_COOKIE}=`))
    ?.slice(SSO_STATE_COOKIE.length + 1);
  if (
    code === null ||
    !SSO_HANDOFF_CODE_PATTERN.test(code) ||
    !matchesSsoState(callbackState, cookieState)
  ) {
    return failureResponse(dashboardOrigin);
  }

  try {
    const res = await fetchDashboardAuthJson(
      `${sentinelayerApiUrl()}/api/v1/auth/sso/exchange`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code }),
        cache: "no-store",
      },
    );
    if (!res.ok) return failureResponse(dashboardOrigin);
    const data = res.body;
    if (data === null || typeof data !== "object" || Array.isArray(data)) {
      return failureResponse(dashboardOrigin);
    }
    const token = (data as { token?: unknown }).token;
    if (typeof token !== "string" || token.trim().length === 0) {
      return failureResponse(dashboardOrigin);
    }

    const response = clearSsoState(
      NextResponse.redirect(new URL("/", dashboardOrigin)),
    );
    response.cookies.set(SESSION_COOKIE, token, {
      httpOnly: true,
      secure: true,
      sameSite: "lax",
      path: "/",
      maxAge: SESSION_MAX_AGE_SECONDS,
    });
    return response;
  } catch {
    return failureResponse(dashboardOrigin);
  }
}
