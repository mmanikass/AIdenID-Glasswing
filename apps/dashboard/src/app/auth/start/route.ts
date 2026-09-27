import { NextResponse } from "next/server.js";

import {
  dashboardPublicOrigin,
  sentinelayerWebUrl,
  SSO_STATE_COOKIE,
} from "../../../auth/constants.js";
import {
  createSsoState,
  SSO_STATE_MAX_AGE_SECONDS,
} from "../../../auth/ssoState.js";

export const dynamic = "force-dynamic";

/** Start a browser-bound Sentinelayer SSO handoff. */
export function GET(request: Request): Response {
  const state = createSsoState();
  const callback = new URL(
    "/auth/callback",
    dashboardPublicOrigin(request.url),
  );
  callback.searchParams.set("state", state);

  const login = new URL("/login", sentinelayerWebUrl());
  login.searchParams.set("redirect_to", callback.toString());

  const response = NextResponse.redirect(login);
  response.cookies.set(SSO_STATE_COOKIE, state, {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    path: "/",
    maxAge: SSO_STATE_MAX_AGE_SECONDS,
  });
  response.headers.set("Cache-Control", "no-store");
  return response;
}
