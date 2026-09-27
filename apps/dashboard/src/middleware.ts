import { NextResponse, type NextRequest } from "next/server";

import { SESSION_COOKIE, requireLogin } from "./auth/constants.js";

/**
 * Gate the dashboard behind a logged-in session (cookie presence). Enforcement
 * is opt-in via AIDENID_REQUIRE_LOGIN so the login flow can ship before the
 * dashboard is hard-gated. Full /auth/me validation happens in the pages that
 * read the user (see auth/session.ts).
 */
export function middleware(request: NextRequest): NextResponse {
  if (!requireLogin()) {
    return NextResponse.next();
  }
  const hasSession = Boolean(request.cookies.get(SESSION_COOKIE)?.value);
  if (!hasSession) {
    return NextResponse.redirect(new URL("/login", request.url));
  }
  return NextResponse.next();
}

export const config = {
  // Gate everything except the login page, the auth routes, and static assets.
  matcher: ["/((?!login|auth|_next|favicon.ico|icon.svg).*)"],
};
