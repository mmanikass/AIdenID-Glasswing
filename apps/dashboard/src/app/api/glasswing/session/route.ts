import { NextResponse } from "next/server.js";

import { requireLogin } from "../../../../auth/constants.js";
import { issueDevOperatorSession } from "../../../../glasswing/session.js";

export const dynamic = "force-dynamic";

/**
 * Local-development session issuer. When the dashboard login gate is OFF (the loopback
 * `pnpm dev` profile), this sets the dashboard operator request cookie so the browser can
 * call the operator-gated routes. With AIDENID_REQUIRE_LOGIN=true it refuses: the SSO
 * callback is the only issuer there. It never reveals the token in a response body.
 */
export async function POST(request: Request): Promise<Response> {
  const outcome = issueDevOperatorSession(process.env, { loginRequired: requireLogin(), requestUrl: request.url });
  if (!outcome.ok) {
    return NextResponse.json({ error: outcome.error }, { status: outcome.status, headers: { "Cache-Control": "no-store" } });
  }
  const response = new NextResponse(null, { status: 204, headers: { "Cache-Control": "no-store" } });
  response.cookies.set(outcome.cookie.name, outcome.cookie.value, {
    httpOnly: true,
    sameSite: "lax",
    secure: outcome.cookie.secure,
    path: "/",
    maxAge: outcome.cookie.maxAgeSeconds
  });
  return response;
}
