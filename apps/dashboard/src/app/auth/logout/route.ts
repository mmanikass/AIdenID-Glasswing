import { NextResponse } from "next/server";

import { SESSION_COOKIE } from "../../../auth/constants.js";

export const dynamic = "force-dynamic";

/** Clear the session cookie and return to the login page. */
export async function GET(request: Request): Promise<Response> {
  const response = NextResponse.redirect(new URL("/login", request.url));
  response.cookies.set(SESSION_COOKIE, "", {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    path: "/",
    maxAge: 0,
  });
  return response;
}
