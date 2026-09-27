import { cookies } from "next/headers";

import { SESSION_COOKIE, sentinelayerApiUrl } from "./constants.js";
import { fetchDashboardAuthJson } from "./upstreamFetch.js";

export interface SessionUser {
  readonly id: string;
  readonly email: string;
  readonly github_username: string;
  readonly avatar_url: string;
  readonly is_admin: boolean;
}

/**
 * Validate the current session by calling sentinelayer-api `/auth/me` with the
 * shared session JWT. Returns identity ONLY — Clearance entitlements are
 * tracked separately, so this never reads sentinelayer's membership tier.
 * Returns null when there is no valid session.
 */
export async function getSessionUser(): Promise<SessionUser | null> {
  const token = (await cookies()).get(SESSION_COOKIE)?.value;
  if (!token) return null;
  try {
    const res = await fetchDashboardAuthJson(
      `${sentinelayerApiUrl()}/api/v1/auth/me`,
      {
        headers: { Authorization: `Bearer ${token}` },
        cache: "no-store",
      },
    );
    if (!res.ok) return null;
    const user = res.body;
    if (user === null || typeof user !== "object" || Array.isArray(user)) {
      return null;
    }
    return typeof (user as Partial<SessionUser>).id === "string"
      ? (user as SessionUser)
      : null;
  } catch {
    return null;
  }
}
