import { randomBytes, timingSafeEqual } from "node:crypto";

const SSO_STATE_BYTES = 32;
const SSO_STATE_PATTERN = /^[A-Za-z0-9_-]{43}$/;

export const SSO_STATE_MAX_AGE_SECONDS = 5 * 60;

export function createSsoState(): string {
  return randomBytes(SSO_STATE_BYTES).toString("base64url");
}

export function matchesSsoState(
  callbackState: string | null,
  cookieState: string | undefined,
): boolean {
  if (
    callbackState === null ||
    cookieState === undefined ||
    !SSO_STATE_PATTERN.test(callbackState) ||
    !SSO_STATE_PATTERN.test(cookieState)
  ) {
    return false;
  }

  return timingSafeEqual(
    Buffer.from(callbackState, "ascii"),
    Buffer.from(cookieState, "ascii"),
  );
}
