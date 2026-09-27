import { readHeader } from "./headers.js";
import type { RateLimitSignal, RequestHeaders } from "./types.js";

function parsePositiveInt(value: string | undefined): number | undefined {
  if (value === undefined) {
    return undefined;
  }
  const parsed = Number.parseInt(value.trim(), 10);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : undefined;
}

function parseRetryAfter(value: string | undefined, now: Date): number | undefined {
  if (value === undefined) {
    return undefined;
  }
  const asSeconds = parsePositiveInt(value);
  if (asSeconds !== undefined) {
    return asSeconds;
  }
  const asDate = Date.parse(value);
  if (!Number.isFinite(asDate)) {
    return undefined;
  }
  return Math.max(0, Math.ceil((asDate - now.getTime()) / 1000));
}

export function ingestUpstreamRateLimit(
  headers: RequestHeaders | undefined,
  statusCode: number | undefined,
  now: Date
): RateLimitSignal {
  const retryAfterSeconds = parseRetryAfter(readHeader(headers, "retry-after"), now);
  const remaining =
    parsePositiveInt(readHeader(headers, "ratelimit-remaining")) ??
    parsePositiveInt(readHeader(headers, "x-ratelimit-remaining"));
  const resetAtEpochSeconds =
    parsePositiveInt(readHeader(headers, "ratelimit-reset")) ?? parsePositiveInt(readHeader(headers, "x-ratelimit-reset"));

  const status = statusCode === 429 || remaining === 0 ? "throttled" : remaining !== undefined && remaining <= 2 ? "warning" : "ok";
  const signal: {
    status: RateLimitSignal["status"];
    retryAfterSeconds?: number;
    remaining?: number;
    resetAtEpochSeconds?: number;
  } = { status };

  if (retryAfterSeconds !== undefined) {
    signal.retryAfterSeconds = retryAfterSeconds;
  }
  if (remaining !== undefined) {
    signal.remaining = remaining;
  }
  if (resetAtEpochSeconds !== undefined) {
    signal.resetAtEpochSeconds = resetAtEpochSeconds;
  }

  return signal;
}
