import {
  buildAgentIdentityChallenge,
  httpStatusForDecision,
  type AgentIdentityChallenge,
  type CascadeTrace
} from "@aidenid/common-schemas";
import type { ActorClass, DecisionResult } from "./types.js";

export const AIDENID_REGISTER_URL = "https://api.aidenid.com/v1/identities";
export const AIDENID_CHALLENGE_URL = "https://api.aidenid.com/v1/identities";
export const AIDENID_AGENT_ONBOARDING_DOCS_URL = "https://aidenid.com/docs/agent-onboarding";

const DENY_HINT_ACTOR_CLASSES = new Set<ActorClass>(["unknown", "suspicious_automation"]);
const PURPOSE_CHALLENGE_REASONS = new Set(["purpose_required", "purpose_disallowed"]);

export interface DecisionHttpResponse {
  readonly status: number;
  readonly headers: Record<string, string>;
  readonly body: {
    readonly code: string;
    readonly message: string;
    readonly requestId: string;
    readonly decision: string;
    readonly register_url?: string | undefined;
    readonly docs_url?: string | undefined;
    readonly identity_challenge?: AgentIdentityChallenge | undefined;
    readonly retry_after_seconds?: number | undefined;
    readonly retry_token?: string | undefined;
    readonly sandbox_origin?: string | undefined;
    readonly price_metadata?:
      | {
          readonly unit: string;
          readonly currency: "USD";
          readonly amount_micros: number;
        }
      | undefined;
  };
}

function quoteWwwAuthenticateParam(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}

function priceMetadataFromHeaders(headers: Readonly<Record<string, string>>) {
  const raw = headers["X-AIdenID-Price-Metadata"] ?? headers["x-aidenid-price-metadata"];
  if (raw === undefined) {
    return undefined;
  }
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      return undefined;
    }
    const value = parsed as Readonly<Record<string, unknown>>;
    return typeof value.unit === "string" &&
      value.unit.length > 0 &&
      value.currency === "USD" &&
      typeof value.amount_micros === "number" &&
      Number.isInteger(value.amount_micros) &&
      value.amount_micros >= 0
      ? { unit: value.unit, currency: "USD" as const, amount_micros: value.amount_micros }
      : undefined;
  } catch {
    return undefined;
  }
}

function responseHeader(headers: Readonly<Record<string, string>>, name: string): string | undefined {
  const wanted = name.toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === wanted) {
      return value;
    }
  }
  return undefined;
}

function positiveIntegerHeader(headers: Readonly<Record<string, string>>, name: string): number | undefined {
  const raw = responseHeader(headers, name);
  if (raw === undefined) {
    return undefined;
  }
  const parsed = Number(raw);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : undefined;
}

function cascadeTraceHeader(trace: CascadeTrace | undefined): string | undefined {
  if (trace === undefined) {
    return undefined;
  }
  return trace.map((entry) => `${entry.layer}=${entry.status}:${entry.reason}`).join(";");
}

function shouldIncludeIdentityChallenge(decision: DecisionResult): boolean {
  if (DENY_HINT_ACTOR_CLASSES.has(decision.actorClass)) {
    return true;
  }
  return decision.reasons.some((reason) => PURPOSE_CHALLENGE_REASONS.has(reason));
}

function identityChallenge(decision: DecisionResult): AgentIdentityChallenge | undefined {
  try {
    return buildAgentIdentityChallenge({
      siteId: decision.siteId,
      requestId: decision.requestId,
      actorClass: decision.actorClass,
      decision: decision.decision,
      reasonCodes: decision.reasons,
      challengeUrl: AIDENID_CHALLENGE_URL,
      registerUrl: AIDENID_REGISTER_URL,
      docsUrl: AIDENID_AGENT_ONBOARDING_DOCS_URL
    });
  } catch {
    return undefined;
  }
}

export function decisionToHttpResponse(decision: DecisionResult): DecisionHttpResponse {
  const cascadeTrace = cascadeTraceHeader(decision.cascadeTrace);
  const headers: Record<string, string> = {
    "X-AIdenID-Request-Id": decision.requestId,
    "X-AIdenID-Actor-Class": decision.actorClass,
    "X-AIdenID-Decision": decision.decision,
    ...(cascadeTrace === undefined ? {} : { "X-AIdenID-Cascade-Trace": cascadeTrace }),
    ...decision.responseHeaders
  };

  if (decision.rateLimit.retryAfterSeconds !== undefined && headers["Retry-After"] === undefined) {
    headers["Retry-After"] = String(decision.rateLimit.retryAfterSeconds);
  }

  if (decision.decision === "throttle") {
    if (headers["Retry-After"] === undefined) {
      headers["Retry-After"] = "30";
    }
    return {
      status: httpStatusForDecision(decision.decision),
      headers,
      body: {
        code: "AIDENID_THROTTLED",
        message: "request throttled by AIdenID verifier policy",
        requestId: decision.requestId,
        decision: decision.decision,
        ...(positiveIntegerHeader(headers, "Retry-After") === undefined
          ? {}
          : { retry_after_seconds: positiveIntegerHeader(headers, "Retry-After") })
      }
    };
  }

  if (decision.decision === "queue") {
    if (headers["Retry-After"] === undefined) {
      headers["Retry-After"] = "30";
    }
    return {
      status: httpStatusForDecision(decision.decision),
      headers,
      body: {
        code: "AIDENID_QUEUED",
        message: "request queued by AIdenID verifier policy",
        requestId: decision.requestId,
        decision: decision.decision,
        ...(positiveIntegerHeader(headers, "Retry-After") === undefined
          ? {}
          : { retry_after_seconds: positiveIntegerHeader(headers, "Retry-After") }),
        ...(responseHeader(headers, "X-AIdenID-Retry-Token") === undefined
          ? {}
          : { retry_token: responseHeader(headers, "X-AIdenID-Retry-Token") })
      }
    };
  }

  if (decision.decision === "deny") {
    const includeRegisterHint = DENY_HINT_ACTOR_CLASSES.has(decision.actorClass);
    const includeChallenge = shouldIncludeIdentityChallenge(decision);
    const challenge = includeChallenge ? identityChallenge(decision) : undefined;
    const denyHeaders = includeRegisterHint
      ? {
          ...headers,
          ...(challenge === undefined ? {} : { "X-AIdenID-Challenge": "agent-identity" }),
          "WWW-Authenticate": `AIdenID realm="${quoteWwwAuthenticateParam(decision.siteId)}", register="${AIDENID_REGISTER_URL}"`
        }
      : challenge !== undefined
        ? { ...headers, "X-AIdenID-Challenge": "agent-identity" }
        : headers;

    return {
      status: httpStatusForDecision(decision.decision),
      headers: denyHeaders,
      body: {
        code: "AIDENID_DENIED",
        message: "request denied by AIdenID verifier policy",
        requestId: decision.requestId,
        decision: decision.decision,
        ...(includeRegisterHint
          ? {
              register_url: AIDENID_REGISTER_URL,
              docs_url: AIDENID_AGENT_ONBOARDING_DOCS_URL
            }
          : {}),
        ...(challenge === undefined ? {} : { identity_challenge: challenge })
      }
    };
  }

  if (decision.decision === "price_required") {
    const priceMetadata = priceMetadataFromHeaders(headers);
    return {
      status: httpStatusForDecision(decision.decision),
      headers,
      body: {
        code: "AIDENID_PRICE_REQUIRED",
        message: "request requires AIdenID price authorization",
        requestId: decision.requestId,
        decision: decision.decision,
        ...(priceMetadata === undefined ? {} : { price_metadata: priceMetadata })
      }
    };
  }

  if (decision.decision === "sandbox") {
    headers["X-AIdenID-Sandbox"] = responseHeader(headers, "X-AIdenID-Sandbox") ?? "true";
    const sandboxOrigin = responseHeader(headers, "X-AIdenID-Sandbox-Origin");
    return {
      status: httpStatusForDecision(decision.decision),
      headers,
      body: {
        code: "AIDENID_SANDBOX",
        message: "request routed by AIdenID sandbox policy",
        requestId: decision.requestId,
        decision: decision.decision,
        ...(sandboxOrigin === undefined ? {} : { sandbox_origin: sandboxOrigin })
      }
    };
  }

  return {
    status: httpStatusForDecision(decision.decision),
    headers,
    body: {
      code: "AIDENID_ALLOWED",
      message: "request allowed by AIdenID verifier policy",
      requestId: decision.requestId,
      decision: decision.decision
    }
  };
}
