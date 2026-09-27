import type {
  ActorClass,
  DecisionAction,
  DecisionEvaluation,
  DegradedState,
  MatchedPolicy,
  PriceMetadata,
  RateOutcome,
  ReasonCode,
  VerifierMode
} from "./types.js";

const DEFERRED_RETRY_HANDLE = "rty_deferred";

export interface DecisionContext {
  readonly match: MatchedPolicy;
  readonly actorClass: ActorClass;
  readonly mode?: VerifierMode | undefined;
  readonly rateOutcome?: RateOutcome | undefined;
  readonly degraded?: DegradedState | boolean | undefined;
  readonly signatureFailureReason?: ReasonCode | undefined;
  readonly sessionPresent?: boolean | undefined;
  readonly sessionRequired?: boolean | undefined;
  readonly retryToken?: string | undefined;
}

interface CandidateResult {
  readonly action: DecisionAction;
  readonly httpStatus: number;
  readonly headers: Readonly<Record<string, string>>;
  readonly reasonCodes: readonly ReasonCode[];
  readonly route?: string | undefined;
  readonly forceEnforce?: boolean | undefined;
}

function isDegraded(state: DegradedState | boolean | undefined): boolean {
  return state === true || (state !== undefined && state !== false && state !== "healthy");
}

function contextIsDegraded(ctx: DecisionContext): boolean {
  return isDegraded(ctx.degraded) || isDegraded(ctx.rateOutcome?.degraded);
}

function signatureRequired(ctx: DecisionContext): boolean {
  return (
    ctx.sessionRequired === true ||
    ctx.match.routePolicy.signatureRequired.length > 0 ||
    ctx.match.actorPolicy.signatureRequired.length > 0
  );
}

function result(action: DecisionAction, reasonCodes: readonly ReasonCode[], httpStatus: number, headers: Record<string, string> = {}, route?: string): CandidateResult {
  return {
    action,
    httpStatus,
    headers,
    reasonCodes,
    ...(route === undefined ? {} : { route })
  };
}

function retryAfter(value: number | undefined, fallback: number): string {
  return String(value ?? fallback);
}

function priceMetadataHeaderValue(metadata: PriceMetadata): string {
  return JSON.stringify({
    unit: metadata.unit,
    currency: metadata.currency,
    amount_micros: metadata.amountMicros
  });
}

function priceHeaders(priceUsd: number | undefined, metadata: PriceMetadata | undefined): Record<string, string> {
  const resolvedPriceUsd = priceUsd ?? (metadata === undefined ? 0 : metadata.amountMicros / 1_000_000);
  const resolvedMetadata =
    metadata ??
    ({
      unit: "request",
      currency: "USD",
      amountMicros: Math.round(resolvedPriceUsd * 1_000_000)
    } satisfies PriceMetadata);
  return {
    "X-AIdenID-Price-USD": String(resolvedPriceUsd),
    "X-AIdenID-Price-Metadata": priceMetadataHeaderValue(resolvedMetadata)
  };
}

function candidateForContext(ctx: DecisionContext): CandidateResult {
  const routePolicy = ctx.match.routePolicy;
  const actorPolicy = ctx.match.actorPolicy;

  if (actorPolicy.decision === "deny") {
    return result("deny", ["matched_policy"], 403);
  }

  if ((routePolicy.strict || actorPolicy.strict) && contextIsDegraded(ctx)) {
    if (routePolicy.onDegraded === "deny") {
      return { ...result("deny", ["strict_route_degraded"], 403), forceEnforce: true };
    }
    return {
      ...result("queue", ["strict_route_degraded"], 202, {
        "Retry-After": retryAfter(actorPolicy.queueRetrySeconds, 30),
        "X-AIdenID-Retry-Token": ctx.retryToken ?? DEFERRED_RETRY_HANDLE
      }),
      forceEnforce: true
    };
  }

  if (signatureRequired(ctx) && ctx.actorClass !== "verified_agent") {
    return {
      ...result("deny", [ctx.signatureFailureReason ?? "missing_signature"], 403),
      forceEnforce: routePolicy.strict || actorPolicy.strict
    };
  }

  if (ctx.rateOutcome !== undefined && !ctx.rateOutcome.allow) {
    return result("throttle", ["rate_limited"], 429, {
      "Retry-After": retryAfter(ctx.rateOutcome.retryAfterSeconds, actorPolicy.retryAfterSeconds)
    });
  }

  if (actorPolicy.decision === "price_required") {
    return result("price_required", ["price_required"], 402, priceHeaders(actorPolicy.priceUsd, actorPolicy.priceMetadata));
  }

  if (actorPolicy.decision === "sandbox") {
    return result(
      "sandbox",
      ["sandbox_policy"],
      200,
      {
        "X-AIdenID-Sandbox": "true",
        ...(actorPolicy.sandboxOrigin === undefined ? {} : { "X-AIdenID-Sandbox-Origin": actorPolicy.sandboxOrigin })
      },
      actorPolicy.sandboxOrigin
    );
  }

  if (actorPolicy.decision === "queue") {
    return result("queue", ["matched_policy"], 202, {
      "Retry-After": retryAfter(actorPolicy.queueRetrySeconds, 30),
      "X-AIdenID-Retry-Token": ctx.retryToken ?? DEFERRED_RETRY_HANDLE
    });
  }

  if (actorPolicy.decision === "throttle") {
    return result("throttle", ["rate_limited"], 429, {
      "Retry-After": retryAfter(actorPolicy.retryAfterSeconds, 30)
    });
  }

  return result("allow", ["matched_policy"], 200);
}

export function evaluateDecision(ctx: DecisionContext): DecisionEvaluation {
  const candidate = candidateForContext(ctx);
  const mode = ctx.mode ?? ctx.match.routePolicy.mode;

  if (candidate.forceEnforce === true || mode === "enforce" || candidate.action === "allow") {
    return {
      action: candidate.action,
      recommendedAction: candidate.action,
      httpStatus: candidate.httpStatus,
      headers: candidate.headers,
      reasonCodes: candidate.reasonCodes,
      route: candidate.route,
      annotations: []
    };
  }

  if (mode === "recommend") {
    return {
      action: "allow",
      recommendedAction: candidate.action,
      httpStatus: 200,
      headers: {
        "X-AIdenID-Recommended-Decision": candidate.action
      },
      reasonCodes: candidate.reasonCodes,
      route: candidate.route,
      annotations: [`recommend:${candidate.action}`]
    };
  }

  return {
    action: "allow",
    recommendedAction: candidate.action,
    httpStatus: 200,
    headers: {
      "X-AIdenID-Observed-Decision": candidate.action
    },
    reasonCodes: candidate.reasonCodes,
    route: candidate.route,
    annotations: [`observe:${candidate.action}`]
  };
}
