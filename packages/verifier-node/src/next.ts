import { evaluateAndEmit } from "./hotpath.js";
import { decisionToHttpResponse, type DecisionHttpResponse } from "./response.js";
import type { AidenIdVerifierOptions, HeaderReader } from "./types.js";

export interface NextLikeRequest {
  readonly method?: string;
  readonly url: string;
  readonly nextUrl?: {
    readonly pathname: string;
  };
  readonly headers?: HeaderReader;
}

export type NextMiddlewareDecision = DecisionHttpResponse | undefined;

export function aidenidNextMiddleware(options: AidenIdVerifierOptions) {
  return async function aidenidMiddleware(request: NextLikeRequest): Promise<NextMiddlewareDecision> {
    const decision = await evaluateAndEmit(
      {
        method: request.method ?? "GET",
        url: request.nextUrl?.pathname ?? request.url,
        headers: request.headers
      },
      options
    );

    if (decision.decision === "allow") {
      return undefined;
    }

    return decisionToHttpResponse(decision);
  };
}
