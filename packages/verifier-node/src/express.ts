import { evaluateAndEmit } from "./hotpath.js";
import { decisionToHttpResponse } from "./response.js";
import type { AidenIdVerifierOptions, DecisionResult, HeaderBag } from "./types.js";

export interface ExpressLikeRequest {
  readonly method?: string;
  readonly originalUrl?: string;
  readonly url?: string;
  readonly path?: string;
  readonly headers?: HeaderBag;
  aidenid?: DecisionResult | undefined;
}

export interface ExpressLikeResponse {
  readonly statusCode?: number;
  setHeader(name: string, value: string): void;
  status(code: number): ExpressLikeResponse;
  json(body: unknown): void;
}

export type ExpressNext = (error?: unknown) => void;

export function aidenidVerifier(options: AidenIdVerifierOptions) {
  return async function aidenidExpressMiddleware(req: ExpressLikeRequest, res: ExpressLikeResponse, next: ExpressNext) {
    try {
      const decision = await evaluateAndEmit(
        {
          method: req.method ?? "GET",
          url: req.originalUrl ?? req.url ?? req.path ?? "/",
          headers: req.headers,
          statusCode: res.statusCode
        },
        options
      );
      req.aidenid = decision;
      res.setHeader("X-AIdenID-Actor-Class", decision.actorClass);
      res.setHeader("X-AIdenID-Decision", decision.decision);

      if (decision.decision === "allow") {
        next();
        return;
      }

      const response = decisionToHttpResponse(decision);
      for (const [name, value] of Object.entries(response.headers)) {
        res.setHeader(name, value);
      }
      res.status(response.status).json(response.body);
    } catch (error) {
      next(error);
    }
  };
}
