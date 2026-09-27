import { evaluateAndEmit } from "./hotpath.js";
import { decisionToHttpResponse } from "./response.js";
import type { AidenIdVerifierOptions, DecisionResult, HeaderBag } from "./types.js";

export interface FastifyLikeRequest {
  readonly method?: string;
  readonly url?: string;
  readonly headers?: HeaderBag;
  aidenid?: DecisionResult | undefined;
}

export interface FastifyLikeReply {
  readonly statusCode?: number;
  header(name: string, value: string): FastifyLikeReply;
  code(statusCode: number): FastifyLikeReply;
  send(body: unknown): void;
}

export interface FastifyLikeInstance {
  addHook(name: "onRequest", hook: (request: FastifyLikeRequest, reply: FastifyLikeReply) => Promise<void>): void;
}

export function aidenidFastifyPlugin(options: AidenIdVerifierOptions) {
  return async function registerAidenIdFastify(instance: FastifyLikeInstance): Promise<void> {
    instance.addHook("onRequest", async (request, reply) => {
      const decision = await evaluateAndEmit(
        {
          method: request.method ?? "GET",
          url: request.url ?? "/",
          headers: request.headers,
          statusCode: reply.statusCode
        },
        options
      );
      request.aidenid = decision;
      reply.header("X-AIdenID-Actor-Class", decision.actorClass).header("X-AIdenID-Decision", decision.decision);

      if (decision.decision !== "allow") {
        const response = decisionToHttpResponse(decision);
        for (const [name, value] of Object.entries(response.headers)) {
          reply.header(name, value);
        }
        reply.code(response.status).send(response.body);
      }
    });
  };
}
