import { AsyncLocalStorage } from "node:async_hooks";
import type { FastifyInstance } from "fastify";

import { prefixedId } from "../ids.js";

export interface RequestContext {
  readonly traceId: string;
}

const requestContextStore = new AsyncLocalStorage<RequestContext>();

export function currentContext(): RequestContext | undefined {
  return requestContextStore.getStore();
}

export async function registerCorrelationPlugin(app: FastifyInstance): Promise<void> {
  app.addHook("onRequest", (request, reply, done) => {
    const requestId = request.headers["x-request-id"];
    const traceId = typeof requestId === "string" && requestId.trim() !== "" ? requestId : prefixedId("trc");
    reply.header("x-request-id", traceId);
    requestContextStore.run({ traceId }, done);
  });

  app.addHook("onSend", (request, reply, payload, done) => {
    if (reply.statusCode < 400 || payload === null || payload === undefined) {
      done(null, payload);
      return;
    }

    const contentType = String(reply.getHeader("content-type") ?? "");
    if (!contentType.toLowerCase().includes("application/json")) {
      done(null, payload);
      return;
    }

    const payloadText = typeof payload === "string" ? payload : Buffer.isBuffer(payload) ? payload.toString("utf8") : undefined;
    if (payloadText === undefined || payloadText.trim().length === 0) {
      done(null, payload);
      return;
    }

    try {
      const body = JSON.parse(payloadText) as unknown;
      if (body === null || typeof body !== "object" || Array.isArray(body)) {
        done(null, payload);
        return;
      }

      const requestId = currentContext()?.traceId ?? request.id;
      const envelope = body as Record<string, unknown>;
      done(
        null,
        JSON.stringify({
          ...envelope,
          request_id: envelope.request_id ?? requestId,
          requestId: envelope.requestId ?? requestId
        })
      );
    } catch {
      done(null, payload);
    }
  });
}
