import { describe, expect, it } from "vitest";

import {
  aidenidFastifyPlugin,
  aidenidNextMiddleware,
  aidenidVerifier,
  type DecisionResult,
  type ExpressLikeRequest
} from "../src/index.js";

describe("middleware adapters", () => {
  it("attaches observe-mode decisions in Express-style middleware", async () => {
    const seen: DecisionResult[] = [];
    const middleware = aidenidVerifier({
      siteId: "sit_123",
      apiKey: "key",
      onDecision: (decision) => {
        seen.push(decision);
      }
    });
    const headers: Record<string, string> = {};
    const req: ExpressLikeRequest = {
      method: "GET",
      originalUrl: "/demo",
      headers: { signature: "sig" }
    };
    const res = {
      statusCode: 200,
      setHeader(name: string, value: string) {
        headers[name] = value;
      },
      status() {
        return this;
      },
      json() {
        throw new Error("observe mode should call next");
      }
    };
    let nextCalled = false;

    await middleware(req, res, () => {
      nextCalled = true;
    });

    expect(nextCalled).toBe(true);
    expect(req.aidenid).toMatchObject({ actorClass: "signed_agent", decision: "allow" });
    expect(headers["X-AIdenID-Actor-Class"]).toBe("signed_agent");
    expect(seen).toHaveLength(1);
  });

  it("registers a Fastify-style onRequest hook", async () => {
    const hooks: Array<(request: { method: string; url: string; headers: Record<string, string> }, reply: never) => Promise<void>> = [];
    const plugin = aidenidFastifyPlugin({ siteId: "sit_123", apiKey: "key" });

    await plugin({
      addHook(_name, hook) {
        hooks.push(hook as never);
      }
    });

    expect(hooks).toHaveLength(1);
  });

  it("returns undefined for allowed Next-style middleware requests", async () => {
    const middleware = aidenidNextMiddleware({ siteId: "sit_123", apiKey: "key" });

    await expect(
      middleware({
        method: "GET",
        url: "https://example.com/",
        headers: new Headers({ accept: "text/html", "user-agent": "Mozilla/5.0" })
      })
    ).resolves.toBeUndefined();
  });
});
