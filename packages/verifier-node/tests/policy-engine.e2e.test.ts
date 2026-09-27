import { MemoryTokenBucketStore, parsePolicyYaml, type AsyncTokenBucketStore, type TokenBucketStore } from "@aidenid/policy-engine";
import { describe, expect, it } from "vitest";

import { decisionToHttpResponse, evaluateRequest, evaluateRequestAsync } from "../src/index.js";

const loaded = parsePolicyYaml(`
version: 1
site_id: sit_policy_sdk
mode: enforce
defaults:
  strict: false
  on_degraded: queue
  sandbox_origin: https://sandbox.example.com
  suspicion_threshold: 0.85
  rate: { capacity: 100, refill_per_sec: 10, cost: 1 }
routes:
  - template: /open
    method: GET
    per_actor_class:
      likely_human: { decision: allow }
  - template: /checkout
    method: POST
    per_actor_class:
      signed_agent: { decision: queue, queue_retry_s: 20 }
      suspicious_automation: { decision: deny }
      unknown: { decision: throttle, retry_after_s: 10 }
  - template: /premium-content/*
    method: GET
    per_actor_class:
      signed_agent: { decision: price_required, price_usd: 0.01 }
      unknown: { decision: deny }
  - template: /api/:endpoint
    method: POST
    per_actor_class:
      suspicious_automation: { decision: sandbox, sandbox_origin: https://sandbox.example.com }
`);

const options = {
  siteId: "sit_policy_sdk",
  apiKey: "key",
  policy: {
    trie: loaded.trie,
    tokenBucketStore: new MemoryTokenBucketStore()
  }
};

describe("verifier policy engine integration", () => {
  it("lets policy.yaml drive all six SDK decision outcomes", () => {
    const scenarios = [
      {
        request: { method: "GET", url: "/open", headers: { "user-agent": "Mozilla/5.0 Chrome", accept: "text/html" } },
        expected: "allow"
      },
      {
        request: { method: "POST", url: "/checkout", headers: {} },
        expected: "throttle"
      },
      {
        request: { method: "POST", url: "/checkout", headers: { signature: "sig" } },
        expected: "queue"
      },
      {
        request: { method: "POST", url: "/api/comment", headers: { "user-agent": "curl/8.0" } },
        expected: "sandbox"
      },
      {
        request: { method: "POST", url: "/checkout", headers: { "user-agent": "curl/8.0" } },
        expected: "deny"
      },
      {
        request: { method: "GET", url: "/premium-content/story", headers: { signature: "sig" } },
        expected: "price_required"
      }
    ] as const;

    for (const scenario of scenarios) {
      const decision = evaluateRequest(scenario.request, options);
      expect(decision.decision).toBe(scenario.expected);
      const response = decisionToHttpResponse(decision);
      if (scenario.expected === "throttle") {
        expect(response.status).toBe(429);
        expect(response.headers["Retry-After"]).toBe("10");
        expect(response.body).toMatchObject({ retry_after_seconds: 10 });
      }
      if (scenario.expected === "queue") {
        expect(response.status).toBe(202);
        expect(response.headers["Retry-After"]).toBe("20");
        expect(response.headers["X-AIdenID-Retry-Token"]).toMatch(/^rty_/);
        expect(response.body).toMatchObject({
          retry_after_seconds: 20,
          retry_token: expect.stringMatching(/^rty_/)
        });
      }
      if (scenario.expected === "sandbox") {
        expect(response.status).toBe(200);
        expect(response.headers["X-AIdenID-Sandbox"]).toBe("true");
        expect(response.headers["X-AIdenID-Sandbox-Origin"]).toBe("https://sandbox.example.com");
        expect(response.body).toMatchObject({
          sandbox_origin: "https://sandbox.example.com"
        });
      }
      if (scenario.expected === "price_required") {
        expect(decision.responseHeaders?.["X-AIdenID-Price-USD"]).toBe("0.01");
        expect(JSON.parse(decision.responseHeaders?.["X-AIdenID-Price-Metadata"] ?? "")).toEqual({
          unit: "request",
          currency: "USD",
          amount_micros: 10_000
        });
        expect(response.body).toMatchObject({
          price_metadata: { unit: "request", currency: "USD", amount_micros: 10_000 }
        });
      }
    }
  });

  it("uses async token buckets from middleware/runtime paths", async () => {
    const asyncStore: AsyncTokenBucketStore = {
      async take() {
        return { allow: false, remaining: 0 };
      }
    };

    await expect(
      evaluateRequestAsync(
        { method: "GET", url: "/open", headers: { "user-agent": "Mozilla/5.0 Chrome", accept: "text/html" } },
        {
          siteId: "sit_policy_sdk",
          apiKey: "key",
          policy: {
            trie: loaded.trie,
            asyncTokenBucketStore: asyncStore
          }
        }
      )
    ).resolves.toMatchObject({
      decision: "throttle",
      reasons: ["rate_limited"],
      rateLimit: { status: "throttled" }
    });
  });

  it("auto-wires Redis token buckets from top-level redis options", async () => {
    const calls: string[] = [];
    const redis = {
      scriptRunner: {
        async load() {
          calls.push("load");
          return "sha-token-bucket";
        },
        async runSha(_sha: string, options: { readonly keys: readonly string[] }) {
          calls.push(options.keys[0] ?? "");
          return [0, 0];
        },
        async run() {
          throw new Error("EVAL fallback should not run when EVALSHA is available");
        }
      }
    };

    await expect(
      evaluateRequestAsync(
        { method: "GET", url: "/open", headers: { "user-agent": "Mozilla/5.0 Chrome", accept: "text/html" } },
        {
          siteId: "sit_policy_sdk",
          apiKey: "key",
          policy: {
            trie: loaded.trie
          },
          redis
        }
      )
    ).resolves.toMatchObject({
      decision: "throttle",
      reasons: ["rate_limited"],
      rateLimit: { status: "throttled" }
    });
    expect(calls[0]).toBe("load");
    expect(calls[1]).toMatch(/^aidenid:bkt:sit_policy_sdk:ip:/);
  });

  it("denies purpose-constrained routes before rate buckets", async () => {
    const purposePolicy = parsePolicyYaml(`
version: 1
site_id: sit_policy_sdk
mode: enforce
defaults:
  strict: false
  on_degraded: queue
  rate: { capacity: 100, refill_per_sec: 10, cost: 1 }
routes:
  - template: /purpose
    method: GET
    allowed_purposes: [benefits_lookup, research]
    per_actor_class:
      likely_human: { decision: allow }
  - template: /unconstrained
    method: GET
    per_actor_class:
      likely_human: { decision: allow }
`);
    const browserHeaders = { "user-agent": "Mozilla/5.0 Chrome", accept: "text/html" };
    const throwingStore: TokenBucketStore = {
      take() {
        throw new Error("purpose denied requests must not consume token buckets");
      }
    };
    const throwingAsyncStore: AsyncTokenBucketStore = {
      async take() {
        throw new Error("purpose denied requests must not consume async token buckets");
      }
    };

    expect(
      evaluateRequest(
        { method: "GET", url: "/purpose", headers: browserHeaders },
        {
          siteId: "sit_policy_sdk",
          apiKey: "key",
          policy: { trie: purposePolicy.trie, tokenBucketStore: throwingStore }
        }
      )
    ).toMatchObject({
      decision: "deny",
      recommendedDecision: "deny",
      reasons: ["purpose_required"],
      observeOnly: false
    });

    await expect(
      evaluateRequestAsync(
        { method: "GET", url: "/purpose", headers: { ...browserHeaders, "x-aidenid-purpose": "not_allowed" } },
        {
          siteId: "sit_policy_sdk",
          apiKey: "key",
          policy: { trie: purposePolicy.trie, asyncTokenBucketStore: throwingAsyncStore }
        }
      )
    ).resolves.toMatchObject({
      decision: "deny",
      recommendedDecision: "deny",
      reasons: ["purpose_disallowed"],
      observeOnly: false
    });

    expect(
      evaluateRequest(
        { method: "GET", url: "/purpose", headers: { ...browserHeaders, "x-aidenid-purpose": "Benefits_Lookup" } },
        {
          siteId: "sit_policy_sdk",
          apiKey: "key",
          policy: { trie: purposePolicy.trie, tokenBucketStore: new MemoryTokenBucketStore() }
        }
      )
    ).toMatchObject({ decision: "allow", reasons: ["matched_policy"] });

    expect(
      evaluateRequest(
        { method: "GET", url: "/purpose", headers: { ...browserHeaders, "x-aidenid-purpose": "research" } },
        {
          siteId: "sit_policy_sdk",
          apiKey: "key",
          policy: { trie: purposePolicy.trie, tokenBucketStore: new MemoryTokenBucketStore() }
        }
      )
    ).toMatchObject({
      decision: "allow",
      purpose: "research",
      responseHeaders: expect.objectContaining({ "X-AIdenID-Purpose": "research" })
    });

    expect(
      evaluateRequest(
        { method: "GET", url: "/purpose", headers: { ...browserHeaders, "x-aidenid-purpose": "bad value" } },
        {
          siteId: "sit_policy_sdk",
          apiKey: "key",
          policy: { trie: purposePolicy.trie, tokenBucketStore: throwingStore }
        }
      )
    ).toMatchObject({ decision: "deny", reasons: ["purpose_required"] });

    expect(
      evaluateRequest(
        { method: "GET", url: "/unconstrained", headers: { ...browserHeaders, "x-aidenid-purpose": "bad value" } },
        {
          siteId: "sit_policy_sdk",
          apiKey: "key",
          policy: { trie: purposePolicy.trie, tokenBucketStore: new MemoryTokenBucketStore() }
        }
      )
    ).toMatchObject({ decision: "allow", reasons: ["matched_policy"] });
  });
});
