import { describe, expect, it } from "vitest";

import {
  DECISION_LADDER,
  MemoryTokenBucketStore,
  RedisTokenBucketStore,
  applyRatePolicy,
  applyRatePolicyAsync,
  compilePolicyDocument,
  evaluateDecision,
  parsePolicyYaml,
  policyPreset,
  resolveDecision,
  type RedisTokenBucketScriptRunner,
  type RouteRule,
  type TokenBucketStore
} from "../src/index.js";

const policyYaml = `
version: 1
site_id: sit_test
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
      unknown: { decision: allow }

  - template: /checkout
    method: POST
    strict: true
    route_bucket: checkout
    rate: { capacity: 1, refill_per_sec: 0.1, cost: 1 }
    per_actor_class:
      verified_agent: { decision: allow }
      signed_agent: { decision: queue, queue_retry_s: 30 }
      likely_human: { decision: allow }
      suspicious_automation: { decision: deny }
      unknown: { decision: throttle, retry_after_s: 10 }

  - template: /premium-content/*
    method: GET
    per_actor_class:
      verified_agent: { decision: price_required, price_usd: 0.01 }
      signed_agent: { decision: queue, queue_retry_s: 10 }
      likely_human: { decision: allow }
      unknown: { decision: deny }

  - template: /api/:endpoint
    method: POST
    per_actor_class:
      suspicious_automation: { decision: sandbox, sandbox_origin: https://sandbox.example.com }
      likely_human: { decision: allow }
`;

describe("policy engine", () => {
  it("keeps the six-outcome ladder exported", () => {
    expect(DECISION_LADDER).toEqual(["allow", "throttle", "queue", "sandbox", "deny", "price_required"]);
  });

  it("observes all six decisions from a policy-driven path", () => {
    const loaded = parsePolicyYaml(policyYaml);

    const scenarios = [
      { method: "GET", path: "/open", actorClass: "likely_human", expected: "allow" },
      { method: "POST", path: "/checkout", actorClass: "unknown", expected: "throttle" },
      { method: "POST", path: "/checkout", actorClass: "signed_agent", expected: "queue" },
      { method: "POST", path: "/api/comment", actorClass: "suspicious_automation", expected: "sandbox" },
      { method: "POST", path: "/checkout", actorClass: "suspicious_automation", expected: "deny" },
      { method: "GET", path: "/premium-content/story", actorClass: "verified_agent", expected: "price_required" }
    ] as const;

    for (const scenario of scenarios) {
      const match = loaded.trie.match(scenario.method, scenario.path, scenario.actorClass);
      const evaluation = evaluateDecision({ match, actorClass: scenario.actorClass, retryToken: "retry_test" });
      expect(evaluation.action, scenario.expected).toBe(scenario.expected);
      if (scenario.expected === "price_required") {
        expect(evaluation.headers["X-AIdenID-Price-USD"]).toBe("0.01");
        expect(JSON.parse(evaluation.headers["X-AIdenID-Price-Metadata"] ?? "")).toEqual({
          unit: "request",
          currency: "USD",
          amount_micros: 10_000
        });
      }
    }
  });

  it("accepts explicit price metadata and derives the USD header", () => {
    const loaded = parsePolicyYaml(`
version: 1
site_id: sit_test
mode: enforce
defaults: { strict: false, on_degraded: queue, rate: { capacity: 10, refill_per_sec: 1, cost: 1 } }
routes:
  - template: /premium
    method: GET
    per_actor_class:
      verified_agent:
        decision: price_required
        price_metadata: { unit: page_view, currency: USD, amount_micros: 25000 }
`);

    const match = loaded.trie.match("GET", "/premium", "verified_agent");
    const evaluation = evaluateDecision({ match, actorClass: "verified_agent" });

    expect(evaluation.action).toBe("price_required");
    expect(evaluation.headers["X-AIdenID-Price-USD"]).toBe("0.025");
    expect(JSON.parse(evaluation.headers["X-AIdenID-Price-Metadata"] ?? "")).toEqual({
      unit: "page_view",
      currency: "USD",
      amount_micros: 25_000
    });
  });

  it("uses static before param before wildcard route matches", () => {
    const loaded = parsePolicyYaml(`
version: 1
site_id: sit_test
mode: enforce
defaults: { strict: false, on_degraded: queue, rate: { capacity: 10, refill_per_sec: 1, cost: 1 } }
routes:
  - template: /api/*
    method: GET
    per_actor_class:
      unknown: { decision: queue }
  - template: /api/:endpoint
    method: GET
    per_actor_class:
      unknown: { decision: throttle }
  - template: /api/status
    method: GET
    per_actor_class:
      unknown: { decision: allow }
`);

    const staticMatch = loaded.trie.match("GET", "/api/status", "unknown");
    const paramMatch = loaded.trie.match("GET", "/api/users", "unknown");

    expect(staticMatch.routeTemplate).toBe("/api/status");
    expect(paramMatch.routeTemplate).toBe("/api/:endpoint");
  });

  it("compiles route-level purpose constraints from policy YAML", () => {
    const loaded = parsePolicyYaml(`
version: 1
site_id: sit_test
mode: enforce
defaults: { strict: false, on_degraded: queue, rate: { capacity: 10, refill_per_sec: 1, cost: 1 } }
routes:
  - template: /claims
    method: POST
    allowed_purposes: [benefits_lookup, care-review]
    per_actor_class:
      verified_agent: { decision: allow }
`);

    const match = loaded.trie.match("POST", "/claims", "verified_agent");
    expect(match.routePolicy.allowedPurposes).toEqual(["benefits_lookup", "care-review"]);
    expect(() =>
      parsePolicyYaml(`
version: 1
site_id: sit_test
mode: enforce
defaults: { strict: false, on_degraded: queue, rate: { capacity: 10, refill_per_sec: 1, cost: 1 } }
routes:
  - template: /claims
    method: POST
    allowed_purposes: [BenefitsLookup]
    per_actor_class:
      verified_agent: { decision: allow }
`)
    ).toThrow();
  });

  it("compiles route-level required permission scopes from policy YAML", () => {
    const loaded = parsePolicyYaml(`
version: 1
site_id: sit_test
mode: enforce
defaults: { strict: false, on_degraded: queue, rate: { capacity: 10, refill_per_sec: 1, cost: 1 } }
routes:
  - template: /checkout
    method: POST
    required_permissions: [checkout:create, orders:read]
    per_actor_class:
      verified_agent: { decision: allow }
`);

    const match = loaded.trie.match("POST", "/checkout", "verified_agent");
    expect(match.routePolicy.requiredPermissions).toEqual(["checkout:create", "orders:read"]);
    expect(() =>
      parsePolicyYaml(`
version: 1
site_id: sit_test
mode: enforce
defaults: { strict: false, on_degraded: queue, rate: { capacity: 10, refill_per_sec: 1, cost: 1 } }
routes:
  - template: /checkout
    method: POST
    required_permissions: []
    per_actor_class:
      verified_agent: { decision: allow }
`)
    ).toThrow();
  });

  it("applies deny bias while preserving observe and recommend pass-through", () => {
    const rules: RouteRule[] = [
      { methodPattern: "*", routeTemplate: "/admin/*", actorClass: "*", behavior: "deny", ruleId: "deny-admin" },
      { methodPattern: "GET", routeTemplate: "/admin/users", actorClass: "verified_agent", behavior: "allow", ruleId: "allow-users" }
    ];

    expect(resolveDecision(rules, "GET", "/admin/users", "verified_agent", "enforce")).toMatchObject({
      decision: "deny",
      recommendedDecision: "deny",
      ruleId: "deny-admin"
    });
    expect(resolveDecision(rules, "GET", "/admin/users", "verified_agent", "observe")).toMatchObject({
      decision: "allow",
      recommendedDecision: "deny",
      observedOnly: true
    });
  });

  it("enforces token buckets and reports strict degraded state", () => {
    const store = new MemoryTokenBucketStore();
    const policy = { capacity: 1, refillPerSec: 0.1, cost: 1 };
    const first = applyRatePolicy({
      siteId: "sit_test",
      routeBucket: "checkout",
      policy,
      strict: true,
      onDegraded: "queue",
      store,
      remoteIp: "203.0.113.10",
      nowMs: 1_000
    });
    const second = applyRatePolicy({
      siteId: "sit_test",
      routeBucket: "checkout",
      policy,
      strict: true,
      onDegraded: "queue",
      store,
      remoteIp: "203.0.113.10",
      nowMs: 1_100
    });

    expect(first.allow).toBe(true);
    expect(second).toMatchObject({ allow: false, retryAfterSeconds: 10 });

    const failingStore: TokenBucketStore = {
      take: () => {
        throw new Error("redis unavailable");
      }
    };

    expect(
      applyRatePolicy({
        siteId: "sit_test",
        routeBucket: "checkout",
        policy,
        strict: true,
        onDegraded: "queue",
        store: failingStore,
        remoteIp: "203.0.113.10"
      })
    ).toMatchObject({ allow: false, degraded: "redis_down" });
  });

  it("uses Redis Lua token buckets through the async rate-policy path", async () => {
    const calls: Array<{ readonly script: string; readonly keys: readonly string[]; readonly arguments: readonly string[] }> = [];
    const scriptRunner: RedisTokenBucketScriptRunner = {
      async run(script, options) {
        calls.push({ script, keys: options.keys, arguments: options.arguments });
        return calls.length === 1 ? [1, 0] : [0, 0];
      }
    };
    const store = new RedisTokenBucketStore(scriptRunner, { keyPrefix: "test:" });
    const policy = { capacity: 1, refillPerSec: 0.1, cost: 1 };
    const request = {
      siteId: "sit_test",
      routeBucket: "checkout",
      policy,
      strict: true,
      onDegraded: "queue" as const,
      store,
      remoteIp: "203.0.113.10",
      nowMs: 1_000
    };

    await expect(applyRatePolicyAsync(request)).resolves.toMatchObject({ allow: true, remaining: 0 });
    await expect(applyRatePolicyAsync({ ...request, nowMs: 1_100 })).resolves.toMatchObject({
      allow: false,
      retryAfterSeconds: 10
    });
    expect(calls[0]?.keys[0]).toMatch(/^test:bkt:sit_test:ip:/);
    expect(calls[0]?.arguments).toEqual(["1000", "1", "0.1", "1"]);
    expect(calls[0]?.script).toContain("redis.call('HMGET'");
  });

  it("loads Redis token bucket Lua once and then uses EVALSHA", async () => {
    const calls: string[] = [];
    const scriptRunner: RedisTokenBucketScriptRunner = {
      async load(script) {
        calls.push(`load:${script.slice(0, 12)}`);
        return "sha-token-bucket";
      },
      async runSha(_sha, options) {
        calls.push(`sha:${options.keys[0] ?? ""}`);
        return calls.length === 2 ? [1, 0] : [0, 0];
      },
      async run() {
        throw new Error("EVAL fallback should not run when EVALSHA is available");
      }
    };
    const store = new RedisTokenBucketStore(scriptRunner, { keyPrefix: "test:" });
    const policy = { capacity: 1, refillPerSec: 0.1, cost: 1 };
    const request = {
      siteId: "sit_test",
      routeBucket: "checkout",
      policy,
      strict: true,
      onDegraded: "queue" as const,
      store,
      remoteIp: "203.0.113.10",
      nowMs: 1_000
    };

    await expect(applyRatePolicyAsync(request)).resolves.toMatchObject({ allow: true, remaining: 0 });
    await expect(applyRatePolicyAsync({ ...request, nowMs: 1_100 })).resolves.toMatchObject({ allow: false });
    expect(calls).toEqual([
      "load:local b = re",
      expect.stringMatching(/^sha:test:bkt:sit_test:ip:/),
      expect.stringMatching(/^sha:test:bkt:sit_test:ip:/)
    ]);
  });

  it("ships all named presets through the validator", () => {
    for (const name of ["starter", "strict_auth", "content_site", "marketplace"] as const) {
      const compiled = compilePolicyDocument(policyPreset(name));
      expect(compiled.siteId).toContain("sit_");
      expect(compiled.routes.length).toBeGreaterThan(0);
    }
  });
});
