import { performance } from "node:perf_hooks";

import { describe, expect, it } from "vitest";

import { evaluateRequest } from "../src/index.js";

describe("verifier hot-path latency", () => {
  it("keeps deterministic decision overhead below 2ms p99", () => {
    const samples: number[] = [];
    for (let i = 0; i < 10_000; i += 1) {
      const started = performance.now();
      evaluateRequest(
        {
          method: "GET",
          url: `/checkout/${i}`,
          headers: { signature: "sig", "x-request-id": `req_${i}` }
        },
        { siteId: "sit_123", apiKey: "key" }
      );
      samples.push((performance.now() - started) * 1000);
    }

    samples.sort((a, b) => a - b);
    const p99 = samples[Math.floor(samples.length * 0.99)] ?? Number.POSITIVE_INFINITY;
    expect(p99).toBeLessThan(2000);
  });
});
