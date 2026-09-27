import { describe, expect, it } from "vitest";

import { ingestUpstreamRateLimit } from "../src/index.js";

describe("upstream rate-limit ingestion", () => {
  it("marks 429 traffic throttled and preserves retry-after seconds", () => {
    expect(ingestUpstreamRateLimit({ "retry-after": "30" }, 429, new Date("2026-04-24T00:00:00Z"))).toMatchObject({
      status: "throttled",
      retryAfterSeconds: 30
    });
  });

  it("warns on near-empty remaining budgets", () => {
    expect(ingestUpstreamRateLimit({ "x-ratelimit-remaining": "2" }, 200, new Date())).toMatchObject({
      status: "warning",
      remaining: 2
    });
  });
});
