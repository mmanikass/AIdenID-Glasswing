import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { decisionToHttpResponse, evaluateRequest } from "../src/index.js";

const testDir = path.dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(readFileSync(path.join(testDir, "fixtures", "cross-language-vectors.json"), "utf8")) as Array<{
  readonly name: string;
  readonly input: {
    readonly method: string;
    readonly url: string;
    readonly statusCode?: number;
    readonly headers?: Record<string, string>;
  };
  readonly options: {
    readonly siteId: string;
    readonly apiKey: string;
    readonly mode?: "observe" | "recommend" | "enforce";
    readonly rollback?: {
      readonly globalEnforcementPause?: boolean;
      readonly routeModeOverrides?: Record<string, "observe" | "recommend" | "enforce">;
    };
  };
  readonly expected: {
    readonly requestId: string;
    readonly actorClass: string;
    readonly decision: string;
    readonly recommendedDecision: string;
    readonly path: string;
    readonly routeTemplate: string;
    readonly observeOnly: boolean;
    readonly rateLimitStatus: string;
    readonly retryAfterSeconds?: number;
    readonly httpStatus: number;
  };
}>;

describe("cross-language verifier vectors", () => {
  for (const vector of vectors) {
    it(vector.name, () => {
      const decision = evaluateRequest(vector.input, {
        ...vector.options,
        now: () => new Date("2026-04-24T14:00:00.000Z")
      });
      const response = decisionToHttpResponse(decision);
      const expectedRateLimit = {
        status: vector.expected.rateLimitStatus,
        ...(vector.expected.retryAfterSeconds === undefined ? {} : { retryAfterSeconds: vector.expected.retryAfterSeconds })
      };

      expect(decision).toMatchObject({
        requestId: vector.expected.requestId,
        actorClass: vector.expected.actorClass,
        decision: vector.expected.decision,
        recommendedDecision: vector.expected.recommendedDecision,
        path: vector.expected.path,
        routeTemplate: vector.expected.routeTemplate,
        observeOnly: vector.expected.observeOnly,
        rateLimit: expectedRateLimit
      });
      expect(response.status).toBe(vector.expected.httpStatus);
    });
  }
});
