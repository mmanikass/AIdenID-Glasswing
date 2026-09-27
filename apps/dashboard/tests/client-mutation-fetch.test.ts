import { describe, expect, it } from "vitest";

import {
  DASHBOARD_CLIENT_MUTATION_TIMEOUT_MS,
  fetchWithDashboardMutationTimeout,
} from "../src/clientMutationFetch.js";

function replaceFetch(implementation: typeof fetch): () => void {
  const previous = globalThis.fetch;
  globalThis.fetch = implementation;
  return () => {
    globalThis.fetch = previous;
  };
}

describe("dashboard client mutation fetch", () => {
  it("attaches an AbortSignal to client-side mutation requests", async () => {
    const calls: RequestInit[] = [];
    const restoreFetch = replaceFetch(
      async (_input: Parameters<typeof fetch>[0], init?: RequestInit) => {
        calls.push(init ?? {});
        return Response.json({ ok: true });
      },
    );
    try {
      const response = await fetchWithDashboardMutationTimeout(
        "https://dashboard.example.com/api/operators/reputation/op_1",
        {
          method: "PUT",
          body: JSON.stringify({ trust_tier: "trusted" }),
        },
      );

      expect(response.ok).toBe(true);
      expect(calls[0]?.signal).toBeInstanceOf(AbortSignal);
    } finally {
      restoreFetch();
    }
  });

  it("surfaces bounded timeout failures with an operator-readable error", async () => {
    const restoreFetch = replaceFetch(async () => {
      throw new DOMException("aborted", "AbortError");
    });
    try {
      await expect(
        fetchWithDashboardMutationTimeout(
          "https://dashboard.example.com/api/identity-challenges/sub_1/review",
          { method: "POST" },
          25,
        ),
      ).rejects.toThrow("Dashboard request timed out after 25ms.");
      expect(DASHBOARD_CLIENT_MUTATION_TIMEOUT_MS).toBe(10_000);
    } finally {
      restoreFetch();
    }
  });
});
