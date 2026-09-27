import { afterEach, describe, expect, it, vi } from "vitest";

import {
  dashboardAuthTimeoutMs,
  fetchDashboardAuthJson,
} from "../src/auth/upstreamFetch.js";

function stalledJsonResponse(): Response {
  return new Response(
    new ReadableStream<Uint8Array>({
      start() {
        // Headers are available, but the response body never produces data.
      },
    }),
    { headers: { "Content-Type": "application/json" } },
  );
}

afterEach(() => {
  vi.useRealTimers();
});

describe("dashboard auth upstream fetch", () => {
  it("owns redirect policy and parses a bounded JSON response", async () => {
    let capturedInit: RequestInit | undefined;
    const response = await fetchDashboardAuthJson(
      "https://api.sentinelayer.com/api/v1/auth/me",
      {
        headers: { Authorization: "Bearer session-token" },
        fetchImpl: async (_input, init) => {
          capturedInit = init;
          return Response.json({ id: "usr_123" });
        },
        timeoutMs: 500,
      },
    );

    expect(response).toEqual({
      body: { id: "usr_123" },
      ok: true,
      status: 200,
    });
    expect(capturedInit?.redirect).toBe("error");
    expect(capturedInit?.signal).toBeInstanceOf(AbortSignal);
  });

  it("keeps the deadline armed while a post-header body is consumed", async () => {
    vi.useFakeTimers();
    const pending = fetchDashboardAuthJson(
      "https://api.sentinelayer.com/api/v1/auth/me",
      {
        fetchImpl: async () => stalledJsonResponse(),
        timeoutMs: 250,
      },
    );
    const rejection = expect(pending).rejects.toMatchObject({
      name: "TimeoutError",
    });

    await vi.advanceTimersByTimeAsync(250);

    await rejection;
  });

  it("preserves caller cancellation through response body consumption", async () => {
    const caller = new AbortController();
    const reason = new DOMException("caller stopped", "AbortError");
    const pending = fetchDashboardAuthJson(
      "https://api.sentinelayer.com/api/v1/auth/me",
      {
        fetchImpl: async () => stalledJsonResponse(),
        signal: caller.signal,
        timeoutMs: 500,
      },
    );
    const rejection = expect(pending).rejects.toBe(reason);

    caller.abort(reason);

    await rejection;
  });

  it("rejects a chunked JSON body that exceeds the byte limit", async () => {
    await expect(
      fetchDashboardAuthJson("https://api.sentinelayer.com/api/v1/auth/me", {
        fetchImpl: async () => Response.json({ value: "too large" }),
        maxResponseBytes: 8,
        timeoutMs: 500,
      }),
    ).rejects.toThrow("response exceeded the byte limit");
  });

  it("rejects successful non-JSON responses", async () => {
    await expect(
      fetchDashboardAuthJson("https://api.sentinelayer.com/api/v1/auth/me", {
        fetchImpl: async () =>
          new Response("not json", {
            headers: { "Content-Type": "text/plain" },
          }),
        timeoutMs: 500,
      }),
    ).rejects.toThrow("returned non-JSON data");
  });

  it("does not consume an unsuccessful response body", async () => {
    const response = await fetchDashboardAuthJson(
      "https://api.sentinelayer.com/api/v1/auth/me",
      {
        fetchImpl: async () =>
          Response.json({ error: "denied" }, { status: 401 }),
        timeoutMs: 500,
      },
    );

    expect(response).toEqual({ body: undefined, ok: false, status: 401 });
  });

  it("bounds auth timeout configuration", () => {
    expect(dashboardAuthTimeoutMs({})).toBe(5_000);
    expect(
      dashboardAuthTimeoutMs({ AIDENID_DASHBOARD_AUTH_TIMEOUT_MS: "100" }),
    ).toBe(250);
    expect(
      dashboardAuthTimeoutMs({ AIDENID_DASHBOARD_AUTH_TIMEOUT_MS: "1200" }),
    ).toBe(1_200);
    expect(
      dashboardAuthTimeoutMs({ AIDENID_DASHBOARD_AUTH_TIMEOUT_MS: "70000" }),
    ).toBe(30_000);
    expect(
      dashboardAuthTimeoutMs({
        AIDENID_DASHBOARD_AUTH_TIMEOUT_MS: "not-a-number",
      }),
    ).toBe(5_000);
  });
});
