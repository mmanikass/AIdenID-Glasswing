import { describe, expect, it, vi } from "vitest";

import {
  getFingerprintEvidence,
  sanitizeFingerprintRequest,
  type FingerprintProviderResult,
  type FingerprintEvidenceProvider,
  type SanitizedFingerprintRequest
} from "../src/index.js";

describe("fingerprint sidecar", () => {
  it("stays disabled by default and does not call a provider", async () => {
    const provider: FingerprintEvidenceProvider = {
      lookup: vi.fn(async () => ({ provider: "should_not_run" }))
    };

    await expect(
      getFingerprintEvidence({ method: "GET", url: "https://example.test" }, { enabled: false, provider })
    ).resolves.toMatchObject({
      enabled: false,
      available: false,
      suspicionDelta: 0,
      evidence: ["fingerprint-sidecar-disabled"]
    });
    expect(provider.lookup).not.toHaveBeenCalled();
  });

  it("strips credential-bearing headers before provider lookup", async () => {
    const seen: SanitizedFingerprintRequest[] = [];
    const provider: FingerprintEvidenceProvider = {
      async lookup(request) {
        seen.push(request);
        return {
          provider: "datadome",
          deviceId: "dev_123",
          botScore: 0.8,
          suspicionDelta: 0.4,
          operatorActorIdHint: "operator:openai",
          llmBrandHint: "openai",
          evidence: ["fingerprint-provider-match"]
        };
      }
    };
    let index = 0;
    const times = [100, 142];

    const result = await getFingerprintEvidence(
      {
        method: "post",
        url: "https://site.example/checkout",
        remoteAddress: "203.0.113.10",
        routeTemplate: "/checkout",
        headers: {
          authorization: "Bearer secret",
          cookie: "sid=secret",
          dpop: "proof",
          signature: "sig1=:abc:",
          "signature-input": "sig1=()",
          "x-api-key": "secret",
          "x-amz-security-token": "secret",
          "user-agent": "Mozilla/5.0",
          "accept-language": "en-US",
          "sec-fetch-site": "same-origin"
        }
      },
      { provider, timeoutMs: 50, now: () => times[index++] ?? 142 }
    );

    expect(result).toMatchObject({
      enabled: true,
      available: true,
      timedOut: false,
      provider: "datadome",
      deviceId: "dev_123",
      botScore: 0.8,
      suspicionDelta: 0.4,
      operatorActorIdHint: "operator:openai",
      llmBrandHint: "openai",
      providerLatencyMs: 42,
      evidence: ["fingerprint-provider-match"]
    });
    expect(seen).toHaveLength(1);
    expect(seen[0]).toMatchObject({
      method: "POST",
      url: "https://site.example/checkout",
      remoteAddress: "203.0.113.10",
      routeTemplate: "/checkout",
      headers: {
        "user-agent": "Mozilla/5.0",
        "accept-language": "en-US",
        "sec-fetch-site": "same-origin"
      }
    });
    expect(seen[0]?.headers).not.toHaveProperty("authorization");
    expect(seen[0]?.headers).not.toHaveProperty("cookie");
    expect(seen[0]?.headers).not.toHaveProperty("x-api-key");
    expect(seen[0]?.headers).not.toHaveProperty("x-amz-security-token");
    expect(seen[0]?.headers).not.toHaveProperty("dpop");
    expect(seen[0]?.headers).not.toHaveProperty("signature");
    expect(seen[0]?.headers).not.toHaveProperty("signature-input");
  });

  it("fails open to no evidence when provider lookup times out", async () => {
    vi.useFakeTimers();
    try {
      const provider: FingerprintEvidenceProvider = {
        lookup: vi.fn(
          (_request, signal) =>
            new Promise<FingerprintProviderResult>((resolve) => {
              signal.addEventListener(
                "abort",
                () => {
                  resolve({ provider: "late_provider", suspicionDelta: 1 });
                },
                { once: true }
              );
            })
        )
      };

      const pending = getFingerprintEvidence({ method: "GET", url: "https://example.test" }, { provider, timeoutMs: 25 });
      await vi.advanceTimersByTimeAsync(25);

      await expect(pending).resolves.toMatchObject({
        enabled: true,
        available: false,
        timedOut: true,
        suspicionDelta: 0,
        evidence: ["fingerprint-timeout-bypassed"],
        error: "timeout"
      });
    } finally {
      vi.useRealTimers();
    }
  });

  it("fails open on invalid provider risk values", async () => {
    const result = await getFingerprintEvidence(
      { method: "GET", url: "https://example.test" },
      {
        provider: {
          async lookup() {
            return { provider: "bad_provider", suspicionDelta: 1.5 };
          }
        }
      }
    );

    expect(result).toMatchObject({
      available: false,
      suspicionDelta: 0,
      error: "invalid_provider_result",
      evidence: ["fingerprint-invalid-result-bypassed"]
    });
  });

  it("sanitizes Headers-like readers", () => {
    const request = sanitizeFingerprintRequest({
      method: "GET",
      url: "https://example.test",
      headers: new Headers({
        authorization: "Bearer secret",
        "user-agent": "Mozilla/5.0",
        "accept-language": "en-US"
      })
    });

    expect(request.headers).toEqual({
      "accept-language": "en-US",
      "user-agent": "Mozilla/5.0"
    });
  });
});
