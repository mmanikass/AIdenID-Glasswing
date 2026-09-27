import { describe, expect, it } from "vitest";

import { createLocalFingerprintProvider } from "@aidenid/fingerprint-sidecar";
import { decisionToHttpResponse, evaluateRequest, evaluateRequestAsync } from "../src/index.js";

const options = { siteId: "sit_123", apiKey: "key" };

describe("hot-path decision pipeline", () => {
  it("defaults to observe mode and does not block suspicious traffic", () => {
    const decision = evaluateRequest(
      {
        method: "GET",
        url: "/checkout",
        headers: { "user-agent": "curl/8.0" }
      },
      options
    );

    expect(decision).toMatchObject({
      mode: "observe",
      actorClass: "suspicious_automation",
      decision: "allow",
      recommendedDecision: "throttle",
      observeOnly: true,
      cascadeTrace: [
        { ordinal: 1, layer: "crypto_identity", status: "skipped", reason: "actor_class_not_signed_agent" },
        { ordinal: 2, layer: "delegation_authorization", status: "skipped", reason: "depends_on_crypto_identity" },
        { ordinal: 3, layer: "fingerprint_sidecar", status: "not_configured", reason: "fingerprint_provider_missing" },
        { ordinal: 4, layer: "operator_reputation", status: "not_configured", reason: "operator_reputation_provider_missing" }
      ]
    });
    expect(decisionToHttpResponse(decision).headers["X-AIdenID-Cascade-Trace"]).toBe(
      "crypto_identity=skipped:actor_class_not_signed_agent;delegation_authorization=skipped:depends_on_crypto_identity;fingerprint_sidecar=not_configured:fingerprint_provider_missing;operator_reputation=not_configured:operator_reputation_provider_missing"
    );
  });

  it("enforces recommended decisions outside observe mode", () => {
    expect(
      evaluateRequest(
        {
          method: "GET",
          url: "/checkout",
          headers: { "retry-after": "5" },
          statusCode: 429
        },
        { ...options, mode: "enforce" }
      )
    ).toMatchObject({
      decision: "throttle",
      recommendedDecision: "throttle",
      reasons: ["rate_limited"]
    });
  });

  it("executes the fingerprint sidecar on the async path with stripped credentials and high-risk reclassification", async () => {
    const seenHeaders: Record<string, string> = {};
    const decision = await evaluateRequestAsync(
      {
        method: "GET",
        url: "/checkout",
        headers: {
          "user-agent": "Mozilla/5.0 Chrome",
          accept: "text/html",
        authorization: "credential-should-not-reach-provider",
          cookie: "sid=should-not-reach-provider"
        },
        remoteAddress: "203.0.113.10"
      },
      {
        ...options,
        mode: "enforce",
        fingerprint: {
          provider: {
            async lookup(request) {
              Object.assign(seenHeaders, request.headers);
              return {
                provider: "demo-fingerprint",
                deviceId: "fp_device_123",
                botScore: 0.96,
                suspicionDelta: 0.9,
                evidence: ["fingerprint-provider-match"]
              };
            }
          }
        }
      }
    );

    expect(seenHeaders).not.toHaveProperty("authorization");
    expect(seenHeaders).not.toHaveProperty("cookie");
    expect(decision).toMatchObject({
      actorClass: "suspicious_automation",
      decision: "throttle",
      recommendedDecision: "throttle",
      reasons: ["fingerprint_risk"],
      cascadeTrace: [
        { ordinal: 1, layer: "crypto_identity", status: "skipped" },
        { ordinal: 2, layer: "delegation_authorization", status: "skipped" },
        {
          ordinal: 3,
          layer: "fingerprint_sidecar",
          status: "fail",
          reason: "fingerprint_risk",
          evidence: expect.arrayContaining(["provider:demo-fingerprint", "device_id:fp_device_123", "bot_score:0.960"])
        },
        { ordinal: 4, layer: "operator_reputation", status: "not_configured" }
      ]
    });
  });

  it("reclassifies the white-box Playwright scraper profile through L3 fingerprint evidence", async () => {
    await expect(
      evaluateRequestAsync(
        {
          method: "GET",
          url: "/search?q=Python%20programming%20language",
          headers: {
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            accept: "text/html"
          },
          remoteAddress: "198.51.100.42"
        },
        {
          ...options,
          mode: "enforce",
          fingerprint: {
            providerId: "demo-local-fingerprint",
            provider: createLocalFingerprintProvider()
          }
        }
      )
    ).resolves.toMatchObject({
      actorClass: "suspicious_automation",
      decision: "throttle",
      recommendedDecision: "throttle",
      reasons: ["fingerprint_risk"],
      cascadeTrace: expect.arrayContaining([
        expect.objectContaining({
          ordinal: 3,
          layer: "fingerprint_sidecar",
          status: "fail",
          reason: "fingerprint_risk",
          evidence: expect.arrayContaining([
            "provider:demo-local-fingerprint",
            "scraper-profile-static-playwright-ua",
            "chromium-ua-truncated"
          ])
        })
      ])
    });
  });

  it("propagates known crawler identity hints from L3 into decision records and L4 reputation", async () => {
    const reputationLookups: string[] = [];
    const decision = await evaluateRequestAsync(
      {
        method: "GET",
        url: "/docs/quickstart",
        headers: {
          "user-agent": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot",
          accept: "text/html"
        },
        remoteAddress: "198.51.100.25"
      },
      {
        ...options,
        mode: "enforce",
        fingerprint: {
          providerId: "demo-local-fingerprint",
          provider: createLocalFingerprintProvider()
        },
        operatorReputation: {
          providerId: "demo-static-operator-reputation",
          provider: {
            async lookup(input: { readonly llmBrand?: string | undefined }) {
              reputationLookups.push(input.llmBrand ?? "");
              if (input.llmBrand !== "openai") {
                return undefined;
              }
              return {
                operatorActorId: "operator:openai",
                trustTier: "trusted" as const,
                status: "active" as const,
                reputationScore: 92,
                evidence: ["stable_user_agent_history"]
              };
            }
          }
        }
      }
    );

    expect(reputationLookups).toEqual(["openai"]);
    expect(decision).toMatchObject({
      actorClass: "suspicious_automation",
      llmBrand: "openai",
      decision: "throttle",
      recommendedDecision: "throttle",
      reasons: ["fingerprint_risk"]
    });
    expect(decision.cascadeTrace).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          ordinal: 3,
          layer: "fingerprint_sidecar",
          status: "fail",
          reason: "fingerprint_risk",
          evidence: expect.arrayContaining(["ua-match-chatgpt-user", "operator-actor-id-hint-openai"])
        }),
        expect.objectContaining({
          ordinal: 4,
          layer: "operator_reputation",
          status: "pass",
          reason: "operator_reputation_active",
          evidence: expect.arrayContaining(["operator_actor_id:operator:openai", "reputation_score:92"])
        })
      ])
    );
  });

  it("fails loudly when a sync verifier call is configured with the async fingerprint sidecar", () => {
    expect(() =>
      evaluateRequest(
        {
          method: "GET",
          url: "/checkout",
          headers: { "user-agent": "Mozilla/5.0 Chrome", accept: "text/html" }
        },
        {
          ...options,
          fingerprint: {
            provider: {
              async lookup() {
                return { provider: "demo-fingerprint", botScore: 0.1 };
              }
            }
          }
        }
      )
    ).toThrow(/fingerprint provider/);
  });
});
