import { generateKeyPairSync, sign as nodeSign } from "node:crypto";

import {
  base64Url,
  buildSignatureBase,
  canonicalJwkThumbprintBase64Url,
  parseSignatureInput,
  signCompactJws
} from "@aidenid/crypto";
import { createLocalFingerprintProvider } from "@aidenid/fingerprint-sidecar";
import { parsePolicyYaml } from "@aidenid/policy-engine";
import { describe, expect, it } from "vitest";

import {
  evaluateAndEmit,
  evaluateRequest,
  evaluateRequestAsync,
  MemoryQuarantinePinCache,
  type DecisionAction,
  type AidenIdVerifierOptions
} from "../src/index.js";

const DECISION_ACTIONS: readonly DecisionAction[] = ["allow", "throttle", "queue", "sandbox", "deny", "price_required"];

function buildVerifiedRequestFixture(
  input: {
    readonly llmBrand?: string | undefined;
    readonly grantId?: string | undefined;
    readonly chainId?: string | undefined;
    readonly permissions?: readonly string[] | undefined;
    readonly nonce?: string | undefined;
    readonly jti?: string | undefined;
  } = {}
) {
  const issuerKeys = generateKeyPairSync("ed25519");
  const dpopKeys = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const httpKeys = generateKeyPairSync("ed25519");
  const dpopPublicJwk = dpopKeys.publicKey.export({ format: "jwk" });
  const proofJkt = canonicalJwkThumbprintBase64Url(dpopPublicJwk);
  const nowSeconds = 1_776_000_000;
  const resource = "https://site.example.com/checkout";
  const sessionToken = signCompactJws(
    {
      iss: "https://issuer.example.com",
      sub: "sub_123",
      aud: "sit_abc",
      site_id: "sit_abc",
      resource,
      grant_id: input.grantId ?? "grt_checkout",
      chain_id: input.chainId ?? "chn_checkout",
      permissions: [...(input.permissions ?? ["checkout:create"])],
      cnf: { jkt: proofJkt },
      revocation_epoch: 9,
      ...(input.llmBrand === undefined ? {} : { llm_brand: input.llmBrand }),
      iat: nowSeconds - 5,
      exp: nowSeconds + 300
    },
    issuerKeys.privateKey,
    "EdDSA",
    { kid: "issuer-key-1" }
  );
  const dpopProof = signCompactJws(
    {
      htm: "GET",
      htu: resource,
      jti: input.jti ?? "jti_123",
      iat: nowSeconds
    },
    dpopKeys.privateKey,
    "ES256",
    { typ: "dpop+jwt", jwk: dpopPublicJwk }
  );
  const authorization = `DPoP ${sessionToken}`;
  const signatureInput = `sig1=("@method" "@path" "authorization" "dpop");created=${nowSeconds};expires=${
    nowSeconds + 300
  };keyid="agent-key-1";alg="ed25519";nonce="${input.nonce ?? "nonce_123"}"`;
  const baseRequest = {
    method: "GET",
    url: resource,
    headers: {
      authorization,
      dpop: dpopProof,
      "signature-input": signatureInput
    }
  };
  const signatureBase = buildSignatureBase(baseRequest, parseSignatureInput(signatureInput));
  const signature = nodeSign(null, Buffer.from(signatureBase, "utf8"), httpKeys.privateKey);
  const options: AidenIdVerifierOptions = {
    siteId: "sit_abc",
    apiKey: "key",
    mode: "enforce",
    now: () => new Date(nowSeconds * 1000),
    crypto: {
      sessionTokenPublicJwksByIssuer: {
        "https://issuer.example.com": issuerKeys.publicKey.export({ format: "jwk" })
      },
      httpMessageSignaturePublicJwksByKeyId: {
        "agent-key-1": httpKeys.publicKey.export({ format: "jwk" })
      },
      minRevocationEpoch: 9
    }
  };

  return {
    request: {
      ...baseRequest,
      headers: {
        ...baseRequest.headers,
        signature: `sig1=:${base64Url(signature)}:`
      }
    },
    options
  };
}

describe("verifier crypto path", () => {
  it("upgrades signed traffic to verified_agent when HTTP signature, DPoP, and session token all verify", () => {
    const fixture = buildVerifiedRequestFixture();
    const decision = evaluateRequest(fixture.request, fixture.options);

    expect(decision).toMatchObject({
      actorClass: "verified_agent",
      decision: "allow",
      recommendedDecision: "allow",
      reasons: ["matched_policy"],
      cascadeTrace: [
        { ordinal: 1, layer: "crypto_identity", status: "pass", reason: "http_signature_dpop_verified" },
        { ordinal: 2, layer: "delegation_authorization", status: "pass", reason: "proof_bound_session_verified" },
        { ordinal: 3, layer: "fingerprint_sidecar", status: "not_configured", reason: "fingerprint_provider_missing" },
        { ordinal: 4, layer: "operator_reputation", status: "not_configured", reason: "operator_reputation_provider_missing" }
      ]
    });
    expect(decision.cascadeTrace?.[1]?.evidence).toEqual(
      expect.arrayContaining(["grant_id:grt_checkout", "chain_id:chn_checkout", "scope_match:true", "permission:checkout:create"])
    );
  });

  it("surfaces optional LLM brand metadata from verified session tokens without changing policy", () => {
    const fixture = buildVerifiedRequestFixture({ llmBrand: "openai" });

    expect(evaluateRequest(fixture.request, fixture.options)).toMatchObject({
      actorClass: "verified_agent",
      llmBrand: "openai",
      decision: "allow",
      recommendedDecision: "allow",
      reasons: ["matched_policy"]
    });
  });

  it("does not let user-agent fingerprint hints override a crypto-bound LLM brand", async () => {
    const fixture = buildVerifiedRequestFixture({ llmBrand: "anthropic" });
    const reputationLookups: string[] = [];

    const decision = await evaluateRequestAsync(
      {
        ...fixture.request,
        headers: {
          ...fixture.request.headers,
          "user-agent": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot"
        }
      },
      {
        ...fixture.options,
        fingerprint: {
          providerId: "demo-local-fingerprint",
          provider: createLocalFingerprintProvider()
        },
        operatorReputation: {
          providerId: "rep-capture",
          provider: {
            async lookup(input: { readonly llmBrand?: string | undefined }) {
              reputationLookups.push(input.llmBrand ?? "");
              return undefined;
            }
          }
        }
      }
    );

    expect(decision).toMatchObject({
      actorClass: "verified_agent",
      llmBrand: "anthropic",
      decision: "allow"
    });
    expect(reputationLookups).toEqual(["anthropic"]);
    expect(decision.cascadeTrace).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          ordinal: 3,
          layer: "fingerprint_sidecar",
          evidence: expect.arrayContaining(["ua-match-chatgpt-user"])
        })
      ])
    );
  });

  it("records route permission scope matches from signed session claims without a grant lookup", () => {
    const fixture = buildVerifiedRequestFixture({ permissions: ["checkout:create", "orders:read"] });
    const policy = parsePolicyYaml(`
version: 1
site_id: sit_abc
mode: enforce
defaults:
  strict: true
  on_degraded: deny
  rate: { capacity: 100, refill_per_sec: 10, cost: 1 }
routes:
  - template: /checkout
    method: GET
    required_permissions: [checkout:create]
    per_actor_class:
      verified_agent: { decision: allow }
`);

    expect(
      evaluateRequest(fixture.request, {
        ...fixture.options,
        policy: { trie: policy.trie }
      })
    ).toMatchObject({
      actorClass: "verified_agent",
      decision: "allow",
      cascadeTrace: [
        { ordinal: 1, layer: "crypto_identity", status: "pass", reason: "http_signature_dpop_verified" },
        {
          ordinal: 2,
          layer: "delegation_authorization",
          status: "pass",
          reason: "scope_match",
          evidence: expect.arrayContaining([
            "grant_id:grt_checkout",
            "scope_match:true",
            "required_permission:checkout:create",
            "permission:checkout:create"
          ])
        },
        { ordinal: 3, layer: "fingerprint_sidecar", status: "not_configured", reason: "fingerprint_provider_missing" },
        { ordinal: 4, layer: "operator_reputation", status: "not_configured", reason: "operator_reputation_provider_missing" }
      ]
    });
  });

  it("denies verified tokens missing required route permissions before rate limiting", () => {
    const fixture = buildVerifiedRequestFixture({ permissions: ["orders:read"], nonce: "nonce_scope_miss", jti: "jti_scope_miss" });
    const policy = parsePolicyYaml(`
version: 1
site_id: sit_abc
mode: enforce
defaults:
  strict: true
  on_degraded: deny
  rate: { capacity: 100, refill_per_sec: 10, cost: 1 }
routes:
  - template: /checkout
    method: GET
    required_permissions: [checkout:create]
    per_actor_class:
      verified_agent: { decision: allow }
`);

    expect(
      evaluateRequest(fixture.request, {
        ...fixture.options,
        policy: {
          trie: policy.trie,
          tokenBucketStore: {
            take() {
              throw new Error("rate policy should not run when delegation scope mismatches");
            }
          }
        }
      })
    ).toMatchObject({
      actorClass: "verified_agent",
      decision: "deny",
      recommendedDecision: "deny",
      reasons: ["permission_scope_mismatch"],
      cascadeTrace: [
        { ordinal: 1, layer: "crypto_identity", status: "pass", reason: "http_signature_dpop_verified" },
        {
          ordinal: 2,
          layer: "delegation_authorization",
          status: "fail",
          reason: "permission_scope_mismatch",
          evidence: expect.arrayContaining([
            "grant_id:grt_checkout",
            "scope_match:false",
            "required_permission:checkout:create",
            "missing_permission:checkout:create"
          ])
        },
        { ordinal: 3, layer: "fingerprint_sidecar", status: "not_configured", reason: "fingerprint_provider_missing" },
        { ordinal: 4, layer: "operator_reputation", status: "not_configured", reason: "operator_reputation_provider_missing" }
      ]
    });
  });

  it("denies quarantine-pinned verified subjects before policy or rate evaluation", () => {
    const fixture = buildVerifiedRequestFixture();
    const cache = new MemoryQuarantinePinCache();
    const nowMs = fixture.options.now!().getTime();
    const policy = parsePolicyYaml(`
version: 1
site_id: sit_abc
mode: enforce
defaults:
  strict: true
  on_degraded: deny
  rate: { capacity: 100, refill_per_sec: 10, cost: 1 }
routes:
  - template: /checkout
    method: GET
    per_actor_class:
      verified_agent: { decision: allow }
`);

    expect(
      cache.pin(
        {
          siteId: "sit_abc",
          subjectHandle: "sub_123",
          expiresAt: new Date(nowMs + 60_000).toISOString(),
          decisionId: "dec_quarantine"
        },
        nowMs
      )
    ).toBe(true);

    const decision = evaluateRequest(fixture.request, {
      ...fixture.options,
      quarantinePinCache: cache,
      policy: {
        trie: policy.trie,
        tokenBucketStore: {
          take() {
            throw new Error("rate policy should not run for pinned quarantine subjects");
          }
        }
      }
    });

    expect(decision).toMatchObject({
      actorClass: "verified_agent",
      subjectHandle: "sub_123",
      decision: "deny",
      recommendedDecision: "deny",
      reasons: ["operator_pinned", "quarantine"],
      responseHeaders: {
        "X-AIdenID-Operator-Action": "quarantine",
        "X-AIdenID-Operator-Effective-Decision": "deny"
      },
      observeOnly: false
    });
  });

  it("supports async quarantine pin caches on the async verifier path", async () => {
    const fixture = buildVerifiedRequestFixture();
    const quarantinePinCache = {
      asyncQuarantinePinCache: true,
      async pin() {
        return true;
      },
      async isPinned(input: { readonly siteId: string; readonly subjectHandle: string | undefined }) {
        return input.siteId === "sit_abc" && input.subjectHandle === "sub_123";
      }
    } as const;

    await expect(evaluateRequestAsync(fixture.request, { ...fixture.options, quarantinePinCache })).resolves.toMatchObject({
      actorClass: "verified_agent",
      subjectHandle: "sub_123",
      decision: "deny",
      reasons: ["operator_pinned", "quarantine"]
    });
  });

  it("denies suspended operator reputation before policy rate evaluation on the async verifier path", async () => {
    const fixture = buildVerifiedRequestFixture({ nonce: "nonce_reputation_suspended", jti: "jti_reputation_suspended" });
    const policy = parsePolicyYaml(`
version: 1
site_id: sit_abc
mode: enforce
defaults:
  strict: true
  on_degraded: deny
  rate: { capacity: 100, refill_per_sec: 10, cost: 1 }
routes:
  - template: /checkout
    method: GET
    per_actor_class:
      verified_agent: { decision: allow }
`);

    await expect(
      evaluateRequestAsync(fixture.request, {
        ...fixture.options,
        policy: {
          trie: policy.trie,
          asyncTokenBucketStore: {
            async take() {
              throw new Error("rate policy should not run for suspended operator reputation");
            }
          }
        },
        operatorReputation: {
          provider: {
            async lookup(input) {
              expect(input.actorClass).toBe("verified_agent");
              expect(input.issuer).toBe("https://issuer.example.com");
              expect(input.subjectHandle).toBe("sub_123");
              return {
                operatorActorId: "https://issuer.example.com",
                trustTier: "restricted",
                status: "suspended",
                reputationScore: 2,
                evidence: ["watchlist-hit"]
              };
            }
          }
        }
      })
    ).resolves.toMatchObject({
      actorClass: "verified_agent",
      decision: "deny",
      recommendedDecision: "deny",
      reasons: ["operator_reputation_suspended"],
      responseHeaders: {
        "X-AIdenID-Operator-Reputation-Status": "suspended"
      },
      cascadeTrace: [
        { ordinal: 1, layer: "crypto_identity", status: "pass", reason: "http_signature_dpop_verified" },
        { ordinal: 2, layer: "delegation_authorization", status: "pass", reason: "proof_bound_session_verified" },
        { ordinal: 3, layer: "fingerprint_sidecar", status: "not_configured", reason: "fingerprint_provider_missing" },
        {
          ordinal: 4,
          layer: "operator_reputation",
          status: "fail",
          reason: "operator_reputation_suspended",
          evidence: expect.arrayContaining([
            "operator_actor_id:https://issuer.example.com",
            "status:suspended",
            "trust_tier:restricted",
            "reputation_score:2",
            "watchlist-hit"
          ])
        }
      ]
    });
  });

  it("applies all six L4 default actions from the in-memory reputation snapshot", () => {
    for (const action of DECISION_ACTIONS) {
      const fixture = buildVerifiedRequestFixture({ nonce: `nonce_l4_default_${action}`, jti: `jti_l4_default_${action}` });
      const decision = evaluateRequest(fixture.request, {
        ...fixture.options,
        operatorReputation: {
          provider: {
            lookup() {
              return {
                operatorActorId: "operator:openai",
                trustTier: "trusted",
                status: "active",
                reputationScore: 93,
                defaultAction: action,
                evidence: ["operator-default-action"]
              };
            }
          }
        }
      });

      expect(decision).toMatchObject({
        actorClass: "verified_agent",
        decision: action,
        recommendedDecision: action,
        reasons:
          action === "price_required" ? ["price_required"] : action === "sandbox" ? ["sandbox_policy"] : ["matched_policy"],
        cascadeTrace: expect.arrayContaining([
          expect.objectContaining({
            layer: "operator_reputation",
            status: "pass",
            evidence: expect.arrayContaining([`default_action:${action}`])
          })
        ])
      });
    }
  });

  it("enforces L4 default scopes before applying default actions", () => {
    for (const action of DECISION_ACTIONS) {
      const allowed = buildVerifiedRequestFixture({ nonce: `nonce_l4_scope_allowed_${action}`, jti: `jti_l4_scope_allowed_${action}` });
      expect(
        evaluateRequest(allowed.request, {
          ...allowed.options,
          operatorReputation: {
            provider: {
              lookup() {
                return {
                  operatorActorId: "operator:openai",
                  trustTier: "trusted",
                  status: "active",
                  reputationScore: 93,
                  defaultAction: action,
                  defaultScopeRoutes: ["/checkout"]
                };
              }
            }
          }
        })
      ).toMatchObject({
        decision: action,
        recommendedDecision: action
      });

      const mismatched = buildVerifiedRequestFixture({ nonce: `nonce_l4_scope_denied_${action}`, jti: `jti_l4_scope_denied_${action}` });
      expect(
        evaluateRequest(mismatched.request, {
          ...mismatched.options,
          operatorReputation: {
            provider: {
              lookup() {
                return {
                  operatorActorId: "operator:openai",
                  trustTier: "trusted",
                  status: "active",
                  reputationScore: 93,
                  defaultAction: action,
                  defaultScopeRoutes: ["/docs/*"],
                  defaultScopeRedirectPath: "/agent-access"
                };
              }
            }
          }
        })
      ).toMatchObject({
        decision: "deny",
        recommendedDecision: "deny",
        reasons: ["operator_scope_mismatch"],
        responseHeaders: {
          "X-AIdenID-Operator-Scope": "mismatch",
          "X-AIdenID-Scope-Redirect": "/agent-access"
        },
        cascadeTrace: expect.arrayContaining([
          expect.objectContaining({
            layer: "operator_reputation",
            status: "fail",
            reason: "operator_scope_mismatch",
            evidence: expect.arrayContaining(["scope_match:false", "scope_route_count:1"])
          })
        ])
      });
    }
  });

  it("lets an explicit per-request decision override win after L4 default action evaluation", async () => {
    for (const action of DECISION_ACTIONS) {
      const fixture = buildVerifiedRequestFixture({ nonce: `nonce_l4_override_${action}`, jti: `jti_l4_override_${action}` });
      await expect(
        evaluateAndEmit(fixture.request, {
          ...fixture.options,
          operatorReputation: {
            provider: {
              lookup() {
                return {
                  operatorActorId: "operator:openai",
                  trustTier: "trusted",
                  status: "active",
                  reputationScore: 93,
                  defaultAction: action
                };
              }
            }
          },
          decisionOverride(decision) {
            return {
              ...decision,
              decision: "allow",
              reasons: ["operator_override"],
              responseHeaders: {
                ...decision.responseHeaders,
                "X-AIdenID-Operator-Action": "allow"
              }
            };
          }
        })
      ).resolves.toMatchObject({
        decision: "allow",
        recommendedDecision: action,
        reasons: ["operator_override"],
        responseHeaders: {
          "X-AIdenID-Operator-Action": "allow"
        }
      });
    }
  });

  it("applies L4 default action after an allow policy match without bypassing policy denials", () => {
    const fixture = buildVerifiedRequestFixture({ nonce: "nonce_l4_policy_default", jti: "jti_l4_policy_default" });
    const policy = parsePolicyYaml(`
version: 1
site_id: sit_abc
mode: enforce
defaults:
  strict: true
  on_degraded: deny
  rate: { capacity: 100, refill_per_sec: 10, cost: 1 }
routes:
  - template: /checkout
    method: GET
    per_actor_class:
      verified_agent: { decision: allow }
`);

    expect(
      evaluateRequest(fixture.request, {
        ...fixture.options,
        policy: { trie: policy.trie },
        operatorReputation: {
          provider: {
            lookup() {
              return {
                operatorActorId: "operator:openai",
                trustTier: "trusted",
                status: "active",
                reputationScore: 93,
                defaultAction: "queue"
              };
            }
          }
        }
      })
    ).toMatchObject({
      decision: "queue",
      recommendedDecision: "queue",
      reasons: ["matched_policy"],
      responseHeaders: {
        "X-AIdenID-Operator-Default-Action": "queue",
        "X-AIdenID-Retry-Token": expect.stringMatching(/^rty_/)
      }
    });
  });

  it("records missing operator reputation as a fail-open cascade skip", async () => {
    const fixture = buildVerifiedRequestFixture({ nonce: "nonce_reputation_missing", jti: "jti_reputation_missing" });

    await expect(
      evaluateRequestAsync(fixture.request, {
        ...fixture.options,
        operatorReputation: {
          provider: {
            async lookup() {
              return undefined;
            }
          }
        }
      })
    ).resolves.toMatchObject({
      actorClass: "verified_agent",
      decision: "allow",
      cascadeTrace: [
        { ordinal: 1, layer: "crypto_identity", status: "pass" },
        { ordinal: 2, layer: "delegation_authorization", status: "pass" },
        { ordinal: 3, layer: "fingerprint_sidecar", status: "not_configured" },
        { ordinal: 4, layer: "operator_reputation", status: "skipped", reason: "operator_reputation_not_found" }
      ]
    });
  });

  it("fails the sync verifier path when a pinned subject requires an async quarantine cache", () => {
    const fixture = buildVerifiedRequestFixture();
    const quarantinePinCache = {
      asyncQuarantinePinCache: true,
      async pin() {
        return true;
      },
      async isPinned() {
        return true;
      }
    } as const;

    expect(() => evaluateRequest(fixture.request, { ...fixture.options, quarantinePinCache })).toThrow(/async quarantinePinCache/);
  });

  it("denies signed traffic when the HTTP message signature is bad", () => {
    const fixture = buildVerifiedRequestFixture();

    expect(
      evaluateRequest(
        {
          ...fixture.request,
          headers: {
            ...fixture.request.headers,
            signature: "sig1=:bad:"
          }
        },
        fixture.options
      )
    ).toMatchObject({
      actorClass: "signed_agent",
      decision: "deny",
      recommendedDecision: "deny",
      reasons: ["bad_signature"]
    });
  });

  it("denies signed traffic when a DPoP jti and HTTP signature nonce are replayed", () => {
    const fixture = buildVerifiedRequestFixture();

    expect(evaluateRequest(fixture.request, fixture.options)).toMatchObject({
      actorClass: "verified_agent",
      decision: "allow"
    });
    expect(evaluateRequest(fixture.request, fixture.options)).toMatchObject({
      actorClass: "signed_agent",
      decision: "deny",
      recommendedDecision: "deny",
      reasons: ["bad_signature"]
    });
  });

  it("keeps default replay protection stable across fresh crypto option objects", () => {
    const fixture = buildVerifiedRequestFixture();
    const firstOptions = {
      ...fixture.options,
      crypto: {
        ...fixture.options.crypto!
      }
    };
    const secondOptions = {
      ...fixture.options,
      crypto: {
        ...fixture.options.crypto!
      }
    };

    expect(evaluateRequest(fixture.request, firstOptions)).toMatchObject({
      actorClass: "verified_agent",
      decision: "allow"
    });
    expect(evaluateRequest(fixture.request, secondOptions)).toMatchObject({
      actorClass: "signed_agent",
      decision: "deny",
      recommendedDecision: "deny",
      reasons: ["bad_signature"]
    });
  });

  it("auto-wires Redis replay cache from top-level redis options on the async path", async () => {
    const fixture = buildVerifiedRequestFixture();
    const seen = new Set<string>();
    const redis = {
      scriptRunner: {
        async load() {
          return "sha-replay";
        },
        async runSha(_sha: string, options: { readonly keys: readonly string[]; readonly arguments: readonly string[] }) {
          if (options.arguments[0] === "has") {
            return 0;
          }
          const key = options.keys[0] ?? "";
          if (seen.has(key)) {
            return 0;
          }
          seen.add(key);
          return 1;
        },
        async run() {
          throw new Error("EVAL fallback should not run when EVALSHA is available");
        }
      }
    };

    await expect(evaluateRequestAsync(fixture.request, { ...fixture.options, redis })).resolves.toMatchObject({
      actorClass: "verified_agent",
      decision: "allow"
    });
    await expect(evaluateRequestAsync(fixture.request, { ...fixture.options, redis })).resolves.toMatchObject({
      actorClass: "signed_agent",
      decision: "deny",
      reasons: ["bad_signature"]
    });
    expect(() => evaluateRequest(fixture.request, { ...fixture.options, redis })).toThrow(/async replayCache/);
  });
});
