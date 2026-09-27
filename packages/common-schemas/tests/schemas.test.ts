import { describe, expect, it } from "vitest";

import {
  AgentIdentityChallengeSchema,
  AgentIdentityChallengeReviewSchema,
  AgentIdentityChallengeSubmissionSchema,
  buildAgentIdentityChallenge
} from "../src/agentChallenge.js";
import { CascadeTraceSchema } from "../src/cascadeTrace.js";
import { REASON_CODES } from "../src/enums.js";
import { DecisionEventSchema } from "../src/events.js";
import { buildMcpProtectedResourceMetadata, McpProtectedResourceMetadataSchema } from "../src/mcp.js";
import { PolicyBundleSchema, RoutePolicySchema } from "../src/policy.js";
import { SessionExchangeRequestSchema, SessionTokenClaimsSchema } from "../src/session.js";

const sha256 = "a".repeat(64);

describe("runtime schemas", () => {
  it("includes operator quarantine pin reasons in shared reason codes", () => {
    expect(REASON_CODES).toContain("operator_pinned");
    expect(REASON_CODES).toContain("purpose_required");
    expect(REASON_CODES).toContain("purpose_disallowed");
    expect(REASON_CODES).toContain("permission_scope_mismatch");
    expect(REASON_CODES).toContain("fingerprint_risk");
    expect(REASON_CODES).toContain("operator_reputation_suspended");
    expect(REASON_CODES).toContain("operator_scope_mismatch");
  });

  it("validates the locked four-layer cascade trace order", () => {
    const trace = [
      { ordinal: 1, layer: "crypto_identity", status: "pass", reason: "http_signature_dpop_verified", latency_us: 410 },
      { ordinal: 2, layer: "delegation_authorization", status: "pass", reason: "proof_bound_session_verified", latency_us: 410 },
      { ordinal: 3, layer: "fingerprint_sidecar", status: "not_configured", reason: "fingerprint_provider_missing", latency_us: 0 },
      { ordinal: 4, layer: "operator_reputation", status: "not_configured", reason: "operator_reputation_provider_missing", latency_us: 0 }
    ];

    expect(CascadeTraceSchema.parse(trace)).toHaveLength(4);
    expect(() => CascadeTraceSchema.parse([...trace].reverse())).toThrow(/cascade trace ordinal/);
  });

  it("validates audience-bound session token claims", () => {
    expect(
      SessionTokenClaimsSchema.parse({
        iss: "https://issuer.example.com",
        sub: "sub_123",
        aud: "sit_abc",
        resource: "https://site.example.com",
        site_id: "sit_abc",
        grant_id: "grt_abc",
        chain_id: "chn_abc",
        permissions: ["read:checkout"],
        llm_brand: "openai",
        cnf: { jkt: "thumbprint-123456" },
        revocation_epoch: 3,
        iat: 100,
        exp: 200
      })
    ).toMatchObject({ aud: "sit_abc", revocation_epoch: 3, llm_brand: "openai" });
  });

  it("rejects malformed LLM brand session metadata", () => {
    const claims = {
      iss: "https://issuer.example.com",
      sub: "sub_123",
      aud: "sit_abc",
      resource: "https://site.example.com",
      site_id: "sit_abc",
      grant_id: "grt_abc",
      chain_id: "chn_abc",
      permissions: ["read:checkout"],
      cnf: { jkt: "thumbprint-123456" },
      revocation_epoch: 3,
      iat: 100,
      exp: 200
    };

    expect(() => SessionTokenClaimsSchema.parse({ ...claims, llm_brand: "OpenAI" })).toThrow();
    expect(() => SessionTokenClaimsSchema.parse({ ...claims, llm_brand: "a".repeat(33) })).toThrow();
  });

  it("validates optional LLM brand metadata on session exchange requests", () => {
    const request = {
      grant_id: "grt_abc",
      audience: "sit_abc",
      resource: "https://site.example.com",
      proof_jkt: "thumbprint-123456",
      requested_permissions: ["read:checkout"],
      llm_brand: "anthropic"
    };

    expect(SessionExchangeRequestSchema.parse(request)).toMatchObject({ llm_brand: "anthropic" });
    expect(() => SessionExchangeRequestSchema.parse({ ...request, llm_brand: "Anthropic" })).toThrow();
  });

  it("builds RFC 9728-style MCP protected-resource metadata without token passthrough", () => {
    const metadata = buildMcpProtectedResourceMetadata({
      resource: "https://mcp.aidenid.test/",
      authorizationServers: ["https://api.aidenid.test/"]
    });

    expect(McpProtectedResourceMetadataSchema.parse(metadata)).toMatchObject({
      resource: "https://mcp.aidenid.test",
      authorization_servers: ["https://api.aidenid.test"],
      bearer_methods_supported: ["header"],
      dpop_bound_access_tokens_required: true,
      dpop_signing_alg_values_supported: ["EdDSA", "ES256"]
    });
    expect(metadata.scopes_supported).toContain("aidenid:session.exchange");
    expect(metadata).not.toHaveProperty("token_endpoint");
    expect(() =>
      buildMcpProtectedResourceMetadata({
        resource: "http://mcp.aidenid.test",
        authorizationServers: ["https://api.aidenid.test"]
      })
    ).toThrow(/resource must use https/);
  });

  it("rejects expired session token claims", () => {
    expect(() =>
      SessionTokenClaimsSchema.parse({
        iss: "https://issuer.example.com",
        sub: "sub_123",
        aud: "sit_abc",
        resource: "https://site.example.com",
        site_id: "sit_abc",
        grant_id: "grt_abc",
        chain_id: "chn_abc",
        permissions: ["read:checkout"],
        cnf: { jkt: "thumbprint-123456" },
        revocation_epoch: 3,
        iat: 200,
        exp: 100
      })
    ).toThrow(/exp must be greater/);
  });

  it("requires outcome-specific metadata", () => {
    expect(() => RoutePolicySchema.parse({ route: "/premium", default: { decision: "price_required" } })).toThrow(
      /price_metadata/
    );
  });

  it("validates policy bundles with issuer key ledger entries", () => {
    expect(
      PolicyBundleSchema.parse({
        version: "pol_v1",
        site_id: "sit_abc",
        issued_at: "2026-04-24T07:00:00.000Z",
        revocation_epoch: 1,
        routes: [
          {
            route: "/checkout",
            strict: true,
            allowed_purposes: ["benefits_lookup"],
            required_permissions: ["checkout:create"],
            default: { decision: "deny", reason: "strict_route_degraded" },
            actors: {
              verified_agent: { decision: "allow", reason: "matched_policy" }
            }
          }
        ],
        issuer_key_ledger: [
          {
            issuer: "https://issuer.example.com",
            kid: "key-1",
            jwk_thumbprint_sha256: sha256,
            alg: "EdDSA",
            state: "trusted",
            first_seen_at: "2026-04-24T07:00:00.000Z",
            approved_at: "2026-04-24T07:00:01.000Z"
          }
        ]
      })
    ).toMatchObject({ version: "pol_v1", routes: [expect.objectContaining({ required_permissions: ["checkout:create"] })] });
  });

  it("rejects malformed route allowed purposes", () => {
    expect(() =>
      RoutePolicySchema.parse({
        route: "/checkout",
        strict: true,
        allowed_purposes: ["Benefits Lookup"],
        default: { decision: "deny", reason: "purpose_required" }
      })
    ).toThrow();
  });

  it("validates optional decision event purpose metadata", () => {
    const event = {
      id: "dec_1",
      request_id: "req_1",
      site_id: "sit_abc",
      occurred_at: "2026-04-24T07:00:00.000Z",
      actor_class: "verified_agent",
      decision: "allow",
      reason_codes: ["matched_policy"],
      route_template: "/agent-purpose/*",
      method: "GET",
      path_hash_sha256: sha256,
      latency_us: 120,
      purpose: "research"
    };

    expect(DecisionEventSchema.parse(event)).toMatchObject({ purpose: "research" });
    expect(() => DecisionEventSchema.parse({ ...event, purpose: "Research" })).toThrow();
    expect(() => DecisionEventSchema.parse({ ...event, purpose: "bad value" })).toThrow();
  });

  it("validates the bounded agent identity challenge contract", () => {
    const challenge = buildAgentIdentityChallenge({
      siteId: "sit_abc",
      requestId: "req_agent_1",
      actorClass: "unknown",
      decision: "deny",
      reasonCodes: ["purpose_required", "matched_policy"],
      challengeUrl: "https://api.aidenid.com/v1/identities",
      registerUrl: "https://api.aidenid.com/v1/identities",
      docsUrl: "https://aidenid.com/docs/agent-onboarding"
    });

    expect(AgentIdentityChallengeSchema.parse(challenge)).toMatchObject({
      type: "aidenid.agent_identity_challenge",
      required_fields: [
        "purpose",
        "requested_access_duration_seconds",
        "provider_name",
        "contact_url",
        "cascade_attestation"
      ],
      optional_fields: ["operator_actor_id", "purpose_rationale", "jwks_url", "delegation_authority_jwk_thumbprint_sha256", "declaration"],
      allowed_purposes: expect.arrayContaining(["research", "ai_training", "competitive_intelligence", "other"])
    });
    expect(challenge.cascade_layers.map((layer) => layer.layer)).toEqual([
      "crypto_identity",
      "delegation_authorization",
      "fingerprint_sidecar",
      "operator_reputation"
    ]);
    expect(() =>
      AgentIdentityChallengeSchema.parse({
        ...challenge,
        cascade_layers: [...challenge.cascade_layers].reverse()
      })
    ).toThrow(/cascade challenge ordinal/);
  });

  it("requires challenge submissions to declare purpose, identity, and all four cascade layers", () => {
    const submission = {
      site_id: "sit_abc",
      request_id: "req_agent_1",
      purpose: "research",
      requested_access_duration_seconds: 3_600,
      provider_name: "Example Agent Lab",
      operator_actor_id: "operator:example-lab",
      contact_url: "https://example.com/security",
      jwks_url: "https://example.com/.well-known/aidenid-jwks.json",
      delegation_authority_jwk_thumbprint_sha256: "a".repeat(64),
      cascade_attestation: [
        "crypto_identity",
        "delegation_authorization",
        "fingerprint_sidecar",
        "operator_reputation"
      ],
      declaration: "We are requesting access for an agentic research workflow."
    };

    expect(AgentIdentityChallengeSubmissionSchema.parse(submission)).toMatchObject({
      purpose: "research",
      requested_access_duration_seconds: 3_600,
      operator_actor_id: "operator:example-lab"
    });
    expect(() =>
      AgentIdentityChallengeSubmissionSchema.parse({
        ...submission,
        contact_url: undefined
      })
    ).toThrow();
    expect(() =>
      AgentIdentityChallengeSubmissionSchema.parse({
        ...submission,
        purpose: "Research"
      })
    ).toThrow();
    expect(() =>
      AgentIdentityChallengeSubmissionSchema.parse({
        ...submission,
        requested_access_duration_seconds: 30
      })
    ).toThrow();
    expect(() =>
      AgentIdentityChallengeSubmissionSchema.parse({
        ...submission,
        cascade_attestation: ["crypto_identity", "fingerprint_sidecar", "delegation_authorization", "operator_reputation"]
      })
    ).toThrow(/cascade challenge layer/);
    expect(() =>
      AgentIdentityChallengeSubmissionSchema.parse({
        ...submission,
        purpose: "other",
        purpose_rationale: undefined
      })
    ).toThrow(/purpose_rationale/);
    expect(
      AgentIdentityChallengeSubmissionSchema.parse({
        ...submission,
        purpose: "other",
        purpose_rationale: "new category for a design-partner pilot"
      })
    ).toMatchObject({ purpose: "other", purpose_rationale: "new category for a design-partner pilot" });
  });

  it("validates bounded L4 default action and scope on challenge review approvals", () => {
    expect(
      AgentIdentityChallengeReviewSchema.parse({
        action: "approve",
        default_action: "price_required",
        default_scope_routes: ["/docs", "/pricing/*"],
        default_scope_redirect_path: "/agent-access",
        approval_expires_at: "2026-05-18T01:00:00.000Z"
      })
    ).toMatchObject({
      action: "approve",
      default_action: "price_required",
      default_scope_routes: ["/docs", "/pricing/*"],
      default_scope_redirect_path: "/agent-access",
      approval_expires_at: "2026-05-18T01:00:00.000Z"
    });
    expect(
      AgentIdentityChallengeReviewSchema.parse({
        action: "approve"
      })
    ).toMatchObject({ default_action: "allow", default_scope_routes: [] });
    expect(() =>
      AgentIdentityChallengeReviewSchema.parse({
        action: "approve",
        default_scope_routes: Array.from({ length: 33 }, (_, index) => `/r${index}`)
      })
    ).toThrow();
    expect(() =>
      AgentIdentityChallengeReviewSchema.parse({
        action: "approve",
        default_scope_redirect_path: "https://evil.example/redirect"
      })
    ).toThrow();
    expect(() =>
      AgentIdentityChallengeReviewSchema.parse({
        action: "approve",
        approval_expires_at: "not-a-date"
      })
    ).toThrow();
  });

  it("rejects certainty labels outside the locked actor classes", () => {
    expect(() =>
      DecisionEventSchema.parse({
        id: "dec_1",
        request_id: "req_1",
        site_id: "sit_abc",
        occurred_at: "2026-04-24T07:00:00.000Z",
        actor_class: "human",
        decision: "allow",
        reason_codes: ["matched_policy"],
        route_template: "/",
        method: "GET",
        path_hash_sha256: sha256,
        latency_us: 120
      })
    ).toThrow();
  });
});
