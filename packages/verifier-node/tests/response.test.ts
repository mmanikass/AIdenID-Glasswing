import { describe, expect, it } from "vitest";

import {
  AIDENID_AGENT_ONBOARDING_DOCS_URL,
  AIDENID_CHALLENGE_URL,
  AIDENID_REGISTER_URL,
  decisionToHttpResponse
} from "../src/response.js";

import type { ActorClass, DecisionResult } from "../src/types.js";

const ACTOR_CLASSES: readonly ActorClass[] = [
  "verified_agent",
  "signed_agent",
  "likely_human",
  "suspicious_automation",
  "unknown"
];

function denyDecision(actorClass: ActorClass, overrides: Partial<DecisionResult> = {}): DecisionResult {
  return {
    requestId: `req_${actorClass}`,
    siteId: "sit_demo",
    mode: "enforce",
    method: "GET",
    path: "/strict",
    routeTemplate: "/strict",
    actorClass,
    decision: "deny",
    recommendedDecision: "deny",
    reasons: ["matched_policy"],
    observeOnly: false,
    rateLimit: { status: "ok" },
    latencyUs: 500,
    ...overrides
  };
}

describe("decisionToHttpResponse", () => {
  it.each(ACTOR_CLASSES)("maps deny responses for %s without changing the status contract", (actorClass) => {
    const response = decisionToHttpResponse(denyDecision(actorClass));

    expect(response.status).toBe(403);
    expect(response.headers["X-AIdenID-Actor-Class"]).toBe(actorClass);
    expect(response.headers["X-AIdenID-Decision"]).toBe("deny");
    expect(response.body).toMatchObject({
      code: "AIDENID_DENIED",
      message: "request denied by AIdenID verifier policy",
      requestId: `req_${actorClass}`,
      decision: "deny"
    });
  });

  it.each(["unknown", "suspicious_automation"] satisfies readonly ActorClass[])(
    "adds registration hints for %s denies",
    (actorClass) => {
      const response = decisionToHttpResponse(denyDecision(actorClass));

      expect(response.headers["WWW-Authenticate"]).toBe(
        `AIdenID realm="sit_demo", register="${AIDENID_REGISTER_URL}"`
      );
      expect(response.body.register_url).toBe(AIDENID_REGISTER_URL);
      expect(response.body.docs_url).toBe(AIDENID_AGENT_ONBOARDING_DOCS_URL);
      expect(response.headers["X-AIdenID-Challenge"]).toBe("agent-identity");
      expect(response.body.identity_challenge).toMatchObject({
        type: "aidenid.agent_identity_challenge",
        site_id: "sit_demo",
        request_id: `req_${actorClass}`,
        actor_class: actorClass,
        challenge_url: AIDENID_CHALLENGE_URL,
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
      expect(response.body.identity_challenge?.cascade_layers.map((layer) => layer.layer)).toEqual([
        "crypto_identity",
        "delegation_authorization",
        "fingerprint_sidecar",
        "operator_reputation"
      ]);
    }
  );

  it.each(["verified_agent", "signed_agent", "likely_human"] satisfies readonly ActorClass[])(
    "does not add registration hints for %s denies",
    (actorClass) => {
      const response = decisionToHttpResponse(denyDecision(actorClass));

      expect(response.headers).not.toHaveProperty("WWW-Authenticate");
      expect(response.body).not.toHaveProperty("register_url");
      expect(response.body).not.toHaveProperty("docs_url");
    }
  );

  it("quotes the site realm without leaking route or policy details", () => {
    const response = decisionToHttpResponse(denyDecision("unknown", { siteId: 'sit_"demo\\realm' }));

    expect(response.headers["WWW-Authenticate"]).toBe(
      `AIdenID realm="sit_\\"demo\\\\realm", register="${AIDENID_REGISTER_URL}"`
    );
    expect(response.headers["WWW-Authenticate"]).not.toContain("/strict");
    expect(response.body).not.toHaveProperty("routeTemplate");
    expect(response.body).not.toHaveProperty("reasons");
  });

  it("adds purpose challenge metadata without a registration WWW-Authenticate header for known actors", () => {
    const response = decisionToHttpResponse(
      denyDecision("verified_agent", {
        reasons: ["purpose_required"]
      })
    );

    expect(response.headers).not.toHaveProperty("WWW-Authenticate");
    expect(response.headers["X-AIdenID-Challenge"]).toBe("agent-identity");
    expect(response.body).not.toHaveProperty("register_url");
    expect(response.body.identity_challenge).toMatchObject({
      actor_class: "verified_agent",
      reason_codes: ["purpose_required"],
      submit: {
        method: "POST",
        content_type: "application/json",
        headers: ["X-AIdenID-Purpose", "Signature", "Signature-Input", "DPoP"]
      }
    });
  });
});
