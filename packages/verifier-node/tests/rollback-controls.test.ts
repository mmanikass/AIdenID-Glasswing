import { generateKeyPairSync, sign as nodeSign } from "node:crypto";

import { parsePolicyYaml } from "@aidenid/policy-engine";
import {
  base64Url,
  buildSignatureBase,
  canonicalJwkThumbprintBase64Url,
  parseSignatureInput,
  signCompactJws
} from "@aidenid/crypto";
import { describe, expect, it } from "vitest";

import { evaluateRequest, type AidenIdVerifierOptions } from "../src/index.js";

const nowSeconds = 1_776_000_000;
const resource = "https://site.example.com/checkout";

const policy = parsePolicyYaml(`
version: 1
site_id: sit_rollback
mode: enforce
defaults:
  strict: false
  on_degraded: queue
  rate: { capacity: 100, refill_per_sec: 10, cost: 1 }
routes:
  - template: /checkout
    method: GET
    per_actor_class:
      likely_human: { decision: deny }
      signed_agent: { decision: deny }
`);

function browserRequest() {
  return {
    method: "GET",
    url: resource,
    headers: {
      "user-agent": "Mozilla/5.0 Chrome",
      accept: "text/html"
    }
  };
}

function buildVerifiedRequestFixture() {
  const issuerKeys = generateKeyPairSync("ed25519");
  const dpopKeys = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const httpKeys = generateKeyPairSync("ed25519");
  const dpopPublicJwk = dpopKeys.publicKey.export({ format: "jwk" });
  const proofJkt = canonicalJwkThumbprintBase64Url(dpopPublicJwk);
  const sessionToken = signCompactJws(
    {
      iss: "https://issuer.example.com",
      sub: "sub_123",
      aud: "sit_rollback",
      site_id: "sit_rollback",
      resource,
      grant_id: "grt_checkout",
      chain_id: "chn_checkout",
      permissions: ["checkout:read"],
      cnf: { jkt: proofJkt },
      revocation_epoch: 4,
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
      jti: "jti_rollback",
      iat: nowSeconds
    },
    dpopKeys.privateKey,
    "ES256",
    { typ: "dpop+jwt", jwk: dpopPublicJwk }
  );
  const authorization = `DPoP ${sessionToken}`;
  const signatureInput = `sig1=("@method" "@path" "authorization" "dpop");created=${nowSeconds};expires=${
    nowSeconds + 300
  };keyid="agent-key-1";alg="ed25519";nonce="nonce_rollback"`;
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

  return {
    request: {
      ...baseRequest,
      headers: {
        ...baseRequest.headers,
        signature: `sig1=:${base64Url(signature)}:`
      }
    },
    options: {
      siteId: "sit_rollback",
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
        minRevocationEpoch: 4
      }
    }
  } satisfies { readonly request: Parameters<typeof evaluateRequest>[0]; readonly options: AidenIdVerifierOptions };
}

describe("rollback controls", () => {
  it("pauses global enforcement without changing the policy bundle", () => {
    expect(
      evaluateRequest(browserRequest(), {
        siteId: "sit_rollback",
        apiKey: "key",
        policy: { trie: policy.trie },
        rollback: { globalEnforcementPause: true }
      })
    ).toMatchObject({
      decision: "allow",
      recommendedDecision: "deny",
      mode: "observe",
      observeOnly: true
    });
  });

  it("applies per-route mode overrides as one-route enforce toggles", () => {
    expect(
      evaluateRequest(browserRequest(), {
        siteId: "sit_rollback",
        apiKey: "key",
        policy: { trie: policy.trie },
        rollback: { routeModeOverrides: { "/checkout": "observe" } }
      })
    ).toMatchObject({
      decision: "allow",
      recommendedDecision: "deny",
      mode: "observe"
    });
  });

  it("can disable crypto-path enforcement during staged rollout", () => {
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
        {
          ...fixture.options,
          rollback: { cryptoPathRollout: "disabled" }
        }
      )
    ).toMatchObject({
      actorClass: "signed_agent",
      decision: "allow",
      recommendedDecision: "allow"
    });
  });

  it("applies a global revocation floor to crypto-path verification", () => {
    const fixture = buildVerifiedRequestFixture();

    expect(
      evaluateRequest(fixture.request, {
        ...fixture.options,
        rollback: { globalRevocationEpoch: 5 }
      })
    ).toMatchObject({
      actorClass: "signed_agent",
      decision: "deny",
      recommendedDecision: "deny",
      reasons: ["revoked"]
    });
  });
});
