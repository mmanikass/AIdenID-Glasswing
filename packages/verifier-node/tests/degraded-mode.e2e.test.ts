import { generateKeyPairSync, sign as nodeSign } from "node:crypto";

import {
  MemoryTokenBucketStore,
  parsePolicyYaml,
  type TokenBucketStore
} from "@aidenid/policy-engine";
import {
  base64Url,
  buildSignatureBase,
  canonicalJwkThumbprintBase64Url,
  parseSignatureInput,
  signCompactJws
} from "@aidenid/crypto";
import { describe, expect, it } from "vitest";

import { evaluateRequest, type AidenIdVerifierOptions, type VerifierPolicyOptions } from "../src/index.js";

const nowSeconds = 1_776_000_000;
const resource = "https://site.example.com/strict";

const strictPolicy = parsePolicyYaml(`
version: 1
site_id: sit_chaos
mode: enforce
defaults:
  strict: false
  on_degraded: queue
  rate: { capacity: 100, refill_per_sec: 10, cost: 1 }
routes:
  - template: /strict
    method: GET
    strict: true
    on_degraded: deny
    signature_required: [session, dpop, http_message_signature]
    per_actor_class:
      verified_agent: { decision: allow }
      signed_agent: { decision: allow }
      likely_human: { decision: allow }
      unknown: { decision: allow }
`);

const browserRequest = {
  method: "GET",
  url: resource,
  remoteAddress: "198.51.100.44",
  headers: {
    "user-agent": "Mozilla/5.0 Chrome",
    accept: "text/html"
  }
};

function optionsWithPolicy(policy: Partial<VerifierPolicyOptions> = {}): AidenIdVerifierOptions {
  return {
    siteId: "sit_chaos",
    apiKey: "key",
    mode: "enforce",
    now: () => new Date(nowSeconds * 1000),
    policy: {
      trie: strictPolicy.trie,
      tokenBucketStore: new MemoryTokenBucketStore(),
      ...policy
    }
  };
}

function buildSignedFixture() {
  const trustedIssuerKeys = generateKeyPairSync("ed25519");
  const pendingIssuerKeys = generateKeyPairSync("ed25519");
  const dpopKeys = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const httpKeys = generateKeyPairSync("ed25519");
  const dpopPublicJwk = dpopKeys.publicKey.export({ format: "jwk" });
  const proofJkt = canonicalJwkThumbprintBase64Url(dpopPublicJwk);
  const sessionToken = signCompactJws(
    {
      iss: "https://issuer.example.com",
      sub: "sub_123",
      aud: "sit_chaos",
      site_id: "sit_chaos",
      resource,
      grant_id: "grt_strict",
      chain_id: "chn_strict",
      permissions: ["strict:read"],
      cnf: { jkt: proofJkt },
      revocation_epoch: 4,
      iat: nowSeconds - 5,
      exp: nowSeconds + 300
    },
    pendingIssuerKeys.privateKey,
    "EdDSA",
    { kid: "issuer-key-2" }
  );
  const dpopProof = signCompactJws(
    {
      htm: "GET",
      htu: resource,
      jti: "jti_rotation",
      iat: nowSeconds
    },
    dpopKeys.privateKey,
    "ES256",
    { typ: "dpop+jwt", jwk: dpopPublicJwk }
  );
  const authorization = `DPoP ${sessionToken}`;
  const signatureInput = `sig1=("@method" "@path" "authorization" "dpop");created=${nowSeconds};expires=${
    nowSeconds + 300
  };keyid="agent-key-1";alg="ed25519";nonce="nonce_rotation"`;
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
    crypto: {
      sessionTokenPublicJwksByIssuer: {
        "https://issuer.example.com": trustedIssuerKeys.publicKey.export({ format: "jwk" })
      },
      httpMessageSignaturePublicJwksByKeyId: {
        "agent-key-1": httpKeys.publicKey.export({ format: "jwk" })
      },
      issuerKeyStatesByIssuer: {
        "https://issuer.example.com": {
          "issuer-key-1": "trusted",
          "issuer-key-2": "rotation_pending"
        }
      },
      minRevocationEpoch: 4
    }
  } satisfies Pick<AidenIdVerifierOptions, "crypto"> & {
    readonly request: Parameters<typeof evaluateRequest>[0];
  };
}

describe("degraded mode fail-closed regressions", () => {
  it("denies strict routes while the control plane is down", () => {
    expect(
      evaluateRequest(
        browserRequest,
        optionsWithPolicy({
          degraded: "control_plane_down"
        })
      )
    ).toMatchObject({
      decision: "deny",
      recommendedDecision: "deny",
      reasons: ["strict_route_degraded"],
      observeOnly: false
    });
  });

  it("denies strict routes when Redis token buckets are unavailable", () => {
    const failingStore: TokenBucketStore = {
      take: () => {
        throw new Error("redis unavailable");
      }
    };

    expect(
      evaluateRequest(
        browserRequest,
        optionsWithPolicy({
          tokenBucketStore: failingStore
        })
      )
    ).toMatchObject({
      decision: "deny",
      recommendedDecision: "deny",
      reasons: ["strict_route_degraded"]
    });
  });

  it("denies strict routes when JWKS fetch slowness makes issuer cache stale", () => {
    expect(
      evaluateRequest(
        {
          method: "GET",
          url: resource,
          headers: { signature: "sig", "signature-input": "sig1=();keyid=\"agent-key-1\"", dpop: "slow-jwks" }
        },
        optionsWithPolicy({
          degraded: "issuer_cache_stale"
        })
      )
    ).toMatchObject({
      actorClass: "signed_agent",
      decision: "deny",
      reasons: ["strict_route_degraded"]
    });
  });

  it("denies strict routes when issuer key rotation is pending mid-session", () => {
    const fixture = buildSignedFixture();

    expect(
      evaluateRequest(fixture.request, {
        ...optionsWithPolicy(),
        crypto: fixture.crypto
      })
    ).toMatchObject({
      actorClass: "signed_agent",
      decision: "deny",
      recommendedDecision: "deny",
      reasons: ["issuer_key_rotation_pending"]
    });
  });
});
