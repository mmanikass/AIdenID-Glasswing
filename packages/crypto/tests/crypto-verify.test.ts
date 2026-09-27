import { generateKeyPairSync, sign as nodeSign } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  base64Url,
  buildSignatureBase,
  canonicalJwkThumbprintBase64Url,
  MemoryReplayCache,
  parseSignatureInput,
  RedisReplayCache,
  signCompactJws,
  verifyDpopProofAsync,
  verifyDpopProof,
  verifyHttpMessageSignatureAsync,
  verifyHttpMessageSignature,
  verifySessionToken
} from "../src/index.js";

describe("crypto verification primitives", () => {
  it("verifies session tokens and DPoP proof key binding", () => {
    const issuerKeys = generateKeyPairSync("ed25519");
    const dpopKeys = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const dpopPublicJwk = dpopKeys.publicKey.export({ format: "jwk" });
    const proofJkt = canonicalJwkThumbprintBase64Url(dpopPublicJwk);
    const nowSeconds = 1_776_000_000;

    const sessionToken = signCompactJws(
      {
        iss: "https://issuer.example.com",
        sub: "sub_123",
        aud: "sit_abc",
        site_id: "sit_abc",
        resource: "https://site.example.com/checkout",
        grant_id: "grt_checkout",
        chain_id: "chn_checkout",
        permissions: ["checkout:create"],
        cnf: { jkt: proofJkt },
        revocation_epoch: 4,
        llm_brand: "openai",
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
        htu: "https://site.example.com/checkout",
        jti: "jti_123",
        iat: nowSeconds
      },
      dpopKeys.privateKey,
      "ES256",
      { typ: "dpop+jwt", jwk: dpopPublicJwk }
    );

    expect(
      verifySessionToken({
        token: sessionToken,
        publicJwk: issuerKeys.publicKey.export({ format: "jwk" }),
        expectedAudience: "sit_abc",
        expectedResource: "https://site.example.com/checkout",
        expectedProofJkt: proofJkt,
        minRevocationEpoch: 4,
        now: new Date(nowSeconds * 1000)
      }).claims
    ).toMatchObject({ aud: "sit_abc", site_id: "sit_abc", grant_id: "grt_checkout", permissions: ["checkout:create"], llm_brand: "openai" });

    expect(
      verifyDpopProof({
        proofJwt: dpopProof,
        method: "GET",
        url: "https://site.example.com/checkout",
        expectedJwkThumbprint: proofJkt,
        now: new Date(nowSeconds * 1000)
      }).jwkThumbprint
    ).toBe(proofJkt);

    const replayCache = new MemoryReplayCache();
    expect(
      verifyDpopProof({
        proofJwt: dpopProof,
        method: "GET",
        url: "https://site.example.com/checkout",
        expectedJwkThumbprint: proofJkt,
        now: new Date(nowSeconds * 1000),
        replayCache
      }).jwkThumbprint
    ).toBe(proofJkt);
    expect(() =>
      verifyDpopProof({
        proofJwt: dpopProof,
        method: "GET",
        url: "https://site.example.com/checkout",
        expectedJwkThumbprint: proofJkt,
        now: new Date(nowSeconds * 1000),
        replayCache
      })
    ).toThrow(/replay/);
  });

  it("rejects malformed LLM brand metadata in session tokens", () => {
    const issuerKeys = generateKeyPairSync("ed25519");
    const dpopKeys = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const dpopPublicJwk = dpopKeys.publicKey.export({ format: "jwk" });
    const proofJkt = canonicalJwkThumbprintBase64Url(dpopPublicJwk);
    const nowSeconds = 1_776_000_000;
    const sessionToken = signCompactJws(
      {
        iss: "https://issuer.example.com",
        sub: "sub_123",
        aud: "sit_abc",
        site_id: "sit_abc",
        resource: "https://site.example.com/checkout",
        grant_id: "grt_checkout",
        chain_id: "chn_checkout",
        permissions: ["checkout:create"],
        cnf: { jkt: proofJkt },
        revocation_epoch: 4,
        llm_brand: "OpenAI",
        iat: nowSeconds - 5,
        exp: nowSeconds + 300
      },
      issuerKeys.privateKey,
      "EdDSA",
      { kid: "issuer-key-1" }
    );

    expect(() =>
      verifySessionToken({
        token: sessionToken,
        publicJwk: issuerKeys.publicKey.export({ format: "jwk" }),
        expectedAudience: "sit_abc",
        expectedResource: "https://site.example.com/checkout",
        expectedProofJkt: proofJkt,
        now: new Date(nowSeconds * 1000)
      })
    ).toThrow(/llm_brand/);
  });

  it("bounds the in-memory replay cache instead of purging every insert unbounded", () => {
    const replayCache = new MemoryReplayCache({ maxEntries: 2, purgeIntervalMs: 60_000 });

    expect(replayCache.storeOnce("a", 60_000, 1_000)).toBe(true);
    expect(replayCache.storeOnce("b", 60_000, 1_001)).toBe(true);
    expect(replayCache.storeOnce("c", 60_000, 1_002)).toBe(true);

    expect(Object.keys(replayCache.snapshot(1_003))).toHaveLength(2);
    expect(replayCache.has("a", 1_003)).toBe(false);
    expect(replayCache.has("b", 1_003)).toBe(true);
    expect(replayCache.has("c", 1_003)).toBe(true);
  });

  it("uses Redis replay cache through SCRIPT LOAD and EVALSHA", async () => {
    const seen = new Set<string>();
    const calls: string[] = [];
    const replayCache = new RedisReplayCache(
      {
        async load(script) {
          calls.push(`load:${script.slice(0, 12)}`);
          return "sha-replay";
        },
        async runSha(_sha, options) {
          calls.push(`sha:${options.keys[0] ?? ""}`);
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
      },
      { keyPrefix: "test:" }
    );

    await expect(replayCache.storeOnce("dpop:jkt:jti", 5_000, 1_000)).resolves.toBe(true);
    await expect(replayCache.storeOnce("dpop:jkt:jti", 5_000, 1_001)).resolves.toBe(false);
    expect(calls).toEqual(["load:local stored", "sha:test:dpop:jkt:jti", "sha:test:dpop:jkt:jti"]);
  });

  it("verifies HTTP Message Signatures and rejects nonce replay", () => {
    const keys = generateKeyPairSync("ed25519");
    const nowSeconds = 1_776_000_000;
    const signatureInput = `sig1=("@method" "@path" "authorization" "dpop");created=${nowSeconds};expires=${
      nowSeconds + 300
    };keyid="agent-key-1";alg="ed25519";nonce="nonce_123"`;
    const request = {
      method: "GET",
      url: "https://site.example.com/checkout?x=1",
      headers: {
        authorization: "DPoP session",
        dpop: "proof",
        "signature-input": signatureInput
      }
    };
    const base = buildSignatureBase(request, parseSignatureInput(signatureInput));
    const signature = nodeSign(null, Buffer.from(base, "utf8"), keys.privateKey);
    const signedRequest = {
      ...request,
      headers: {
        ...request.headers,
        signature: `sig1=:${base64Url(signature)}:`
      }
    };

    expect(
      verifyHttpMessageSignature({
        request: signedRequest,
        publicJwk: keys.publicKey.export({ format: "jwk" }),
        now: new Date(nowSeconds * 1000),
        requireNonce: true
      }).label
    ).toBe("sig1");

    const replayCache = new MemoryReplayCache();
    expect(
      verifyHttpMessageSignature({
        request: signedRequest,
        publicJwk: keys.publicKey.export({ format: "jwk" }),
        now: new Date(nowSeconds * 1000),
        replayCache,
        requireNonce: true
      }).label
    ).toBe("sig1");
    expect(() =>
      verifyHttpMessageSignature({
        request: signedRequest,
        publicJwk: keys.publicKey.export({ format: "jwk" }),
        now: new Date(nowSeconds * 1000),
        replayCache,
        requireNonce: true
      })
    ).toThrow(/replay/);
  });

  it("supports async replay caches in DPoP and HTTP Message Signature verification", async () => {
    const dpopKeys = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const httpKeys = generateKeyPairSync("ed25519");
    const dpopPublicJwk = dpopKeys.publicKey.export({ format: "jwk" });
    const proofJkt = canonicalJwkThumbprintBase64Url(dpopPublicJwk);
    const nowSeconds = 1_776_000_000;
    const dpopProof = signCompactJws(
      {
        htm: "GET",
        htu: "https://site.example.com/checkout",
        jti: "jti_async",
        iat: nowSeconds
      },
      dpopKeys.privateKey,
      "ES256",
      { typ: "dpop+jwt", jwk: dpopPublicJwk }
    );
    const signatureInput = `sig1=("@method" "@path" "dpop");created=${nowSeconds};expires=${
      nowSeconds + 300
    };keyid="agent-key-async";alg="ed25519";nonce="nonce_async"`;
    const request = {
      method: "GET",
      url: "https://site.example.com/checkout",
      headers: {
        dpop: dpopProof,
        "signature-input": signatureInput
      }
    };
    const signatureBase = buildSignatureBase(request, parseSignatureInput(signatureInput));
    const signature = nodeSign(null, Buffer.from(signatureBase, "utf8"), httpKeys.privateKey);
    const signedRequest = {
      ...request,
      headers: {
        ...request.headers,
        signature: `sig1=:${base64Url(signature)}:`
      }
    };
    const seen = new Set<string>();
    const replayCache = {
      asyncReplayCache: true,
      async storeOnce(key: string) {
        if (seen.has(key)) {
          return false;
        }
        seen.add(key);
        return true;
      }
    } as const;

    await expect(
      verifyDpopProofAsync({
        proofJwt: dpopProof,
        method: "GET",
        url: "https://site.example.com/checkout",
        expectedJwkThumbprint: proofJkt,
        now: new Date(nowSeconds * 1000),
        replayCache
      })
    ).resolves.toMatchObject({ jwkThumbprint: proofJkt });
    await expect(
      verifyHttpMessageSignatureAsync({
        request: signedRequest,
        publicJwk: httpKeys.publicKey.export({ format: "jwk" }),
        now: new Date(nowSeconds * 1000),
        replayCache,
        requireNonce: true
      })
    ).resolves.toMatchObject({ label: "sig1" });
    await expect(
      verifyDpopProofAsync({
        proofJwt: dpopProof,
        method: "GET",
        url: "https://site.example.com/checkout",
        expectedJwkThumbprint: proofJkt,
        now: new Date(nowSeconds * 1000),
        replayCache
      })
    ).rejects.toThrow(/replay/);
    await expect(
      verifyHttpMessageSignatureAsync({
        request: signedRequest,
        publicJwk: httpKeys.publicKey.export({ format: "jwk" }),
        now: new Date(nowSeconds * 1000),
        replayCache,
        requireNonce: true
      })
    ).rejects.toThrow(/replay/);
  });
});
