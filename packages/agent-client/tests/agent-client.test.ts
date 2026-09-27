import { generateKeyPairSync } from "node:crypto";

import { canonicalJwkThumbprintBase64Url, decodeCompactJwt, signCompactJws } from "@aidenid/crypto";
import { verifyCryptoPath, type VerifierCryptoOptions } from "@aidenid/verifier-node";
import { describe, expect, it } from "vitest";

import { buildSignedHeaders, createDpopProof, exchangeSession, httpSignatureTrustEntry, mintAgentKey, SessionExchangeError, signHttpRequest } from "../src/index.js";

const ISSUER = "https://api.aidenid.local";
const SITE_ID = "sit_glasswing";
const RESOURCE = "https://shop.example.test/api/catalog";

/** A stand-in for the control plane's session signer: Ed25519 issuer key + public JWK. */
function issuer() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const jwk = publicKey.export({ format: "jwk" }) as Record<string, unknown>;
  return { privateKey, publicJwk: { kty: jwk.kty, crv: jwk.crv, x: jwk.x } };
}

function sessionTokenFor(iss: ReturnType<typeof issuer>, proofJkt: string, overrides: Record<string, unknown> = {}): string {
  const now = Math.floor(Date.now() / 1000);
  return signCompactJws(
    {
      iss: ISSUER,
      sub: "agent:gpt-luna-xh",
      aud: SITE_ID,
      site_id: SITE_ID,
      resource: RESOURCE,
      grant_id: "grt_test",
      chain_id: "chn_test",
      permissions: ["catalog:read"],
      cnf: { jkt: proofJkt },
      revocation_epoch: 0,
      iat: now,
      nbf: now,
      exp: now + 90,
      ...overrides
    },
    iss.privateKey,
    "EdDSA",
    { kid: "cpk_test" }
  );
}

function cryptoOptions(iss: ReturnType<typeof issuer>, agent: ReturnType<typeof mintAgentKey>): VerifierCryptoOptions {
  return {
    sessionTokenPublicJwksByIssuer: { [ISSUER]: iss.publicJwk },
    httpMessageSignaturePublicJwksByKeyId: httpSignatureTrustEntry(agent),
    requireHttpSignatureNonce: true
  };
}

describe("agent key", () => {
  it("mints an Ed25519 key whose public JWK has no private members and a canonical thumbprint", () => {
    const key = mintAgentKey();
    expect(key.keyId).toMatch(/^agk_[0-9a-f]{32}$/);
    expect(key.publicJwk).toEqual({ kty: "OKP", crv: "Ed25519", x: expect.any(String) });
    expect(key.thumbprint).toBe(canonicalJwkThumbprintBase64Url(key.publicJwk));
    expect(JSON.stringify(key.publicJwk)).not.toContain('"d"');
  });
});

describe("signed request round trip against the verifier crypto path", () => {
  it("is verified with delegation evidence when the session is bound to this key", () => {
    const iss = issuer();
    const agent = mintAgentKey();
    const token = sessionTokenFor(iss, agent.thumbprint);
    const headers = buildSignedHeaders(agent, { method: "GET", url: RESOURCE, sessionToken: token, requestId: "req_1" });

    expect(headers.authorization).toBe(`DPoP ${token}`);
    expect(decodeCompactJwt(headers.dpop!).header).toMatchObject({ typ: "dpop+jwt", alg: "EdDSA", jwk: agent.publicJwk });
    expect(headers["signature-input"]).toContain(`keyid="${agent.keyId}"`);

    const result = verifyCryptoPath({ method: "GET", url: RESOURCE, headers }, SITE_ID, cryptoOptions(iss, agent), new Date());
    expect(result).toMatchObject({ verified: true, issuer: ISSUER, subject: "agent:gpt-luna-xh" });
    expect(result.delegation).toMatchObject({ grantId: "grt_test", chainId: "chn_test" });
  });

  it("fails when the method, the audience, the proof key, or the HTTP key does not match", () => {
    const iss = issuer();
    const agent = mintAgentKey();
    const token = sessionTokenFor(iss, agent.thumbprint);
    const headers = buildSignedHeaders(agent, { method: "GET", url: RESOURCE, sessionToken: token });

    // Signed for GET, presented as POST: the HTTP signature (and DPoP htm) no longer cover the request.
    expect(verifyCryptoPath({ method: "POST", url: RESOURCE, headers }, SITE_ID, cryptoOptions(iss, agent), new Date()).verified).toBe(false);

    // Token for another site.
    expect(verifyCryptoPath({ method: "GET", url: RESOURCE, headers }, "sit_other", cryptoOptions(iss, agent), new Date())).toMatchObject({
      verified: false,
      reason: "audience_mismatch"
    });

    // Session bound to a different agent key: the DPoP thumbprint does not match cnf.jkt.
    const stranger = mintAgentKey();
    const stolen = buildSignedHeaders(stranger, { method: "GET", url: RESOURCE, sessionToken: token });
    const options = { ...cryptoOptions(iss, agent), httpMessageSignaturePublicJwksByKeyId: { ...httpSignatureTrustEntry(agent), ...httpSignatureTrustEntry(stranger) } };
    expect(verifyCryptoPath({ method: "GET", url: RESOURCE, headers: stolen }, SITE_ID, options, new Date()).verified).toBe(false);

    // HTTP signature key not registered with the site.
    const unregistered = { ...cryptoOptions(iss, agent), httpMessageSignaturePublicJwksByKeyId: {} };
    expect(verifyCryptoPath({ method: "GET", url: RESOURCE, headers }, SITE_ID, unregistered, new Date()).verified).toBe(false);
  });

  it("refuses a token whose revocation epoch is below the verifier floor", () => {
    const iss = issuer();
    const agent = mintAgentKey();
    const token = sessionTokenFor(iss, agent.thumbprint, { revocation_epoch: 0 });
    const headers = buildSignedHeaders(agent, { method: "GET", url: RESOURCE, sessionToken: token });
    const result = verifyCryptoPath({ method: "GET", url: RESOURCE, headers }, SITE_ID, { ...cryptoOptions(iss, agent), minRevocationEpoch: 1 }, new Date());
    expect(result).toMatchObject({ verified: false, reason: "revoked" });
  });

  it("produces a DPoP proof and HTTP signature that expire and carry a fresh nonce per request", () => {
    const agent = mintAgentKey();
    const a = signHttpRequest(agent, { method: "GET", url: RESOURCE, dpop: createDpopProof(agent, { method: "GET", url: RESOURCE }) });
    const b = signHttpRequest(agent, { method: "GET", url: RESOURCE, dpop: createDpopProof(agent, { method: "GET", url: RESOURCE }) });
    expect(a["signature-input"]).not.toBe(b["signature-input"]);
    expect(a["signature-input"]).toMatch(/created=\d+;expires=\d+;nonce="http-[0-9a-f-]+";keyid="agk_[0-9a-f]+";alg="EdDSA"/);
  });
});

describe("exchangeSession", () => {
  it("posts the proof thumbprint and returns the session, or throws the control-plane refusal", async () => {
    const agent = mintAgentKey();
    const calls: Array<{ url: string; body: Record<string, unknown> }> = [];
    const ok: typeof fetch = async (url, init) => {
      calls.push({ url: String(url), body: JSON.parse(String(init?.body)) as Record<string, unknown> });
      return new Response(JSON.stringify({ access_token: "tok", token_type: "DPoP", expires_in: 90, session_id: "ses_1", revocation_epoch: 2 }), { status: 201 });
    };
    const session = await exchangeSession(agent, {
      controlPlaneUrl: "http://127.0.0.1:1/",
      grantId: "grt_1",
      audience: SITE_ID,
      resource: RESOURCE,
      requestedPermissions: ["catalog:read"],
      fetchImpl: ok
    });
    expect(session).toEqual({ accessToken: "tok", tokenType: "DPoP", expiresIn: 90, sessionId: "ses_1", revocationEpoch: 2 });
    expect(calls[0]).toEqual({
      url: "http://127.0.0.1:1/v1/sessions/exchange",
      body: { grant_id: "grt_1", audience: SITE_ID, resource: RESOURCE, proof_jkt: agent.thumbprint, requested_permissions: ["catalog:read"] }
    });

    const refused: typeof fetch = async () => new Response(JSON.stringify({ error: "grant_not_active" }), { status: 403 });
    await expect(
      exchangeSession(agent, { controlPlaneUrl: "http://127.0.0.1:1", grantId: "grt_1", audience: SITE_ID, resource: RESOURCE, requestedPermissions: ["catalog:read"], fetchImpl: refused })
    ).rejects.toMatchObject({ name: "SessionExchangeError", status: 403, code: "grant_not_active" } satisfies Partial<SessionExchangeError>);
  });
});
