import { createPrivateKey, generateKeyPairSync } from "node:crypto";

import { decodeCompactJwt, verifyCompactJws } from "@aidenid/crypto";
import { describe, expect, it } from "vitest";

import { createControlPlaneRuntime, sessionSignerFromOptions } from "../src/index.js";
import { SESSION_JWKS_PATH } from "../src/routes/sessions.js";

const ADMIN_TOKEN = "test_operator_token_admin_123456";
const OPERATOR_AUTH = {
  entries: [{ actorId: "platform_admin", token: ADMIN_TOKEN, roles: ["admin"] }]
} as const;
const ADMIN_HEADERS = { Authorization: `Bearer ${ADMIN_TOKEN}` };

type Runtime = Awaited<ReturnType<typeof createControlPlaneRuntime>>;

async function exchangeOnce(runtime: Runtime): Promise<string> {
  const target = (
    await runtime.app.inject({
      method: "POST",
      url: "/v1/targets",
      headers: ADMIN_HEADERS,
      payload: { tenant_id: "ten_demo", site_id: "sit_signer", name: "Signer Shop", origin: "https://signer.example.com" }
    })
  ).json<{ id: string; site_id: string; origin: string }>();
  const grant = (
    await runtime.app.inject({
      method: "POST",
      url: "/v1/grants",
      headers: ADMIN_HEADERS,
      payload: { target_id: target.id, subject: "agent:gpt-luna-xh", resource: target.origin, permissions: ["catalog:read"], expires_in_seconds: 600 }
    })
  ).json<{ id: string }>();
  const session = await runtime.app.inject({
    method: "POST",
    url: "/v1/sessions/exchange",
    payload: { grant_id: grant.id, audience: target.site_id, resource: target.origin, proof_jkt: "proof-thumbprint-signer", requested_permissions: ["catalog:read"] }
  });
  expect(session.statusCode).toBe(201);
  return session.json<{ access_token: string }>().access_token;
}

describe("session signer", () => {
  it("publishes the verification key and mints tokens that verify with it (per-process default)", async () => {
    const runtime = await createControlPlaneRuntime({ operatorAuth: OPERATOR_AUTH });
    try {
      const jwks = await runtime.app.inject({ method: "GET", url: SESSION_JWKS_PATH });
      expect(jwks.statusCode).toBe(200);
      const body = jwks.json<{ issuer: string; keys: Array<Record<string, unknown>> }>();
      expect(body.issuer).toBe(runtime.services.issuer);
      expect(body.keys).toHaveLength(1);
      expect(body.keys[0]).toEqual({ kty: "OKP", crv: "Ed25519", x: expect.any(String), kid: "cpk_local_ed25519", use: "sig", alg: "EdDSA" });
      expect(JSON.stringify(body)).not.toContain('"d"');

      const token = await exchangeOnce(runtime);
      expect(decodeCompactJwt(token).header).toMatchObject({ alg: "EdDSA", kid: "cpk_local_ed25519" });
      const verified = verifyCompactJws(token, body.keys[0]!, "EdDSA");
      expect(verified.payload).toMatchObject({ iss: runtime.services.issuer, aud: "sit_signer" });
    } finally {
      await runtime.app.close();
    }
  });

  it("uses an injected signing key, so a second process holding the public JWK can verify", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const runtime = await createControlPlaneRuntime({ operatorAuth: OPERATOR_AUTH, sessionSigningKey: { kid: "cpk_demo_2026", privateKey } });
    try {
      const token = await exchangeOnce(runtime);
      expect(decodeCompactJwt(token).header).toMatchObject({ kid: "cpk_demo_2026" });
      const exported = publicKey.export({ format: "jwk" }) as Record<string, unknown>;
      expect(() => verifyCompactJws(token, { kty: exported.kty, crv: exported.crv, x: exported.x }, "EdDSA")).not.toThrow();
      expect(runtime.services.sessionSigner.publicJwk).toEqual({ kty: "OKP", crv: "Ed25519", x: exported.x });
    } finally {
      await runtime.app.close();
    }
  });

  it("loads the signing key from AIDENID_CONTROL_PLANE_SESSION_SIGNING_JWK and rejects a key without kid or of the wrong type", () => {
    const { privateKey } = generateKeyPairSync("ed25519");
    const jwk = privateKey.export({ format: "jwk" }) as Record<string, unknown>;
    const signer = sessionSignerFromOptions({}, { AIDENID_CONTROL_PLANE_SESSION_SIGNING_JWK: JSON.stringify({ ...jwk, kid: "cpk_env" }) });
    expect(signer.kid).toBe("cpk_env");
    expect(signer.publicJwk).toEqual({ kty: "OKP", crv: "Ed25519", x: jwk.x });
    // The same private key round-trips: what the env said is what signs.
    expect(createPrivateKey({ key: jwk, format: "jwk" } as never).export({ format: "jwk" })).toEqual(signer.privateKey.export({ format: "jwk" }));

    expect(() => sessionSignerFromOptions({}, { AIDENID_CONTROL_PLANE_SESSION_SIGNING_JWK: JSON.stringify(jwk) })).toThrow(/kid/);
    expect(() => sessionSignerFromOptions({}, { AIDENID_CONTROL_PLANE_SESSION_SIGNING_JWK: "not-json" })).toThrow(/JSON private JWK/);
    const ec = generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey;
    expect(() => sessionSignerFromOptions({ sessionSigningKey: { kid: "cpk_ec", privateKey: ec } })).toThrow(/Ed25519/);

    // Two default signers are independent per-process keys.
    expect(sessionSignerFromOptions({}, {}).publicJwk).not.toEqual(sessionSignerFromOptions({}, {}).publicJwk);
  });
});
