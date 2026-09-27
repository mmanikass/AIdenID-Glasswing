import { generateKeyPairSync, sign as nodeSign } from "node:crypto";

import { describe, expect, it } from "vitest";

import { verifyEd25519Signature, verifyP256Signature } from "../src/index.js";

describe("signature verification", () => {
  it("verifies Ed25519 signatures from public JWKs", () => {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const payload = Buffer.from("signed request components");
    const signature = nodeSign(null, payload, privateKey);
    const publicJwk = publicKey.export({ format: "jwk" });

    expect(verifyEd25519Signature({ publicJwk, payload, signature })).toBe(true);
    expect(verifyEd25519Signature({ publicJwk, payload: Buffer.from("tampered"), signature })).toBe(false);
  });

  it("verifies P-256 signatures from public JWKs using JOSE raw encoding", () => {
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const payload = Buffer.from("signed request components");
    const signature = nodeSign("sha256", payload, { key: privateKey, dsaEncoding: "ieee-p1363" });
    const publicJwk = publicKey.export({ format: "jwk" });

    expect(verifyP256Signature({ publicJwk, payload, signature })).toBe(true);
    expect(verifyP256Signature({ publicJwk, payload, signature: Buffer.from(signature).reverse() })).toBe(false);
  });
});
