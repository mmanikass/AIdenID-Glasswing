import { createPublicKey, verify as nodeVerify } from "node:crypto";

import type { PublicJwk } from "./jwkThumbprint.js";

export type SignatureInput = string | Uint8Array;

function toBuffer(input: SignatureInput): Buffer {
  return typeof input === "string" ? Buffer.from(input, "utf8") : Buffer.from(input);
}

function publicKeyFromJwk(publicJwk: PublicJwk) {
  return createPublicKey({ key: publicJwk, format: "jwk" } as never);
}

export interface VerifySignatureInput {
  readonly publicJwk: PublicJwk;
  readonly payload: SignatureInput;
  readonly signature: SignatureInput;
}

export function verifyEd25519Signature(input: VerifySignatureInput): boolean {
  return nodeVerify(null, toBuffer(input.payload), publicKeyFromJwk(input.publicJwk), toBuffer(input.signature));
}

export function verifyP256Signature(input: VerifySignatureInput): boolean {
  return nodeVerify(
    "sha256",
    toBuffer(input.payload),
    { key: publicKeyFromJwk(input.publicJwk), dsaEncoding: "ieee-p1363" },
    toBuffer(input.signature)
  );
}
