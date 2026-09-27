import { createPublicKey, sign as nodeSign, verify as nodeVerify, type KeyObject } from "node:crypto";

import { base64Url, base64UrlToBuffer } from "./digest.js";
import type { PublicJwk } from "./jwkThumbprint.js";

export type JwsAlg = "EdDSA" | "ES256";

export interface DecodedCompactJwt {
  readonly header: Record<string, unknown>;
  readonly payload: Record<string, unknown>;
  readonly signingInput: string;
  readonly signature: Buffer;
}

function jsonToBase64Url(value: Record<string, unknown>): string {
  return base64Url(Buffer.from(JSON.stringify(value), "utf8"));
}

function parseJsonPart(part: string, name: string): Record<string, unknown> {
  try {
    const parsed = JSON.parse(base64UrlToBuffer(part).toString("utf8"));
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error(`${name} must be a JSON object`);
    }
    return parsed as Record<string, unknown>;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`invalid compact JWT ${name}: ${message}`);
  }
}

function publicKeyFromJwk(publicJwk: PublicJwk) {
  return createPublicKey({ key: publicJwk, format: "jwk" } as never);
}

export function decodeCompactJwt(token: string): DecodedCompactJwt {
  const parts = token.split(".");
  if (parts.length !== 3 || parts.some((part) => part.length === 0)) {
    throw new Error("compact JWT must contain three non-empty parts");
  }
  const [encodedHeader, encodedPayload, encodedSignature] = parts as [string, string, string];
  return {
    header: parseJsonPart(encodedHeader, "header"),
    payload: parseJsonPart(encodedPayload, "payload"),
    signingInput: `${encodedHeader}.${encodedPayload}`,
    signature: base64UrlToBuffer(encodedSignature)
  };
}

export function verifyCompactJws(token: string, publicJwk: PublicJwk, expectedAlg?: JwsAlg): DecodedCompactJwt {
  const decoded = decodeCompactJwt(token);
  const alg = decoded.header.alg;
  if (alg !== "EdDSA" && alg !== "ES256") {
    throw new Error(`unsupported JWS alg: ${String(alg)}`);
  }
  if (expectedAlg !== undefined && alg !== expectedAlg) {
    throw new Error(`unexpected JWS alg: expected ${expectedAlg}, got ${alg}`);
  }

  const data = Buffer.from(decoded.signingInput, "ascii");
  const publicKey = publicKeyFromJwk(publicJwk);
  const verified =
    alg === "EdDSA"
      ? nodeVerify(null, data, publicKey, decoded.signature)
      : nodeVerify("sha256", data, { key: publicKey, dsaEncoding: "ieee-p1363" }, decoded.signature);

  if (!verified) {
    throw new Error("JWS signature verification failed");
  }
  return decoded;
}

export function signCompactJws(
  payload: Record<string, unknown>,
  privateKey: KeyObject,
  alg: JwsAlg,
  protectedHeader: Record<string, unknown> = {}
): string {
  const header = { typ: "JWT", ...protectedHeader, alg };
  const signingInput = `${jsonToBase64Url(header)}.${jsonToBase64Url(payload)}`;
  const signature =
    alg === "EdDSA"
      ? nodeSign(null, Buffer.from(signingInput, "ascii"), privateKey)
      : nodeSign("sha256", Buffer.from(signingInput, "ascii"), { key: privateKey, dsaEncoding: "ieee-p1363" });
  return `${signingInput}.${base64Url(signature)}`;
}
