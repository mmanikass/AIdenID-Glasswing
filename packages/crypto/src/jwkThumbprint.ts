import { base64Url, sha256Bytes, sha256Hex } from "./digest.js";

export type PublicJwk = Record<string, unknown>;

const OKP_THUMBPRINT_MEMBERS = ["crv", "kty", "x"] as const;
const EC_THUMBPRINT_MEMBERS = ["crv", "kty", "x", "y"] as const;

function requireStringMember(jwk: PublicJwk, member: string): string {
  const value = jwk[member];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`JWK member '${member}' is required for thumbprint`);
  }
  return value;
}

function canonicalThumbprintJson(jwk: PublicJwk): string {
  const kty = requireStringMember(jwk, "kty");
  const members =
    kty === "OKP" ? OKP_THUMBPRINT_MEMBERS : kty === "EC" ? EC_THUMBPRINT_MEMBERS : null;
  if (members === null) {
    throw new Error(`unsupported JWK kty for thumbprint: ${kty}`);
  }

  const canonical: Record<string, string> = {};
  for (const member of members) {
    canonical[member] = requireStringMember(jwk, member);
  }
  return JSON.stringify(canonical);
}

export function canonicalJwkThumbprintSha256(jwk: PublicJwk): string {
  return sha256Hex(canonicalThumbprintJson(jwk));
}

export function canonicalJwkThumbprintBase64Url(jwk: PublicJwk): string {
  return base64Url(sha256Bytes(canonicalThumbprintJson(jwk)));
}
