import { verifyCompactJws } from "./jwt.js";
import type { PublicJwk } from "./jwkThumbprint.js";

const LLM_BRAND_PATTERN = /^[a-z][a-z0-9_-]{0,31}$/;

export interface VerifiedSessionToken {
  readonly header: Record<string, unknown>;
  readonly claims: Record<string, unknown>;
}

export interface VerifySessionTokenInput {
  readonly token: string;
  readonly publicJwk: PublicJwk;
  readonly expectedAudience: string;
  readonly expectedResource: string;
  readonly expectedProofJkt: string;
  readonly now?: Date | undefined;
  readonly minRevocationEpoch?: number | undefined;
}

function requireStringClaim(claims: Record<string, unknown>, name: string): string {
  const value = claims[name];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`session token claim '${name}' is required`);
  }
  return value;
}

function requireNumberClaim(claims: Record<string, unknown>, name: string): number {
  const value = claims[name];
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new Error(`session token claim '${name}' is required`);
  }
  return value;
}

function requireStringArrayClaim(claims: Record<string, unknown>, name: string): readonly string[] {
  const value = claims[name];
  if (!Array.isArray(value)) {
    throw new Error(`session token claim '${name}' is required`);
  }
  const strings = value.map((item) => (typeof item === "string" ? item.trim() : ""));
  if (strings.length === 0 || strings.some((item) => item.length === 0)) {
    throw new Error(`session token claim '${name}' is required`);
  }
  return strings;
}

function optionalLlmBrandClaim(claims: Record<string, unknown>): string | undefined {
  const value = claims.llm_brand;
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== "string") {
    throw new Error("session token llm_brand claim must be a string");
  }
  const trimmed = value.trim();
  if (!LLM_BRAND_PATTERN.test(trimmed)) {
    throw new Error("session token llm_brand claim is invalid");
  }
  return trimmed;
}

export function verifySessionToken(input: VerifySessionTokenInput): VerifiedSessionToken {
  const decoded = verifyCompactJws(input.token, input.publicJwk);
  const claims = decoded.payload;
  const nowSeconds = Math.floor((input.now ?? new Date()).getTime() / 1000);

  const subject = requireStringClaim(claims, "sub");
  const audience = requireStringClaim(claims, "aud");
  const siteId = requireStringClaim(claims, "site_id");
  const resource = requireStringClaim(claims, "resource");
  const grantId = requireStringClaim(claims, "grant_id");
  const chainId = requireStringClaim(claims, "chain_id");
  const permissions = requireStringArrayClaim(claims, "permissions");

  if (audience !== input.expectedAudience) {
    throw new Error("session token audience mismatch");
  }
  if (siteId !== input.expectedAudience) {
    throw new Error("session token site_id mismatch");
  }
  if (resource !== input.expectedResource) {
    throw new Error("session token resource mismatch");
  }
  if (requireNumberClaim(claims, "exp") <= nowSeconds) {
    throw new Error("session token expired");
  }
  const nbf = claims.nbf;
  if (typeof nbf === "number" && nbf > nowSeconds) {
    throw new Error("session token not yet valid");
  }

  const cnf = claims.cnf;
  if (cnf === null || typeof cnf !== "object" || Array.isArray(cnf)) {
    throw new Error("session token cnf claim is required");
  }
  const proofJkt = (cnf as Record<string, unknown>).jkt;
  if (proofJkt !== input.expectedProofJkt) {
    throw new Error("session token proof key thumbprint mismatch");
  }

  const tokenEpoch = requireNumberClaim(claims, "revocation_epoch");
  if (input.minRevocationEpoch !== undefined && tokenEpoch < input.minRevocationEpoch) {
    throw new Error("session token revoked by epoch");
  }
  const llmBrand = optionalLlmBrandClaim(claims);

  return {
    header: decoded.header,
    claims: {
      ...claims,
      sub: subject,
      aud: audience,
      site_id: siteId,
      resource,
      grant_id: grantId,
      chain_id: chainId,
      permissions,
      ...(llmBrand === undefined ? {} : { llm_brand: llmBrand })
    }
  };
}
