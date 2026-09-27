import {
  canonicalJwkThumbprintBase64Url,
  decodeCompactJwt,
  isAsyncReplayCache,
  parseSignatureInput,
  verifyDpopProof,
  verifyDpopProofAsync,
  verifyHttpMessageSignature,
  verifyHttpMessageSignatureAsync,
  verifySessionToken
} from "@aidenid/crypto";

import { readHeader } from "./headers.js";
import type { ReasonCode, RequestHeaders, VerifierCryptoOptions } from "./types.js";

const RELATIVE_URL_BASE = "https://aidenid.local";

export interface CryptoPathRequest {
  readonly method: string;
  readonly url: string;
  readonly headers?: RequestHeaders | undefined;
}

export interface CryptoDelegationEvidence {
  readonly grantId: string;
  readonly chainId: string;
  readonly audience: string;
  readonly resource: string;
  readonly siteId: string;
  readonly permissions: readonly string[];
  readonly proofJkt: string;
  readonly revocationEpoch: number;
}

export interface CryptoPathResult {
  readonly verified: boolean;
  readonly issuer?: string | undefined;
  readonly subject?: string | undefined;
  readonly llmBrand?: string | undefined;
  readonly delegation?: CryptoDelegationEvidence | undefined;
  readonly reason?:
    | Extract<
        ReasonCode,
        | "missing_signature"
        | "bad_signature"
        | "unknown_issuer"
        | "issuer_key_rotation_pending"
        | "audience_mismatch"
        | "resource_mismatch"
        | "token_expired"
        | "revoked"
      >
    | undefined;
  readonly error?: string | undefined;
}

function headerRecord(headers: RequestHeaders | undefined): Record<string, string | undefined> {
  const names = ["authorization", "dpop", "signature", "signature-input"];
  const record: Record<string, string | undefined> = {};
  for (const name of names) {
    record[name] = readHeader(headers, name);
  }
  return record;
}

function sessionTokenFromAuthorization(headers: RequestHeaders | undefined): string | undefined {
  const authorization = readHeader(headers, "authorization") ?? "";
  const match = authorization.match(/^DPoP\s+(.+)$/i);
  return match?.[1]?.trim();
}

function normalizedResource(url: string): string {
  return new URL(url, RELATIVE_URL_BASE).toString();
}

function optionalLlmBrand(claims: Readonly<Record<string, unknown>>): string | undefined {
  return typeof claims.llm_brand === "string" ? claims.llm_brand : undefined;
}

function stringClaim(claims: Readonly<Record<string, unknown>>, name: string): string {
  const value = claims[name];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`session token claim '${name}' is required`);
  }
  return value;
}

function numberClaim(claims: Readonly<Record<string, unknown>>, name: string): number {
  const value = claims[name];
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new Error(`session token claim '${name}' is required`);
  }
  return value;
}

function stringArrayClaim(claims: Readonly<Record<string, unknown>>, name: string): readonly string[] {
  const value = claims[name];
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string" || item.length === 0)) {
    throw new Error(`session token claim '${name}' is required`);
  }
  return value as readonly string[];
}

function delegationEvidenceFromClaims(
  claims: Readonly<Record<string, unknown>>,
  proofJkt: string
): CryptoDelegationEvidence {
  return {
    grantId: stringClaim(claims, "grant_id"),
    chainId: stringClaim(claims, "chain_id"),
    audience: stringClaim(claims, "aud"),
    resource: stringClaim(claims, "resource"),
    siteId: stringClaim(claims, "site_id"),
    permissions: stringArrayClaim(claims, "permissions"),
    proofJkt,
    revocationEpoch: numberClaim(claims, "revocation_epoch")
  };
}

function reasonFromError(error: unknown): CryptoPathResult["reason"] {
  const message = error instanceof Error ? error.message : String(error);
  if (message.includes("audience mismatch")) {
    return "audience_mismatch";
  }
  if (message.includes("resource mismatch") || message.includes("proof key thumbprint mismatch")) {
    return "resource_mismatch";
  }
  if (message.includes("expired")) {
    return "token_expired";
  }
  if (message.includes("revoked")) {
    return "revoked";
  }
  return "bad_signature";
}

export function verifyCryptoPath(
  request: CryptoPathRequest,
  siteId: string,
  crypto: VerifierCryptoOptions,
  now: Date
): CryptoPathResult {
  try {
    const sessionToken = sessionTokenFromAuthorization(request.headers);
    const dpopProof = readHeader(request.headers, "dpop");
    const signatureInput = readHeader(request.headers, "signature-input");
    if (sessionToken === undefined || dpopProof === undefined || signatureInput === undefined) {
      return { verified: false, reason: "missing_signature", error: "missing session token, DPoP proof, or Signature-Input" };
    }

    const parsedSession = decodeCompactJwt(sessionToken);
    const issuer = parsedSession.payload.iss;
    if (typeof issuer !== "string") {
      throw new Error("session token issuer is required");
    }
    const sessionKid = parsedSession.header.kid;
    if (typeof sessionKid === "string") {
      const keyState = crypto.issuerKeyStatesByIssuer?.[issuer]?.[sessionKid];
      if (keyState === "rotation_pending" || keyState === "tofu_pending") {
        return { verified: false, reason: "issuer_key_rotation_pending", error: `issuer key ${sessionKid} is not approved` };
      }
      if (keyState === "revoked") {
        return { verified: false, reason: "revoked", error: `issuer key ${sessionKid} is revoked` };
      }
    }
    const sessionPublicJwk = crypto.sessionTokenPublicJwksByIssuer[issuer];
    if (sessionPublicJwk === undefined) {
      return { verified: false, reason: "unknown_issuer", error: `no trusted session public key for issuer ${issuer}` };
    }

    const dpopHeader = decodeCompactJwt(dpopProof).header;
    const dpopJwk = dpopHeader.jwk;
    if (dpopJwk === null || typeof dpopJwk !== "object" || Array.isArray(dpopJwk)) {
      throw new Error("DPoP proof jwk is required");
    }
    const proofJkt = canonicalJwkThumbprintBase64Url(dpopJwk as Record<string, unknown>);
    const resource = normalizedResource(request.url);

    const replayCache = crypto.replayCache;
    if (isAsyncReplayCache(replayCache)) {
      throw new Error("async replay cache requires async crypto path verification");
    }

    const verifiedSession = verifySessionToken({
      token: sessionToken,
      publicJwk: sessionPublicJwk,
      expectedAudience: siteId,
      expectedResource: resource,
      expectedProofJkt: proofJkt,
      minRevocationEpoch: crypto.minRevocationEpoch,
      now
    });
    verifyDpopProof({
      proofJwt: dpopProof,
      method: request.method,
      url: resource,
      expectedJwkThumbprint: proofJkt,
      now,
      replayCache
    });

    const parsedSignatureInput = parseSignatureInput(signatureInput);
    const keyId = parsedSignatureInput.params.keyid;
    if (typeof keyId !== "string" || keyId.length === 0) {
      throw new Error("HTTP message signature keyid is required");
    }
    const httpPublicJwk = crypto.httpMessageSignaturePublicJwksByKeyId[keyId];
    if (httpPublicJwk === undefined) {
      throw new Error(`no trusted HTTP signature public key for keyid ${keyId}`);
    }
    verifyHttpMessageSignature({
      request: {
        method: request.method,
        url: resource,
        headers: headerRecord(request.headers)
      },
      publicJwk: httpPublicJwk,
      now,
      maxAgeSeconds: 60,
      replayCache,
      requireNonce: crypto.requireHttpSignatureNonce ?? true
    });

    return {
      verified: true,
      issuer,
      subject: typeof verifiedSession.claims.sub === "string" ? verifiedSession.claims.sub : undefined,
      llmBrand: optionalLlmBrand(verifiedSession.claims),
      delegation: delegationEvidenceFromClaims(verifiedSession.claims, proofJkt)
    };
  } catch (error) {
    return { verified: false, reason: reasonFromError(error), error: error instanceof Error ? error.message : String(error) };
  }
}

export async function verifyCryptoPathAsync(
  request: CryptoPathRequest,
  siteId: string,
  crypto: VerifierCryptoOptions,
  now: Date
): Promise<CryptoPathResult> {
  try {
    const sessionToken = sessionTokenFromAuthorization(request.headers);
    const dpopProof = readHeader(request.headers, "dpop");
    const signatureInput = readHeader(request.headers, "signature-input");
    if (sessionToken === undefined || dpopProof === undefined || signatureInput === undefined) {
      return { verified: false, reason: "missing_signature", error: "missing session token, DPoP proof, or Signature-Input" };
    }

    const parsedSession = decodeCompactJwt(sessionToken);
    const issuer = parsedSession.payload.iss;
    if (typeof issuer !== "string") {
      throw new Error("session token issuer is required");
    }
    const sessionKid = parsedSession.header.kid;
    if (typeof sessionKid === "string") {
      const keyState = crypto.issuerKeyStatesByIssuer?.[issuer]?.[sessionKid];
      if (keyState === "rotation_pending" || keyState === "tofu_pending") {
        return { verified: false, reason: "issuer_key_rotation_pending", error: `issuer key ${sessionKid} is not approved` };
      }
      if (keyState === "revoked") {
        return { verified: false, reason: "revoked", error: `issuer key ${sessionKid} is revoked` };
      }
    }
    const sessionPublicJwk = crypto.sessionTokenPublicJwksByIssuer[issuer];
    if (sessionPublicJwk === undefined) {
      return { verified: false, reason: "unknown_issuer", error: `no trusted session public key for issuer ${issuer}` };
    }

    const dpopHeader = decodeCompactJwt(dpopProof).header;
    const dpopJwk = dpopHeader.jwk;
    if (dpopJwk === null || typeof dpopJwk !== "object" || Array.isArray(dpopJwk)) {
      throw new Error("DPoP proof jwk is required");
    }
    const proofJkt = canonicalJwkThumbprintBase64Url(dpopJwk as Record<string, unknown>);
    const resource = normalizedResource(request.url);

    const verifiedSession = verifySessionToken({
      token: sessionToken,
      publicJwk: sessionPublicJwk,
      expectedAudience: siteId,
      expectedResource: resource,
      expectedProofJkt: proofJkt,
      minRevocationEpoch: crypto.minRevocationEpoch,
      now
    });
    await verifyDpopProofAsync({
      proofJwt: dpopProof,
      method: request.method,
      url: resource,
      expectedJwkThumbprint: proofJkt,
      now,
      replayCache: crypto.replayCache
    });

    const parsedSignatureInput = parseSignatureInput(signatureInput);
    const keyId = parsedSignatureInput.params.keyid;
    if (typeof keyId !== "string" || keyId.length === 0) {
      throw new Error("HTTP message signature keyid is required");
    }
    const httpPublicJwk = crypto.httpMessageSignaturePublicJwksByKeyId[keyId];
    if (httpPublicJwk === undefined) {
      throw new Error(`no trusted HTTP signature public key for keyid ${keyId}`);
    }
    await verifyHttpMessageSignatureAsync({
      request: {
        method: request.method,
        url: resource,
        headers: headerRecord(request.headers)
      },
      publicJwk: httpPublicJwk,
      now,
      maxAgeSeconds: 60,
      replayCache: crypto.replayCache,
      requireNonce: crypto.requireHttpSignatureNonce ?? true
    });

    return {
      verified: true,
      issuer,
      subject: typeof verifiedSession.claims.sub === "string" ? verifiedSession.claims.sub : undefined,
      llmBrand: optionalLlmBrand(verifiedSession.claims),
      delegation: delegationEvidenceFromClaims(verifiedSession.claims, proofJkt)
    };
  } catch (error) {
    return { verified: false, reason: reasonFromError(error), error: error instanceof Error ? error.message : String(error) };
  }
}
