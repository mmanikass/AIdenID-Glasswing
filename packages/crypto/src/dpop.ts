import { URL } from "node:url";

import { canonicalJwkThumbprintBase64Url, type PublicJwk } from "./jwkThumbprint.js";
import { verifyCompactJws } from "./jwt.js";
import { requireFreshReplayKey, requireFreshReplayKeyAsync, type ReplayCache, type ReplayCacheLike } from "./replayCache.js";

const RELATIVE_URL_BASE = "https://aidenid.local";

export interface VerifiedDpopProof {
  readonly header: Record<string, unknown>;
  readonly claims: Record<string, unknown>;
  readonly publicJwk: PublicJwk;
  readonly jwkThumbprint: string;
}

export interface VerifyDpopProofInput {
  readonly proofJwt: string;
  readonly method: string;
  readonly url: string;
  readonly expectedJwkThumbprint: string;
  readonly now?: Date | undefined;
  readonly maxAgeSeconds?: number | undefined;
  readonly replayCache?: ReplayCache | undefined;
}

export interface VerifyDpopProofAsyncInput extends Omit<VerifyDpopProofInput, "replayCache"> {
  readonly replayCache?: ReplayCacheLike | undefined;
}

function normalizeHtu(url: string): string {
  const parsed = new URL(url, RELATIVE_URL_BASE);
  parsed.hash = "";
  return parsed.toString();
}

interface DpopReplayCheck {
  readonly key: string;
  readonly ttlMs: number;
  readonly nowMs: number;
}

function verifyDpopProofCore(input: VerifyDpopProofAsyncInput): {
  readonly verified: VerifiedDpopProof;
  readonly replayCheck?: DpopReplayCheck | undefined;
} {
  const decoded = (() => {
    const unverified = input.proofJwt.split(".");
    if (unverified.length !== 3) {
      throw new Error("DPoP proof must be a compact JWT");
    }
    const header = JSON.parse(Buffer.from(unverified[0] ?? "", "base64url").toString("utf8")) as Record<string, unknown>;
    const jwk = header.jwk;
    if (jwk === null || typeof jwk !== "object" || Array.isArray(jwk)) {
      throw new Error("DPoP proof header jwk is required");
    }
    return verifyCompactJws(input.proofJwt, jwk as PublicJwk);
  })();

  const publicJwk = decoded.header.jwk as PublicJwk;
  const jwkThumbprint = canonicalJwkThumbprintBase64Url(publicJwk);
  if (jwkThumbprint !== input.expectedJwkThumbprint) {
    throw new Error("DPoP proof key thumbprint mismatch");
  }

  const htm = decoded.payload.htm;
  if (typeof htm !== "string" || htm.toUpperCase() !== input.method.toUpperCase()) {
    throw new Error("DPoP htm mismatch");
  }
  const htu = decoded.payload.htu;
  if (typeof htu !== "string" || normalizeHtu(htu) !== normalizeHtu(input.url)) {
    throw new Error("DPoP htu mismatch");
  }
  if (typeof decoded.payload.jti !== "string" || decoded.payload.jti.length === 0) {
    throw new Error("DPoP jti is required");
  }
  const iat = decoded.payload.iat;
  if (typeof iat !== "number" || !Number.isFinite(iat)) {
    throw new Error("DPoP iat is required");
  }
  const now = input.now ?? new Date();
  const nowSeconds = Math.floor(now.getTime() / 1000);
  const maxAge = input.maxAgeSeconds ?? 300;
  if (iat > nowSeconds + 30 || iat < nowSeconds - maxAge) {
    throw new Error("DPoP proof outside accepted time window");
  }

  return {
    verified: { header: decoded.header, claims: decoded.payload, publicJwk, jwkThumbprint },
    replayCheck: {
      key: `dpop:${jwkThumbprint}:${decoded.payload.jti}`,
      ttlMs: Math.max(1_000, (iat + maxAge + 30 - nowSeconds) * 1000),
      nowMs: now.getTime()
    }
  };
}

export function verifyDpopProof(input: VerifyDpopProofInput): VerifiedDpopProof {
  const { verified, replayCheck } = verifyDpopProofCore(input);
  if (input.replayCache !== undefined && replayCheck !== undefined) {
    requireFreshReplayKey(input.replayCache, replayCheck.key, replayCheck.ttlMs, replayCheck.nowMs, "DPoP");
  }
  return verified;
}

export async function verifyDpopProofAsync(input: VerifyDpopProofAsyncInput): Promise<VerifiedDpopProof> {
  const { verified, replayCheck } = verifyDpopProofCore(input);
  if (input.replayCache !== undefined && replayCheck !== undefined) {
    await requireFreshReplayKeyAsync(input.replayCache, replayCheck.key, replayCheck.ttlMs, replayCheck.nowMs, "DPoP");
  }
  return verified;
}
