import { randomUUID, sign as nodeSign } from "node:crypto";
import { URL } from "node:url";

import { buildSignatureBase, parseSignatureInput, signCompactJws } from "@aidenid/crypto";

import type { AgentKeyMaterial } from "./keys.js";

const RELATIVE_URL_BASE = "https://aidenid.local";
const SIGNATURE_LABEL = "sig1";
const DEFAULT_SIGNATURE_TTL_SECONDS = 60;

/** Same normalisation the verifier applies: absolute URL, fragment stripped. */
export function normalizeResource(url: string): string {
  const parsed = new URL(url, RELATIVE_URL_BASE);
  parsed.hash = "";
  return parsed.toString();
}

export interface DpopProofInput {
  readonly method: string;
  readonly url: string;
  readonly nowMs?: number | undefined;
  readonly jti?: string | undefined;
}

/** DPoP proof JWT (RFC 9449): header typ dpop+jwt + public jwk, claims htm/htu/jti/iat, EdDSA. */
export function createDpopProof(key: AgentKeyMaterial, input: DpopProofInput): string {
  const iat = Math.floor((input.nowMs ?? Date.now()) / 1000);
  return signCompactJws(
    {
      htm: input.method.toUpperCase(),
      htu: normalizeResource(input.url),
      jti: input.jti ?? `dpop-${randomUUID()}`,
      iat
    },
    key.privateKey,
    "EdDSA",
    { typ: "dpop+jwt", jwk: key.publicJwk }
  );
}

export interface HttpSignatureInput {
  readonly method: string;
  readonly url: string;
  readonly authorization?: string | undefined;
  readonly dpop: string;
  readonly nowMs?: number | undefined;
  readonly nonce?: string | undefined;
  readonly ttlSeconds?: number | undefined;
}

export interface HttpSignatureHeaders {
  readonly signature: string;
  readonly "signature-input": string;
}

/**
 * RFC 9421 HTTP message signature over @method, @target-uri, authorization (when present)
 * and dpop, with created/expires/nonce/keyid/alg params. The signature base is produced by
 * the same @aidenid/crypto builder the verifier uses, so client and verifier cannot drift.
 */
export function signHttpRequest(key: AgentKeyMaterial, input: HttpSignatureInput): HttpSignatureHeaders {
  const method = input.method.toUpperCase();
  const url = normalizeResource(input.url);
  const created = Math.floor((input.nowMs ?? Date.now()) / 1000);
  const expires = created + (input.ttlSeconds ?? DEFAULT_SIGNATURE_TTL_SECONDS);
  const nonce = input.nonce ?? `http-${randomUUID()}`;
  const components = input.authorization === undefined ? ["@method", "@target-uri", "dpop"] : ["@method", "@target-uri", "authorization", "dpop"];
  const params = `(${components.map((component) => `"${component}"`).join(" ")});created=${created};expires=${expires};nonce="${nonce}";keyid="${key.keyId}";alg="EdDSA"`;
  const signatureInput = `${SIGNATURE_LABEL}=${params}`;
  const parsed = parseSignatureInput(signatureInput);
  const base = buildSignatureBase(
    {
      method,
      url,
      headers: { authorization: input.authorization, dpop: input.dpop }
    },
    parsed
  );
  const signature = nodeSign(null, Buffer.from(base, "utf8"), key.privateKey);
  return {
    signature: `${SIGNATURE_LABEL}=:${signature.toString("base64url")}:`,
    "signature-input": signatureInput
  };
}

export interface SignedHeadersInput {
  readonly method: string;
  readonly url: string;
  /** Session token from POST /v1/sessions/exchange. Omitted for an unauthenticated signed request. */
  readonly sessionToken?: string | undefined;
  readonly nowMs?: number | undefined;
  readonly requestId?: string | undefined;
}

/** Every header a verifier-protected route needs from this agent for one request. */
export function buildSignedHeaders(key: AgentKeyMaterial, input: SignedHeadersInput): Record<string, string> {
  const dpop = createDpopProof(key, { method: input.method, url: input.url, nowMs: input.nowMs });
  const authorization = input.sessionToken === undefined ? undefined : `DPoP ${input.sessionToken}`;
  const signed = signHttpRequest(key, { method: input.method, url: input.url, authorization, dpop, nowMs: input.nowMs });
  return {
    ...(authorization === undefined ? {} : { authorization }),
    dpop,
    signature: signed.signature,
    "signature-input": signed["signature-input"],
    ...(input.requestId === undefined ? {} : { "x-request-id": input.requestId })
  };
}
