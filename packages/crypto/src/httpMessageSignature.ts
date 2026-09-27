import { createPublicKey, verify as nodeVerify } from "node:crypto";
import { URL } from "node:url";

import { base64UrlToBuffer } from "./digest.js";
import type { PublicJwk } from "./jwkThumbprint.js";
import { requireFreshReplayKey, requireFreshReplayKeyAsync, type ReplayCache, type ReplayCacheLike } from "./replayCache.js";

const RELATIVE_URL_BASE = "https://aidenid.local";

export interface HttpMessageSignatureRequest {
  readonly method: string;
  readonly url: string;
  readonly headers: Record<string, string | undefined>;
}

export interface ParsedSignatureInput {
  readonly label: string;
  readonly components: readonly string[];
  readonly params: Record<string, string | number | boolean>;
  readonly serializedParams: string;
}

export interface VerifyHttpMessageSignatureInput {
  readonly request: HttpMessageSignatureRequest;
  readonly publicJwk: PublicJwk;
  readonly now?: Date;
  readonly maxAgeSeconds?: number | undefined;
  readonly replayCache?: ReplayCache | undefined;
  readonly requireNonce?: boolean | undefined;
}

export interface VerifyHttpMessageSignatureAsyncInput extends Omit<VerifyHttpMessageSignatureInput, "replayCache"> {
  readonly replayCache?: ReplayCacheLike | undefined;
}

function readHeader(headers: Record<string, string | undefined>, name: string): string | undefined {
  const wanted = name.toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === wanted) {
      return value;
    }
  }
  return undefined;
}

function parseParams(input: string): Record<string, string | number | boolean> {
  const params: Record<string, string | number | boolean> = {};
  for (const rawPart of input.split(";").slice(1)) {
    const part = rawPart.trim();
    if (!part) {
      continue;
    }
    const [key, rawValue] = part.split("=", 2) as [string, string | undefined];
    if (rawValue === undefined) {
      params[key] = true;
      continue;
    }
    if (/^\d+$/.test(rawValue)) {
      params[key] = Number.parseInt(rawValue, 10);
      continue;
    }
    params[key] = rawValue.replace(/^"|"$/g, "");
  }
  return params;
}

export function parseSignatureInput(value: string): ParsedSignatureInput {
  const match = value.match(/^([A-Za-z0-9_-]+)=\(([^)]*)\)(.*)$/);
  if (match === null) {
    throw new Error("invalid Signature-Input header");
  }
  const [, label, rawComponents, rawParams] = match as [string, string, string, string];
  const components = Array.from(rawComponents.matchAll(/"([^"]+)"/g), (componentMatch) => componentMatch[1] ?? "");
  if (components.length === 0) {
    throw new Error("Signature-Input must include at least one covered component");
  }
  return {
    label,
    components,
    params: parseParams(rawParams),
    serializedParams: `(${components.map((component) => `"${component}"`).join(" ")})${rawParams}`
  };
}

function componentValue(component: string, request: HttpMessageSignatureRequest): string {
  if (component === "@method") {
    return request.method.toUpperCase();
  }
  if (component === "@path") {
    return new URL(request.url, RELATIVE_URL_BASE).pathname;
  }
  if (component === "@target-uri") {
    return new URL(request.url, RELATIVE_URL_BASE).toString();
  }
  const value = readHeader(request.headers, component);
  if (value === undefined) {
    throw new Error(`missing covered header '${component}'`);
  }
  return value;
}

export function buildSignatureBase(request: HttpMessageSignatureRequest, signatureInput: ParsedSignatureInput): string {
  const lines = signatureInput.components.map((component) => `"${component}": ${componentValue(component, request)}`);
  lines.push(`"@signature-params": ${signatureInput.serializedParams}`);
  return lines.join("\n");
}

function signatureBytes(signatureHeader: string, label: string): Buffer {
  const match = signatureHeader.match(new RegExp(`${label}=:([^:]+):`));
  if (match === null) {
    throw new Error(`Signature header missing label '${label}'`);
  }
  return base64UrlToBuffer(match[1] ?? "");
}

interface HttpSignatureReplayCheck {
  readonly key: string;
  readonly ttlMs: number;
  readonly nowMs: number;
}

function verifyHttpMessageSignatureCore(input: VerifyHttpMessageSignatureAsyncInput): {
  readonly parsed: ParsedSignatureInput;
  readonly replayCheck?: HttpSignatureReplayCheck | undefined;
} {
  const signatureInputHeader = readHeader(input.request.headers, "signature-input");
  const signatureHeader = readHeader(input.request.headers, "signature");
  if (signatureInputHeader === undefined || signatureHeader === undefined) {
    throw new Error("Signature and Signature-Input headers are required");
  }
  const parsed = parseSignatureInput(signatureInputHeader);
  const now = input.now ?? new Date();
  const nowSeconds = Math.floor(now.getTime() / 1000);
  if (typeof parsed.params.created === "number" && parsed.params.created > nowSeconds + 30) {
    throw new Error("HTTP message signature created time is in the future");
  }
  if (
    typeof parsed.params.created === "number" &&
    input.maxAgeSeconds !== undefined &&
    parsed.params.created < nowSeconds - input.maxAgeSeconds
  ) {
    throw new Error("HTTP message signature created time is outside accepted window");
  }
  if (typeof parsed.params.expires === "number" && parsed.params.expires <= nowSeconds) {
    throw new Error("HTTP message signature expired");
  }
  const nonce = parsed.params.nonce;
  if ((typeof nonce !== "string" || nonce.length === 0) && input.requireNonce === true) {
    throw new Error("HTTP message signature nonce is required");
  }
  let replayCheck: HttpSignatureReplayCheck | undefined;
  if (typeof nonce === "string" && nonce.length > 0) {
    const keyId = typeof parsed.params.keyid === "string" && parsed.params.keyid.length > 0 ? parsed.params.keyid : "unknown";
    const ttlMs =
      typeof parsed.params.expires === "number"
        ? Math.max(1_000, (parsed.params.expires - nowSeconds) * 1000)
        : (input.maxAgeSeconds ?? 60) * 1000;
    replayCheck = { key: `http-signature:${keyId}:${nonce}`, ttlMs, nowMs: now.getTime() };
  }
  const alg = String(parsed.params.alg ?? "");
  const publicKey = createPublicKey({ key: input.publicJwk, format: "jwk" } as never);
  const data = Buffer.from(buildSignatureBase(input.request, parsed), "utf8");
  const verified =
    alg.toLowerCase() === "ed25519" || alg === "EdDSA"
      ? nodeVerify(null, data, publicKey, signatureBytes(signatureHeader, parsed.label))
      : nodeVerify("sha256", data, { key: publicKey, dsaEncoding: "ieee-p1363" }, signatureBytes(signatureHeader, parsed.label));
  if (!verified) {
    throw new Error("HTTP message signature verification failed");
  }
  return { parsed, replayCheck };
}

export function verifyHttpMessageSignature(input: VerifyHttpMessageSignatureInput): ParsedSignatureInput {
  const { parsed, replayCheck } = verifyHttpMessageSignatureCore(input);
  if (input.replayCache !== undefined && replayCheck !== undefined) {
    requireFreshReplayKey(input.replayCache, replayCheck.key, replayCheck.ttlMs, replayCheck.nowMs, "HTTP message signature");
  }
  return parsed;
}

export async function verifyHttpMessageSignatureAsync(input: VerifyHttpMessageSignatureAsyncInput): Promise<ParsedSignatureInput> {
  const { parsed, replayCheck } = verifyHttpMessageSignatureCore(input);
  if (input.replayCache !== undefined && replayCheck !== undefined) {
    await requireFreshReplayKeyAsync(input.replayCache, replayCheck.key, replayCheck.ttlMs, replayCheck.nowMs, "HTTP message signature");
  }
  return parsed;
}
