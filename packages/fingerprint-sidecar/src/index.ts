export interface FingerprintHeaderReader {
  get(name: string): string | null;
}

export type FingerprintHeaderBag = Readonly<Record<string, string | readonly string[] | undefined>>;
export type FingerprintHeaders = FingerprintHeaderBag | FingerprintHeaderReader;

export interface FingerprintRequestInput {
  readonly method: string;
  readonly url: string;
  readonly headers?: FingerprintHeaders | undefined;
  readonly remoteAddress?: string | undefined;
  readonly routeTemplate?: string | undefined;
}

export interface SanitizedFingerprintRequest {
  readonly method: string;
  readonly url: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly remoteAddress?: string | undefined;
  readonly routeTemplate?: string | undefined;
}

export interface FingerprintProviderResult {
  readonly provider: string;
  readonly deviceId?: string | undefined;
  readonly botScore?: number | undefined;
  readonly suspicionDelta?: number | undefined;
  readonly operatorActorIdHint?: string | undefined;
  readonly llmBrandHint?: string | undefined;
  readonly evidence?: readonly string[] | undefined;
}

export interface FingerprintEvidenceProvider {
  lookup(request: SanitizedFingerprintRequest, signal: AbortSignal): Promise<FingerprintProviderResult>;
}

export type FingerprintEvidenceError = "timeout" | "provider_error" | "invalid_provider_result";

export interface FingerprintEvidence {
  readonly enabled: boolean;
  readonly available: boolean;
  readonly timedOut: boolean;
  readonly providerLatencyMs: number;
  readonly suspicionDelta: number;
  readonly evidence: readonly string[];
  readonly provider?: string | undefined;
  readonly deviceId?: string | undefined;
  readonly botScore?: number | undefined;
  readonly operatorActorIdHint?: string | undefined;
  readonly llmBrandHint?: string | undefined;
  readonly error?: FingerprintEvidenceError | undefined;
}

export interface FingerprintEvidenceOptions {
  readonly provider?: FingerprintEvidenceProvider | undefined;
  readonly enabled?: boolean | undefined;
  readonly timeoutMs?: number | undefined;
  readonly now?: (() => number) | undefined;
}

export const DEFAULT_FINGERPRINT_TIMEOUT_MS = 50;

export const FINGERPRINT_ALLOWED_HEADERS = [
  "accept",
  "accept-language",
  "sec-ch-ua",
  "sec-ch-ua-mobile",
  "sec-ch-ua-platform",
  "sec-fetch-dest",
  "sec-fetch-mode",
  "sec-fetch-site",
  "sec-fetch-user",
  "user-agent",
  "x-forwarded-for",
  "x-real-ip"
] as const;

export const FINGERPRINT_STRIPPED_CREDENTIAL_HEADERS = [
  "authorization",
  "proxy-authorization",
  "cookie",
  "set-cookie",
  "dpop",
  "signature",
  "signature-input",
  "x-api-key",
  "x-amz-security-token",
  "aws-session-token"
] as const;

const EVIDENCE_LABEL_RE = /^[a-z][a-z0-9_-]{0,63}$/;

class FingerprintTimeoutError extends Error {
  constructor() {
    super("fingerprint sidecar provider timed out");
  }
}

function readHeader(headers: FingerprintHeaders | undefined, name: string): string | undefined {
  if (headers === undefined) {
    return undefined;
  }
  if (typeof (headers as FingerprintHeaderReader).get === "function") {
    return (headers as FingerprintHeaderReader).get(name) ?? undefined;
  }
  const lowerName = name.toLowerCase();
  const entry = Object.entries(headers).find(([key]) => key.toLowerCase() === lowerName);
  const value = entry?.[1];
  if (Array.isArray(value)) {
    return value.filter((part): part is string => typeof part === "string" && part.length > 0).join(", ");
  }
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function positiveInteger(value: number | undefined, fallback: number, name: string): number {
  const resolved = value ?? fallback;
  if (!Number.isInteger(resolved) || resolved < 1) {
    throw new Error(`${name} must be an integer >= 1`);
  }
  return resolved;
}

function elapsedMs(started: number, now: () => number): number {
  return Math.max(0, Math.round((now() - started) * 1000) / 1000);
}

function boundedUnitInterval(value: number | undefined, field: string): number | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (!Number.isFinite(value) || value < 0 || value > 1) {
    throw new Error(`${field} must be between 0 and 1`);
  }
  return value;
}

function nonEmptyBoundedString(value: string | undefined, field: string, maxLength: number): string | undefined {
  if (value === undefined) {
    return undefined;
  }
  const trimmed = value.trim();
  if (trimmed.length === 0 || trimmed.length > maxLength) {
    throw new Error(`${field} must be non-empty and <= ${maxLength} chars`);
  }
  return trimmed;
}

function optionalLlmBrandHint(value: string | undefined): string | undefined {
  const normalized = nonEmptyBoundedString(value, "llmBrandHint", 32);
  if (normalized === undefined) {
    return undefined;
  }
  if (!/^[a-z][a-z0-9_-]{0,31}$/u.test(normalized)) {
    throw new Error("llmBrandHint must be a lowercase slug");
  }
  return normalized;
}

function normalizedEvidence(evidence: readonly string[] | undefined): readonly string[] {
  const labels = (evidence ?? []).filter((label) => EVIDENCE_LABEL_RE.test(label));
  return labels.length === 0 ? ["fingerprint-provider-evidence"] : labels;
}

function failOpen(
  error: FingerprintEvidenceError,
  providerLatencyMs: number,
  evidence: readonly string[],
  timedOut = false
): FingerprintEvidence {
  return {
    enabled: true,
    available: false,
    timedOut,
    providerLatencyMs,
    suspicionDelta: 0,
    evidence,
    error
  };
}

function normalizeProviderResult(result: FingerprintProviderResult, providerLatencyMs: number): FingerprintEvidence {
  const provider = nonEmptyBoundedString(result.provider, "provider", 64);
  if (provider === undefined) {
    throw new Error("provider is required");
  }
  const deviceId = nonEmptyBoundedString(result.deviceId, "deviceId", 256);
  const botScore = boundedUnitInterval(result.botScore, "botScore");
  const suspicionDelta = boundedUnitInterval(result.suspicionDelta, "suspicionDelta") ?? 0;
  const operatorActorIdHint = nonEmptyBoundedString(result.operatorActorIdHint, "operatorActorIdHint", 128);
  const llmBrandHint = optionalLlmBrandHint(result.llmBrandHint);
  return {
    enabled: true,
    available: true,
    timedOut: false,
    providerLatencyMs,
    suspicionDelta,
    evidence: normalizedEvidence(result.evidence),
    provider,
    ...(deviceId === undefined ? {} : { deviceId }),
    ...(botScore === undefined ? {} : { botScore }),
    ...(operatorActorIdHint === undefined ? {} : { operatorActorIdHint }),
    ...(llmBrandHint === undefined ? {} : { llmBrandHint })
  };
}

export function sanitizeFingerprintRequest(input: FingerprintRequestInput): SanitizedFingerprintRequest {
  const headers: Record<string, string> = {};
  for (const name of FINGERPRINT_ALLOWED_HEADERS) {
    const value = readHeader(input.headers, name);
    if (value !== undefined) {
      headers[name] = value;
    }
  }
  return {
    method: input.method.toUpperCase(),
    url: input.url,
    headers,
    ...(input.remoteAddress === undefined ? {} : { remoteAddress: input.remoteAddress }),
    ...(input.routeTemplate === undefined ? {} : { routeTemplate: input.routeTemplate })
  };
}

export { createLocalFingerprintProvider } from "./local-provider.js";

export async function getFingerprintEvidence(
  input: FingerprintRequestInput,
  options: FingerprintEvidenceOptions = {}
): Promise<FingerprintEvidence> {
  const now = options.now ?? Date.now;
  const started = now();
  const provider = options.provider;
  if (options.enabled === false || provider === undefined) {
    return {
      enabled: false,
      available: false,
      timedOut: false,
      providerLatencyMs: elapsedMs(started, now),
      suspicionDelta: 0,
      evidence: ["fingerprint-sidecar-disabled"]
    };
  }

  const timeoutMs = positiveInteger(options.timeoutMs, DEFAULT_FINGERPRINT_TIMEOUT_MS, "timeoutMs");
  const controller = new AbortController();
  let timedOut = false;
  let timeout: ReturnType<typeof setTimeout> | undefined;
  const timeoutPromise = new Promise<never>((_resolve, reject) => {
    timeout = setTimeout(() => {
      timedOut = true;
      controller.abort();
      reject(new FingerprintTimeoutError());
    }, timeoutMs);
  });
  const lookupPromise = provider.lookup(sanitizeFingerprintRequest(input), controller.signal);
  lookupPromise.catch(() => undefined);

  try {
    const result = await Promise.race([lookupPromise, timeoutPromise]);
    if (timedOut) {
      return failOpen("timeout", elapsedMs(started, now), ["fingerprint-timeout-bypassed"], true);
    }
    return normalizeProviderResult(result, elapsedMs(started, now));
  } catch (error) {
    const providerLatencyMs = elapsedMs(started, now);
    if (timedOut || error instanceof FingerprintTimeoutError) {
      return failOpen("timeout", providerLatencyMs, ["fingerprint-timeout-bypassed"], true);
    }
    if (error instanceof Error && /must be|provider is required/.test(error.message)) {
      return failOpen("invalid_provider_result", providerLatencyMs, ["fingerprint-invalid-result-bypassed"]);
    }
    return failOpen("provider_error", providerLatencyMs, ["fingerprint-provider-error-bypassed"]);
  } finally {
    if (timeout !== undefined) {
      clearTimeout(timeout);
    }
  }
}
