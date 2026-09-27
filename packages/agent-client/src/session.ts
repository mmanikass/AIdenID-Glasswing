import type { AgentKeyMaterial } from "./keys.js";
import { buildSignedHeaders, normalizeResource } from "./signing.js";

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export interface ExchangeSessionInput {
  readonly controlPlaneUrl: string;
  readonly grantId: string;
  /** The site id the grant was issued for (the token audience). */
  readonly audience: string;
  /** The grant's resource, exactly as issued. */
  readonly resource: string;
  readonly requestedPermissions: readonly string[];
  readonly llmBrand?: string | undefined;
  readonly fetchImpl?: FetchLike | undefined;
}

export interface ExchangedSession {
  readonly accessToken: string;
  readonly tokenType: string;
  readonly expiresIn: number;
  readonly sessionId: string;
  readonly revocationEpoch: number;
}

export class SessionExchangeError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    readonly body: unknown
  ) {
    super(`session exchange refused: HTTP ${status} ${code}`);
    this.name = "SessionExchangeError";
  }
}

/**
 * Exchange a delegation grant for a DPoP-bound session token. The control plane binds the
 * token to this agent key's thumbprint; a different key cannot use the token.
 */
export async function exchangeSession(key: AgentKeyMaterial, input: ExchangeSessionInput): Promise<ExchangedSession> {
  const fetchImpl = input.fetchImpl ?? fetch;
  const response = await fetchImpl(`${input.controlPlaneUrl.replace(/\/$/, "")}/v1/sessions/exchange`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      grant_id: input.grantId,
      audience: input.audience,
      resource: input.resource,
      proof_jkt: key.thumbprint,
      requested_permissions: input.requestedPermissions,
      ...(input.llmBrand === undefined ? {} : { llm_brand: input.llmBrand })
    })
  });
  const body = (await response.json().catch(() => ({}))) as Record<string, unknown>;
  if (response.status !== 201) {
    throw new SessionExchangeError(response.status, typeof body.error === "string" ? body.error : "unknown", body);
  }
  return {
    accessToken: String(body.access_token),
    tokenType: String(body.token_type),
    expiresIn: Number(body.expires_in),
    sessionId: String(body.session_id),
    revocationEpoch: Number(body.revocation_epoch)
  };
}

export interface SignedFetchInput {
  readonly method?: string | undefined;
  readonly sessionToken?: string | undefined;
  readonly requestId?: string | undefined;
  readonly headers?: Record<string, string> | undefined;
  readonly body?: string | undefined;
  readonly fetchImpl?: FetchLike | undefined;
}

/** Perform one signed request against a verifier-protected route. */
export async function signedFetch(key: AgentKeyMaterial, url: string, input: SignedFetchInput = {}): Promise<Response> {
  const method = (input.method ?? "GET").toUpperCase();
  const fetchImpl = input.fetchImpl ?? fetch;
  const signed = buildSignedHeaders(key, { method, url: normalizeResource(url), sessionToken: input.sessionToken, requestId: input.requestId });
  return fetchImpl(url, {
    method,
    headers: { ...(input.headers ?? {}), ...signed },
    ...(input.body === undefined ? {} : { body: input.body })
  });
}
