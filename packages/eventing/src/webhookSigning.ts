import { createHmac } from "node:crypto";

export interface SignedWebhookEndpoint {
  readonly id: string;
}

export interface SignedWebhookEnvelope {
  readonly headers: Readonly<Record<string, string>>;
  readonly payload: string;
}

export function createSignedWebhookEnvelope(input: {
  readonly endpoint: SignedWebhookEndpoint;
  readonly payload: unknown;
  readonly signingSecret: string | Uint8Array;
  readonly timestamp?: string | undefined;
}): SignedWebhookEnvelope {
  const timestamp = input.timestamp ?? new Date().toISOString();
  const payload = JSON.stringify(input.payload);
  const signingInput = `${timestamp}.${payload}`;
  const signature = createHmac("sha256", input.signingSecret).update(signingInput, "utf8").digest("base64url");
  return {
    payload,
    headers: {
      "content-type": "application/json",
      "x-aidenid-webhook-id": input.endpoint.id,
      "x-aidenid-webhook-timestamp": timestamp,
      "x-aidenid-webhook-signature": `v1=${signature}`
    }
  };
}
