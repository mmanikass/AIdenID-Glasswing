import { createHmac } from "node:crypto";

import { describe, expect, it } from "vitest";

import { createSignedWebhookEnvelope } from "../src/index.js";

describe("signed webhook envelopes", () => {
  it("signs timestamp and raw JSON payload with HMAC-SHA256", () => {
    const envelope = createSignedWebhookEnvelope({
      endpoint: { id: "whk_1" },
      payload: { event_type: "decision.recorded", data: { id: "dec_1" } },
      signingSecret: "resolved-webhook-secret",
      timestamp: "2026-04-29T08:00:01.000Z"
    });

    const expectedSignature = createHmac("sha256", "resolved-webhook-secret")
      .update(`2026-04-29T08:00:01.000Z.${envelope.payload}`, "utf8")
      .digest("base64url");
    expect(envelope.headers).toEqual(
      expect.objectContaining({
        "content-type": "application/json",
        "x-aidenid-webhook-id": "whk_1",
        "x-aidenid-webhook-timestamp": "2026-04-29T08:00:01.000Z",
        "x-aidenid-webhook-signature": `v1=${expectedSignature}`
      })
    );
  });
});
