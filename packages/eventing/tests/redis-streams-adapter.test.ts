import { describe, expect, it } from "vitest";

import { outboxEventFromRedisStream, redisFieldsToRecord } from "../src/index.js";

describe("Redis Streams outbox adapter", () => {
  it("decodes field/value arrays into outbox events", () => {
    const event = outboxEventFromRedisStream({
      id: "1730000000000-0",
      fieldValues: [
        "id",
        "evt_1",
        "type",
        "decision.created",
        "occurred_at",
        "2026-04-24T10:00:00.000Z",
        "payload",
        JSON.stringify({ decision: "allow" })
      ]
    });

    expect(event).toEqual({
      id: "evt_1",
      type: "decision.created",
      occurredAt: "2026-04-24T10:00:00.000Z",
      payload: { decision: "allow" }
    });
  });

  it("rejects malformed field arrays", () => {
    expect(() => redisFieldsToRecord(["id"])).toThrow(/even length/);
  });
});
