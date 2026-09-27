import { describe, expect, it } from "vitest";

import { InMemoryOutboxStore, RedisStreamsOutboxPublisher, StoreBackedOutboxPublisher, makeOutboxEvent } from "../src/index.js";

describe("outbox event scaffold", () => {
  it("preserves event identity and payload", () => {
    expect(makeOutboxEvent("evt_1", "decision.created", { decision: "allow" })).toMatchObject({
      id: "evt_1",
      type: "decision.created",
      payload: { decision: "allow" }
    });
  });

  it("stores events before asynchronous publication", async () => {
    const store = new InMemoryOutboxStore();
    const publisher = new StoreBackedOutboxPublisher(store);
    publisher.publishAsync(makeOutboxEvent("evt_2", "grant.issued", { grant_id: "grt_1" }));
    await publisher.flush();

    expect(store.all()).toMatchObject([{ id: "evt_2", type: "grant.issued" }]);
    expect(store.pending()).toHaveLength(1);
  });

  it("publishes pending rows to a Redis Streams shaped client", async () => {
    const writes: Array<{ stream: string; fields: string[] }> = [];
    const store = new InMemoryOutboxStore();
    const downstream = new RedisStreamsOutboxPublisher(
      {
        async xadd(stream, _id, ...fieldValues) {
          writes.push({ stream, fields: fieldValues });
          return "1730000000000-0";
        }
      },
      "decisions:ten_demo"
    );
    const publisher = new StoreBackedOutboxPublisher(store, downstream);

    store.append(makeOutboxEvent("evt_3", "decision.created", { decision: "allow" }));
    await publisher.flush();

    expect(writes).toHaveLength(1);
    expect(writes[0]).toMatchObject({ stream: "decisions:ten_demo" });
    expect(writes[0]?.fields).toContain("payload");
    expect(store.pending()).toHaveLength(0);
  });

  it("propagates awaited publish failures and leaves the event pending", async () => {
    const store = new InMemoryOutboxStore();
    const downstream = new RedisStreamsOutboxPublisher(
      {
        async xadd() {
          throw new Error("redis unavailable");
        }
      },
      "decisions:ten_demo"
    );
    const publisher = new StoreBackedOutboxPublisher(store, downstream);

    await expect(publisher.publish(makeOutboxEvent("evt_4", "decision.created", { decision: "deny" }))).rejects.toThrow(
      /redis unavailable/
    );

    expect(store.pending()).toEqual([expect.objectContaining({ id: "evt_4", type: "decision.created" })]);
  });
});
