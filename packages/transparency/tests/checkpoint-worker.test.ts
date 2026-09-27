import { describe, expect, it } from "vitest";

import {
  CheckpointWorker,
  InMemoryCheckpointPublisher,
  LocalMerkleLog,
  S3WormCheckpointPublisher,
  transparencyLeafFromOutboxEvent,
  type LogLeaf,
  type S3PutObjectInput
} from "../src/index.js";

const REVOCATION_LEAF: LogLeaf = {
  id: "evt_revocation_1",
  type: "REVOCATION",
  tenantId: "ten_demo",
  payload: {
    chain_id: "chn_demo",
    epoch: 2
  },
  ts: 1_776_000_000_000
};

const POLICY_LEAF: LogLeaf = {
  id: "evt_policy_1",
  type: "POLICY_CHANGE",
  tenantId: "ten_demo",
  payload: {
    policy_sha256: "a".repeat(64)
  },
  ts: 1_776_000_000_100
};

describe("checkpoint worker", () => {
  it("publishes when the leaf-count threshold is reached", async () => {
    const log = new LocalMerkleLog({ logId: "log_test" });
    const publisher = new InMemoryCheckpointPublisher();
    const worker = new CheckpointWorker(log, publisher, {
      intervalMs: 60_000,
      maxLeavesPerCheckpoint: 2,
      now: () => 1_776_000_000_000
    });

    log.append(REVOCATION_LEAF);
    expect(await worker.tick(1_776_000_001_000)).toEqual({ published: false });

    log.append(POLICY_LEAF);
    const tick = await worker.tick(1_776_000_002_000);

    expect(tick.published).toBe(true);
    expect(tick.checkpoint).toEqual(expect.objectContaining({ treeSize: 2, tenantIds: ["ten_demo"] }));
    expect(publisher.byTenant("ten_demo")).toHaveLength(1);
  });

  it("uses S3 object lock fields for WORM checkpoint publication", async () => {
    let putObjectSeen: S3PutObjectInput | undefined;
    const publisher = new S3WormCheckpointPublisher({
      bucket: "aidenid-evidence",
      prefix: "checkpoints",
      retentionDays: 30,
      now: () => new Date("2026-04-24T10:00:00.000Z"),
      client: {
        async putObject(input) {
          putObjectSeen = input;
          return { ETag: "\"etag\"", VersionId: "ver_1" };
        }
      }
    });
    const log = new LocalMerkleLog({ logId: "log_test" });
    log.append(REVOCATION_LEAF);
    const sth = log.createCheckpoint(1_776_000_001_000);

    const publication = await publisher.publish(sth);

    expect(publication).toEqual(
      expect.objectContaining({
        uri: `s3://aidenid-evidence/checkpoints/${sth.logId}/${sth.checkpointId}.json`,
        etag: "\"etag\"",
        versionId: "ver_1"
      })
    );
    expect(putObjectSeen).toEqual(
      expect.objectContaining({
        Bucket: "aidenid-evidence",
        ContentType: "application/json",
        ObjectLockMode: "COMPLIANCE"
      })
    );
    expect(putObjectSeen?.ObjectLockRetainUntilDate.toISOString()).toBe("2026-05-24T10:00:00.000Z");
  });

  it("maps decision-recorded outbox events into transparency leaves", () => {
    const leaf = transparencyLeafFromOutboxEvent({
      id: "evt_decision_1",
      type: "DECISION_RECORDED",
      occurredAt: "2026-05-03T09:00:00.000Z",
      payload: {
        tenant_id: "ten_demo",
        decision_id: "dec_123",
        receipt_jws_sha256: "a".repeat(64)
      }
    });

    expect(leaf).toMatchObject({
      id: "evt_decision_1",
      type: "DECISION_RECORDED",
      tenantId: "ten_demo",
      payload: { decision_id: "dec_123" }
    });
  });
});
