import { describe, expect, it } from "vitest";

import {
  CheckpointWorker,
  InMemoryCheckpointPublisher,
  LocalMerkleLog,
  transparencyLeafFromOutboxEvent,
  verifyInclusionProof
} from "../src/index.js";

describe("transparency revocation chain proof", () => {
  it("publishes a checkpoint and verifies inclusion for a revocation event", async () => {
    const revocationOutboxEvent = {
      id: "evt_revocation_epoch",
      type: "REVOCATION_EPOCH_BUMP",
      occurredAt: "2026-04-24T10:00:00.000Z",
      payload: {
        tenant_id: "ten_demo",
        chain_id: "chn_demo",
        epoch: 3,
        reason: "compromised_delegate",
        actor_id: "usr_admin"
      }
    };
    const leaf = transparencyLeafFromOutboxEvent(revocationOutboxEvent);
    if (leaf === undefined) {
      throw new Error("expected revocation event to map to a transparency leaf");
    }
    expect(leaf).toEqual(expect.objectContaining({ type: "REVOCATION", tenantId: "ten_demo" }));

    const log = new LocalMerkleLog({ logId: "log_test" });
    const publisher = new InMemoryCheckpointPublisher();
    const worker = new CheckpointWorker(log, publisher);
    const append = log.append(leaf);
    const tick = await worker.forceCheckpoint(1_776_000_001_000);

    expect(tick.published).toBe(true);
    expect(publisher.published).toHaveLength(1);

    const proof = await append.inclusionProofPromise;
    const checkpoint = tick.checkpoint;
    expect(checkpoint).toBeDefined();
    expect(checkpoint === undefined ? false : verifyInclusionProof(leaf, proof, checkpoint)).toBe(true);
    expect(publisher.published[0]).toEqual(
      expect.objectContaining({
        checkpointId: checkpoint?.checkpointId,
        treeSize: 1,
        tenantIds: ["ten_demo"]
      })
    );
  });
});
