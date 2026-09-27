import { describe, expect, it } from "vitest";

import { LocalMerkleLog, verifyInclusionProof, type LogLeaf } from "../src/index.js";

const REVOCATION_LEAF: LogLeaf = {
  id: "evt_revocation_1",
  type: "REVOCATION",
  tenantId: "ten_demo",
  payload: {
    chain_id: "chn_demo",
    epoch: 2,
    reason: "operator_request"
  },
  ts: 1_776_000_000_000
};

describe("local Merkle transparency log", () => {
  it("creates checkpoints and verifies inclusion proofs", async () => {
    const log = new LocalMerkleLog({ logId: "log_test", checkpointLeafInterval: 10 });
    const append = log.append(REVOCATION_LEAF);
    const sth = log.createCheckpoint(1_776_000_001_000);
    const proof = await append.inclusionProofPromise;

    expect(proof).toEqual(
      expect.objectContaining({
        leafIndex: 0,
        treeSize: 1,
        rootHash: sth.rootHash
      })
    );
    expect(verifyInclusionProof(REVOCATION_LEAF, proof, sth)).toBe(true);
    expect(
      verifyInclusionProof(
        {
          ...REVOCATION_LEAF,
          payload: { ...REVOCATION_LEAF.payload, epoch: 3 }
        },
        proof,
        sth
      )
    ).toBe(false);
  });

  it("keeps tenant-indexed checkpoints", () => {
    const log = new LocalMerkleLog({ logId: "log_test" });
    log.append(REVOCATION_LEAF);

    const sth = log.createCheckpoint(1_776_000_001_000);

    expect(sth.tenantIds).toEqual(["ten_demo"]);
    expect(log.checkpointsForTenant("ten_demo")).toEqual([sth]);
    expect(log.checkpointsForTenant("ten_other")).toEqual([]);
  });

  it("verifies inclusion for non-power-of-two trees", async () => {
    const log = new LocalMerkleLog({ logId: "log_test" });
    log.append(REVOCATION_LEAF);
    const middle = log.append({
      ...REVOCATION_LEAF,
      id: "evt_revocation_2",
      payload: { ...REVOCATION_LEAF.payload, epoch: 3 }
    });
    log.append({
      ...REVOCATION_LEAF,
      id: "evt_revocation_3",
      payload: { ...REVOCATION_LEAF.payload, epoch: 4 }
    });
    const sth = log.createCheckpoint(1_776_000_001_000);
    const proof = await middle.inclusionProofPromise;
    const leaf = log.leaf(middle.leafIndex);

    expect(leaf).toBeDefined();
    expect(leaf === undefined ? false : verifyInclusionProof(leaf, proof, sth)).toBe(true);
  });

  it("accepts decision-recorded leaves for per-decision receipt evidence", async () => {
    const log = new LocalMerkleLog({ logId: "log_decision_test" });
    const decisionLeaf: LogLeaf = {
      id: "decision:dec_123",
      type: "DECISION_RECORDED",
      tenantId: "ten_demo",
      payload: {
        decision_id: "dec_123",
        receipt_jws_sha256: "a".repeat(64),
        decision_payload_sha256: "b".repeat(64)
      },
      ts: 1_776_000_002_000
    };
    const append = log.append(decisionLeaf);
    const sth = log.createCheckpoint(1_776_000_003_000);
    const proof = await append.inclusionProofPromise;

    expect(proof.leafIndex).toBe(0);
    expect(verifyInclusionProof(decisionLeaf, proof, sth)).toBe(true);
  });
});
