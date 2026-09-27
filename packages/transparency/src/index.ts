import { createHash } from "node:crypto";

export * from "./checkpointWorker.js";
export * from "./inclusionProof.js";
export * from "./localLog.js";

export interface Commitment {
  readonly type: string;
  readonly digest: string;
}

export function commitmentRoot(commitments: readonly Commitment[]): string {
  const hash = createHash("sha256");
  for (const commitment of commitments) {
    hash.update(commitment.type);
    hash.update("\0");
    hash.update(commitment.digest);
    hash.update("\n");
  }
  return hash.digest("hex");
}
