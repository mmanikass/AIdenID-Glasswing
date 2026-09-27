import { generateKeyPairSync, sign as cryptoSign, type KeyObject } from "node:crypto";

import {
  buildInclusionProof,
  canonicalJson,
  canonicalLogLeaf,
  hashLeaf,
  merkleRoot,
  type InclusionProof,
  type JsonValue,
  type LogEventType,
  type LogLeaf,
  type SignedTreeHead
} from "./inclusionProof.js";

export interface AppendResult {
  readonly leafIndex: number;
  readonly leafHash: string;
  readonly inclusionProofPromise: Promise<InclusionProof>;
}

export interface StoredLogLeaf {
  readonly leaf: LogLeaf;
  readonly canonical: string;
  readonly hash: string;
  readonly leafIndex: number;
}

export interface CheckpointSigner {
  readonly logId: string;
  readonly publicKeyPem?: string;
  sign(payload: string): string;
}

export interface WriteAheadLogSink {
  append(record: StoredLogLeaf): void;
}

export interface LocalMerkleLogOptions {
  readonly logId?: string;
  readonly signer?: CheckpointSigner;
  readonly writeAhead?: WriteAheadLogSink;
  readonly checkpointLeafInterval?: number;
  readonly now?: () => number;
}

interface PendingProof {
  readonly leafIndex: number;
  resolve(proof: InclusionProof): void;
  reject(error: unknown): void;
}

export class Ed25519CheckpointSigner implements CheckpointSigner {
  readonly publicKeyPem: string;

  private constructor(
    readonly logId: string,
    private readonly privateKey: KeyObject,
    publicKey: KeyObject
  ) {
    this.publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  }

  static generate(logId = "aidenid-local-transparency-log"): Ed25519CheckpointSigner {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    return new Ed25519CheckpointSigner(logId, privateKey, publicKey);
  }

  sign(payload: string): string {
    return cryptoSign(null, Buffer.from(payload, "utf8"), this.privateKey).toString("base64url");
  }
}

export class InMemoryWriteAheadLog implements WriteAheadLogSink {
  readonly records: StoredLogLeaf[] = [];

  append(record: StoredLogLeaf): void {
    this.records.push({
      ...record,
      leaf: cloneLeaf(record.leaf)
    });
  }
}

export function checkpointSigningPayload(sth: Omit<SignedTreeHead, "signature">): string {
  return canonicalJson({
    checkpointId: sth.checkpointId,
    logId: sth.logId,
    rootHash: sth.rootHash,
    tenantIds: sth.tenantIds,
    timestamp: sth.timestamp,
    treeSize: sth.treeSize
  });
}

function cloneJsonObject(value: { readonly [key: string]: JsonValue }): { readonly [key: string]: JsonValue } {
  return JSON.parse(canonicalJson(value)) as { readonly [key: string]: JsonValue };
}

function cloneLeaf(leaf: LogLeaf): LogLeaf {
  return {
    ...leaf,
    payload: cloneJsonObject(leaf.payload)
  };
}

function assertSupportedEvent(type: LogEventType): void {
  if (
    type !== "REVOCATION" &&
    type !== "POLICY_CHANGE" &&
    type !== "GRANT_ISSUED" &&
    type !== "SESSION_ISSUED" &&
    type !== "DECISION_RECORDED"
  ) {
    throw new Error(`unsupported transparency event type: ${type}`);
  }
}

function checkpointId(logId: string, treeSize: number, rootHash: string, timestamp: number): string {
  return `chk_${logId}_${treeSize}_${timestamp}_${rootHash.slice(0, 16)}`.replace(/[^A-Za-z0-9_-]/g, "_");
}

export class LocalMerkleLog {
  private readonly leaves: StoredLogLeaf[] = [];
  private readonly checkpoints: SignedTreeHead[] = [];
  private readonly pendingProofs: PendingProof[] = [];
  private readonly signer: CheckpointSigner;
  private readonly writeAhead: WriteAheadLogSink | undefined;
  private readonly checkpointLeafInterval: number;

  constructor(options: LocalMerkleLogOptions = {}) {
    this.signer = options.signer ?? Ed25519CheckpointSigner.generate(options.logId);
    this.writeAhead = options.writeAhead;
    this.checkpointLeafInterval = options.checkpointLeafInterval ?? 1_000;
    if (!Number.isInteger(this.checkpointLeafInterval) || this.checkpointLeafInterval <= 0) {
      throw new Error("checkpointLeafInterval must be a positive integer");
    }
  }

  get logId(): string {
    return this.signer.logId;
  }

  append(leaf: LogLeaf): AppendResult {
    assertSupportedEvent(leaf.type);
    const canonical = canonicalLogLeaf(leaf);
    const hash = hashLeaf(leaf);
    const leafIndex = this.leaves.length;
    const record: StoredLogLeaf = {
      leaf: cloneLeaf(leaf),
      canonical,
      hash,
      leafIndex
    };
    this.writeAhead?.append(record);
    this.leaves.push(record);

    const inclusionProofPromise = new Promise<InclusionProof>((resolve, reject) => {
      this.pendingProofs.push({ leafIndex, resolve, reject });
    });

    if (this.leaves.length % this.checkpointLeafInterval === 0) {
      this.createCheckpoint();
    }

    return { leafIndex, leafHash: hash, inclusionProofPromise };
  }

  createCheckpoint(timestamp = Date.now()): SignedTreeHead {
    const leafHashes = this.leafHashes();
    const rootHash = merkleRoot(leafHashes);
    const unsigned = {
      checkpointId: checkpointId(this.logId, leafHashes.length, rootHash, timestamp),
      logId: this.logId,
      treeSize: leafHashes.length,
      rootHash,
      timestamp,
      tenantIds: this.tenantIds()
    };
    const sth: SignedTreeHead = {
      ...unsigned,
      signature: this.signer.sign(checkpointSigningPayload(unsigned))
    };
    this.checkpoints.push(sth);
    this.resolvePendingProofs(sth);
    return sth;
  }

  getCheckpoint(): SignedTreeHead {
    const latest = this.checkpoints.at(-1);
    return latest ?? this.createCheckpoint();
  }

  getInclusionProof(leafIndex: number, treeSize = this.getCheckpoint().treeSize): InclusionProof {
    return buildInclusionProof(this.leafHashes(), leafIndex, treeSize);
  }

  leaf(leafIndex: number): LogLeaf | undefined {
    const record = this.leaves[leafIndex];
    return record === undefined ? undefined : cloneLeaf(record.leaf);
  }

  leafHashes(): readonly string[] {
    return this.leaves.map((leaf) => leaf.hash);
  }

  treeSize(): number {
    return this.leaves.length;
  }

  checkpointCount(): number {
    return this.checkpoints.length;
  }

  latestCheckpointTreeSize(): number {
    return this.checkpoints.at(-1)?.treeSize ?? 0;
  }

  checkpointsForTenant(tenantId: string): readonly SignedTreeHead[] {
    return this.checkpoints.filter((checkpoint) => checkpoint.tenantIds.includes(tenantId));
  }

  private tenantIds(): readonly string[] {
    return [...new Set(this.leaves.map((record) => record.leaf.tenantId))].sort();
  }

  private resolvePendingProofs(sth: SignedTreeHead): void {
    const unresolved: PendingProof[] = [];
    for (const pending of this.pendingProofs) {
      if (pending.leafIndex >= sth.treeSize) {
        unresolved.push(pending);
        continue;
      }

      try {
        pending.resolve(this.getInclusionProof(pending.leafIndex, sth.treeSize));
      } catch (error) {
        pending.reject(error);
      }
    }

    this.pendingProofs.length = 0;
    this.pendingProofs.push(...unresolved);
  }
}
