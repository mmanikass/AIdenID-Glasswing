import { createHash } from "node:crypto";

import { canonicalJson, type JsonValue, type LogLeaf, type SignedTreeHead } from "./inclusionProof.js";
import { type LocalMerkleLog } from "./localLog.js";

export interface PublishedCheckpoint {
  readonly checkpointId: string;
  readonly logId: string;
  readonly treeSize: number;
  readonly rootHash: string;
  readonly uri: string;
  readonly tenantIds: readonly string[];
  readonly publishedAt: string;
  readonly etag?: string;
  readonly versionId?: string;
}

export interface CheckpointPublisher {
  publish(sth: SignedTreeHead): Promise<PublishedCheckpoint>;
}

export interface CheckpointWorkerOptions {
  readonly intervalMs?: number;
  readonly maxLeavesPerCheckpoint?: number;
  readonly now?: () => number;
}

export interface CheckpointWorkerTick {
  readonly published: boolean;
  readonly checkpoint?: SignedTreeHead;
  readonly publication?: PublishedCheckpoint;
}

export interface S3PutObjectInput {
  readonly Bucket: string;
  readonly Key: string;
  readonly Body: string;
  readonly ContentType: string;
  readonly ChecksumSHA256: string;
  readonly ObjectLockMode: "COMPLIANCE";
  readonly ObjectLockRetainUntilDate: Date;
  readonly Metadata: Readonly<Record<string, string>>;
}

export interface S3PutObjectOutput {
  readonly ETag?: string;
  readonly VersionId?: string;
}

export interface S3WormClient {
  putObject(input: S3PutObjectInput): Promise<S3PutObjectOutput>;
}

export interface S3WormCheckpointPublisherOptions {
  readonly client: S3WormClient;
  readonly bucket: string;
  readonly prefix?: string;
  readonly retentionDays?: number;
  readonly now?: () => Date;
}

export class InMemoryCheckpointPublisher implements CheckpointPublisher {
  readonly published: PublishedCheckpoint[] = [];

  async publish(sth: SignedTreeHead): Promise<PublishedCheckpoint> {
    const publication: PublishedCheckpoint = {
      checkpointId: sth.checkpointId,
      logId: sth.logId,
      treeSize: sth.treeSize,
      rootHash: sth.rootHash,
      tenantIds: [...sth.tenantIds],
      uri: `memory://${sth.logId}/${sth.checkpointId}`,
      publishedAt: new Date(sth.timestamp).toISOString()
    };
    this.published.push(publication);
    return publication;
  }

  byTenant(tenantId: string): readonly PublishedCheckpoint[] {
    return this.published.filter((checkpoint) => checkpoint.tenantIds.includes(tenantId));
  }
}

export class S3WormCheckpointPublisher implements CheckpointPublisher {
  private readonly client: S3WormClient;
  private readonly bucket: string;
  private readonly prefix: string;
  private readonly retentionDays: number;
  private readonly now: () => Date;

  constructor(options: S3WormCheckpointPublisherOptions) {
    this.client = options.client;
    this.bucket = options.bucket;
    this.prefix = options.prefix ?? "transparency-checkpoints";
    this.retentionDays = options.retentionDays ?? 365;
    this.now = options.now ?? (() => new Date());
    if (!Number.isInteger(this.retentionDays) || this.retentionDays <= 0) {
      throw new Error("retentionDays must be a positive integer");
    }
  }

  async publish(sth: SignedTreeHead): Promise<PublishedCheckpoint> {
    const publishedAt = this.now();
    const body = JSON.stringify(sth);
    const key = `${this.prefix}/${sth.logId}/${sth.checkpointId}.json`;
    const output = await this.client.putObject({
      Bucket: this.bucket,
      Key: key,
      Body: body,
      ContentType: "application/json",
      ChecksumSHA256: createHash("sha256").update(body).digest("base64"),
      ObjectLockMode: "COMPLIANCE",
      ObjectLockRetainUntilDate: new Date(publishedAt.getTime() + this.retentionDays * 24 * 60 * 60 * 1_000),
      Metadata: {
        checkpoint_id: sth.checkpointId,
        log_id: sth.logId,
        root_hash: sth.rootHash,
        tree_size: String(sth.treeSize)
      }
    });

    return {
      checkpointId: sth.checkpointId,
      logId: sth.logId,
      treeSize: sth.treeSize,
      rootHash: sth.rootHash,
      tenantIds: [...sth.tenantIds],
      uri: `s3://${this.bucket}/${key}`,
      publishedAt: publishedAt.toISOString(),
      ...(output.ETag === undefined ? {} : { etag: output.ETag }),
      ...(output.VersionId === undefined ? {} : { versionId: output.VersionId })
    };
  }
}

export class CheckpointWorker {
  private readonly intervalMs: number;
  private readonly maxLeavesPerCheckpoint: number;
  private readonly now: () => number;
  private lastCheckpointAt: number;
  private lastPublishedTreeSize = 0;

  constructor(
    private readonly log: LocalMerkleLog,
    private readonly publisher: CheckpointPublisher,
    options: CheckpointWorkerOptions = {}
  ) {
    this.intervalMs = options.intervalMs ?? 60_000;
    this.maxLeavesPerCheckpoint = options.maxLeavesPerCheckpoint ?? 1_000;
    this.now = options.now ?? Date.now;
    this.lastCheckpointAt = this.now();
    if (!Number.isInteger(this.intervalMs) || this.intervalMs <= 0) {
      throw new Error("intervalMs must be a positive integer");
    }
    if (!Number.isInteger(this.maxLeavesPerCheckpoint) || this.maxLeavesPerCheckpoint <= 0) {
      throw new Error("maxLeavesPerCheckpoint must be a positive integer");
    }
  }

  async tick(now = this.now()): Promise<CheckpointWorkerTick> {
    if (!this.shouldCheckpoint(now)) {
      return { published: false };
    }

    return this.publishCheckpoint(now);
  }

  async forceCheckpoint(now = this.now()): Promise<CheckpointWorkerTick> {
    if (this.log.treeSize() === 0) {
      return { published: false };
    }
    return this.publishCheckpoint(now);
  }

  private shouldCheckpoint(now: number): boolean {
    const unpublishedLeaves = this.log.treeSize() - this.lastPublishedTreeSize;
    if (unpublishedLeaves <= 0) {
      return false;
    }
    return unpublishedLeaves >= this.maxLeavesPerCheckpoint || now - this.lastCheckpointAt >= this.intervalMs;
  }

  private async publishCheckpoint(now: number): Promise<CheckpointWorkerTick> {
    const checkpoint = this.log.createCheckpoint(now);
    const publication = await this.publisher.publish(checkpoint);
    this.lastCheckpointAt = now;
    this.lastPublishedTreeSize = checkpoint.treeSize;
    return { published: true, checkpoint, publication };
  }
}

interface OutboxEventShape {
  readonly id: string;
  readonly type: string;
  readonly occurredAt: string;
  readonly payload: Readonly<Record<string, unknown>>;
}

const OUTBOX_EVENT_MAP: Readonly<Record<string, LogLeaf["type"]>> = {
  REVOCATION_EPOCH_BUMP: "REVOCATION",
  POLICY_BUNDLE_VERSION: "POLICY_CHANGE",
  GRANT_ISSUED_HASH: "GRANT_ISSUED",
  SESSION_ISSUED_HASH: "SESSION_ISSUED",
  DECISION_RECORDED: "DECISION_RECORDED"
};

function toJsonValue(value: unknown, path: string): JsonValue {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error(`${path} must be finite`);
    }
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item, index) => toJsonValue(item, `${path}[${index}]`));
  }
  if (typeof value === "object") {
    const output: Record<string, JsonValue> = {};
    for (const [key, item] of Object.entries(value)) {
      if (item === undefined) {
        throw new Error(`${path}.${key} cannot be undefined`);
      }
      output[key] = toJsonValue(item, `${path}.${key}`);
    }
    return output;
  }
  throw new Error(`${path} cannot be encoded as transparency JSON`);
}

export function transparencyLeafFromOutboxEvent(
  event: OutboxEventShape,
  options: { readonly tenantId?: string } = {}
): LogLeaf | undefined {
  const mappedType = OUTBOX_EVENT_MAP[event.type];
  if (mappedType === undefined) {
    return undefined;
  }

  const tenantId = typeof event.payload.tenant_id === "string" ? event.payload.tenant_id : options.tenantId;
  if (tenantId === undefined || tenantId.trim().length === 0) {
    throw new Error("tenant_id is required for transparency log event");
  }

  const ts = Date.parse(event.occurredAt);
  if (!Number.isFinite(ts)) {
    throw new Error("outbox event occurredAt is invalid");
  }

  const payload = toJsonValue(event.payload, "payload");
  if (payload === null || typeof payload !== "object" || Array.isArray(payload)) {
    throw new Error("outbox payload must be an object");
  }
  const payloadObject = payload as { readonly [key: string]: JsonValue };

  return {
    id: event.id,
    type: mappedType,
    tenantId,
    payload: payloadObject,
    ts
  };
}

export function commitmentPayloadDigest(payload: { readonly [key: string]: JsonValue }): string {
  return createHash("sha256").update(canonicalJson(payload)).digest("hex");
}
