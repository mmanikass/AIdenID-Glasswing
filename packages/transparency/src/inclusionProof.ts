import { createHash } from "node:crypto";

export type JsonValue =
  | null
  | boolean
  | number
  | string
  | readonly JsonValue[]
  | { readonly [key: string]: JsonValue };

export type LogEventType = "REVOCATION" | "POLICY_CHANGE" | "GRANT_ISSUED" | "SESSION_ISSUED" | "DECISION_RECORDED";

export interface LogLeaf {
  readonly id: string;
  readonly type: LogEventType;
  readonly tenantId: string;
  readonly payload: { readonly [key: string]: JsonValue };
  readonly ts: number;
}

export interface InclusionProofStep {
  readonly position: "left" | "right";
  readonly hash: string;
}

export interface InclusionProof {
  readonly leafIndex: number;
  readonly treeSize: number;
  readonly leafHash: string;
  readonly rootHash: string;
  readonly auditPath: readonly InclusionProofStep[];
}

export interface SignedTreeHead {
  readonly checkpointId: string;
  readonly logId: string;
  readonly treeSize: number;
  readonly rootHash: string;
  readonly timestamp: number;
  readonly signature: string;
  readonly tenantIds: readonly string[];
}

export function sha256Hex(input: string | Uint8Array): string {
  return createHash("sha256").update(input).digest("hex");
}

function assertJsonValue(value: unknown, path: string): asserts value is JsonValue {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error(`${path} must be a finite number`);
    }
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertJsonValue(item, `${path}[${index}]`));
    return;
  }
  if (typeof value === "object") {
    for (const [key, item] of Object.entries(value)) {
      if (item === undefined) {
        throw new Error(`${path}.${key} cannot be undefined`);
      }
      assertJsonValue(item, `${path}.${key}`);
    }
    return;
  }
  throw new Error(`${path} is not canonical JSON`);
}

export function canonicalJson(value: JsonValue): string {
  assertJsonValue(value, "$");
  if (value === null || typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  }

  const entries = Object.entries(value).sort(([left], [right]) => left.localeCompare(right));
  return `{${entries.map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`).join(",")}}`;
}

export function canonicalLogLeaf(leaf: LogLeaf): string {
  if (!leaf.id.trim()) {
    throw new Error("log leaf id is required");
  }
  if (!leaf.tenantId.trim()) {
    throw new Error("log leaf tenantId is required");
  }
  if (!Number.isInteger(leaf.ts) || leaf.ts < 0) {
    throw new Error("log leaf ts must be a non-negative integer");
  }

  return canonicalJson({
    id: leaf.id,
    payload: leaf.payload,
    tenantId: leaf.tenantId,
    ts: leaf.ts,
    type: leaf.type
  });
}

export function hashLeaf(leaf: LogLeaf): string {
  return sha256Hex(Buffer.concat([Buffer.from([0]), Buffer.from(canonicalLogLeaf(leaf), "utf8")]));
}

export function hashNode(leftHash: string, rightHash: string): string {
  return sha256Hex(Buffer.concat([Buffer.from([1]), Buffer.from(leftHash, "hex"), Buffer.from(rightHash, "hex")]));
}

export function merkleRoot(leafHashes: readonly string[]): string {
  if (leafHashes.length === 0) {
    return sha256Hex(new Uint8Array());
  }
  if (leafHashes.length === 1) {
    return leafHashes[0] ?? sha256Hex(new Uint8Array());
  }

  const split = largestPowerOfTwoLessThan(leafHashes.length);
  return hashNode(merkleRoot(leafHashes.slice(0, split)), merkleRoot(leafHashes.slice(split)));
}

function largestPowerOfTwoLessThan(value: number): number {
  let power = 1;
  while (power * 2 < value) {
    power *= 2;
  }
  return power;
}

function inclusionPath(leafHashes: readonly string[], leafIndex: number): readonly InclusionProofStep[] {
  if (leafHashes.length === 1) {
    return [];
  }

  const split = largestPowerOfTwoLessThan(leafHashes.length);
  if (leafIndex < split) {
    return [
      ...inclusionPath(leafHashes.slice(0, split), leafIndex),
      { position: "right", hash: merkleRoot(leafHashes.slice(split)) } satisfies InclusionProofStep
    ];
  }

  return [
    ...inclusionPath(leafHashes.slice(split), leafIndex - split),
    { position: "left", hash: merkleRoot(leafHashes.slice(0, split)) } satisfies InclusionProofStep
  ];
}

export function buildInclusionProof(
  leafHashes: readonly string[],
  leafIndex: number,
  treeSize = leafHashes.length
): InclusionProof {
  if (!Number.isInteger(leafIndex) || leafIndex < 0) {
    throw new Error("leafIndex must be a non-negative integer");
  }
  if (!Number.isInteger(treeSize) || treeSize <= leafIndex || treeSize > leafHashes.length) {
    throw new Error("treeSize must include the requested leaf");
  }

  const committedLeaves = leafHashes.slice(0, treeSize);
  const leafHash = committedLeaves[leafIndex];
  if (leafHash === undefined) {
    throw new Error("leaf hash not found");
  }

  return {
    leafIndex,
    treeSize,
    leafHash,
    rootHash: merkleRoot(committedLeaves),
    auditPath: inclusionPath(committedLeaves, leafIndex)
  };
}

export function verifyInclusionProof(leaf: LogLeaf, proof: InclusionProof, sth: SignedTreeHead): boolean {
  if (proof.treeSize !== sth.treeSize || proof.rootHash !== sth.rootHash || proof.leafIndex >= proof.treeSize) {
    return false;
  }
  if (hashLeaf(leaf) !== proof.leafHash) {
    return false;
  }

  let computed = proof.leafHash;
  for (const step of proof.auditPath) {
    computed = step.position === "left" ? hashNode(step.hash, computed) : hashNode(computed, step.hash);
  }

  return computed === sth.rootHash;
}
