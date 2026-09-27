import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, type JsonWebKey, type KeyObject } from "node:crypto";

import {
  canonicalJwkThumbprintBase64Url,
  canonicalJwkThumbprintSha256,
  signCompactJws,
  verifyCompactJws,
  type PublicJwk
} from "@aidenid/crypto";
import {
  canonicalJson,
  hashLeaf,
  LocalMerkleLog,
  verifyInclusionProof,
  type InclusionProof,
  type JsonValue,
  type LogLeaf,
  type SignedTreeHead
} from "@aidenid/transparency";

import type { ControlPlaneStore, DecisionReceiptIssuer, DecisionReceiptKeyRecord, DecisionReceiptKeyState, DecisionRecord } from "../types.js";

const RECEIPT_TYPE = "aidenid.decision_receipt.v1";
const RECEIPT_AUDIENCE = "aidenid.decision_receipt";

export interface LocalDecisionReceiptIssuerOptions {
  readonly issuer?: string | undefined;
  readonly keyId?: string | undefined;
  readonly privateKey?: KeyObject | undefined;
  readonly publicKey?: KeyObject | undefined;
  readonly transparencyLog?: LocalMerkleLog | undefined;
  readonly now?: (() => Date) | undefined;
}

export interface DecisionReceiptSignerEnvironment {
  readonly NODE_ENV?: string | undefined;
  readonly AIDENID_DECISION_RECEIPT_PRIVATE_JWK?: string | undefined;
  readonly AIDENID_DECISION_RECEIPT_KEY_ID?: string | undefined;
  readonly AIDENID_ALLOW_EPHEMERAL_DECISION_RECEIPT_KEY?: string | undefined;
}

export interface LocalDecisionReceiptIssuerFromEnvironmentOptions {
  readonly issuer: string;
  readonly env?: DecisionReceiptSignerEnvironment | undefined;
  readonly transparencyLog?: LocalMerkleLog | undefined;
  readonly now?: (() => Date) | undefined;
}

export interface DecisionReceiptKeyRecordOptions {
  readonly issuer: string;
  readonly kid: string;
  readonly publicJwk: Readonly<Record<string, unknown>>;
  readonly activatedAt: string;
  readonly state?: DecisionReceiptKeyState | undefined;
  readonly retireAfter?: string | undefined;
  readonly retiredAt?: string | undefined;
  readonly rotationReason?: string | undefined;
  readonly createdAt?: string | undefined;
  readonly updatedAt?: string | undefined;
}

export interface RegistryBackedDecisionReceiptIssuerOptions {
  readonly signer: LocalDecisionReceiptIssuer;
  readonly store: ControlPlaneStore;
  readonly now?: (() => Date) | undefined;
  readonly allowBootstrap?: boolean | undefined;
  readonly allowActiveKeyRotation?: boolean | undefined;
}

type DecisionReceiptIssueResult = Pick<
  DecisionRecord,
  | "receiptJws"
  | "receiptKeyId"
  | "receiptPublicJwk"
  | "receiptPayloadSha256"
  | "receiptJwsSha256"
  | "transparencyLeafHash"
  | "transparencyLeafIndex"
  | "transparencyCheckpoint"
  | "transparencyInclusionProof"
>;

function sha256Hex(input: string): string {
  return createHash("sha256").update(input).digest("hex");
}

function publicJwk(publicKey: KeyObject): Readonly<Record<string, unknown>> {
  return publicKey.export({ format: "jwk" }) as Readonly<Record<string, unknown>>;
}

function trimmed(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  const next = value.trim();
  return next.length === 0 ? undefined : next;
}

function truthy(value: string | undefined): boolean {
  return /^(1|true|yes)$/i.test(value ?? "");
}

function asRecord(value: unknown, name: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${name} must be a JSON object`);
  }
  return value as Record<string, unknown>;
}

function optionalString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim().length > 0 ? value.trim() : undefined;
}

function parseJsonObject(value: string, name: string): Record<string, unknown> {
  try {
    return asRecord(JSON.parse(value) as unknown, name);
  } catch (error) {
    if (error instanceof SyntaxError) {
      throw new Error(`${name} must be valid JSON`);
    }
    throw error;
  }
}

function decisionReceiptPrivateJwkFromSecret(value: string): { readonly jwk: JsonWebKey; readonly keyId?: string | undefined } {
  const root = parseJsonObject(value, "AIDENID_DECISION_RECEIPT_PRIVATE_JWK");
  const envelopeKeyId = optionalString(root.kid) ?? optionalString(root.key_id) ?? optionalString(root.keyId);
  const nested = root.private_jwk ?? root.privateJwk ?? root.jwk;
  const jwkRoot =
    typeof nested === "string"
      ? parseJsonObject(nested, "AIDENID_DECISION_RECEIPT_PRIVATE_JWK.private_jwk")
      : nested === undefined
        ? root
        : asRecord(nested, "AIDENID_DECISION_RECEIPT_PRIVATE_JWK.private_jwk");
  const keyId = envelopeKeyId ?? optionalString(jwkRoot.kid);
  if (jwkRoot.kty !== "OKP" || jwkRoot.crv !== "Ed25519") {
    throw new Error("AIDENID_DECISION_RECEIPT_PRIVATE_JWK must be an Ed25519 private JWK");
  }
  if (typeof jwkRoot.d !== "string" || jwkRoot.d.trim().length === 0 || typeof jwkRoot.x !== "string" || jwkRoot.x.trim().length === 0) {
    throw new Error("AIDENID_DECISION_RECEIPT_PRIVATE_JWK must include Ed25519 public and private key parameters");
  }
  return { jwk: jwkRoot as JsonWebKey, keyId };
}

function requiresConfiguredDecisionReceiptKey(env: DecisionReceiptSignerEnvironment): boolean {
  if (truthy(env.AIDENID_ALLOW_EPHEMERAL_DECISION_RECEIPT_KEY)) return false;
  return env.NODE_ENV?.trim().toLowerCase() === "production";
}

export function localDecisionReceiptIssuerFromEnvironment(options: LocalDecisionReceiptIssuerFromEnvironmentOptions): LocalDecisionReceiptIssuer {
  const env = options.env ?? process.env;
  const privateJwkSecret = trimmed(env.AIDENID_DECISION_RECEIPT_PRIVATE_JWK);
  const configuredKeyId = trimmed(env.AIDENID_DECISION_RECEIPT_KEY_ID);
  if (privateJwkSecret !== undefined) {
    const material = decisionReceiptPrivateJwkFromSecret(privateJwkSecret);
    const privateKey = createPrivateKey({ key: material.jwk, format: "jwk" });
    return new LocalDecisionReceiptIssuer({
      issuer: options.issuer,
      keyId: configuredKeyId ?? material.keyId,
      privateKey,
      publicKey: createPublicKey(privateKey),
      transparencyLog: options.transparencyLog,
      now: options.now
    });
  }
  if (requiresConfiguredDecisionReceiptKey(env)) {
    throw new Error(
      "AIDENID_DECISION_RECEIPT_PRIVATE_JWK is required in production; set AIDENID_ALLOW_EPHEMERAL_DECISION_RECEIPT_KEY=true only for explicit local/demo runs"
    );
  }
  return new LocalDecisionReceiptIssuer({
    issuer: options.issuer,
    transparencyLog: options.transparencyLog,
    now: options.now
  });
}

export function decisionReceiptKeyRecord(input: DecisionReceiptKeyRecordOptions): DecisionReceiptKeyRecord {
  return {
    kid: input.kid,
    issuer: input.issuer,
    alg: "EdDSA",
    publicJwk: input.publicJwk,
    jwkThumbprintSha256: canonicalJwkThumbprintSha256(input.publicJwk as PublicJwk),
    state: input.state ?? "active",
    activatedAt: input.activatedAt,
    retireAfter: input.retireAfter,
    retiredAt: input.retiredAt,
    rotationReason: input.rotationReason,
    createdAt: input.createdAt ?? input.activatedAt,
    updatedAt: input.updatedAt ?? input.activatedAt
  };
}

function decisionReceiptKeyUpsertInput(
  record: DecisionReceiptKeyRecord
): Omit<DecisionReceiptKeyRecord, "createdAt" | "updatedAt"> {
  return {
    kid: record.kid,
    issuer: record.issuer,
    alg: record.alg,
    publicJwk: record.publicJwk,
    jwkThumbprintSha256: record.jwkThumbprintSha256,
    state: record.state,
    activatedAt: record.activatedAt,
    retireAfter: record.retireAfter,
    retiredAt: record.retiredAt,
    rotationReason: record.rotationReason
  };
}

function isIssuableReceiptKey(record: DecisionReceiptKeyRecord, now: string): boolean {
  return record.state === "active" && (record.retireAfter === undefined || record.retireAfter > now);
}

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
        continue;
      }
      output[key] = toJsonValue(item, `${path}.${key}`);
    }
    return output;
  }
  throw new Error(`${path} cannot be encoded as receipt JSON`);
}

function toJsonObject(value: Readonly<Record<string, unknown>>, path: string): { readonly [key: string]: JsonValue } {
  const converted = toJsonValue(value, path);
  if (converted === null || typeof converted !== "object" || Array.isArray(converted)) {
    throw new Error(`${path} must be a JSON object`);
  }
  return converted as { readonly [key: string]: JsonValue };
}

export function decisionReceiptPayload(decision: DecisionRecord): Readonly<Record<string, unknown>> {
  return {
    id: decision.id,
    ...(decision.tenantId === undefined ? {} : { tenant_id: decision.tenantId }),
    site_id: decision.siteId,
    request_id: decision.requestId,
    actor_class: decision.actorClass,
    decision: decision.decision,
    ...(decision.recommendedDecision === undefined ? {} : { recommended_decision: decision.recommendedDecision }),
    route_template: decision.routeTemplate,
    method: decision.method,
    occurred_at: decision.occurredAt,
    ...(decision.latencyUs === undefined ? {} : { latency_us: decision.latencyUs }),
    ...(decision.subjectHandle === undefined ? {} : { subject_handle: decision.subjectHandle }),
    ...(decision.issuer === undefined ? {} : { issuer: decision.issuer }),
    ...(decision.llmBrand === undefined ? {} : { llm_brand: decision.llmBrand }),
    ...(decision.purpose === undefined ? {} : { purpose: decision.purpose }),
    ...(decision.priceUsd === undefined ? {} : { price_usd: decision.priceUsd }),
    ...(decision.suspicionScore === undefined ? {} : { suspicion_score: decision.suspicionScore }),
    reason_codes: decision.reasonCodes ?? [],
    ...(decision.cascadeTrace === undefined ? {} : { cascade_trace: decision.cascadeTrace })
  };
}

export function decisionReceiptPayloadSha256(decision: DecisionRecord): string {
  return sha256Hex(canonicalJson(toJsonObject(decisionReceiptPayload(decision), "decision")));
}

function receiptJwtPayload(
  decision: DecisionRecord,
  input: {
    readonly issuer: string;
    readonly keyId: string;
    readonly issuedAt: Date;
    readonly decisionPayloadSha256: string;
  }
): Readonly<Record<string, unknown>> {
  return {
    iss: input.issuer,
    aud: RECEIPT_AUDIENCE,
    typ: RECEIPT_TYPE,
    iat: Math.floor(input.issuedAt.getTime() / 1000),
    decision_id: decision.id,
    site_id: decision.siteId,
    ...(decision.tenantId === undefined ? {} : { tenant_id: decision.tenantId }),
    request_id: decision.requestId,
    actor_class: decision.actorClass,
    decision: decision.decision,
    recommended_decision: decision.recommendedDecision ?? decision.decision,
    route_template: decision.routeTemplate,
    method: decision.method,
    ...(decision.purpose === undefined ? {} : { purpose: decision.purpose }),
    occurred_at: decision.occurredAt,
    reason_codes: decision.reasonCodes ?? [],
    receipt_key_id: input.keyId,
    decision_payload_sha256: input.decisionPayloadSha256
  };
}

function transparencyLeaf(input: {
  readonly decision: DecisionRecord;
  readonly receiptJwsSha256: string;
  readonly decisionPayloadSha256: string;
  readonly ts: number;
}): LogLeaf {
  return {
    id: `decision:${input.decision.id}`,
    type: "DECISION_RECORDED",
    tenantId: input.decision.tenantId ?? input.decision.siteId,
    ts: input.ts,
    payload: {
      decision_id: input.decision.id,
      site_id: input.decision.siteId,
      ...(input.decision.tenantId === undefined ? {} : { tenant_id: input.decision.tenantId }),
      request_id: input.decision.requestId,
      actor_class: input.decision.actorClass,
      decision: input.decision.decision,
      occurred_at: input.decision.occurredAt,
      receipt_jws_sha256: input.receiptJwsSha256,
      decision_payload_sha256: input.decisionPayloadSha256
    }
  };
}

export class LocalDecisionReceiptIssuer implements DecisionReceiptIssuer {
  private readonly issuer: string;
  private readonly keyId: string;
  private readonly privateKey: KeyObject;
  private readonly publicKey: KeyObject;
  private readonly publicJwk: Readonly<Record<string, unknown>>;
  private readonly transparencyLog: LocalMerkleLog;
  private readonly now: () => Date;

  constructor(options: LocalDecisionReceiptIssuerOptions = {}) {
    if ((options.privateKey === undefined) !== (options.publicKey === undefined)) {
      throw new Error("decision receipt signer requires privateKey and publicKey together");
    }
    const generated = options.privateKey === undefined ? generateKeyPairSync("ed25519") : undefined;
    this.privateKey = options.privateKey ?? generated!.privateKey;
    this.publicKey = options.publicKey ?? generated!.publicKey;
    this.publicJwk = publicJwk(this.publicKey);
    this.issuer = options.issuer ?? "https://api.aidenid.local";
    this.keyId = options.keyId ?? `aidenid-decision-receipt-ed25519-${canonicalJwkThumbprintBase64Url(this.publicJwk as PublicJwk)}`;
    this.transparencyLog =
      options.transparencyLog ?? new LocalMerkleLog({ logId: "aidenid-decision-transparency-log", checkpointLeafInterval: 1_000 });
    this.now = options.now ?? (() => new Date());
  }

  currentKeyRecord(options: {
    readonly activatedAt?: string | undefined;
    readonly state?: DecisionReceiptKeyState | undefined;
    readonly retireAfter?: string | undefined;
    readonly retiredAt?: string | undefined;
    readonly rotationReason?: string | undefined;
    readonly createdAt?: string | undefined;
    readonly updatedAt?: string | undefined;
  } = {}): DecisionReceiptKeyRecord {
    const activatedAt = options.activatedAt ?? this.now().toISOString();
    return decisionReceiptKeyRecord({
      issuer: this.issuer,
      kid: this.keyId,
      publicJwk: this.publicJwk,
      activatedAt,
      state: options.state,
      retireAfter: options.retireAfter,
      retiredAt: options.retiredAt,
      rotationReason: options.rotationReason,
      createdAt: options.createdAt,
      updatedAt: options.updatedAt
    });
  }

  issue(decision: DecisionRecord): Pick<
    DecisionRecord,
    | "receiptJws"
    | "receiptKeyId"
    | "receiptPublicJwk"
    | "receiptPayloadSha256"
    | "receiptJwsSha256"
    | "transparencyLeafHash"
    | "transparencyLeafIndex"
    | "transparencyCheckpoint"
    | "transparencyInclusionProof"
  > {
    const issuedAt = this.now();
    const payloadSha256 = decisionReceiptPayloadSha256(decision);
    const receiptJws = signCompactJws(
      receiptJwtPayload(decision, {
        issuer: this.issuer,
        keyId: this.keyId,
        issuedAt,
        decisionPayloadSha256: payloadSha256
      }),
      this.privateKey,
      "EdDSA",
      { kid: this.keyId, typ: RECEIPT_TYPE }
    );
    const receiptJwsSha256 = sha256Hex(receiptJws);
    const leaf = transparencyLeaf({
      decision,
      receiptJwsSha256,
      decisionPayloadSha256: payloadSha256,
      ts: issuedAt.getTime()
    });
    const append = this.transparencyLog.append(leaf);
    const checkpoint = this.transparencyLog.createCheckpoint(issuedAt.getTime());
    const inclusionProof = this.transparencyLog.getInclusionProof(append.leafIndex, checkpoint.treeSize);

    return {
      receiptJws,
      receiptKeyId: this.keyId,
      receiptPublicJwk: this.publicJwk,
      receiptPayloadSha256: payloadSha256,
      receiptJwsSha256,
      transparencyLeafHash: hashLeaf(leaf),
      transparencyLeafIndex: append.leafIndex,
      transparencyCheckpoint: checkpoint as unknown as Readonly<Record<string, unknown>>,
      transparencyInclusionProof: inclusionProof as unknown as Readonly<Record<string, unknown>>
    };
  }

  verify(decision: DecisionRecord): boolean {
    try {
      if (
        decision.receiptJws === undefined ||
        decision.receiptKeyId === undefined ||
        decision.receiptPublicJwk === undefined ||
        decision.receiptPayloadSha256 === undefined ||
        decision.receiptJwsSha256 === undefined ||
        decision.transparencyCheckpoint === undefined ||
        decision.transparencyInclusionProof === undefined ||
        decision.transparencyLeafHash === undefined
      ) {
        return false;
      }
      const decoded = verifyCompactJws(decision.receiptJws, decision.receiptPublicJwk as PublicJwk, "EdDSA");
      if (
        decoded.header.kid !== decision.receiptKeyId ||
        decoded.header.typ !== RECEIPT_TYPE ||
        decoded.payload.iss !== this.issuer ||
        decoded.payload.aud !== RECEIPT_AUDIENCE ||
        decoded.payload.typ !== RECEIPT_TYPE ||
        decoded.payload.receipt_key_id !== decision.receiptKeyId ||
        decoded.payload.decision_id !== decision.id ||
        decoded.payload.site_id !== decision.siteId ||
        decoded.payload.request_id !== decision.requestId ||
        decoded.payload.actor_class !== decision.actorClass ||
        decoded.payload.decision !== decision.decision ||
        decoded.payload.route_template !== decision.routeTemplate ||
        decoded.payload.method !== decision.method ||
        decoded.payload.occurred_at !== decision.occurredAt ||
        decoded.payload.decision_payload_sha256 !== decision.receiptPayloadSha256
      ) {
        return false;
      }
      if (decisionReceiptPayloadSha256(decision) !== decision.receiptPayloadSha256) {
        return false;
      }
      const receiptJwsSha256 = sha256Hex(decision.receiptJws);
      if (receiptJwsSha256 !== decision.receiptJwsSha256) {
        return false;
      }
      const leaf = transparencyLeaf({
        decision,
        receiptJwsSha256,
        decisionPayloadSha256: decision.receiptPayloadSha256,
        ts: Number((decision.transparencyCheckpoint as { readonly timestamp?: unknown }).timestamp ?? Date.parse(decision.occurredAt))
      });
      if (hashLeaf(leaf) !== decision.transparencyLeafHash) {
        return false;
      }
      return verifyInclusionProof(
        leaf,
        decision.transparencyInclusionProof as unknown as InclusionProof,
        decision.transparencyCheckpoint as unknown as SignedTreeHead
      );
    } catch {
      return false;
    }
  }
}

export class RegistryBackedDecisionReceiptIssuer implements DecisionReceiptIssuer {
  private readonly signer: LocalDecisionReceiptIssuer;
  private readonly store: ControlPlaneStore;
  private readonly now: () => Date;
  private readonly allowBootstrap: boolean;
  private readonly allowActiveKeyRotation: boolean;

  constructor(options: RegistryBackedDecisionReceiptIssuerOptions) {
    this.signer = options.signer;
    this.store = options.store;
    this.now = options.now ?? (() => new Date());
    this.allowBootstrap = options.allowBootstrap ?? true;
    this.allowActiveKeyRotation = options.allowActiveKeyRotation ?? false;
  }

  async issue(decision: DecisionRecord): Promise<DecisionReceiptIssueResult> {
    const activeKey = await this.ensureRegistryKey();
    const issued = await Promise.resolve(this.signer.issue(decision));
    if (issued.receiptKeyId !== activeKey.kid || issued.receiptPublicJwk === undefined) {
      throw new Error("decision receipt signer did not use the registry-active key");
    }
    const issuedThumbprint = canonicalJwkThumbprintSha256(issued.receiptPublicJwk as PublicJwk);
    if (issuedThumbprint !== activeKey.jwkThumbprintSha256) {
      throw new Error("decision receipt signer public key does not match registry-active key");
    }
    return issued;
  }

  async verify(decision: DecisionRecord): Promise<boolean> {
    return await Promise.resolve(this.signer.verify(decision));
  }

  private async ensureRegistryKey(): Promise<DecisionReceiptKeyRecord> {
    const now = this.now().toISOString();
    const signerRecord = this.signer.currentKeyRecord({ activatedAt: now });
    const activeRecord = await Promise.resolve(this.store.getActiveDecisionReceiptKey(signerRecord.issuer, now));
    if (activeRecord !== undefined) {
      if (this.allowActiveKeyRotation && !this.registryMatchesSigner(signerRecord, activeRecord)) {
        return await this.rotateActiveRegistryKey(signerRecord, activeRecord, now);
      }
      this.assertSignerMatchesRegistry(signerRecord, activeRecord);
      return activeRecord;
    }

    const existingSignerRecord = await Promise.resolve(this.store.getDecisionReceiptKey(signerRecord.kid));
    if (existingSignerRecord !== undefined) {
      this.assertSignerMatchesRegistry(signerRecord, existingSignerRecord);
      if (!isIssuableReceiptKey(existingSignerRecord, now)) {
        throw new Error(`decision receipt key '${signerRecord.kid}' is not active for issuance`);
      }
      return existingSignerRecord;
    }

    if (!this.allowBootstrap) {
      throw new Error("decision receipt key registry has no active key for signer");
    }
    return await Promise.resolve(this.store.upsertDecisionReceiptKey(decisionReceiptKeyUpsertInput(signerRecord), now));
  }

  private async rotateActiveRegistryKey(
    signerRecord: DecisionReceiptKeyRecord,
    activeRecord: DecisionReceiptKeyRecord,
    now: string
  ): Promise<DecisionReceiptKeyRecord> {
    const retired = await Promise.resolve(
      this.store.retireDecisionReceiptKey(activeRecord.kid, now, `configured-signer-rotation:${signerRecord.kid}`)
    );
    if (retired === undefined) {
      throw new Error(`decision receipt registry active key '${activeRecord.kid}' could not be retired for signer rotation`);
    }
    return await Promise.resolve(this.store.upsertDecisionReceiptKey(decisionReceiptKeyUpsertInput(signerRecord), now));
  }

  private registryMatchesSigner(signerRecord: DecisionReceiptKeyRecord, registryRecord: DecisionReceiptKeyRecord): boolean {
    return (
      registryRecord.kid === signerRecord.kid &&
      registryRecord.issuer === signerRecord.issuer &&
      registryRecord.jwkThumbprintSha256 === signerRecord.jwkThumbprintSha256
    );
  }

  private assertSignerMatchesRegistry(signerRecord: DecisionReceiptKeyRecord, registryRecord: DecisionReceiptKeyRecord): void {
    if (!this.registryMatchesSigner(signerRecord, registryRecord) && registryRecord.kid !== signerRecord.kid) {
      throw new Error(`decision receipt registry active kid '${registryRecord.kid}' does not match signer kid '${signerRecord.kid}'`);
    }
    if (!this.registryMatchesSigner(signerRecord, registryRecord)) {
      throw new Error("decision receipt registry active key metadata does not match signer");
    }
  }
}
