import type { KeyObject } from "node:crypto";

import type { AgentIdentityPurpose, CascadeTrace, CascadeTraceLayer, DecisionAction } from "@aidenid/common-schemas";
import type { OutboxPublisher } from "@aidenid/eventing";

export type MaybePromise<T> = T | Promise<T>;

/**
 * The key that signs session tokens issued by /v1/sessions/exchange. Its public JWK is what
 * a verifier must hold under `sessionTokenPublicJwksByIssuer[issuer]`; without it no verifier
 * can validate a real exchanged session. Published at /.well-known/aidenid-session-jwks.json.
 */
export interface SessionSigner {
  readonly kid: string;
  readonly alg: "EdDSA";
  readonly privateKey: KeyObject;
  readonly publicJwk: Readonly<Record<string, unknown>>;
}

export interface TargetRecord {
  readonly id: string;
  readonly tenantId: string;
  readonly siteId: string;
  readonly name: string;
  readonly origin: string;
  readonly createdAt: string;
}

export interface GrantRecord {
  readonly id: string;
  readonly targetId: string;
  readonly siteId: string;
  readonly subject: string;
  readonly chainId: string;
  readonly resource: string;
  readonly permissions: readonly string[];
  readonly expiresAt: string;
  readonly createdAt: string;
  readonly revokedAt?: string | undefined;
  /**
   * The authenticated operator that issued this grant, bound server-side at issuance.
   * A grant mints the delegation authority the session exchange later verifies, so it is
   * the record that most needs an attributable issuer.
   *
   * OPTIONAL because grants issued before attribution existed genuinely have no issuer.
   * Absent means "unattributed, predates this field" — it must not be read as "issued by
   * nobody", and it must not be backfilled with a guess.
   */
  readonly issuerActorId?: string | undefined;
}

export interface SessionRecord {
  readonly id: string;
  readonly grantId: string;
  readonly chainId: string;
  readonly siteId: string;
  readonly tokenHashSha256: string;
  readonly proofJkt: string;
  readonly revocationEpoch: number;
  readonly issuedAt: string;
  readonly expiresAt: string;
}

export interface RevocationRecord {
  readonly id: string;
  readonly chainId: string;
  readonly epoch: number;
  readonly reason: string;
  readonly actorId: string;
  readonly occurredAt: string;
}

export interface DecisionRecord {
  readonly id: string;
  readonly tenantId?: string | undefined;
  readonly siteId: string;
  readonly requestId: string;
  readonly actorClass: string;
  readonly decision: string;
  readonly recommendedDecision?: string | undefined;
  readonly routeTemplate: string;
  readonly method: string;
  readonly occurredAt: string;
  readonly latencyUs?: number | undefined;
  readonly subjectHandle?: string | undefined;
  readonly issuer?: string | undefined;
  readonly llmBrand?: string | undefined;
  readonly purpose?: string | undefined;
  readonly priceUsd?: number | undefined;
  readonly suspicionScore?: number | undefined;
  readonly reasonCodes?: readonly string[] | undefined;
  readonly cascadeTrace?: CascadeTrace | undefined;
  readonly receiptJws?: string | undefined;
  readonly receiptKeyId?: string | undefined;
  readonly receiptPublicJwk?: Readonly<Record<string, unknown>> | undefined;
  readonly receiptPayloadSha256?: string | undefined;
  readonly receiptJwsSha256?: string | undefined;
  readonly transparencyLeafHash?: string | undefined;
  readonly transparencyLeafIndex?: number | undefined;
  readonly transparencyCheckpoint?: Readonly<Record<string, unknown>> | undefined;
  readonly transparencyInclusionProof?: Readonly<Record<string, unknown>> | undefined;
  readonly operatorAction?: string | undefined;
  readonly operatorActionActorId?: string | undefined;
  readonly operatorActionReason?: string | undefined;
  readonly operatorActionAt?: string | undefined;
  readonly operatorActionEffectiveDecision?: string | undefined;
  readonly operatorActionExpiresAt?: string | undefined;
  readonly operatorActionEffects?: readonly string[] | undefined;
}

export type DecisionOutboxEventType = "recorded" | "pending" | "resolved" | "updated";

export interface DecisionOutboxEvent {
  readonly seq: number;
  readonly decisionId: string;
  readonly occurredAt: string;
  readonly eventType: DecisionOutboxEventType;
  readonly payload: Readonly<Record<string, unknown>>;
  readonly previousHash: string;
  readonly entryHash: string;
}

export type DecisionOutboxWriteResult =
  | {
      readonly status: "recorded";
      readonly decision: DecisionRecord;
      readonly event: DecisionOutboxEvent;
    }
  | {
      readonly status: "quota_exceeded";
      readonly tenantId: string;
      readonly storedDecisionLimit: number;
    };

export type DecisionReceiptKeyState = "active" | "retiring" | "retired";

export interface DecisionReceiptKeyRecord {
  readonly kid: string;
  readonly issuer: string;
  readonly alg: "EdDSA";
  readonly publicJwk: Readonly<Record<string, unknown>>;
  readonly jwkThumbprintSha256: string;
  readonly state: DecisionReceiptKeyState;
  readonly activatedAt: string;
  readonly retireAfter?: string | undefined;
  readonly retiredAt?: string | undefined;
  readonly rotationReason?: string | undefined;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface TenantQuotaRecord {
  readonly tenantId: string;
  readonly monthlyDecisionLimit: number;
  readonly storedDecisionLimit: number;
  readonly targetLimit: number;
  readonly updatedAt: string;
}

export interface TenantPricingPlanRecord {
  readonly tenantId: string;
  readonly planTier: string;
  readonly currency: "USD";
  readonly unitPriceUsd: number;
  readonly includedMonthlyClearedDecisions: number;
  readonly effectiveFrom: string;
  readonly updatedAt: string;
}

export interface BillingPeriodRollupRecord {
  readonly id: string;
  readonly tenantId: string;
  readonly periodStart: string;
  readonly periodEnd: string;
  readonly planTier: string;
  readonly currency: "USD";
  readonly unitPriceUsd: number;
  readonly includedClearedDecisions: number;
  readonly clearedDecisionCount: number;
  readonly billableClearedDecisionCount: number;
  readonly overageClearedDecisionCount: number;
  readonly estimatedCostUsd: number;
  readonly priceRequiredGrossUsd: number;
  readonly invoiceLineItemId: string;
  readonly exportIdempotencyKey: string;
  readonly generatedAt: string;
}

export type BillingExportProvider = "stripe_meter_event" | "quickbooks_invoice";
export type BillingExportStatus = "prepared" | "delivered";

export interface BillingExportRecord {
  readonly id: string;
  readonly rollupId: string;
  readonly tenantId: string;
  readonly periodStart: string;
  readonly periodEnd: string;
  readonly provider: BillingExportProvider;
  readonly destinationRef: string;
  readonly idempotencyKey: string;
  readonly payloadSha256: string;
  readonly payload: Readonly<Record<string, unknown>>;
  readonly status: BillingExportStatus;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly deliveredAt?: string | undefined;
  readonly providerReceiptId?: string | undefined;
  readonly providerReceiptStatus?: string | undefined;
  readonly providerReceiptPayloadSha256?: string | undefined;
  readonly providerReceiptRecordedAt?: string | undefined;
}

export interface BillingExportListInput {
  readonly tenantId?: string | undefined;
  readonly provider?: BillingExportProvider | undefined;
  readonly status?: BillingExportStatus | undefined;
  readonly periodStart?: string | undefined;
  readonly periodEnd?: string | undefined;
  readonly limit: number;
}

export interface BillingExportDeliveryReceiptInput {
  readonly id: string;
  readonly providerReceiptId: string;
  readonly providerReceiptStatus: string;
  readonly providerReceiptPayloadSha256: string;
  readonly deliveredAt: string;
}

export interface PrivacyErasureRecord {
  readonly id: string;
  readonly siteId: string;
  readonly subjectHandle: string;
  readonly reason: string;
  readonly actorId: string;
  readonly erasedDecisionCount: number;
  readonly occurredAt: string;
}

export interface WebhookEndpointRecord {
  readonly id: string;
  readonly tenantId: string;
  readonly url: string;
  readonly eventTypes: readonly string[];
  readonly signingSecretRef: string;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface QuarantinePinRecord {
  readonly id: string;
  readonly decisionId: string;
  readonly siteId: string;
  readonly actorClass: string;
  readonly issuer?: string | undefined;
  readonly subjectHandle?: string | undefined;
  readonly requestId: string;
  readonly operatorActorId: string;
  readonly reason?: string | undefined;
  readonly expiresAt: string;
  readonly createdAt: string;
}

export type OperatorTrustTier = "unknown" | "trusted" | "restricted";
export type OperatorReputationStatus = "active" | "watchlist" | "suspended" | "expired";

export interface OperatorReputationRecord {
  readonly id: string;
  readonly siteId: string;
  readonly operatorActorId: string;
  readonly displayName?: string | undefined;
  readonly trustTier: OperatorTrustTier;
  readonly status: OperatorReputationStatus;
  readonly reputationScore: number;
  readonly defaultAction?: DecisionAction | undefined;
  readonly defaultScopeRoutes?: readonly string[] | undefined;
  readonly defaultScopeRedirectPath?: string | undefined;
  readonly notes?: string | undefined;
  readonly lastReviewedAt?: string | undefined;
  readonly expiresAt?: string | undefined;
  readonly updatedBy: string;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface OperatorReputationListInput {
  readonly siteId: string;
  readonly status?: OperatorReputationStatus | undefined;
  readonly trustTier?: OperatorTrustTier | undefined;
  readonly limit: number;
}

export type AgentIdentitySubmissionStatus = "pending_review" | "approved" | "rejected";

export interface AgentIdentitySubmissionRecord {
  readonly id: string;
  readonly siteId: string;
  readonly requestId?: string | undefined;
  readonly purpose: AgentIdentityPurpose;
  readonly requestedAccessDurationSeconds: number;
  readonly requestedAccessExpiresAt: string;
  readonly purposeRationale?: string | undefined;
  readonly providerName: string;
  readonly operatorActorId?: string | undefined;
  readonly contactUrl: string;
  readonly jwksUrl?: string | undefined;
  readonly delegationAuthorityJwkThumbprintSha256?: string | undefined;
  readonly cascadeAttestation: readonly CascadeTraceLayer[];
  readonly declaration?: string | undefined;
  readonly submitterHashSha256: string;
  readonly submissionDigestSha256: string;
  readonly operatorClaimHashSha256: string;
  readonly status: AgentIdentitySubmissionStatus;
  readonly submittedAt: string;
  readonly reviewedAt?: string | undefined;
  readonly reviewDecision?: "approve" | "reject" | undefined;
  readonly reviewerIdentityHashSha256?: string | undefined;
  readonly reviewReason?: string | undefined;
  readonly approvedOperatorActorId?: string | undefined;
  readonly operatorReputationId?: string | undefined;
  readonly assignedTrustTier?: OperatorTrustTier | undefined;
  readonly assignedOperatorStatus?: OperatorReputationStatus | undefined;
  readonly assignedReputationScore?: number | undefined;
}

export interface AgentIdentitySubmissionListInput {
  readonly siteId?: string | undefined;
  readonly status?: AgentIdentitySubmissionStatus | undefined;
  readonly limit: number;
}

export type AgentIdentityReviewNotificationStatus = "unread" | "read";

export interface AgentIdentityReviewNotificationRecord {
  readonly id: string;
  readonly siteId: string;
  readonly submissionId: string;
  readonly reviewDecision: "approve" | "reject";
  readonly providerName: string;
  readonly operatorActorId?: string | undefined;
  readonly contactUrl: string;
  readonly reviewerIdentityHashSha256: string;
  readonly reviewReason?: string | undefined;
  readonly status: AgentIdentityReviewNotificationStatus;
  readonly createdAt: string;
  readonly readAt?: string | undefined;
}

export interface AgentIdentityReviewNotificationListInput {
  readonly siteId?: string | undefined;
  readonly status?: AgentIdentityReviewNotificationStatus | undefined;
  readonly limit: number;
}

export type AgentIdentitySubmissionReviewInput =
  | {
      readonly submissionId: string;
      readonly action: "approve";
      readonly reviewerIdentityHashSha256: string;
      readonly reviewReason?: string | undefined;
      readonly approvedOperatorActorId: string;
      readonly operatorReputation: Omit<OperatorReputationRecord, "id" | "createdAt" | "updatedAt">;
    }
  | {
      readonly submissionId: string;
      readonly action: "reject";
      readonly reviewerIdentityHashSha256: string;
      readonly reviewReason: string;
    };

export type AgentIdentitySubmissionReviewResult =
  | {
      readonly status: "not_found";
    }
  | {
      readonly status: "already_reviewed";
      readonly submission: AgentIdentitySubmissionRecord;
    }
  | {
      readonly status: "reviewed";
      readonly submission: AgentIdentitySubmissionRecord;
      readonly operatorReputation?: OperatorReputationRecord | undefined;
    };

export type PersonaAuditTriggerType = "revocation_epoch" | "suspicion_threshold";
export type PersonaAuditStatus = "queued" | "completed";
export type PersonaAuditSeverity = "medium" | "high";

export interface PersonaAuditNarrative {
  readonly title: string;
  readonly summary: string;
  readonly evidenceRefs: readonly string[];
  readonly recommendedActions: readonly string[];
}

export interface PersonaAuditJob {
  readonly id: string;
  readonly triggerType: PersonaAuditTriggerType;
  readonly status: PersonaAuditStatus;
  readonly severity: PersonaAuditSeverity;
  readonly tool: "create-sentinelayer";
  readonly personaPack: "aidenid-post-incident-auditor";
  readonly siteId?: string | undefined;
  readonly chainId?: string | undefined;
  readonly requestId?: string | undefined;
  readonly actorClass?: string | undefined;
  readonly decision?: string | undefined;
  readonly suspicionScore?: number | undefined;
  readonly revocationEpoch?: number | undefined;
  readonly reason?: string | undefined;
  readonly actorId?: string | undefined;
  readonly inputRefs: readonly string[];
  readonly narrative: PersonaAuditNarrative;
  readonly createdAt: string;
}

export interface PersonaAuditEnqueueInput {
  readonly triggerType: PersonaAuditTriggerType;
  readonly siteId?: string | undefined;
  readonly chainId?: string | undefined;
  readonly requestId?: string | undefined;
  readonly actorClass?: string | undefined;
  readonly decision?: string | undefined;
  readonly suspicionScore?: number | undefined;
  readonly revocationEpoch?: number | undefined;
  readonly reason?: string | undefined;
  readonly actorId?: string | undefined;
  readonly occurredAt?: string | undefined;
}

export interface PersonaAuditController {
  readonly suspicionThreshold: number;
  enqueue(input: PersonaAuditEnqueueInput): PersonaAuditJob;
  list(siteId?: string | undefined, limit?: number | undefined): readonly PersonaAuditJob[];
}

export type CryptoPathRolloutMode = "disabled" | "shadow" | "enforce";
export type VerifierMode = "observe" | "recommend" | "enforce";

export interface KillSwitchState {
  readonly active: boolean;
  readonly denyNewSessions: boolean;
  readonly globalEnforcementPause: boolean;
  readonly routeModeOverrides: Readonly<Record<string, VerifierMode>>;
  readonly cryptoPathRollout: CryptoPathRolloutMode;
  readonly minRevocationEpoch?: number | undefined;
  readonly reason?: string | undefined;
  readonly actorId?: string | undefined;
  readonly updatedAt?: string | undefined;
}

export interface KillSwitchUpdate {
  readonly active: boolean;
  readonly reason: string;
  readonly actorId: string;
  readonly denyNewSessions?: boolean | undefined;
  readonly globalEnforcementPause?: boolean | undefined;
  readonly routeModeOverrides?: Readonly<Record<string, VerifierMode>> | undefined;
  readonly cryptoPathRollout?: CryptoPathRolloutMode | undefined;
  readonly minRevocationEpoch?: number | undefined;
  readonly updatedAt?: string | undefined;
}

export interface KillSwitchController {
  current(): KillSwitchState;
  update(input: KillSwitchUpdate): KillSwitchState;
  clear(input: { readonly reason: string; readonly actorId: string; readonly updatedAt?: string | undefined }): KillSwitchState;
}

export interface DecisionSearchInput {
  readonly siteId: string;
  readonly decision?: string | undefined;
  readonly operatorActorId?: string | undefined;
  readonly since?: string | undefined;
  readonly until?: string | undefined;
  readonly issuer?: string | undefined;
  readonly subjectHandle?: string | undefined;
  readonly actorClass?: string | undefined;
  readonly routeTemplate?: string | undefined;
  readonly purpose?: string | undefined;
  readonly limit: number;
}

export interface ControlPlaneStore {
  createTarget(input: Omit<TargetRecord, "id" | "createdAt">): MaybePromise<TargetRecord>;
  getTarget(id: string): MaybePromise<TargetRecord | undefined>;
  getTargetBySiteId(siteId: string): MaybePromise<TargetRecord | undefined>;
  createGrant(input: Omit<GrantRecord, "id" | "chainId" | "createdAt" | "revokedAt">): MaybePromise<GrantRecord>;
  getGrant(id: string): MaybePromise<GrantRecord | undefined>;
  getGrantByChainId(chainId: string): MaybePromise<GrantRecord | undefined>;
  revokeGrant(id: string, occurredAt: string): MaybePromise<void>;
  createSession(input: Omit<SessionRecord, "id">): MaybePromise<SessionRecord>;
  currentEpoch(chainId: string): MaybePromise<number>;
  bumpEpoch(input: Omit<RevocationRecord, "id" | "epoch" | "occurredAt">, occurredAt: string): MaybePromise<RevocationRecord>;
  recordDecision(decision: DecisionRecord): MaybePromise<void>;
  recordDecisionWithOutbox(decision: DecisionRecord, eventType?: DecisionOutboxEventType): MaybePromise<DecisionOutboxEvent>;
  recordDecisionWithTenantQuota(input: {
    readonly tenantId?: string | undefined;
    readonly issueDecision: () => MaybePromise<DecisionRecord>;
    readonly eventType?: DecisionOutboxEventType | undefined;
  }): MaybePromise<DecisionOutboxWriteResult>;
  getDecision(id: string): MaybePromise<DecisionRecord | undefined>;
  findDecisionByRequestId(siteId: string, requestId: string): MaybePromise<DecisionRecord | undefined>;
  upsertDecisionReceiptKey(
    input: Omit<DecisionReceiptKeyRecord, "createdAt" | "updatedAt">,
    now: string
  ): MaybePromise<DecisionReceiptKeyRecord>;
  getDecisionReceiptKey(kid: string): MaybePromise<DecisionReceiptKeyRecord | undefined>;
  getActiveDecisionReceiptKey(issuer: string, now: string): MaybePromise<DecisionReceiptKeyRecord | undefined>;
  listDecisionReceiptKeys(limit?: number): MaybePromise<readonly DecisionReceiptKeyRecord[]>;
  retireDecisionReceiptKey(kid: string, retiredAt: string, reason?: string | undefined): MaybePromise<DecisionReceiptKeyRecord | undefined>;
  applyDecisionOperatorAction(input: {
    readonly decisionId: string;
    readonly action: string;
    readonly actorId: string;
    readonly reason?: string | undefined;
    readonly occurredAt: string;
    readonly ttlSeconds?: number | undefined;
  }): MaybePromise<DecisionOutboxEvent | undefined>;
  listDecisions(siteId?: string | undefined, limit?: number | undefined): MaybePromise<readonly DecisionRecord[]>;
  listDecisionsForTenantPeriod(
    tenantId: string,
    periodStart: string,
    periodEnd: string,
    limit?: number | undefined
  ): MaybePromise<readonly DecisionRecord[]>;
  searchDecisions(input: DecisionSearchInput): MaybePromise<readonly DecisionRecord[]>;
  listQuarantinePins(siteId?: string | undefined, limit?: number | undefined): MaybePromise<readonly QuarantinePinRecord[]>;
  upsertOperatorReputation(
    input: Omit<OperatorReputationRecord, "id" | "createdAt" | "updatedAt">,
    now: string
  ): MaybePromise<OperatorReputationRecord>;
  getOperatorReputation(siteId: string, operatorActorId: string): MaybePromise<OperatorReputationRecord | undefined>;
  listOperatorReputations(input: OperatorReputationListInput): MaybePromise<readonly OperatorReputationRecord[]>;
  recordAgentIdentitySubmission(
    input: Omit<AgentIdentitySubmissionRecord, "id" | "status" | "submittedAt">,
    submittedAt: string
  ): MaybePromise<AgentIdentitySubmissionRecord>;
  getAgentIdentitySubmission(id: string): MaybePromise<AgentIdentitySubmissionRecord | undefined>;
  listAgentIdentitySubmissions(input: AgentIdentitySubmissionListInput): MaybePromise<readonly AgentIdentitySubmissionRecord[]>;
  reviewAgentIdentitySubmission(
    input: AgentIdentitySubmissionReviewInput,
    reviewedAt: string
  ): MaybePromise<AgentIdentitySubmissionReviewResult>;
  recordAgentIdentityReviewNotification(
    input: Omit<AgentIdentityReviewNotificationRecord, "id" | "status" | "createdAt" | "readAt">,
    createdAt: string
  ): MaybePromise<AgentIdentityReviewNotificationRecord>;
  listAgentIdentityReviewNotifications(
    input: AgentIdentityReviewNotificationListInput
  ): MaybePromise<readonly AgentIdentityReviewNotificationRecord[]>;
  markAgentIdentityReviewNotificationRead(
    id: string,
    readAt: string
  ): MaybePromise<AgentIdentityReviewNotificationRecord | undefined>;
  latestDecisionOutboxSeq(): MaybePromise<number>;
  listDecisionOutboxAfter(seq: number, limit?: number | undefined): MaybePromise<readonly DecisionOutboxEvent[]>;
  waitForDecisionOutboxAfter(seq: number, timeoutMs: number): MaybePromise<void>;
  pruneDecisionOutboxBefore(olderThan: string): MaybePromise<number>;
  countTargets(tenantId?: string | undefined): MaybePromise<number>;
  upsertTenantQuota(input: Omit<TenantQuotaRecord, "updatedAt">, updatedAt: string): MaybePromise<TenantQuotaRecord>;
  getTenantQuota(tenantId: string): MaybePromise<TenantQuotaRecord | undefined>;
  upsertTenantPricingPlan(
    input: Omit<TenantPricingPlanRecord, "updatedAt">,
    updatedAt: string
  ): MaybePromise<TenantPricingPlanRecord>;
  getTenantPricingPlan(tenantId: string): MaybePromise<TenantPricingPlanRecord | undefined>;
  upsertBillingPeriodRollup(
    input: Omit<BillingPeriodRollupRecord, "id" | "generatedAt">,
    generatedAt: string
  ): MaybePromise<BillingPeriodRollupRecord>;
  getBillingPeriodRollup(
    tenantId: string,
    periodStart: string,
    periodEnd: string
  ): MaybePromise<BillingPeriodRollupRecord | undefined>;
  upsertBillingExport(
    input: Omit<BillingExportRecord, "id" | "createdAt" | "updatedAt">,
    now: string
  ): MaybePromise<BillingExportRecord>;
  recordBillingExportDeliveryReceipt(
    input: BillingExportDeliveryReceiptInput,
    now: string
  ): MaybePromise<BillingExportRecord | undefined>;
  getBillingExport(id: string): MaybePromise<BillingExportRecord | undefined>;
  listBillingExports(input: BillingExportListInput): MaybePromise<readonly BillingExportRecord[]>;
  recordPrivacyErasure(input: Omit<PrivacyErasureRecord, "id" | "occurredAt">, occurredAt: string): MaybePromise<PrivacyErasureRecord>;
  listPrivacyErasures(siteId?: string | undefined, limit?: number | undefined): MaybePromise<readonly PrivacyErasureRecord[]>;
  eraseSubjectDecisions(siteId: string, subjectHandle: string): MaybePromise<number>;
  upsertWebhookEndpoint(input: Omit<WebhookEndpointRecord, "id" | "createdAt" | "updatedAt">, now: string): MaybePromise<WebhookEndpointRecord>;
  listWebhookEndpoints(tenantId?: string | undefined): MaybePromise<readonly WebhookEndpointRecord[]>;
}

export class WebhookSecretResolutionError extends Error {
  constructor(
    readonly ref: string,
    message = `webhook signing secret could not be resolved for ref '${ref}'`
  ) {
    super(message);
    this.name = "WebhookSecretResolutionError";
  }
}

export interface WebhookSecretResolver {
  resolve(ref: string): MaybePromise<string | Uint8Array>;
}

export interface DecisionReceiptIssuer {
  issue(decision: DecisionRecord): MaybePromise<Pick<
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
  >>;
  verify(decision: DecisionRecord): MaybePromise<boolean>;
}

export interface ControlPlaneServices {
  readonly store: ControlPlaneStore;
  readonly outbox: OutboxPublisher;
  readonly killSwitch: KillSwitchController;
  readonly personaAudit: PersonaAuditController;
  readonly webhookSecrets: WebhookSecretResolver;
  readonly decisionReceipts: DecisionReceiptIssuer;
  readonly issuer: string;
  readonly sessionTtlSeconds: number;
  readonly sessionSigner: SessionSigner;
}
