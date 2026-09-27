import { createHash } from "node:crypto";

import { CascadeTraceSchema } from "@aidenid/common-schemas";
import { canonicalJson, type JsonValue } from "@aidenid/transparency";
import { prefixedId } from "../ids.js";
import type {
  BillingExportListInput,
  BillingExportDeliveryReceiptInput,
  BillingExportRecord,
  BillingPeriodRollupRecord,
  AgentIdentityReviewNotificationListInput,
  AgentIdentityReviewNotificationRecord,
  ControlPlaneStore,
  AgentIdentitySubmissionListInput,
  AgentIdentitySubmissionRecord,
  AgentIdentitySubmissionReviewInput,
  AgentIdentitySubmissionReviewResult,
  DecisionOutboxEvent,
  DecisionOutboxEventType,
  DecisionOutboxWriteResult,
  DecisionReceiptKeyRecord,
  DecisionReceiptKeyState,
  DecisionRecord,
  DecisionSearchInput,
  GrantRecord,
  OperatorReputationListInput,
  OperatorReputationRecord,
  PrivacyErasureRecord,
  QuarantinePinRecord,
  RevocationRecord,
  SessionRecord,
  TargetRecord,
  TenantPricingPlanRecord,
  TenantQuotaRecord,
  WebhookEndpointRecord
} from "../types.js";
import { billingRollupId } from "./adoption.js";

type SqlRow = Record<string, unknown>;
type SqlExecutor = Pick<SqlClient, "query">;
const DECISION_OUTBOX_FALLBACK_POLL_MS = 100;
const DEFAULT_QUARANTINE_TTL_SECONDS = 3_600;
const QUARANTINE_EFFECTS = ["deny", "actor_pin", "ocsf_emit", "webhook_emit"] as const;
const DECISION_SELECT_COLUMNS =
  "id, tenant_id, site_id, request_id, actor_class, decision, recommended_decision, route_template, method, occurred_at, latency_us, subject_handle, issuer, llm_brand, purpose, price_usd, suspicion_score, reason_codes, cascade_trace, receipt_jws, receipt_key_id, receipt_public_jwk, receipt_payload_sha256, receipt_jws_sha256, transparency_leaf_hash, transparency_leaf_index, transparency_checkpoint, transparency_inclusion_proof, operator_action, operator_action_actor_id, operator_action_reason, operator_action_at, operator_action_effective_decision, operator_action_expires_at, operator_action_effects";
const OPERATOR_REPUTATION_SELECT_COLUMNS =
  "id, site_id, operator_actor_id, display_name, trust_tier, status, reputation_score, default_action, default_scope_routes, default_scope_redirect_path, notes, last_reviewed_at, expires_at, updated_by, created_at, updated_at";
const AGENT_IDENTITY_SUBMISSION_SELECT_COLUMNS =
  "id, site_id, request_id, purpose, requested_access_duration_seconds, requested_access_expires_at, purpose_rationale, provider_name, operator_actor_id, contact_url, jwks_url, delegation_authority_jwk_thumbprint_sha256, cascade_attestation, declaration, submitter_hash_sha256, submission_digest_sha256, operator_claim_hash_sha256, status, submitted_at, reviewed_at, review_decision, reviewer_identity_hash_sha256, review_reason, approved_operator_actor_id, operator_reputation_id, assigned_trust_tier, assigned_operator_status, assigned_reputation_score";
const AGENT_IDENTITY_REVIEW_NOTIFICATION_SELECT_COLUMNS =
  "id, site_id, submission_id, review_decision, provider_name, operator_actor_id, contact_url, reviewer_identity_hash_sha256, review_reason, status, created_at, read_at";
const TENANT_PRICING_PLAN_SELECT_COLUMNS =
  "tenant_id, plan_tier, currency, unit_price_usd, included_monthly_cleared_decisions, effective_from, updated_at";
const BILLING_ROLLUP_SELECT_COLUMNS =
  "id, tenant_id, period_start, period_end, plan_tier, currency, unit_price_usd, included_cleared_decisions, cleared_decision_count, billable_cleared_decision_count, overage_cleared_decision_count, estimated_cost_usd, price_required_gross_usd, invoice_line_item_id, export_idempotency_key, generated_at";
const BILLING_EXPORT_SELECT_COLUMNS =
  "id, rollup_id, tenant_id, period_start, period_end, provider, destination_ref, idempotency_key, payload_sha256, payload, status, created_at, updated_at, delivered_at, provider_receipt_id, provider_receipt_status, provider_receipt_payload_sha256, provider_receipt_recorded_at";
const DECISION_RECEIPT_KEY_SELECT_COLUMNS =
  "kid, issuer, alg, public_jwk, jwk_thumbprint_sha256, state, activated_at, retire_after, retired_at, rotation_reason, created_at, updated_at";
export const DECISION_OUTBOX_GENESIS_HASH = "0".repeat(64);

export interface SqlQueryResult<Row extends SqlRow = SqlRow> {
  readonly rows: readonly Row[];
  readonly rowCount?: number | null | undefined;
}

export interface SqlClient {
  query<Row extends SqlRow = SqlRow>(text: string, values?: readonly unknown[]): Promise<SqlQueryResult<Row>>;
  connect?(): Promise<SqlLease>;
}

export interface SqlNotification {
  readonly channel: string;
  readonly payload?: string | undefined;
}

export interface DecisionOutboxChainFinding {
  readonly seq?: number | undefined;
  readonly code: string;
  readonly expected?: string | number | undefined;
  readonly actual?: string | number | undefined;
}

export interface DecisionOutboxChainValidation {
  readonly valid: boolean;
  readonly genesisHash: string;
  readonly fromSeq?: number | undefined;
  readonly toSeq?: number | undefined;
  readonly count: number;
  readonly anchorPreviousHash?: string | undefined;
  readonly terminalEntryHash?: string | undefined;
  readonly findings: readonly DecisionOutboxChainFinding[];
}

export interface SqlLease {
  query<Row extends SqlRow = SqlRow>(text: string, values?: readonly unknown[]): Promise<SqlQueryResult<Row>>;
  on?(event: "notification", listener: (message: SqlNotification) => void): void;
  on?(event: "error", listener: (error: Error) => void): void;
  off?(event: "notification", listener: (message: SqlNotification) => void): void;
  off?(event: "error", listener: (error: Error) => void): void;
  release(): void;
}

interface DecisionOutboxWaiter {
  readonly seq: number;
  readonly resolve: () => void;
  readonly timer: ReturnType<typeof setTimeout>;
}

function isExpiredOperatorReputation(record: OperatorReputationRecord, now: string): boolean {
  return record.expiresAt !== undefined && Date.parse(record.expiresAt) <= Date.parse(now) && record.status !== "expired";
}

export class InMemoryControlPlaneStore implements ControlPlaneStore {
  readonly #targets = new Map<string, TargetRecord>();
  readonly #grants = new Map<string, GrantRecord>();
  readonly #sessions = new Map<string, SessionRecord>();
  readonly #epochs = new Map<string, number>();
  readonly #revocations: RevocationRecord[] = [];
  readonly #decisions: DecisionRecord[] = [];
  readonly #decisionOutbox: DecisionOutboxEvent[] = [];
  readonly #decisionOutboxWaiters = new Set<DecisionOutboxWaiter>();
  #nextDecisionOutboxSeq = 1;
  readonly #tenantQuotas = new Map<string, TenantQuotaRecord>();
  readonly #tenantQuotaLocks = new Map<string, Promise<void>>();
  readonly #tenantPricingPlans = new Map<string, TenantPricingPlanRecord>();
  readonly #billingRollups = new Map<string, BillingPeriodRollupRecord>();
  readonly #billingExports = new Map<string, BillingExportRecord>();
  readonly #decisionReceiptKeys = new Map<string, DecisionReceiptKeyRecord>();
  readonly #privacyErasures: PrivacyErasureRecord[] = [];
  readonly #webhookEndpoints = new Map<string, WebhookEndpointRecord>();
  readonly #quarantinePins = new Map<string, QuarantinePinRecord>();
  readonly #operatorReputations = new Map<string, OperatorReputationRecord>();
  readonly #agentIdentitySubmissions: AgentIdentitySubmissionRecord[] = [];
  readonly #agentIdentityReviewNotifications = new Map<string, AgentIdentityReviewNotificationRecord>();

  createTarget(input: Omit<TargetRecord, "id" | "createdAt">): TargetRecord {
    const target = {
      ...input,
      id: prefixedId("tgt"),
      createdAt: new Date().toISOString()
    };
    this.#targets.set(target.id, target);
    return target;
  }

  getTarget(id: string): TargetRecord | undefined {
    return this.#targets.get(id);
  }

  getTargetBySiteId(siteId: string): TargetRecord | undefined {
    return [...this.#targets.values()].find((target) => target.siteId === siteId);
  }

  createGrant(input: Omit<GrantRecord, "id" | "chainId" | "createdAt" | "revokedAt">): GrantRecord {
    const grant = {
      ...input,
      id: prefixedId("grt"),
      chainId: prefixedId("chn"),
      createdAt: new Date().toISOString()
    };
    this.#grants.set(grant.id, grant);
    this.#epochs.set(grant.chainId, this.#epochs.get(grant.chainId) ?? 0);
    return grant;
  }

  getGrant(id: string): GrantRecord | undefined {
    return this.#grants.get(id);
  }

  getGrantByChainId(chainId: string): GrantRecord | undefined {
    return [...this.#grants.values()].find((grant) => grant.chainId === chainId);
  }

  revokeGrant(id: string, occurredAt: string): void {
    const grant = this.#grants.get(id);
    if (grant !== undefined) {
      this.#grants.set(id, { ...grant, revokedAt: occurredAt });
    }
  }

  createSession(input: Omit<SessionRecord, "id">): SessionRecord {
    const session = { ...input, id: prefixedId("ses") };
    this.#sessions.set(session.id, session);
    return session;
  }

  currentEpoch(chainId: string): number {
    return this.#epochs.get(chainId) ?? 0;
  }

  bumpEpoch(input: Omit<RevocationRecord, "id" | "epoch" | "occurredAt">, occurredAt: string): RevocationRecord {
    const epoch = (this.#epochs.get(input.chainId) ?? 0) + 1;
    this.#epochs.set(input.chainId, epoch);
    const revocation = {
      ...input,
      id: prefixedId("rev"),
      epoch,
      occurredAt
    };
    this.#revocations.push(revocation);
    return revocation;
  }

  recordDecision(decision: DecisionRecord): void {
    void this.recordDecisionWithOutbox(decision);
  }

  recordDecisionWithOutbox(decision: DecisionRecord, eventType: DecisionOutboxEventType = "recorded"): DecisionOutboxEvent {
    this.#decisions.unshift(decision);
    return this.#appendDecisionOutbox(decision, eventType);
  }

  async recordDecisionWithTenantQuota(input: {
    readonly tenantId?: string | undefined;
    readonly issueDecision: () => DecisionRecord | Promise<DecisionRecord>;
    readonly eventType?: DecisionOutboxEventType | undefined;
  }): Promise<DecisionOutboxWriteResult> {
    return await this.#withTenantQuotaLock(input.tenantId, async () => {
      if (input.tenantId !== undefined) {
        const quota = this.#tenantQuotas.get(input.tenantId);
        if (quota !== undefined && this.#decisions.filter((decision) => decision.tenantId === input.tenantId).length >= quota.storedDecisionLimit) {
          return {
            status: "quota_exceeded",
            tenantId: input.tenantId,
            storedDecisionLimit: quota.storedDecisionLimit
          };
        }
      }

      const decision = await input.issueDecision();
      if (input.tenantId !== undefined && decision.tenantId !== input.tenantId) {
        throw new Error("issued decision tenant does not match reserved quota tenant");
      }
      const event = this.recordDecisionWithOutbox(decision, input.eventType ?? "recorded");
      return { status: "recorded", decision, event };
    });
  }

  async #withTenantQuotaLock<T>(tenantId: string | undefined, run: () => Promise<T>): Promise<T> {
    if (tenantId === undefined) {
      return await run();
    }
    const previous = this.#tenantQuotaLocks.get(tenantId) ?? Promise.resolve();
    let release = (): void => {};
    const current = new Promise<void>((resolve) => {
      release = resolve;
    });
    const chained = previous.then(() => current, () => current);
    this.#tenantQuotaLocks.set(tenantId, chained);
    await previous.catch(() => undefined);
    try {
      return await run();
    } finally {
      release();
      if (this.#tenantQuotaLocks.get(tenantId) === chained) {
        this.#tenantQuotaLocks.delete(tenantId);
      }
    }
  }

  #appendDecisionOutbox(decision: DecisionRecord, eventType: DecisionOutboxEventType): DecisionOutboxEvent {
    const payload = decisionOutboxPayload(decision);
    const previousHash = this.#decisionOutbox.at(-1)?.entryHash ?? DECISION_OUTBOX_GENESIS_HASH;
    const event = {
      seq: this.#nextDecisionOutboxSeq,
      decisionId: decision.id,
      occurredAt: new Date().toISOString(),
      eventType,
      payload,
      previousHash,
      entryHash: decisionOutboxEntryHash({
        previousHash,
        decisionId: decision.id,
        eventType,
        payload
      })
    };
    this.#nextDecisionOutboxSeq += 1;
    this.#decisionOutbox.push(event);
    this.#notifyDecisionOutboxWaiters(event.seq);
    return event;
  }

  getDecision(id: string): DecisionRecord | undefined {
    return this.#decisions.find((decision) => decision.id === id);
  }

  findDecisionByRequestId(siteId: string, requestId: string): DecisionRecord | undefined {
    return this.#decisions.find(
      (decision) => decision.siteId === siteId && decision.requestId === requestId
    );
  }

  upsertDecisionReceiptKey(input: Omit<DecisionReceiptKeyRecord, "createdAt" | "updatedAt">, now: string): DecisionReceiptKeyRecord {
    const existing = this.#decisionReceiptKeys.get(input.kid);
    const activeIssuerPeer =
      input.state === "active"
        ? [...this.#decisionReceiptKeys.values()].find(
            (record) => record.issuer === input.issuer && record.state === "active" && record.kid !== input.kid
          )
        : undefined;
    if (activeIssuerPeer !== undefined) {
      throw new Error(`active decision receipt key already exists for issuer '${input.issuer}'`);
    }
    const record = {
      ...input,
      createdAt: existing?.createdAt ?? now,
      updatedAt: now
    };
    this.#decisionReceiptKeys.set(record.kid, record);
    return record;
  }

  getDecisionReceiptKey(kid: string): DecisionReceiptKeyRecord | undefined {
    return this.#decisionReceiptKeys.get(kid);
  }

  getActiveDecisionReceiptKey(issuer: string, now: string): DecisionReceiptKeyRecord | undefined {
    return [...this.#decisionReceiptKeys.values()]
      .filter((record) => record.issuer === issuer && record.state === "active")
      .filter((record) => record.retireAfter === undefined || record.retireAfter > now)
      .sort((left, right) => right.activatedAt.localeCompare(left.activatedAt))
      .at(0);
  }

  listDecisionReceiptKeys(limit = 100): readonly DecisionReceiptKeyRecord[] {
    return [...this.#decisionReceiptKeys.values()]
      .sort((left, right) => right.activatedAt.localeCompare(left.activatedAt))
      .slice(0, limit);
  }

  retireDecisionReceiptKey(kid: string, retiredAt: string, reason?: string | undefined): DecisionReceiptKeyRecord | undefined {
    const existing = this.#decisionReceiptKeys.get(kid);
    if (existing === undefined) {
      return undefined;
    }
    const record = {
      ...existing,
      state: "retired" as const,
      retiredAt,
      rotationReason: reason ?? existing.rotationReason,
      updatedAt: retiredAt
    };
    this.#decisionReceiptKeys.set(kid, record);
    return record;
  }

  applyDecisionOperatorAction(input: {
    readonly decisionId: string;
    readonly action: string;
    readonly actorId: string;
    readonly reason?: string | undefined;
    readonly occurredAt: string;
    readonly ttlSeconds?: number | undefined;
  }): DecisionOutboxEvent | undefined {
    const index = this.#decisions.findIndex((decision) => decision.id === input.decisionId);
    const current = this.#decisions[index];
    if (current === undefined) {
      return undefined;
    }
    const actionUpdate = operatorActionUpdate(input.action, input.occurredAt, input.ttlSeconds);
    const updated = {
      ...current,
      operatorAction: input.action,
      operatorActionActorId: input.actorId,
      operatorActionReason: input.reason,
      operatorActionAt: input.occurredAt,
      operatorActionEffectiveDecision: actionUpdate.effectiveDecision,
      operatorActionExpiresAt: actionUpdate.expiresAt,
      operatorActionEffects: actionUpdate.effects
    };
    this.#decisions[index] = updated;
    const pin = quarantinePinFromDecision(updated, input, actionUpdate);
    if (pin !== undefined) {
      this.#quarantinePins.set(pin.decisionId, pin);
    }
    return this.#appendDecisionOutbox(updated, "updated");
  }

  listDecisions(siteId?: string | undefined, limit = 100): readonly DecisionRecord[] {
    const filtered = siteId === undefined ? this.#decisions : this.#decisions.filter((decision) => decision.siteId === siteId);
    return filtered.slice(0, limit);
  }

  listDecisionsForTenantPeriod(tenantId: string, periodStart: string, periodEnd: string, limit = 100): readonly DecisionRecord[] {
    const filtered = this.#decisions
      .filter((decision) => decision.tenantId === tenantId && decision.occurredAt >= periodStart && decision.occurredAt < periodEnd)
      .sort((left, right) => right.occurredAt.localeCompare(left.occurredAt));
    return filtered.slice(0, limit);
  }

  searchDecisions(input: DecisionSearchInput): readonly DecisionRecord[] {
    const matches = this.#decisions.filter((decision) => {
      if (decision.siteId !== input.siteId) return false;
      if (input.decision !== undefined && decision.decision !== input.decision) return false;
      if (input.operatorActorId !== undefined && decision.operatorActionActorId !== input.operatorActorId) return false;
      if (input.since !== undefined && decision.occurredAt < input.since) return false;
      if (input.until !== undefined && decision.occurredAt > input.until) return false;
      if (input.issuer !== undefined && decision.issuer !== input.issuer) return false;
      if (input.subjectHandle !== undefined && decision.subjectHandle !== input.subjectHandle) return false;
      if (input.actorClass !== undefined && decision.actorClass !== input.actorClass) return false;
      if (input.routeTemplate !== undefined && decision.routeTemplate !== input.routeTemplate) return false;
      if (input.purpose !== undefined && decision.purpose !== input.purpose) return false;
      return true;
    });
    const sorted = [...matches].sort((left, right) => right.occurredAt.localeCompare(left.occurredAt));
    return sorted.slice(0, input.limit);
  }

  listQuarantinePins(siteId?: string | undefined, limit = 100): readonly QuarantinePinRecord[] {
    const pins = [...this.#quarantinePins.values()].sort((left, right) => right.createdAt.localeCompare(left.createdAt));
    const filtered = siteId === undefined ? pins : pins.filter((pin) => pin.siteId === siteId);
    return filtered.slice(0, limit);
  }

  upsertOperatorReputation(
    input: Omit<OperatorReputationRecord, "id" | "createdAt" | "updatedAt">,
    now: string
  ): OperatorReputationRecord {
    const key = operatorReputationKey(input.siteId, input.operatorActorId);
    const existing = this.#operatorReputations.get(key);
    const record = {
      ...input,
      defaultAction: input.defaultAction ?? "allow",
      defaultScopeRoutes: input.defaultScopeRoutes ?? [],
      id: existing?.id ?? prefixedId("opr"),
      createdAt: existing?.createdAt ?? now,
      updatedAt: now
    };
    this.#operatorReputations.set(key, record);
    return record;
  }

  #expireOperatorReputations(now: string, siteId?: string | undefined): void {
    for (const [key, record] of this.#operatorReputations.entries()) {
      if ((siteId === undefined || record.siteId === siteId) && isExpiredOperatorReputation(record, now)) {
        this.#operatorReputations.set(key, {
          ...record,
          status: "expired",
          updatedAt: now
        });
      }
    }
  }

  getOperatorReputation(siteId: string, operatorActorId: string): OperatorReputationRecord | undefined {
    this.#expireOperatorReputations(new Date().toISOString(), siteId);
    return this.#operatorReputations.get(operatorReputationKey(siteId, operatorActorId));
  }

  listOperatorReputations(input: OperatorReputationListInput): readonly OperatorReputationRecord[] {
    this.#expireOperatorReputations(new Date().toISOString(), input.siteId);
    const filtered = [...this.#operatorReputations.values()]
      .filter((record) => record.siteId === input.siteId)
      .filter((record) => input.status === undefined || record.status === input.status)
      .filter((record) => input.trustTier === undefined || record.trustTier === input.trustTier)
      .sort((left, right) => right.updatedAt.localeCompare(left.updatedAt));
    return filtered.slice(0, input.limit);
  }

  recordAgentIdentitySubmission(
    input: Omit<AgentIdentitySubmissionRecord, "id" | "status" | "submittedAt">,
    submittedAt: string
  ): AgentIdentitySubmissionRecord {
    const record = {
      ...input,
      id: prefixedId("ais"),
      status: "pending_review" as const,
      submittedAt
    };
    this.#agentIdentitySubmissions.unshift(record);
    return record;
  }

  getAgentIdentitySubmission(id: string): AgentIdentitySubmissionRecord | undefined {
    return this.#agentIdentitySubmissions.find((record) => record.id === id);
  }

  listAgentIdentitySubmissions(input: AgentIdentitySubmissionListInput): readonly AgentIdentitySubmissionRecord[] {
    return this.#agentIdentitySubmissions
      .filter((record) => input.siteId === undefined || record.siteId === input.siteId)
      .filter((record) => input.status === undefined || record.status === input.status)
      .sort((left, right) => right.submittedAt.localeCompare(left.submittedAt))
      .slice(0, input.limit);
  }

  reviewAgentIdentitySubmission(
    input: AgentIdentitySubmissionReviewInput,
    reviewedAt: string
  ): AgentIdentitySubmissionReviewResult {
    const index = this.#agentIdentitySubmissions.findIndex((record) => record.id === input.submissionId);
    if (index === -1) {
      return { status: "not_found" };
    }
    const existing = this.#agentIdentitySubmissions[index];
    if (existing === undefined) {
      return { status: "not_found" };
    }
    if (existing.status !== "pending_review") {
      return { status: "already_reviewed", submission: existing };
    }

    const operatorReputation =
      input.action === "approve" ? this.upsertOperatorReputation(input.operatorReputation, reviewedAt) : undefined;
    const reviewed: AgentIdentitySubmissionRecord = {
      ...existing,
      status: input.action === "approve" ? "approved" : "rejected",
      reviewedAt,
      reviewDecision: input.action,
      reviewerIdentityHashSha256: input.reviewerIdentityHashSha256,
      reviewReason: input.reviewReason,
      approvedOperatorActorId: input.action === "approve" ? input.approvedOperatorActorId : undefined,
      operatorReputationId: operatorReputation?.id,
      assignedTrustTier: input.action === "approve" ? input.operatorReputation.trustTier : undefined,
      assignedOperatorStatus: input.action === "approve" ? input.operatorReputation.status : undefined,
      assignedReputationScore: input.action === "approve" ? input.operatorReputation.reputationScore : undefined
    };
    this.#agentIdentitySubmissions.splice(index, 1, reviewed);
    return operatorReputation === undefined
      ? { status: "reviewed", submission: reviewed }
      : { status: "reviewed", submission: reviewed, operatorReputation };
  }

  recordAgentIdentityReviewNotification(
    input: Omit<AgentIdentityReviewNotificationRecord, "id" | "status" | "createdAt" | "readAt">,
    createdAt: string
  ): AgentIdentityReviewNotificationRecord {
    const key = agentIdentityReviewNotificationKey(input.submissionId, input.reviewDecision);
    const existing = this.#agentIdentityReviewNotifications.get(key);
    if (existing !== undefined) {
      return existing;
    }
    const notification = {
      ...input,
      id: prefixedId("arn"),
      status: "unread" as const,
      createdAt
    };
    this.#agentIdentityReviewNotifications.set(key, notification);
    return notification;
  }

  listAgentIdentityReviewNotifications(
    input: AgentIdentityReviewNotificationListInput
  ): readonly AgentIdentityReviewNotificationRecord[] {
    return [...this.#agentIdentityReviewNotifications.values()]
      .filter((record) => input.siteId === undefined || record.siteId === input.siteId)
      .filter((record) => input.status === undefined || record.status === input.status)
      .sort((left, right) => right.createdAt.localeCompare(left.createdAt))
      .slice(0, input.limit);
  }

  markAgentIdentityReviewNotificationRead(id: string, readAt: string): AgentIdentityReviewNotificationRecord | undefined {
    for (const [key, notification] of this.#agentIdentityReviewNotifications.entries()) {
      if (notification.id !== id) {
        continue;
      }
      const updated = {
        ...notification,
        status: "read" as const,
        readAt: notification.readAt ?? readAt
      };
      this.#agentIdentityReviewNotifications.set(key, updated);
      return updated;
    }
    return undefined;
  }

  latestDecisionOutboxSeq(): number {
    return this.#nextDecisionOutboxSeq - 1;
  }

  listDecisionOutboxAfter(seq: number, limit = 100): readonly DecisionOutboxEvent[] {
    return this.#decisionOutbox.filter((event) => event.seq > seq).sort((left, right) => left.seq - right.seq).slice(0, limit);
  }

  async waitForDecisionOutboxAfter(seq: number, timeoutMs: number): Promise<void> {
    if (this.#decisionOutbox.some((event) => event.seq > seq) || timeoutMs <= 0) {
      return;
    }
    await new Promise<void>((resolve) => {
      const waiter: DecisionOutboxWaiter = {
        seq,
        resolve: () => {
          clearTimeout(waiter.timer);
          this.#decisionOutboxWaiters.delete(waiter);
          resolve();
        },
        timer: setTimeout(() => {
          this.#decisionOutboxWaiters.delete(waiter);
          resolve();
        }, timeoutMs)
      };
      this.#decisionOutboxWaiters.add(waiter);
    });
  }

  #notifyDecisionOutboxWaiters(seq: number): void {
    for (const waiter of [...this.#decisionOutboxWaiters]) {
      if (seq > waiter.seq) {
        waiter.resolve();
      }
    }
  }

  pruneDecisionOutboxBefore(olderThan: string): number {
    const before = this.#decisionOutbox.length;
    for (let index = this.#decisionOutbox.length - 1; index >= 0; index -= 1) {
      const event = this.#decisionOutbox[index];
      if (event !== undefined && event.occurredAt < olderThan) {
        this.#decisionOutbox.splice(index, 1);
      }
    }
    return before - this.#decisionOutbox.length;
  }

  countTargets(tenantId?: string | undefined): number {
    if (tenantId === undefined) {
      return this.#targets.size;
    }
    return [...this.#targets.values()].filter((target) => target.tenantId === tenantId).length;
  }

  upsertTenantQuota(input: Omit<TenantQuotaRecord, "updatedAt">, updatedAt: string): TenantQuotaRecord {
    const quota = { ...input, updatedAt };
    this.#tenantQuotas.set(quota.tenantId, quota);
    return quota;
  }

  getTenantQuota(tenantId: string): TenantQuotaRecord | undefined {
    return this.#tenantQuotas.get(tenantId);
  }

  upsertTenantPricingPlan(input: Omit<TenantPricingPlanRecord, "updatedAt">, updatedAt: string): TenantPricingPlanRecord {
    const plan = { ...input, updatedAt };
    this.#tenantPricingPlans.set(plan.tenantId, plan);
    return plan;
  }

  getTenantPricingPlan(tenantId: string): TenantPricingPlanRecord | undefined {
    return this.#tenantPricingPlans.get(tenantId);
  }

  upsertBillingPeriodRollup(
    input: Omit<BillingPeriodRollupRecord, "id" | "generatedAt">,
    generatedAt: string
  ): BillingPeriodRollupRecord {
    const rollup = {
      ...input,
      id: billingRollupId(input.tenantId, input.periodStart, input.periodEnd),
      generatedAt
    };
    this.#billingRollups.set(billingRollupKey(input.tenantId, input.periodStart, input.periodEnd), rollup);
    return rollup;
  }

  getBillingPeriodRollup(tenantId: string, periodStart: string, periodEnd: string): BillingPeriodRollupRecord | undefined {
    return this.#billingRollups.get(billingRollupKey(tenantId, periodStart, periodEnd));
  }

  upsertBillingExport(input: Omit<BillingExportRecord, "createdAt" | "updatedAt">, now: string): BillingExportRecord {
    const existing = this.#billingExports.get(input.id);
    const record = {
      ...input,
      status: existing?.status === "delivered" ? existing.status : input.status,
      createdAt: existing?.createdAt ?? now,
      updatedAt: now,
      deliveredAt: existing?.deliveredAt ?? input.deliveredAt,
      providerReceiptId: existing?.providerReceiptId ?? input.providerReceiptId,
      providerReceiptStatus: existing?.providerReceiptStatus ?? input.providerReceiptStatus,
      providerReceiptPayloadSha256: existing?.providerReceiptPayloadSha256 ?? input.providerReceiptPayloadSha256,
      providerReceiptRecordedAt: existing?.providerReceiptRecordedAt ?? input.providerReceiptRecordedAt
    };
    this.#billingExports.set(record.id, record);
    return record;
  }

  recordBillingExportDeliveryReceipt(input: BillingExportDeliveryReceiptInput, now: string): BillingExportRecord | undefined {
    const existing = this.#billingExports.get(input.id);
    if (existing === undefined) {
      return undefined;
    }
    const record = {
      ...existing,
      status: "delivered" as const,
      deliveredAt: input.deliveredAt,
      providerReceiptId: input.providerReceiptId,
      providerReceiptStatus: input.providerReceiptStatus,
      providerReceiptPayloadSha256: input.providerReceiptPayloadSha256,
      providerReceiptRecordedAt: now,
      updatedAt: now
    };
    this.#billingExports.set(record.id, record);
    return record;
  }

  getBillingExport(id: string): BillingExportRecord | undefined {
    return this.#billingExports.get(id);
  }

  listBillingExports(input: BillingExportListInput): readonly BillingExportRecord[] {
    const exports = [...this.#billingExports.values()]
      .filter((record) => input.tenantId === undefined || record.tenantId === input.tenantId)
      .filter((record) => input.provider === undefined || record.provider === input.provider)
      .filter((record) => input.status === undefined || record.status === input.status)
      .filter((record) => input.periodStart === undefined || record.periodStart === input.periodStart)
      .filter((record) => input.periodEnd === undefined || record.periodEnd === input.periodEnd)
      .sort((left, right) => right.createdAt.localeCompare(left.createdAt));
    return exports.slice(0, input.limit);
  }

  recordPrivacyErasure(input: Omit<PrivacyErasureRecord, "id" | "occurredAt">, occurredAt: string): PrivacyErasureRecord {
    const erasure = {
      ...input,
      id: prefixedId("dsr"),
      occurredAt
    };
    this.#privacyErasures.unshift(erasure);
    return erasure;
  }

  listPrivacyErasures(siteId?: string | undefined, limit = 100): readonly PrivacyErasureRecord[] {
    const filtered = siteId === undefined ? this.#privacyErasures : this.#privacyErasures.filter((request) => request.siteId === siteId);
    return filtered.slice(0, limit);
  }

  eraseSubjectDecisions(siteId: string, subjectHandle: string): number {
    const before = this.#decisions.length;
    for (let index = this.#decisions.length - 1; index >= 0; index -= 1) {
      const decision = this.#decisions[index];
      if (decision?.siteId === siteId && decision.subjectHandle === subjectHandle) {
        this.#decisions.splice(index, 1);
      }
    }
    return before - this.#decisions.length;
  }

  upsertWebhookEndpoint(input: Omit<WebhookEndpointRecord, "id" | "createdAt" | "updatedAt">, now: string): WebhookEndpointRecord {
    const existing = [...this.#webhookEndpoints.values()].find(
      (endpoint) => endpoint.tenantId === input.tenantId && endpoint.url === input.url
    );
    const endpoint = {
      ...input,
      id: existing?.id ?? prefixedId("whk"),
      createdAt: existing?.createdAt ?? now,
      updatedAt: now
    };
    this.#webhookEndpoints.set(endpoint.id, endpoint);
    return endpoint;
  }

  listWebhookEndpoints(tenantId?: string | undefined): readonly WebhookEndpointRecord[] {
    const endpoints = [...this.#webhookEndpoints.values()].sort((left, right) => right.updatedAt.localeCompare(left.updatedAt));
    return tenantId === undefined ? endpoints : endpoints.filter((endpoint) => endpoint.tenantId === tenantId);
  }
}

function requiredRow<Row extends SqlRow>(rows: readonly Row[], label: string): Row {
  const row = rows[0];
  if (row === undefined) {
    throw new Error(`postgres ${label} did not return a row`);
  }
  return row;
}

function operatorReputationKey(siteId: string, operatorActorId: string): string {
  return `${siteId}\0${operatorActorId}`;
}

function agentIdentityReviewNotificationKey(submissionId: string, reviewDecision: "approve" | "reject"): string {
  return `${submissionId}\0${reviewDecision}`;
}

function billingRollupKey(tenantId: string, periodStart: string, periodEnd: string): string {
  return `${tenantId}\0${periodStart}\0${periodEnd}`;
}

function iso(value: unknown): string {
  if (value instanceof Date) {
    return value.toISOString();
  }
  return String(value);
}

function optionalIso(value: unknown): string | undefined {
  return value === null || value === undefined ? undefined : iso(value);
}

function numberValue(value: unknown): number {
  return typeof value === "number" ? value : Number(value);
}

function optionalNumber(value: unknown): number | undefined {
  return value === null || value === undefined ? undefined : numberValue(value);
}

async function sleep(timeoutMs: number): Promise<void> {
  await new Promise<void>((resolve) => {
    setTimeout(resolve, timeoutMs);
  });
}

interface OperatorActionUpdate {
  readonly effectiveDecision: string;
  readonly expiresAt?: string | undefined;
  readonly effects?: readonly string[] | undefined;
}

function operatorActionUpdate(action: string, occurredAt: string, ttlSeconds?: number | undefined): OperatorActionUpdate {
  if (action !== "quarantine") {
    return { effectiveDecision: action };
  }
  const ttl = ttlSeconds ?? DEFAULT_QUARANTINE_TTL_SECONDS;
  const occurredAtMs = Date.parse(occurredAt);
  if (!Number.isFinite(occurredAtMs)) {
    throw new Error("operator action occurredAt is invalid");
  }
  return {
    effectiveDecision: "deny",
    expiresAt: new Date(occurredAtMs + ttl * 1_000).toISOString(),
    effects: QUARANTINE_EFFECTS
  };
}

function quarantinePinFromDecision(
  decision: DecisionRecord,
  input: { readonly actorId: string; readonly reason?: string | undefined },
  update: OperatorActionUpdate
): QuarantinePinRecord | undefined {
  if (update.effects === undefined || !update.effects.includes("actor_pin") || update.expiresAt === undefined) {
    return undefined;
  }
  return {
    id: prefixedId("qpn"),
    decisionId: decision.id,
    siteId: decision.siteId,
    actorClass: decision.actorClass,
    ...(decision.issuer === undefined ? {} : { issuer: decision.issuer }),
    ...(decision.subjectHandle === undefined ? {} : { subjectHandle: decision.subjectHandle }),
    requestId: decision.requestId,
    operatorActorId: input.actorId,
    ...(input.reason === undefined ? {} : { reason: input.reason }),
    expiresAt: update.expiresAt,
    createdAt: decision.operatorActionAt ?? new Date().toISOString()
  };
}

function decisionOutboxEventType(value: unknown): DecisionOutboxEventType {
  const eventType = String(value);
  if (eventType === "recorded" || eventType === "pending" || eventType === "resolved" || eventType === "updated") {
    return eventType;
  }
  throw new Error(`unsupported decision outbox event type: ${eventType}`);
}

function recordPayload(value: unknown): Readonly<Record<string, unknown>> {
  const parsed = typeof value === "string" ? (JSON.parse(value) as unknown) : value;
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("decision outbox payload must be an object");
  }
  return parsed as Readonly<Record<string, unknown>>;
}

function sha256Hex(input: string): string {
  return createHash("sha256").update(input).digest("hex");
}

function jsonValue(value: unknown, path: string): JsonValue {
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
    return value.map((item, index) => jsonValue(item, `${path}[${index}]`));
  }
  if (typeof value === "object") {
    const output: Record<string, JsonValue> = {};
    for (const [key, item] of Object.entries(value)) {
      if (item === undefined) {
        continue;
      }
      output[key] = jsonValue(item, `${path}.${key}`);
    }
    return output;
  }
  throw new Error(`${path} cannot be encoded as canonical JSON`);
}

function jsonObject(value: Readonly<Record<string, unknown>>, path: string): { readonly [key: string]: JsonValue } {
  const converted = jsonValue(value, path);
  if (converted === null || typeof converted !== "object" || Array.isArray(converted)) {
    throw new Error(`${path} must be a JSON object`);
  }
  return converted as { readonly [key: string]: JsonValue };
}

export function decisionOutboxEntryHash(input: {
  readonly previousHash: string;
  readonly decisionId: string;
  readonly eventType: DecisionOutboxEventType;
  readonly payload: Readonly<Record<string, unknown>>;
}): string {
  return sha256Hex(
    canonicalJson({
      version: "aidenid.decision_outbox.v1",
      previous_hash: input.previousHash,
      decision_id: input.decisionId,
      event_type: input.eventType,
      payload: jsonObject(input.payload, "decision_outbox.payload")
    })
  );
}

export function validateDecisionOutboxChain(
  events: readonly DecisionOutboxEvent[],
  options: { readonly expectedPreviousHash?: string | undefined } = {}
): DecisionOutboxChainValidation {
  const findings: DecisionOutboxChainFinding[] = [];
  let previous: DecisionOutboxEvent | undefined;

  for (const event of events) {
    const expectedEntryHash = decisionOutboxEntryHash({
      previousHash: event.previousHash,
      decisionId: event.decisionId,
      eventType: event.eventType,
      payload: event.payload
    });
    if (event.entryHash !== expectedEntryHash) {
      findings.push({ seq: event.seq, code: "entry_hash_mismatch", expected: expectedEntryHash, actual: event.entryHash });
    }
    if (event.seq === 1 && event.previousHash !== DECISION_OUTBOX_GENESIS_HASH) {
      findings.push({ seq: event.seq, code: "genesis_hash_mismatch", expected: DECISION_OUTBOX_GENESIS_HASH, actual: event.previousHash });
    }
    if (previous !== undefined) {
      if (event.seq !== previous.seq + 1) {
        findings.push({ seq: event.seq, code: "seq_gap", expected: previous.seq + 1, actual: event.seq });
      }
      if (event.previousHash !== previous.entryHash) {
        findings.push({ seq: event.seq, code: "previous_hash_mismatch", expected: previous.entryHash, actual: event.previousHash });
      }
    }
    previous = event;
  }

  const first = events[0];
  const last = events.at(-1);
  if (first !== undefined && options.expectedPreviousHash !== undefined && first.previousHash !== options.expectedPreviousHash) {
    findings.push({
      seq: first.seq,
      code: "expected_previous_hash_mismatch",
      expected: options.expectedPreviousHash,
      actual: first.previousHash
    });
  }

  return {
    valid: findings.length === 0,
    genesisHash: DECISION_OUTBOX_GENESIS_HASH,
    fromSeq: first?.seq,
    toSeq: last?.seq,
    count: events.length,
    anchorPreviousHash: first?.previousHash,
    terminalEntryHash: last?.entryHash,
    findings
  };
}

function stringArray(value: unknown): readonly string[] {
  if (Array.isArray(value)) {
    return value.map((item) => String(item));
  }
  if (typeof value === "string") {
    const parsed = JSON.parse(value) as unknown;
    return Array.isArray(parsed) ? parsed.map((item) => String(item)) : [];
  }
  return [];
}

function optionalStringArray(value: unknown): readonly string[] | undefined {
  return value === null || value === undefined ? undefined : stringArray(value);
}

function optionalCascadeTrace(value: unknown): DecisionRecord["cascadeTrace"] {
  if (value === null || value === undefined) {
    return undefined;
  }
  const parsed = typeof value === "string" ? (JSON.parse(value) as unknown) : value;
  return CascadeTraceSchema.parse(parsed);
}

function optionalRecord(value: unknown): Readonly<Record<string, unknown>> | undefined {
  if (value === null || value === undefined) {
    return undefined;
  }
  const parsed = typeof value === "string" ? (JSON.parse(value) as unknown) : value;
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("expected JSON object");
  }
  return parsed as Readonly<Record<string, unknown>>;
}

function requiredRecord(value: unknown, field: string): Readonly<Record<string, unknown>> {
  const parsed = optionalRecord(value);
  if (parsed === undefined) {
    throw new Error(`${field} is required`);
  }
  return parsed;
}

function optionalString(value: unknown): string | undefined {
  return value === null || value === undefined ? undefined : String(value);
}

function decisionReceiptKeyState(value: unknown): DecisionReceiptKeyState {
  const state = String(value);
  if (state === "active" || state === "retiring" || state === "retired") {
    return state;
  }
  throw new Error(`unsupported decision receipt key state: ${state}`);
}

function targetFromRow(row: SqlRow): TargetRecord {
  return {
    id: String(row.id),
    tenantId: String(row.tenant_id),
    siteId: String(row.site_id),
    name: String(row.name),
    origin: String(row.origin),
    createdAt: iso(row.created_at)
  };
}

function grantFromRow(row: SqlRow): GrantRecord {
  return {
    id: String(row.id),
    targetId: String(row.target_id),
    siteId: String(row.site_id),
    subject: String(row.subject),
    chainId: String(row.chain_id),
    resource: String(row.resource),
    permissions: stringArray(row.permissions),
    expiresAt: iso(row.expires_at),
    createdAt: iso(row.created_at),
    revokedAt: optionalIso(row.revoked_at),
    // NULL for grants issued before attribution existed. Left undefined rather than
    // substituted with a placeholder: "we do not know who issued this" is the truth, and
    // an invented issuer would be worse than an absent one.
    issuerActorId:
      row.issuer_actor_id === null || row.issuer_actor_id === undefined
        ? undefined
        : String(row.issuer_actor_id)
  };
}

function sessionFromRow(row: SqlRow): SessionRecord {
  return {
    id: String(row.id),
    grantId: String(row.grant_id),
    chainId: String(row.chain_id),
    siteId: String(row.site_id),
    tokenHashSha256: String(row.token_hash_sha256),
    proofJkt: String(row.proof_jkt),
    revocationEpoch: numberValue(row.revocation_epoch),
    issuedAt: iso(row.issued_at),
    expiresAt: iso(row.expires_at)
  };
}

function revocationFromRow(row: SqlRow): RevocationRecord {
  return {
    id: String(row.id),
    chainId: String(row.chain_id),
    epoch: numberValue(row.epoch),
    reason: String(row.reason),
    actorId: String(row.actor_id),
    occurredAt: iso(row.occurred_at)
  };
}

function decisionFromRow(row: SqlRow): DecisionRecord {
  return {
    id: String(row.id),
    tenantId: row.tenant_id === null || row.tenant_id === undefined ? undefined : String(row.tenant_id),
    siteId: String(row.site_id),
    requestId: String(row.request_id),
    actorClass: String(row.actor_class),
    decision: String(row.decision),
    recommendedDecision: row.recommended_decision === null || row.recommended_decision === undefined ? undefined : String(row.recommended_decision),
    routeTemplate: String(row.route_template),
    method: String(row.method),
    occurredAt: iso(row.occurred_at),
    latencyUs: optionalNumber(row.latency_us),
    subjectHandle: row.subject_handle === null || row.subject_handle === undefined ? undefined : String(row.subject_handle),
    issuer: row.issuer === null || row.issuer === undefined ? undefined : String(row.issuer),
    llmBrand: row.llm_brand === null || row.llm_brand === undefined ? undefined : String(row.llm_brand),
    purpose: row.purpose === null || row.purpose === undefined ? undefined : String(row.purpose),
    priceUsd: optionalNumber(row.price_usd),
    suspicionScore: optionalNumber(row.suspicion_score),
    reasonCodes: stringArray(row.reason_codes),
    cascadeTrace: optionalCascadeTrace(row.cascade_trace),
    receiptJws: row.receipt_jws === null || row.receipt_jws === undefined ? undefined : String(row.receipt_jws),
    receiptKeyId: row.receipt_key_id === null || row.receipt_key_id === undefined ? undefined : String(row.receipt_key_id),
    receiptPublicJwk: optionalRecord(row.receipt_public_jwk),
    receiptPayloadSha256:
      row.receipt_payload_sha256 === null || row.receipt_payload_sha256 === undefined ? undefined : String(row.receipt_payload_sha256),
    receiptJwsSha256: row.receipt_jws_sha256 === null || row.receipt_jws_sha256 === undefined ? undefined : String(row.receipt_jws_sha256),
    transparencyLeafHash:
      row.transparency_leaf_hash === null || row.transparency_leaf_hash === undefined ? undefined : String(row.transparency_leaf_hash),
    transparencyLeafIndex: optionalNumber(row.transparency_leaf_index),
    transparencyCheckpoint: optionalRecord(row.transparency_checkpoint),
    transparencyInclusionProof: optionalRecord(row.transparency_inclusion_proof),
    operatorAction: row.operator_action === null || row.operator_action === undefined ? undefined : String(row.operator_action),
    operatorActionActorId:
      row.operator_action_actor_id === null || row.operator_action_actor_id === undefined ? undefined : String(row.operator_action_actor_id),
    operatorActionReason:
      row.operator_action_reason === null || row.operator_action_reason === undefined ? undefined : String(row.operator_action_reason),
    operatorActionAt: row.operator_action_at === null || row.operator_action_at === undefined ? undefined : iso(row.operator_action_at),
    operatorActionEffectiveDecision:
      row.operator_action_effective_decision === null || row.operator_action_effective_decision === undefined
        ? undefined
        : String(row.operator_action_effective_decision),
    operatorActionExpiresAt:
      row.operator_action_expires_at === null || row.operator_action_expires_at === undefined ? undefined : iso(row.operator_action_expires_at),
    operatorActionEffects: optionalStringArray(row.operator_action_effects)
  };
}

function decisionOutboxPayload(decision: DecisionRecord): Readonly<Record<string, unknown>> {
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
    ...(decision.cascadeTrace === undefined ? {} : { cascade_trace: decision.cascadeTrace }),
    ...(decision.receiptKeyId === undefined
      ? {}
      : {
          receipt: {
            key_id: decision.receiptKeyId,
            payload_sha256: decision.receiptPayloadSha256,
            jws_sha256: decision.receiptJwsSha256,
            transparency_leaf_hash: decision.transparencyLeafHash,
            transparency_leaf_index: decision.transparencyLeafIndex,
            transparency_checkpoint: decision.transparencyCheckpoint,
            transparency_inclusion_proof: decision.transparencyInclusionProof
          }
        }),
    ...(decision.operatorAction === undefined ? {} : { operator_action: decision.operatorAction }),
    ...(decision.operatorActionActorId === undefined ? {} : { operator_action_actor_id: decision.operatorActionActorId }),
    ...(decision.operatorActionReason === undefined ? {} : { operator_action_reason: decision.operatorActionReason }),
    ...(decision.operatorActionAt === undefined ? {} : { operator_action_at: decision.operatorActionAt }),
    ...(decision.operatorActionEffectiveDecision === undefined
      ? {}
      : { operator_action_effective_decision: decision.operatorActionEffectiveDecision }),
    ...(decision.operatorActionExpiresAt === undefined ? {} : { operator_action_expires_at: decision.operatorActionExpiresAt }),
    ...(decision.operatorActionEffects === undefined ? {} : { operator_action_effects: decision.operatorActionEffects })
  };
}

function decisionOutboxEventFromRow(row: SqlRow): DecisionOutboxEvent {
  const payload = recordPayload(row.payload);
  const previousHash = optionalString(row.previous_hash) ?? DECISION_OUTBOX_GENESIS_HASH;
  return {
    seq: numberValue(row.seq),
    decisionId: String(row.decision_id),
    occurredAt: iso(row.occurred_at),
    eventType: decisionOutboxEventType(row.event_type),
    payload,
    previousHash,
    entryHash:
      optionalString(row.entry_hash) ??
      decisionOutboxEntryHash({
        previousHash,
        decisionId: String(row.decision_id),
        eventType: decisionOutboxEventType(row.event_type),
        payload
      })
  };
}

function decisionReceiptKeyFromRow(row: SqlRow): DecisionReceiptKeyRecord {
  return {
    kid: String(row.kid),
    issuer: String(row.issuer),
    alg: "EdDSA",
    publicJwk: requiredRecord(row.public_jwk, "decision receipt public_jwk"),
    jwkThumbprintSha256: String(row.jwk_thumbprint_sha256),
    state: decisionReceiptKeyState(row.state),
    activatedAt: iso(row.activated_at),
    retireAfter: row.retire_after === null || row.retire_after === undefined ? undefined : iso(row.retire_after),
    retiredAt: row.retired_at === null || row.retired_at === undefined ? undefined : iso(row.retired_at),
    rotationReason: optionalString(row.rotation_reason),
    createdAt: iso(row.created_at),
    updatedAt: iso(row.updated_at)
  };
}

function quotaFromRow(row: SqlRow): TenantQuotaRecord {
  return {
    tenantId: String(row.tenant_id),
    monthlyDecisionLimit: numberValue(row.monthly_decision_limit),
    storedDecisionLimit: numberValue(row.stored_decision_limit),
    targetLimit: numberValue(row.target_limit),
    updatedAt: iso(row.updated_at)
  };
}

function tenantPricingPlanFromRow(row: SqlRow): TenantPricingPlanRecord {
  return {
    tenantId: String(row.tenant_id),
    planTier: String(row.plan_tier),
    currency: "USD",
    unitPriceUsd: numberValue(row.unit_price_usd),
    includedMonthlyClearedDecisions: numberValue(row.included_monthly_cleared_decisions),
    effectiveFrom: iso(row.effective_from),
    updatedAt: iso(row.updated_at)
  };
}

function billingPeriodRollupFromRow(row: SqlRow): BillingPeriodRollupRecord {
  return {
    id: String(row.id),
    tenantId: String(row.tenant_id),
    periodStart: iso(row.period_start),
    periodEnd: iso(row.period_end),
    planTier: String(row.plan_tier),
    currency: "USD",
    unitPriceUsd: numberValue(row.unit_price_usd),
    includedClearedDecisions: numberValue(row.included_cleared_decisions),
    clearedDecisionCount: numberValue(row.cleared_decision_count),
    billableClearedDecisionCount: numberValue(row.billable_cleared_decision_count),
    overageClearedDecisionCount: numberValue(row.overage_cleared_decision_count),
    estimatedCostUsd: numberValue(row.estimated_cost_usd),
    priceRequiredGrossUsd: numberValue(row.price_required_gross_usd),
    invoiceLineItemId: String(row.invoice_line_item_id),
    exportIdempotencyKey: String(row.export_idempotency_key),
    generatedAt: iso(row.generated_at)
  };
}

function billingExportPayloadFromRow(value: unknown): Readonly<Record<string, unknown>> {
  return recordPayload(value);
}

function billingExportProvider(value: unknown): BillingExportRecord["provider"] {
  const provider = String(value);
  if (provider === "stripe_meter_event" || provider === "quickbooks_invoice") {
    return provider;
  }
  throw new Error(`unsupported billing export provider: ${provider}`);
}

function billingExportStatus(value: unknown): BillingExportRecord["status"] {
  const status = String(value);
  if (status === "prepared" || status === "delivered") {
    return status;
  }
  throw new Error(`unsupported billing export status: ${status}`);
}

function billingExportFromRow(row: SqlRow): BillingExportRecord {
  return {
    id: String(row.id),
    rollupId: String(row.rollup_id),
    tenantId: String(row.tenant_id),
    periodStart: iso(row.period_start),
    periodEnd: iso(row.period_end),
    provider: billingExportProvider(row.provider),
    destinationRef: String(row.destination_ref),
    idempotencyKey: String(row.idempotency_key),
    payloadSha256: String(row.payload_sha256),
    payload: billingExportPayloadFromRow(row.payload),
    status: billingExportStatus(row.status),
    createdAt: iso(row.created_at),
    updatedAt: iso(row.updated_at),
    deliveredAt: optionalIso(row.delivered_at),
    providerReceiptId: optionalString(row.provider_receipt_id),
    providerReceiptStatus: optionalString(row.provider_receipt_status),
    providerReceiptPayloadSha256: optionalString(row.provider_receipt_payload_sha256),
    providerReceiptRecordedAt: optionalIso(row.provider_receipt_recorded_at)
  };
}

function privacyErasureFromRow(row: SqlRow): PrivacyErasureRecord {
  return {
    id: String(row.id),
    siteId: String(row.site_id),
    subjectHandle: String(row.subject_handle),
    reason: String(row.reason),
    actorId: String(row.actor_id),
    erasedDecisionCount: numberValue(row.erased_decision_count),
    occurredAt: iso(row.occurred_at)
  };
}

function webhookEndpointFromRow(row: SqlRow): WebhookEndpointRecord {
  return {
    id: String(row.id),
    tenantId: String(row.tenant_id),
    url: String(row.url),
    eventTypes: stringArray(row.event_types),
    signingSecretRef: String(row.signing_secret_ref),
    createdAt: iso(row.created_at),
    updatedAt: iso(row.updated_at)
  };
}

function quarantinePinFromRow(row: SqlRow): QuarantinePinRecord {
  return {
    id: String(row.id),
    decisionId: String(row.decision_id),
    siteId: String(row.site_id),
    actorClass: String(row.actor_class),
    issuer: row.issuer === null || row.issuer === undefined ? undefined : String(row.issuer),
    subjectHandle: row.subject_handle === null || row.subject_handle === undefined ? undefined : String(row.subject_handle),
    requestId: String(row.request_id),
    operatorActorId: String(row.operator_actor_id),
    reason: row.reason === null || row.reason === undefined ? undefined : String(row.reason),
    expiresAt: iso(row.expires_at),
    createdAt: iso(row.created_at)
  };
}

function operatorReputationFromRow(row: SqlRow): OperatorReputationRecord {
  return {
    id: String(row.id),
    siteId: String(row.site_id),
    operatorActorId: String(row.operator_actor_id),
    displayName: row.display_name === null || row.display_name === undefined ? undefined : String(row.display_name),
    trustTier: String(row.trust_tier) as OperatorReputationRecord["trustTier"],
    status: String(row.status) as OperatorReputationRecord["status"],
    reputationScore: numberValue(row.reputation_score),
    defaultAction:
      row.default_action === null || row.default_action === undefined ? "allow" : (String(row.default_action) as OperatorReputationRecord["defaultAction"]),
    defaultScopeRoutes: stringArray(row.default_scope_routes),
    defaultScopeRedirectPath:
      row.default_scope_redirect_path === null || row.default_scope_redirect_path === undefined
        ? undefined
        : String(row.default_scope_redirect_path),
    notes: row.notes === null || row.notes === undefined ? undefined : String(row.notes),
    lastReviewedAt: optionalIso(row.last_reviewed_at),
    expiresAt: optionalIso(row.expires_at),
    updatedBy: String(row.updated_by),
    createdAt: iso(row.created_at),
    updatedAt: iso(row.updated_at)
  };
}

function agentIdentitySubmissionFromRow(row: SqlRow): AgentIdentitySubmissionRecord {
  return {
    id: String(row.id),
    siteId: String(row.site_id),
    requestId: row.request_id === null || row.request_id === undefined ? undefined : String(row.request_id),
    purpose: String(row.purpose) as AgentIdentitySubmissionRecord["purpose"],
    requestedAccessDurationSeconds: Number(row.requested_access_duration_seconds),
    requestedAccessExpiresAt: iso(row.requested_access_expires_at),
    purposeRationale: row.purpose_rationale === null || row.purpose_rationale === undefined ? undefined : String(row.purpose_rationale),
    providerName: String(row.provider_name),
    operatorActorId: row.operator_actor_id === null || row.operator_actor_id === undefined ? undefined : String(row.operator_actor_id),
    contactUrl: String(row.contact_url),
    jwksUrl: row.jwks_url === null || row.jwks_url === undefined ? undefined : String(row.jwks_url),
    delegationAuthorityJwkThumbprintSha256:
      row.delegation_authority_jwk_thumbprint_sha256 === null || row.delegation_authority_jwk_thumbprint_sha256 === undefined
        ? undefined
        : String(row.delegation_authority_jwk_thumbprint_sha256),
    cascadeAttestation: stringArray(row.cascade_attestation) as AgentIdentitySubmissionRecord["cascadeAttestation"],
    declaration: row.declaration === null || row.declaration === undefined ? undefined : String(row.declaration),
    submitterHashSha256: String(row.submitter_hash_sha256),
    submissionDigestSha256: String(row.submission_digest_sha256),
    operatorClaimHashSha256: String(row.operator_claim_hash_sha256),
    status: String(row.status) as AgentIdentitySubmissionRecord["status"],
    submittedAt: iso(row.submitted_at),
    reviewedAt: optionalIso(row.reviewed_at),
    reviewDecision:
      row.review_decision === null || row.review_decision === undefined
        ? undefined
        : (String(row.review_decision) as AgentIdentitySubmissionRecord["reviewDecision"]),
    reviewerIdentityHashSha256:
      row.reviewer_identity_hash_sha256 === null || row.reviewer_identity_hash_sha256 === undefined
        ? undefined
        : String(row.reviewer_identity_hash_sha256),
    reviewReason: row.review_reason === null || row.review_reason === undefined ? undefined : String(row.review_reason),
    approvedOperatorActorId:
      row.approved_operator_actor_id === null || row.approved_operator_actor_id === undefined
        ? undefined
        : String(row.approved_operator_actor_id),
    operatorReputationId:
      row.operator_reputation_id === null || row.operator_reputation_id === undefined ? undefined : String(row.operator_reputation_id),
    assignedTrustTier:
      row.assigned_trust_tier === null || row.assigned_trust_tier === undefined
        ? undefined
        : (String(row.assigned_trust_tier) as AgentIdentitySubmissionRecord["assignedTrustTier"]),
    assignedOperatorStatus:
      row.assigned_operator_status === null || row.assigned_operator_status === undefined
        ? undefined
        : (String(row.assigned_operator_status) as AgentIdentitySubmissionRecord["assignedOperatorStatus"]),
    assignedReputationScore: optionalNumber(row.assigned_reputation_score)
  };
}

function agentIdentityReviewNotificationFromRow(row: SqlRow): AgentIdentityReviewNotificationRecord {
  return {
    id: String(row.id),
    siteId: String(row.site_id),
    submissionId: String(row.submission_id),
    reviewDecision: String(row.review_decision) as AgentIdentityReviewNotificationRecord["reviewDecision"],
    providerName: String(row.provider_name),
    operatorActorId: row.operator_actor_id === null || row.operator_actor_id === undefined ? undefined : String(row.operator_actor_id),
    contactUrl: String(row.contact_url),
    reviewerIdentityHashSha256: String(row.reviewer_identity_hash_sha256),
    reviewReason: row.review_reason === null || row.review_reason === undefined ? undefined : String(row.review_reason),
    status: String(row.status) as AgentIdentityReviewNotificationRecord["status"],
    createdAt: iso(row.created_at),
    readAt: optionalIso(row.read_at)
  };
}

export class PostgresControlPlaneStore implements ControlPlaneStore {
  constructor(readonly client: SqlClient) {}

  async #withTransaction<T>(operation: (client: SqlLease) => Promise<T>): Promise<T> {
    if (this.client.connect === undefined) {
      throw new Error("Postgres transactions require a leased SQL client");
    }
    const lease = await this.client.connect();
    try {
      await lease.query("BEGIN");
      const result = await operation(lease);
      await lease.query("COMMIT");
      return result;
    } catch (error) {
      await lease.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      lease.release();
    }
  }

  async #appendDecisionOutbox(client: SqlLease, decision: DecisionRecord, eventType: DecisionOutboxEventType): Promise<DecisionOutboxEvent> {
    await client.query("LOCK TABLE decision_outbox IN EXCLUSIVE MODE");
    const latestHash = await client.query(
      `SELECT entry_hash
       FROM decision_outbox
       WHERE entry_hash IS NOT NULL
       ORDER BY seq DESC
       LIMIT 1`
    );
    const payload = decisionOutboxPayload(decision);
    const previousHash = optionalString(latestHash.rows[0]?.entry_hash) ?? DECISION_OUTBOX_GENESIS_HASH;
    const entryHash = decisionOutboxEntryHash({
      previousHash,
      decisionId: decision.id,
      eventType,
      payload
    });
    const result = await client.query(
      `INSERT INTO decision_outbox (decision_id, event_type, payload, previous_hash, entry_hash)
       VALUES ($1, $2, $3::jsonb, $4, $5)
       RETURNING seq, decision_id, occurred_at, event_type, payload, previous_hash, entry_hash`,
      [decision.id, eventType, JSON.stringify(payload), previousHash, entryHash]
    );
    const event = decisionOutboxEventFromRow(requiredRow(result.rows, "appendDecisionOutbox"));
    await client.query("SELECT pg_notify('aidenid_decision_outbox', $1)", [String(event.seq)]);
    return event;
  }

  async createTarget(input: Omit<TargetRecord, "id" | "createdAt">): Promise<TargetRecord> {
    const result = await this.client.query(
      `INSERT INTO targets (id, tenant_id, site_id, name, origin)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, tenant_id, site_id, name, origin, created_at`,
      [prefixedId("tgt"), input.tenantId, input.siteId, input.name, input.origin]
    );
    return targetFromRow(requiredRow(result.rows, "createTarget"));
  }

  async getTarget(id: string): Promise<TargetRecord | undefined> {
    const result = await this.client.query(
      `SELECT id, tenant_id, site_id, name, origin, created_at
       FROM targets
       WHERE id = $1`,
      [id]
    );
    const row = result.rows[0];
    return row === undefined ? undefined : targetFromRow(row);
  }

  async getTargetBySiteId(siteId: string): Promise<TargetRecord | undefined> {
    const result = await this.client.query(
      `SELECT id, tenant_id, site_id, name, origin, created_at
       FROM targets
       WHERE site_id = $1`,
      [siteId]
    );
    const row = result.rows[0];
    return row === undefined ? undefined : targetFromRow(row);
  }

  async createGrant(input: Omit<GrantRecord, "id" | "chainId" | "createdAt" | "revokedAt">): Promise<GrantRecord> {
    const chainId = prefixedId("chn");
    const result = await this.client.query(
      `INSERT INTO delegation_grants (id, target_id, site_id, subject, chain_id, resource, permissions, expires_at, issuer_actor_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9)
       RETURNING id, target_id, site_id, subject, chain_id, resource, permissions, expires_at, created_at, revoked_at, issuer_actor_id`,
      [
        prefixedId("grt"),
        input.targetId,
        input.siteId,
        input.subject,
        chainId,
        input.resource,
        JSON.stringify(input.permissions),
        input.expiresAt,
        input.issuerActorId ?? null
      ]
    );
    await this.client.query(
      `INSERT INTO revocation_epochs (chain_id, epoch)
       VALUES ($1, 0)
       ON CONFLICT (chain_id) DO NOTHING`,
      [chainId]
    );
    return grantFromRow(requiredRow(result.rows, "createGrant"));
  }

  async getGrant(id: string): Promise<GrantRecord | undefined> {
    const result = await this.client.query(
      `SELECT id, target_id, site_id, subject, chain_id, resource, permissions, expires_at, created_at, revoked_at, issuer_actor_id
       FROM delegation_grants
       WHERE id = $1`,
      [id]
    );
    const row = result.rows[0];
    return row === undefined ? undefined : grantFromRow(row);
  }

  async getGrantByChainId(chainId: string): Promise<GrantRecord | undefined> {
    const result = await this.client.query(
      `SELECT id, target_id, site_id, subject, chain_id, resource, permissions, expires_at, created_at, revoked_at, issuer_actor_id
       FROM delegation_grants
       WHERE chain_id = $1
       ORDER BY created_at DESC
       LIMIT 1`,
      [chainId]
    );
    const row = result.rows[0];
    return row === undefined ? undefined : grantFromRow(row);
  }

  async revokeGrant(id: string, occurredAt: string): Promise<void> {
    await this.client.query("UPDATE delegation_grants SET revoked_at = $2 WHERE id = $1", [id, occurredAt]);
  }

  async createSession(input: Omit<SessionRecord, "id">): Promise<SessionRecord> {
    const result = await this.client.query(
      `INSERT INTO issued_sessions (id, grant_id, chain_id, site_id, token_hash_sha256, proof_jkt, revocation_epoch, issued_at, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       RETURNING id, grant_id, chain_id, site_id, token_hash_sha256, proof_jkt, revocation_epoch, issued_at, expires_at`,
      [
        prefixedId("ses"),
        input.grantId,
        input.chainId,
        input.siteId,
        input.tokenHashSha256,
        input.proofJkt,
        input.revocationEpoch,
        input.issuedAt,
        input.expiresAt
      ]
    );
    return sessionFromRow(requiredRow(result.rows, "createSession"));
  }

  async currentEpoch(chainId: string): Promise<number> {
    const result = await this.client.query("SELECT epoch FROM revocation_epochs WHERE chain_id = $1", [chainId]);
    const row = result.rows[0];
    return row === undefined ? 0 : numberValue(row.epoch);
  }

  async bumpEpoch(input: Omit<RevocationRecord, "id" | "epoch" | "occurredAt">, occurredAt: string): Promise<RevocationRecord> {
    const epochResult = await this.client.query(
      `INSERT INTO revocation_epochs (chain_id, epoch, updated_at)
       VALUES ($1, 1, $2)
       ON CONFLICT (chain_id) DO UPDATE
       SET epoch = revocation_epochs.epoch + 1,
           updated_at = EXCLUDED.updated_at
       RETURNING epoch`,
      [input.chainId, occurredAt]
    );
    const epoch = numberValue(requiredRow(epochResult.rows, "bumpEpoch").epoch);
    const result = await this.client.query(
      `INSERT INTO revocations (id, chain_id, epoch, reason, actor_id, occurred_at)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, chain_id, epoch, reason, actor_id, occurred_at`,
      [prefixedId("rev"), input.chainId, epoch, input.reason, input.actorId, occurredAt]
    );
    return revocationFromRow(requiredRow(result.rows, "recordRevocation"));
  }

  async recordDecision(decision: DecisionRecord): Promise<void> {
    await this.recordDecisionWithOutbox(decision);
  }

  async #insertDecision(client: SqlLease, decision: DecisionRecord): Promise<void> {
    await client.query(
      `INSERT INTO decisions
       (id, tenant_id, site_id, request_id, actor_class, decision, recommended_decision, route_template, method, occurred_at, latency_us, subject_handle, issuer, llm_brand, purpose, price_usd, suspicion_score, reason_codes, cascade_trace, receipt_jws, receipt_key_id, receipt_public_jwk, receipt_payload_sha256, receipt_jws_sha256, transparency_leaf_hash, transparency_leaf_index, transparency_checkpoint, transparency_inclusion_proof, operator_action, operator_action_actor_id, operator_action_reason, operator_action_at, operator_action_effective_decision, operator_action_expires_at, operator_action_effects)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18::jsonb, $19::jsonb, $20, $21, $22::jsonb, $23, $24, $25, $26, $27::jsonb, $28::jsonb, $29, $30, $31, $32, $33, $34, $35::jsonb)`,
      [
        decision.id,
        decision.tenantId ?? null,
        decision.siteId,
        decision.requestId,
        decision.actorClass,
        decision.decision,
        decision.recommendedDecision ?? null,
        decision.routeTemplate,
        decision.method,
        decision.occurredAt,
        decision.latencyUs ?? null,
        decision.subjectHandle ?? null,
        decision.issuer ?? null,
        decision.llmBrand ?? null,
        decision.purpose ?? null,
        decision.priceUsd ?? null,
        decision.suspicionScore ?? null,
        JSON.stringify(decision.reasonCodes ?? []),
        decision.cascadeTrace === undefined ? null : JSON.stringify(decision.cascadeTrace),
        decision.receiptJws ?? null,
        decision.receiptKeyId ?? null,
        decision.receiptPublicJwk === undefined ? null : JSON.stringify(decision.receiptPublicJwk),
        decision.receiptPayloadSha256 ?? null,
        decision.receiptJwsSha256 ?? null,
        decision.transparencyLeafHash ?? null,
        decision.transparencyLeafIndex ?? null,
        decision.transparencyCheckpoint === undefined ? null : JSON.stringify(decision.transparencyCheckpoint),
        decision.transparencyInclusionProof === undefined ? null : JSON.stringify(decision.transparencyInclusionProof),
        decision.operatorAction ?? null,
        decision.operatorActionActorId ?? null,
        decision.operatorActionReason ?? null,
        decision.operatorActionAt ?? null,
        decision.operatorActionEffectiveDecision ?? null,
        decision.operatorActionExpiresAt ?? null,
        decision.operatorActionEffects === undefined ? null : JSON.stringify(decision.operatorActionEffects)
      ]
    );
  }

  async recordDecisionWithOutbox(decision: DecisionRecord, eventType: DecisionOutboxEventType = "recorded"): Promise<DecisionOutboxEvent> {
    return await this.#withTransaction(async (client) => {
      await this.#insertDecision(client, decision);
      return await this.#appendDecisionOutbox(client, decision, eventType);
    });
  }

  async recordDecisionWithTenantQuota(input: {
    readonly tenantId?: string | undefined;
    readonly issueDecision: () => DecisionRecord | Promise<DecisionRecord>;
    readonly eventType?: DecisionOutboxEventType | undefined;
  }): Promise<DecisionOutboxWriteResult> {
    return await this.#withTransaction(async (client) => {
      if (input.tenantId !== undefined) {
        const quotaResult = await client.query(
          `SELECT tenant_id, monthly_decision_limit, stored_decision_limit, target_limit, updated_at
           FROM tenant_quotas
           WHERE tenant_id = $1
           FOR UPDATE`,
          [input.tenantId]
        );
        const quotaRow = quotaResult.rows[0];
        if (quotaRow !== undefined) {
          const quota = quotaFromRow(quotaRow);
          const countResult = await client.query("SELECT count(*) AS count FROM decisions WHERE tenant_id = $1", [input.tenantId]);
          const storedDecisionCount = numberValue(requiredRow(countResult.rows, "countTenantStoredDecisions").count);
          if (storedDecisionCount >= quota.storedDecisionLimit) {
            return {
              status: "quota_exceeded",
              tenantId: input.tenantId,
              storedDecisionLimit: quota.storedDecisionLimit
            };
          }
        }
      }

      const decision = await input.issueDecision();
      if (input.tenantId !== undefined && decision.tenantId !== input.tenantId) {
        throw new Error("issued decision tenant does not match reserved quota tenant");
      }
      await this.#insertDecision(client, decision);
      const event = await this.#appendDecisionOutbox(client, decision, input.eventType ?? "recorded");
      return { status: "recorded", decision, event };
    });
  }

  async getDecision(id: string): Promise<DecisionRecord | undefined> {
    const result = await this.client.query(
      `SELECT ${DECISION_SELECT_COLUMNS}
       FROM decisions
       WHERE id = $1`,
      [id]
    );
    const row = result.rows[0];
    return row === undefined ? undefined : decisionFromRow(row);
  }

  async findDecisionByRequestId(siteId: string, requestId: string): Promise<DecisionRecord | undefined> {
    const result = await this.client.query(
      `SELECT ${DECISION_SELECT_COLUMNS}
       FROM decisions
       WHERE site_id = $1 AND request_id = $2
       ORDER BY occurred_at DESC
       LIMIT 1`,
      [siteId, requestId]
    );
    const row = result.rows[0];
    return row === undefined ? undefined : decisionFromRow(row);
  }

  async upsertDecisionReceiptKey(
    input: Omit<DecisionReceiptKeyRecord, "createdAt" | "updatedAt">,
    now: string
  ): Promise<DecisionReceiptKeyRecord> {
    const result = await this.client.query(
      `INSERT INTO decision_receipt_keys
         (kid, issuer, alg, public_jwk, jwk_thumbprint_sha256, state, activated_at, retire_after, retired_at, rotation_reason, created_at, updated_at)
       VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7, $8, $9, $10, $11, $11)
       ON CONFLICT (kid) DO UPDATE
       SET issuer = EXCLUDED.issuer,
           alg = EXCLUDED.alg,
           public_jwk = EXCLUDED.public_jwk,
           jwk_thumbprint_sha256 = EXCLUDED.jwk_thumbprint_sha256,
           state = EXCLUDED.state,
           activated_at = EXCLUDED.activated_at,
           retire_after = EXCLUDED.retire_after,
           retired_at = EXCLUDED.retired_at,
           rotation_reason = EXCLUDED.rotation_reason,
           updated_at = EXCLUDED.updated_at
       RETURNING ${DECISION_RECEIPT_KEY_SELECT_COLUMNS}`,
      [
        input.kid,
        input.issuer,
        input.alg,
        JSON.stringify(input.publicJwk),
        input.jwkThumbprintSha256,
        input.state,
        input.activatedAt,
        input.retireAfter ?? null,
        input.retiredAt ?? null,
        input.rotationReason ?? null,
        now
      ]
    );
    return decisionReceiptKeyFromRow(requiredRow(result.rows, "upsertDecisionReceiptKey"));
  }

  async getDecisionReceiptKey(kid: string): Promise<DecisionReceiptKeyRecord | undefined> {
    const result = await this.client.query(
      `SELECT ${DECISION_RECEIPT_KEY_SELECT_COLUMNS}
       FROM decision_receipt_keys
       WHERE kid = $1`,
      [kid]
    );
    const row = result.rows[0];
    return row === undefined ? undefined : decisionReceiptKeyFromRow(row);
  }

  async getActiveDecisionReceiptKey(issuer: string, now: string): Promise<DecisionReceiptKeyRecord | undefined> {
    const result = await this.client.query(
      `SELECT ${DECISION_RECEIPT_KEY_SELECT_COLUMNS}
       FROM decision_receipt_keys
       WHERE issuer = $1
         AND state = 'active'
         AND (retire_after IS NULL OR retire_after > $2)
       ORDER BY activated_at DESC
       LIMIT 1`,
      [issuer, now]
    );
    const row = result.rows[0];
    return row === undefined ? undefined : decisionReceiptKeyFromRow(row);
  }

  async listDecisionReceiptKeys(limit = 100): Promise<readonly DecisionReceiptKeyRecord[]> {
    const result = await this.client.query(
      `SELECT ${DECISION_RECEIPT_KEY_SELECT_COLUMNS}
       FROM decision_receipt_keys
       ORDER BY activated_at DESC
       LIMIT $1`,
      [limit]
    );
    return result.rows.map(decisionReceiptKeyFromRow);
  }

  async retireDecisionReceiptKey(
    kid: string,
    retiredAt: string,
    reason?: string | undefined
  ): Promise<DecisionReceiptKeyRecord | undefined> {
    const result = await this.client.query(
      `UPDATE decision_receipt_keys
       SET state = 'retired',
           retired_at = $2,
           rotation_reason = COALESCE($3, rotation_reason),
           updated_at = $2
       WHERE kid = $1
       RETURNING ${DECISION_RECEIPT_KEY_SELECT_COLUMNS}`,
      [kid, retiredAt, reason ?? null]
    );
    const row = result.rows[0];
    return row === undefined ? undefined : decisionReceiptKeyFromRow(row);
  }

  async applyDecisionOperatorAction(input: {
    readonly decisionId: string;
    readonly action: string;
    readonly actorId: string;
    readonly reason?: string | undefined;
    readonly occurredAt: string;
    readonly ttlSeconds?: number | undefined;
  }): Promise<DecisionOutboxEvent | undefined> {
    return await this.#withTransaction(async (client) => {
      const actionUpdate = operatorActionUpdate(input.action, input.occurredAt, input.ttlSeconds);
      const updated = await client.query(
        `UPDATE decisions
         SET operator_action = $2,
             operator_action_actor_id = $3,
             operator_action_reason = $4,
             operator_action_at = $5,
             operator_action_effective_decision = $6,
             operator_action_expires_at = $7,
             operator_action_effects = $8::jsonb
         WHERE id = $1
         RETURNING ${DECISION_SELECT_COLUMNS}`,
        [
          input.decisionId,
          input.action,
          input.actorId,
          input.reason ?? null,
          input.occurredAt,
          actionUpdate.effectiveDecision,
          actionUpdate.expiresAt ?? null,
          actionUpdate.effects === undefined ? null : JSON.stringify(actionUpdate.effects)
        ]
      );
      const row = updated.rows[0];
      if (row === undefined) {
        return undefined;
      }
      const decision = decisionFromRow(row);
      const pin = quarantinePinFromDecision(decision, input, actionUpdate);
      if (pin !== undefined) {
        await client.query(
          `INSERT INTO quarantine_pins
           (id, decision_id, site_id, actor_class, issuer, subject_handle, request_id, operator_actor_id, reason, expires_at, created_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
           ON CONFLICT (decision_id) DO UPDATE
           SET issuer = EXCLUDED.issuer,
               subject_handle = EXCLUDED.subject_handle,
               operator_actor_id = EXCLUDED.operator_actor_id,
               reason = EXCLUDED.reason,
               expires_at = EXCLUDED.expires_at,
               created_at = EXCLUDED.created_at`,
          [
            pin.id,
            pin.decisionId,
            pin.siteId,
            pin.actorClass,
            pin.issuer ?? null,
            pin.subjectHandle ?? null,
            pin.requestId,
            pin.operatorActorId,
            pin.reason ?? null,
            pin.expiresAt,
            pin.createdAt
          ]
        );
      }
      return await this.#appendDecisionOutbox(client, decision, "updated");
    });
  }

  async latestDecisionOutboxSeq(): Promise<number> {
    const result = await this.client.query("SELECT COALESCE(MAX(seq), 0) AS seq FROM decision_outbox");
    return numberValue(requiredRow(result.rows, "latestDecisionOutboxSeq").seq);
  }

  async listDecisionOutboxAfter(seq: number, limit = 100): Promise<readonly DecisionOutboxEvent[]> {
    const result = await this.client.query(
      `SELECT seq, decision_id, occurred_at, event_type, payload, previous_hash, entry_hash
       FROM decision_outbox
       WHERE seq > $1
       ORDER BY seq ASC
       LIMIT $2`,
      [seq, limit]
    );
    return result.rows.map(decisionOutboxEventFromRow);
  }

  async waitForDecisionOutboxAfter(seq: number, timeoutMs: number): Promise<void> {
    if (timeoutMs <= 0) {
      return;
    }
    if (this.client.connect === undefined) {
      await this.#pollDecisionOutboxAfter(seq, timeoutMs);
      return;
    }
    const lease = await this.client.connect();
    try {
      await lease.query("LISTEN aidenid_decision_outbox");
      if (lease.on === undefined || lease.off === undefined) {
        await this.#pollDecisionOutboxAfter(seq, timeoutMs);
        return;
      }
      await new Promise<void>((resolve) => {
        let resolved = false;
        function finish() {
          if (resolved) {
            return;
          }
          resolved = true;
          clearTimeout(timer);
          lease.off?.("notification", onNotification);
          lease.off?.("error", onError);
          resolve();
        }
        const onNotification = (message: SqlNotification) => {
          if (message.channel === "aidenid_decision_outbox" && Number(message.payload ?? 0) > seq) {
            finish();
          }
        };
        const onError = (_error: Error) => finish();
        const timer = setTimeout(finish, timeoutMs);
        lease.on?.("notification", onNotification);
        lease.on?.("error", onError);
        void Promise.resolve(this.listDecisionOutboxAfter(seq, 1))
          .then((events) => {
            if (events.length > 0) {
              finish();
            }
          })
          .catch(() => finish());
      });
    } finally {
      await lease.query("UNLISTEN aidenid_decision_outbox").catch(() => undefined);
      lease.release();
    }
  }

  async #pollDecisionOutboxAfter(seq: number, timeoutMs: number): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while (true) {
      if ((await this.listDecisionOutboxAfter(seq, 1)).length > 0) {
        return;
      }
      const remainingMs = deadline - Date.now();
      if (remainingMs <= 0) {
        return;
      }
      await sleep(Math.min(DECISION_OUTBOX_FALLBACK_POLL_MS, remainingMs));
    }
  }

  async pruneDecisionOutboxBefore(olderThan: string): Promise<number> {
    const result = await this.client.query(
      `DELETE FROM decision_outbox
       WHERE occurred_at < $1
       RETURNING seq`,
      [olderThan]
    );
    return result.rowCount ?? result.rows.length;
  }

  async listDecisions(siteId?: string | undefined, limit = 100): Promise<readonly DecisionRecord[]> {
    const result =
      siteId === undefined
        ? await this.client.query(
            `SELECT ${DECISION_SELECT_COLUMNS}
             FROM decisions
             ORDER BY occurred_at DESC
             LIMIT $1`,
            [limit]
          )
        : await this.client.query(
            `SELECT ${DECISION_SELECT_COLUMNS}
             FROM decisions
             WHERE site_id = $1
             ORDER BY occurred_at DESC
             LIMIT $2`,
            [siteId, limit]
          );
    return result.rows.map(decisionFromRow);
  }

  async listDecisionsForTenantPeriod(
    tenantId: string,
    periodStart: string,
    periodEnd: string,
    limit = 100
  ): Promise<readonly DecisionRecord[]> {
    const result = await this.client.query(
      `SELECT ${DECISION_SELECT_COLUMNS}
       FROM decisions
       WHERE tenant_id = $1 AND occurred_at >= $2 AND occurred_at < $3
       ORDER BY occurred_at DESC
       LIMIT $4`,
      [tenantId, periodStart, periodEnd, limit]
    );
    return result.rows.map(decisionFromRow);
  }

  async searchDecisions(input: DecisionSearchInput): Promise<readonly DecisionRecord[]> {
    const conditions: string[] = ["site_id = $1"];
    const values: unknown[] = [input.siteId];
    const push = (column: string, value: unknown, op = "="): void => {
      values.push(value);
      conditions.push(`${column} ${op} $${values.length}`);
    };
    if (input.decision !== undefined) push("decision", input.decision);
    if (input.operatorActorId !== undefined) push("operator_action_actor_id", input.operatorActorId);
    if (input.since !== undefined) push("occurred_at", input.since, ">=");
    if (input.until !== undefined) push("occurred_at", input.until, "<=");
    if (input.issuer !== undefined) push("issuer", input.issuer);
    if (input.subjectHandle !== undefined) push("subject_handle", input.subjectHandle);
    if (input.actorClass !== undefined) push("actor_class", input.actorClass);
    if (input.routeTemplate !== undefined) push("route_template", input.routeTemplate);
    if (input.purpose !== undefined) push("purpose", input.purpose);
    values.push(input.limit);
    const result = await this.client.query(
      `SELECT ${DECISION_SELECT_COLUMNS}
       FROM decisions
       WHERE ${conditions.join(" AND ")}
       ORDER BY occurred_at DESC
       LIMIT $${values.length}`,
      values
    );
    return result.rows.map(decisionFromRow);
  }

  async listQuarantinePins(siteId?: string | undefined, limit = 100): Promise<readonly QuarantinePinRecord[]> {
    const result =
      siteId === undefined
        ? await this.client.query(
            `SELECT id, decision_id, site_id, actor_class, issuer, subject_handle, request_id, operator_actor_id, reason, expires_at, created_at
             FROM quarantine_pins
             ORDER BY created_at DESC
             LIMIT $1`,
            [limit]
          )
        : await this.client.query(
            `SELECT id, decision_id, site_id, actor_class, issuer, subject_handle, request_id, operator_actor_id, reason, expires_at, created_at
             FROM quarantine_pins
             WHERE site_id = $1
             ORDER BY created_at DESC
             LIMIT $2`,
            [siteId, limit]
          );
    return result.rows.map(quarantinePinFromRow);
  }

  async #expireOperatorReputationsWithClient(
    client: SqlExecutor,
    now: string,
    siteId?: string | undefined
  ): Promise<void> {
    if (siteId === undefined) {
      await client.query(
        `UPDATE operator_reputation
         SET status = 'expired',
             updated_at = $1
         WHERE expires_at IS NOT NULL
           AND expires_at <= $1
           AND status <> 'expired'`,
        [now]
      );
      return;
    }
    await client.query(
      `UPDATE operator_reputation
       SET status = 'expired',
           updated_at = $2
       WHERE site_id = $1
         AND expires_at IS NOT NULL
         AND expires_at <= $2
         AND status <> 'expired'`,
      [siteId, now]
    );
  }

  async upsertOperatorReputation(
    input: Omit<OperatorReputationRecord, "id" | "createdAt" | "updatedAt">,
    now: string
  ): Promise<OperatorReputationRecord> {
    return this.#upsertOperatorReputationWithClient(this.client, input, now);
  }

  async #upsertOperatorReputationWithClient(
    client: SqlExecutor,
    input: Omit<OperatorReputationRecord, "id" | "createdAt" | "updatedAt">,
    now: string
  ): Promise<OperatorReputationRecord> {
    const result = await client.query(
      `INSERT INTO operator_reputation
       (id, site_id, operator_actor_id, display_name, trust_tier, status, reputation_score, default_action, default_scope_routes, default_scope_redirect_path, notes, last_reviewed_at, expires_at, updated_by, created_at, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10, $11, $12, $13, $14, $15, $15)
       ON CONFLICT (site_id, operator_actor_id) DO UPDATE
       SET display_name = EXCLUDED.display_name,
           trust_tier = EXCLUDED.trust_tier,
           status = EXCLUDED.status,
           reputation_score = EXCLUDED.reputation_score,
           default_action = EXCLUDED.default_action,
           default_scope_routes = EXCLUDED.default_scope_routes,
           default_scope_redirect_path = EXCLUDED.default_scope_redirect_path,
           notes = EXCLUDED.notes,
           last_reviewed_at = EXCLUDED.last_reviewed_at,
           expires_at = EXCLUDED.expires_at,
           updated_by = EXCLUDED.updated_by,
           updated_at = EXCLUDED.updated_at
       RETURNING ${OPERATOR_REPUTATION_SELECT_COLUMNS}`,
      [
        prefixedId("opr"),
        input.siteId,
        input.operatorActorId,
        input.displayName ?? null,
        input.trustTier,
        input.status,
        input.reputationScore,
        input.defaultAction ?? "allow",
        JSON.stringify(input.defaultScopeRoutes ?? []),
        input.defaultScopeRedirectPath ?? null,
        input.notes ?? null,
        input.lastReviewedAt ?? null,
        input.expiresAt ?? null,
        input.updatedBy,
        now
      ]
    );
    return operatorReputationFromRow(requiredRow(result.rows, "upsertOperatorReputation"));
  }

  async getOperatorReputation(siteId: string, operatorActorId: string): Promise<OperatorReputationRecord | undefined> {
    await this.#expireOperatorReputationsWithClient(this.client, new Date().toISOString(), siteId);
    const result = await this.client.query(
      `SELECT ${OPERATOR_REPUTATION_SELECT_COLUMNS}
       FROM operator_reputation
       WHERE site_id = $1 AND operator_actor_id = $2`,
      [siteId, operatorActorId]
    );
    const row = result.rows[0];
    return row === undefined ? undefined : operatorReputationFromRow(row);
  }

  async listOperatorReputations(input: OperatorReputationListInput): Promise<readonly OperatorReputationRecord[]> {
    await this.#expireOperatorReputationsWithClient(this.client, new Date().toISOString(), input.siteId);
    const conditions = ["site_id = $1"];
    const values: unknown[] = [input.siteId];
    if (input.status !== undefined) {
      values.push(input.status);
      conditions.push(`status = $${values.length}`);
    }
    if (input.trustTier !== undefined) {
      values.push(input.trustTier);
      conditions.push(`trust_tier = $${values.length}`);
    }
    values.push(input.limit);
    const result = await this.client.query(
      `SELECT ${OPERATOR_REPUTATION_SELECT_COLUMNS}
       FROM operator_reputation
       WHERE ${conditions.join(" AND ")}
       ORDER BY updated_at DESC
       LIMIT $${values.length}`,
      values
    );
    return result.rows.map(operatorReputationFromRow);
  }

  async recordAgentIdentitySubmission(
    input: Omit<AgentIdentitySubmissionRecord, "id" | "status" | "submittedAt">,
    submittedAt: string
  ): Promise<AgentIdentitySubmissionRecord> {
    const result = await this.client.query(
      `INSERT INTO agent_identity_submissions
       (id, site_id, request_id, purpose, requested_access_duration_seconds, requested_access_expires_at, purpose_rationale, provider_name, operator_actor_id, contact_url, jwks_url, delegation_authority_jwk_thumbprint_sha256, cascade_attestation, declaration, submitter_hash_sha256, submission_digest_sha256, operator_claim_hash_sha256, status, submitted_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13::jsonb, $14, $15, $16, $17, 'pending_review', $18)
       RETURNING ${AGENT_IDENTITY_SUBMISSION_SELECT_COLUMNS}`,
      [
        prefixedId("ais"),
        input.siteId,
        input.requestId ?? null,
        input.purpose,
        input.requestedAccessDurationSeconds,
        input.requestedAccessExpiresAt,
        input.purposeRationale ?? null,
        input.providerName,
        input.operatorActorId ?? null,
        input.contactUrl,
        input.jwksUrl ?? null,
        input.delegationAuthorityJwkThumbprintSha256 ?? null,
        JSON.stringify(input.cascadeAttestation),
        input.declaration ?? null,
        input.submitterHashSha256,
        input.submissionDigestSha256,
        input.operatorClaimHashSha256,
        submittedAt
      ]
    );
    return agentIdentitySubmissionFromRow(requiredRow(result.rows, "recordAgentIdentitySubmission"));
  }

  async getAgentIdentitySubmission(id: string): Promise<AgentIdentitySubmissionRecord | undefined> {
    const result = await this.client.query(
      `SELECT ${AGENT_IDENTITY_SUBMISSION_SELECT_COLUMNS}
       FROM agent_identity_submissions
       WHERE id = $1`,
      [id]
    );
    const row = result.rows[0];
    return row === undefined ? undefined : agentIdentitySubmissionFromRow(row);
  }

  async listAgentIdentitySubmissions(input: AgentIdentitySubmissionListInput): Promise<readonly AgentIdentitySubmissionRecord[]> {
    const conditions: string[] = [];
    const values: unknown[] = [];
    if (input.siteId !== undefined) {
      values.push(input.siteId);
      conditions.push(`site_id = $${values.length}`);
    }
    if (input.status !== undefined) {
      values.push(input.status);
      conditions.push(`status = $${values.length}`);
    }
    values.push(input.limit);
    const result = await this.client.query(
      `SELECT ${AGENT_IDENTITY_SUBMISSION_SELECT_COLUMNS}
       FROM agent_identity_submissions
       ${conditions.length === 0 ? "" : `WHERE ${conditions.join(" AND ")}`}
       ORDER BY submitted_at DESC
       LIMIT $${values.length}`,
      values
    );
    return result.rows.map(agentIdentitySubmissionFromRow);
  }

  async reviewAgentIdentitySubmission(
    input: AgentIdentitySubmissionReviewInput,
    reviewedAt: string
  ): Promise<AgentIdentitySubmissionReviewResult> {
    return this.#withTransaction(async (client) => {
      const existingResult = await client.query(
        `SELECT ${AGENT_IDENTITY_SUBMISSION_SELECT_COLUMNS}
         FROM agent_identity_submissions
         WHERE id = $1
         FOR UPDATE`,
        [input.submissionId]
      );
      const existingRow = existingResult.rows[0];
      if (existingRow === undefined) {
        return { status: "not_found" };
      }
      const existing = agentIdentitySubmissionFromRow(existingRow);
      if (existing.status !== "pending_review") {
        return { status: "already_reviewed", submission: existing };
      }

      const operatorReputation =
        input.action === "approve"
          ? await this.#upsertOperatorReputationWithClient(client, input.operatorReputation, reviewedAt)
          : undefined;
      const reviewedResult = await client.query(
        `UPDATE agent_identity_submissions
         SET status = $2,
             reviewed_at = $3,
             review_decision = $4,
             reviewer_identity_hash_sha256 = $5,
             review_reason = $6,
             approved_operator_actor_id = $7,
             operator_reputation_id = $8,
             assigned_trust_tier = $9,
             assigned_operator_status = $10,
             assigned_reputation_score = $11
         WHERE id = $1
         RETURNING ${AGENT_IDENTITY_SUBMISSION_SELECT_COLUMNS}`,
        [
          input.submissionId,
          input.action === "approve" ? "approved" : "rejected",
          reviewedAt,
          input.action,
          input.reviewerIdentityHashSha256,
          input.reviewReason ?? null,
          input.action === "approve" ? input.approvedOperatorActorId : null,
          operatorReputation?.id ?? null,
          input.action === "approve" ? input.operatorReputation.trustTier : null,
          input.action === "approve" ? input.operatorReputation.status : null,
          input.action === "approve" ? input.operatorReputation.reputationScore : null
        ]
      );
      const submission = agentIdentitySubmissionFromRow(requiredRow(reviewedResult.rows, "reviewAgentIdentitySubmission"));
      return operatorReputation === undefined
        ? { status: "reviewed", submission }
        : { status: "reviewed", submission, operatorReputation };
    });
  }

  async recordAgentIdentityReviewNotification(
    input: Omit<AgentIdentityReviewNotificationRecord, "id" | "status" | "createdAt" | "readAt">,
    createdAt: string
  ): Promise<AgentIdentityReviewNotificationRecord> {
    const result = await this.client.query(
      `INSERT INTO agent_identity_review_notifications
       (id, site_id, submission_id, review_decision, provider_name, operator_actor_id, contact_url, reviewer_identity_hash_sha256, review_reason, status, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'unread', $10)
       ON CONFLICT (submission_id, review_decision) DO UPDATE
       SET provider_name = agent_identity_review_notifications.provider_name
       RETURNING ${AGENT_IDENTITY_REVIEW_NOTIFICATION_SELECT_COLUMNS}`,
      [
        prefixedId("arn"),
        input.siteId,
        input.submissionId,
        input.reviewDecision,
        input.providerName,
        input.operatorActorId ?? null,
        input.contactUrl,
        input.reviewerIdentityHashSha256,
        input.reviewReason ?? null,
        createdAt
      ]
    );
    return agentIdentityReviewNotificationFromRow(requiredRow(result.rows, "recordAgentIdentityReviewNotification"));
  }

  async listAgentIdentityReviewNotifications(
    input: AgentIdentityReviewNotificationListInput
  ): Promise<readonly AgentIdentityReviewNotificationRecord[]> {
    const conditions: string[] = [];
    const values: unknown[] = [];
    if (input.siteId !== undefined) {
      values.push(input.siteId);
      conditions.push(`site_id = $${values.length}`);
    }
    if (input.status !== undefined) {
      values.push(input.status);
      conditions.push(`status = $${values.length}`);
    }
    values.push(input.limit);
    const result = await this.client.query(
      `SELECT ${AGENT_IDENTITY_REVIEW_NOTIFICATION_SELECT_COLUMNS}
       FROM agent_identity_review_notifications
       ${conditions.length === 0 ? "" : `WHERE ${conditions.join(" AND ")}`}
       ORDER BY created_at DESC
       LIMIT $${values.length}`,
      values
    );
    return result.rows.map(agentIdentityReviewNotificationFromRow);
  }

  async markAgentIdentityReviewNotificationRead(
    id: string,
    readAt: string
  ): Promise<AgentIdentityReviewNotificationRecord | undefined> {
    const result = await this.client.query(
      `UPDATE agent_identity_review_notifications
       SET status = 'read',
           read_at = COALESCE(read_at, $2)
       WHERE id = $1
       RETURNING ${AGENT_IDENTITY_REVIEW_NOTIFICATION_SELECT_COLUMNS}`,
      [id, readAt]
    );
    const row = result.rows[0];
    return row === undefined ? undefined : agentIdentityReviewNotificationFromRow(row);
  }

  async countTargets(tenantId?: string | undefined): Promise<number> {
    const result =
      tenantId === undefined
        ? await this.client.query("SELECT count(*) AS count FROM targets")
        : await this.client.query("SELECT count(*) AS count FROM targets WHERE tenant_id = $1", [tenantId]);
    return numberValue(requiredRow(result.rows, "countTargets").count);
  }

  async upsertTenantQuota(input: Omit<TenantQuotaRecord, "updatedAt">, updatedAt: string): Promise<TenantQuotaRecord> {
    const result = await this.client.query(
      `INSERT INTO tenant_quotas (tenant_id, monthly_decision_limit, stored_decision_limit, target_limit, updated_at)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (tenant_id) DO UPDATE
       SET monthly_decision_limit = EXCLUDED.monthly_decision_limit,
           stored_decision_limit = EXCLUDED.stored_decision_limit,
           target_limit = EXCLUDED.target_limit,
           updated_at = EXCLUDED.updated_at
       RETURNING tenant_id, monthly_decision_limit, stored_decision_limit, target_limit, updated_at`,
      [input.tenantId, input.monthlyDecisionLimit, input.storedDecisionLimit, input.targetLimit, updatedAt]
    );
    return quotaFromRow(requiredRow(result.rows, "upsertTenantQuota"));
  }

  async getTenantQuota(tenantId: string): Promise<TenantQuotaRecord | undefined> {
    const result = await this.client.query(
      `SELECT tenant_id, monthly_decision_limit, stored_decision_limit, target_limit, updated_at
       FROM tenant_quotas
       WHERE tenant_id = $1`,
      [tenantId]
    );
    const row = result.rows[0];
    return row === undefined ? undefined : quotaFromRow(row);
  }

  async upsertTenantPricingPlan(
    input: Omit<TenantPricingPlanRecord, "updatedAt">,
    updatedAt: string
  ): Promise<TenantPricingPlanRecord> {
    const result = await this.client.query(
      `INSERT INTO tenant_pricing_plans
       (tenant_id, plan_tier, currency, unit_price_usd, included_monthly_cleared_decisions, effective_from, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       ON CONFLICT (tenant_id) DO UPDATE
       SET plan_tier = EXCLUDED.plan_tier,
           currency = EXCLUDED.currency,
           unit_price_usd = EXCLUDED.unit_price_usd,
           included_monthly_cleared_decisions = EXCLUDED.included_monthly_cleared_decisions,
           effective_from = EXCLUDED.effective_from,
           updated_at = EXCLUDED.updated_at
       RETURNING ${TENANT_PRICING_PLAN_SELECT_COLUMNS}`,
      [
        input.tenantId,
        input.planTier,
        input.currency,
        input.unitPriceUsd,
        input.includedMonthlyClearedDecisions,
        input.effectiveFrom,
        updatedAt
      ]
    );
    return tenantPricingPlanFromRow(requiredRow(result.rows, "upsertTenantPricingPlan"));
  }

  async getTenantPricingPlan(tenantId: string): Promise<TenantPricingPlanRecord | undefined> {
    const result = await this.client.query(
      `SELECT ${TENANT_PRICING_PLAN_SELECT_COLUMNS}
       FROM tenant_pricing_plans
       WHERE tenant_id = $1`,
      [tenantId]
    );
    const row = result.rows[0];
    return row === undefined ? undefined : tenantPricingPlanFromRow(row);
  }

  async upsertBillingPeriodRollup(
    input: Omit<BillingPeriodRollupRecord, "id" | "generatedAt">,
    generatedAt: string
  ): Promise<BillingPeriodRollupRecord> {
    const result = await this.client.query(
      `INSERT INTO billing_period_rollups
       (id, tenant_id, period_start, period_end, plan_tier, currency, unit_price_usd, included_cleared_decisions,
        cleared_decision_count, billable_cleared_decision_count, overage_cleared_decision_count, estimated_cost_usd,
        price_required_gross_usd, invoice_line_item_id, export_idempotency_key, generated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
       ON CONFLICT (tenant_id, period_start, period_end) DO UPDATE
       SET plan_tier = EXCLUDED.plan_tier,
           currency = EXCLUDED.currency,
           unit_price_usd = EXCLUDED.unit_price_usd,
           included_cleared_decisions = EXCLUDED.included_cleared_decisions,
           cleared_decision_count = EXCLUDED.cleared_decision_count,
           billable_cleared_decision_count = EXCLUDED.billable_cleared_decision_count,
           overage_cleared_decision_count = EXCLUDED.overage_cleared_decision_count,
           estimated_cost_usd = EXCLUDED.estimated_cost_usd,
           price_required_gross_usd = EXCLUDED.price_required_gross_usd,
           invoice_line_item_id = EXCLUDED.invoice_line_item_id,
           export_idempotency_key = EXCLUDED.export_idempotency_key,
           generated_at = EXCLUDED.generated_at
       RETURNING ${BILLING_ROLLUP_SELECT_COLUMNS}`,
      [
        billingRollupId(input.tenantId, input.periodStart, input.periodEnd),
        input.tenantId,
        input.periodStart,
        input.periodEnd,
        input.planTier,
        input.currency,
        input.unitPriceUsd,
        input.includedClearedDecisions,
        input.clearedDecisionCount,
        input.billableClearedDecisionCount,
        input.overageClearedDecisionCount,
        input.estimatedCostUsd,
        input.priceRequiredGrossUsd,
        input.invoiceLineItemId,
        input.exportIdempotencyKey,
        generatedAt
      ]
    );
    return billingPeriodRollupFromRow(requiredRow(result.rows, "upsertBillingPeriodRollup"));
  }

  async getBillingPeriodRollup(
    tenantId: string,
    periodStart: string,
    periodEnd: string
  ): Promise<BillingPeriodRollupRecord | undefined> {
    const result = await this.client.query(
      `SELECT ${BILLING_ROLLUP_SELECT_COLUMNS}
       FROM billing_period_rollups
       WHERE tenant_id = $1 AND period_start = $2 AND period_end = $3`,
      [tenantId, periodStart, periodEnd]
    );
    const row = result.rows[0];
    return row === undefined ? undefined : billingPeriodRollupFromRow(row);
  }

  async upsertBillingExport(input: Omit<BillingExportRecord, "createdAt" | "updatedAt">, now: string): Promise<BillingExportRecord> {
    const result = await this.client.query(
      `INSERT INTO billing_exports
       (id, rollup_id, tenant_id, period_start, period_end, provider, destination_ref, idempotency_key,
        payload_sha256, payload, status, created_at, updated_at, delivered_at,
        provider_receipt_id, provider_receipt_status, provider_receipt_payload_sha256, provider_receipt_recorded_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11, $12, $12, $13, $14, $15, $16, $17)
       ON CONFLICT (provider, idempotency_key) DO UPDATE
       SET destination_ref = EXCLUDED.destination_ref,
           payload_sha256 = EXCLUDED.payload_sha256,
           payload = EXCLUDED.payload,
           status = CASE WHEN billing_exports.status = 'delivered' THEN billing_exports.status ELSE EXCLUDED.status END,
           updated_at = EXCLUDED.updated_at,
           delivered_at = COALESCE(billing_exports.delivered_at, EXCLUDED.delivered_at),
           provider_receipt_id = COALESCE(billing_exports.provider_receipt_id, EXCLUDED.provider_receipt_id),
           provider_receipt_status = COALESCE(billing_exports.provider_receipt_status, EXCLUDED.provider_receipt_status),
           provider_receipt_payload_sha256 = COALESCE(billing_exports.provider_receipt_payload_sha256, EXCLUDED.provider_receipt_payload_sha256),
           provider_receipt_recorded_at = COALESCE(billing_exports.provider_receipt_recorded_at, EXCLUDED.provider_receipt_recorded_at)
       RETURNING ${BILLING_EXPORT_SELECT_COLUMNS}`,
      [
        input.id,
        input.rollupId,
        input.tenantId,
        input.periodStart,
        input.periodEnd,
        input.provider,
        input.destinationRef,
        input.idempotencyKey,
        input.payloadSha256,
        JSON.stringify(input.payload),
        input.status,
        now,
        input.deliveredAt ?? null,
        input.providerReceiptId ?? null,
        input.providerReceiptStatus ?? null,
        input.providerReceiptPayloadSha256 ?? null,
        input.providerReceiptRecordedAt ?? null
      ]
    );
    return billingExportFromRow(requiredRow(result.rows, "upsertBillingExport"));
  }

  async recordBillingExportDeliveryReceipt(
    input: BillingExportDeliveryReceiptInput,
    now: string
  ): Promise<BillingExportRecord | undefined> {
    const result = await this.client.query(
      `UPDATE billing_exports
       SET status = 'delivered',
           delivered_at = $2,
           provider_receipt_id = $3,
           provider_receipt_status = $4,
           provider_receipt_payload_sha256 = $5,
           provider_receipt_recorded_at = $6,
           updated_at = $6
       WHERE id = $1
       RETURNING ${BILLING_EXPORT_SELECT_COLUMNS}`,
      [input.id, input.deliveredAt, input.providerReceiptId, input.providerReceiptStatus, input.providerReceiptPayloadSha256, now]
    );
    const row = result.rows[0];
    return row === undefined ? undefined : billingExportFromRow(row);
  }

  async getBillingExport(id: string): Promise<BillingExportRecord | undefined> {
    const result = await this.client.query(
      `SELECT ${BILLING_EXPORT_SELECT_COLUMNS}
       FROM billing_exports
       WHERE id = $1`,
      [id]
    );
    const row = result.rows[0];
    return row === undefined ? undefined : billingExportFromRow(row);
  }

  async listBillingExports(input: BillingExportListInput): Promise<readonly BillingExportRecord[]> {
    const conditions: string[] = [];
    const values: unknown[] = [];
    const push = (column: string, value: unknown): void => {
      values.push(value);
      conditions.push(`${column} = $${values.length}`);
    };
    if (input.tenantId !== undefined) push("tenant_id", input.tenantId);
    if (input.provider !== undefined) push("provider", input.provider);
    if (input.status !== undefined) push("status", input.status);
    if (input.periodStart !== undefined) push("period_start", input.periodStart);
    if (input.periodEnd !== undefined) push("period_end", input.periodEnd);
    values.push(input.limit);
    const where = conditions.length === 0 ? "" : `WHERE ${conditions.join(" AND ")}`;
    const result = await this.client.query(
      `SELECT ${BILLING_EXPORT_SELECT_COLUMNS}
       FROM billing_exports
       ${where}
       ORDER BY created_at DESC
       LIMIT $${values.length}`,
      values
    );
    return result.rows.map(billingExportFromRow);
  }

  async recordPrivacyErasure(input: Omit<PrivacyErasureRecord, "id" | "occurredAt">, occurredAt: string): Promise<PrivacyErasureRecord> {
    const result = await this.client.query(
      `INSERT INTO privacy_erasure_requests (id, site_id, subject_handle, reason, actor_id, erased_decision_count, occurred_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING id, site_id, subject_handle, reason, actor_id, erased_decision_count, occurred_at`,
      [prefixedId("dsr"), input.siteId, input.subjectHandle, input.reason, input.actorId, input.erasedDecisionCount, occurredAt]
    );
    return privacyErasureFromRow(requiredRow(result.rows, "recordPrivacyErasure"));
  }

  async listPrivacyErasures(siteId?: string | undefined, limit = 100): Promise<readonly PrivacyErasureRecord[]> {
    const result =
      siteId === undefined
        ? await this.client.query(
            `SELECT id, site_id, subject_handle, reason, actor_id, erased_decision_count, occurred_at
             FROM privacy_erasure_requests
             ORDER BY occurred_at DESC
             LIMIT $1`,
            [limit]
          )
        : await this.client.query(
            `SELECT id, site_id, subject_handle, reason, actor_id, erased_decision_count, occurred_at
             FROM privacy_erasure_requests
             WHERE site_id = $1
             ORDER BY occurred_at DESC
             LIMIT $2`,
            [siteId, limit]
          );
    return result.rows.map(privacyErasureFromRow);
  }

  async eraseSubjectDecisions(siteId: string, subjectHandle: string): Promise<number> {
    const result = await this.client.query(
      `DELETE FROM decisions
       WHERE site_id = $1 AND subject_handle = $2
       RETURNING id`,
      [siteId, subjectHandle]
    );
    return result.rowCount ?? result.rows.length;
  }

  async upsertWebhookEndpoint(input: Omit<WebhookEndpointRecord, "id" | "createdAt" | "updatedAt">, now: string): Promise<WebhookEndpointRecord> {
    const result = await this.client.query(
      `INSERT INTO webhook_endpoints (id, tenant_id, url, event_types, signing_secret_ref, created_at, updated_at)
       VALUES ($1, $2, $3, $4::jsonb, $5, $6, $6)
       ON CONFLICT (tenant_id, url) DO UPDATE
       SET event_types = EXCLUDED.event_types,
           signing_secret_ref = EXCLUDED.signing_secret_ref,
           updated_at = EXCLUDED.updated_at
       RETURNING id, tenant_id, url, event_types, signing_secret_ref, created_at, updated_at`,
      [prefixedId("whk"), input.tenantId, input.url, JSON.stringify(input.eventTypes), input.signingSecretRef, now]
    );
    return webhookEndpointFromRow(requiredRow(result.rows, "upsertWebhookEndpoint"));
  }

  async listWebhookEndpoints(tenantId?: string | undefined): Promise<readonly WebhookEndpointRecord[]> {
    const result =
      tenantId === undefined
        ? await this.client.query(
            `SELECT id, tenant_id, url, event_types, signing_secret_ref, created_at, updated_at
             FROM webhook_endpoints
             ORDER BY updated_at DESC`
          )
        : await this.client.query(
            `SELECT id, tenant_id, url, event_types, signing_secret_ref, created_at, updated_at
             FROM webhook_endpoints
             WHERE tenant_id = $1
             ORDER BY updated_at DESC`,
            [tenantId]
          );
    return result.rows.map(webhookEndpointFromRow);
  }
}
