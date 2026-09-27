import { createHash } from "node:crypto";

import {
  AgentIdentityChallengeReviewSchema,
  AgentIdentityChallengeSubmissionSchema,
  AgentIdentitySubmissionStatusSchema,
  SiteIdSchema
} from "@aidenid/common-schemas";
import type { FastifyInstance, FastifyRequest } from "fastify";
import { z } from "zod";

import { requireOperatorRole } from "../plugins/operatorAuth.js";
import type { AgentIdentitySubmissionRecord, ControlPlaneServices } from "../types.js";
import { serializeOperatorReputation } from "./operators.js";

const AgentIdentitySubmissionQuerySchema = z
  .object({
    site_id: SiteIdSchema.optional(),
    status: AgentIdentitySubmissionStatusSchema.optional(),
    limit: z.coerce.number().int().positive().max(1000).default(100)
  })
  .strict();

const AgentIdentitySubmissionReviewParamsSchema = z
  .object({
    submissionId: z.string().regex(/^ais_[A-Za-z0-9_-]+$/)
  })
  .strict();

const AgentIdentityReviewNotificationQuerySchema = z
  .object({
    site_id: SiteIdSchema.optional(),
    status: z.enum(["unread", "read"]).optional(),
    limit: z.coerce.number().int().positive().max(1000).default(100)
  })
  .strict();

const AgentIdentityReviewNotificationParamsSchema = z
  .object({
    notificationId: z.string().regex(/^arn_[A-Za-z0-9_-]+$/)
  })
  .strict();

const AgentIdentityReviewNotificationReadSchema = z
  .object({
    status: z.literal("read")
  })
  .strict();

const MAX_IDENTITY_SUBMISSION_BODY_BYTES = 16 * 1024;
const SUBMITTER_RATE_WINDOW_MS = 60 * 60 * 1000;
const MAX_SUBMISSIONS_PER_SUBMITTER_WINDOW = 10;
const CONTENT_REPLAY_WINDOW_MS = 24 * 60 * 60 * 1000;
const OPERATOR_CLAIM_COOLDOWN_MS = 24 * 60 * 60 * 1000;
const MAX_GUARD_KEYS = 50_000;

interface RateWindow {
  count: number;
  expiresAt: number;
}

interface GuardRejection {
  readonly statusCode: 413 | 429;
  readonly error: string;
  readonly retryAfterSeconds?: number | undefined;
}

const submitterWindows = new Map<string, RateWindow>();
const contentReplayExpirations = new Map<string, number>();
const operatorClaimExpirations = new Map<string, number>();

function sha256Hex(input: string): string {
  return createHash("sha256").update(input).digest("hex");
}

function secondsUntil(expiresAt: number, now: number): number {
  return Math.max(1, Math.ceil((expiresAt - now) / 1000));
}

function computeRequestedAccessExpiresAt(submittedAt: string, durationSeconds: number): string {
  return new Date(Date.parse(submittedAt) + durationSeconds * 1_000).toISOString();
}

function reviewerApprovalExpiresAt(input: {
  readonly requestedAccessExpiresAt: string;
  readonly reviewerSelectedExpiresAt?: string | undefined;
  readonly reviewedAt: string;
}): { readonly ok: true; readonly expiresAt: string } | { readonly ok: false; readonly error: string } {
  const requestedMs = Date.parse(input.requestedAccessExpiresAt);
  const reviewedMs = Date.parse(input.reviewedAt);
  const selected = input.reviewerSelectedExpiresAt ?? input.requestedAccessExpiresAt;
  const selectedMs = Date.parse(selected);
  if (!Number.isFinite(requestedMs) || !Number.isFinite(reviewedMs) || !Number.isFinite(selectedMs)) {
    return { ok: false, error: "identity_review_expiry_invalid" };
  }
  if (selectedMs > requestedMs) {
    return { ok: false, error: "identity_review_expiry_exceeds_requested_access" };
  }
  if (selectedMs <= reviewedMs) {
    return { ok: false, error: "identity_review_expiry_expired" };
  }
  return { ok: true, expiresAt: new Date(selectedMs).toISOString() };
}

function pruneExpiringMap(map: Map<string, number>, now: number): void {
  for (const [key, expiresAt] of map.entries()) {
    if (expiresAt <= now) {
      map.delete(key);
    }
  }
  while (map.size > MAX_GUARD_KEYS) {
    const oldest = map.keys().next().value as string | undefined;
    if (oldest === undefined) {
      return;
    }
    map.delete(oldest);
  }
}

function pruneRateWindows(now: number): void {
  for (const [key, window] of submitterWindows.entries()) {
    if (window.expiresAt <= now) {
      submitterWindows.delete(key);
    }
  }
  while (submitterWindows.size > MAX_GUARD_KEYS) {
    const oldest = submitterWindows.keys().next().value as string | undefined;
    if (oldest === undefined) {
      return;
    }
    submitterWindows.delete(oldest);
  }
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value) ?? "null";
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, entryValue]) => entryValue !== undefined)
    .sort(([left], [right]) => left.localeCompare(right));
  return `{${entries.map(([key, entryValue]) => `${JSON.stringify(key)}:${canonicalJson(entryValue)}`).join(",")}}`;
}

function jsonBodySizeBytes(value: unknown): number {
  return Buffer.byteLength(canonicalJson(value), "utf8");
}

function headerValue(value: string | string[] | undefined): string | undefined {
  if (Array.isArray(value)) {
    return value[0];
  }
  return value;
}

function boundedHeaderString(value: string | string[] | undefined, max: number): string | undefined {
  const raw = headerValue(value)?.trim();
  return raw === undefined || raw.length === 0 || raw.length > max ? undefined : raw;
}

function submitterFingerprint(request: FastifyRequest): string {
  const forwardedFor = headerValue(request.headers["x-forwarded-for"]);
  const connectingIp = headerValue(request.headers["cf-connecting-ip"]);
  const realIp = headerValue(request.headers["x-real-ip"]);
  const ip = forwardedFor?.split(",")[0]?.trim() ?? connectingIp?.trim() ?? realIp?.trim() ?? request.ip ?? "unknown";
  return sha256Hex(`submitter:${ip}`);
}

function reviewerIdentityHash(request: FastifyRequest, fallbackActorId: string): string {
  const reviewer = boundedHeaderString(request.headers["x-aidenid-reviewer-id"], 256) ?? fallbackActorId;
  return sha256Hex(`reviewer:${fallbackActorId}:${reviewer}`);
}

function claimKey(input: z.infer<typeof AgentIdentityChallengeSubmissionSchema>): string {
  const claim = input.operator_actor_id ?? `provider:${input.provider_name.toLowerCase()}`;
  return `${input.site_id}:${claim.toLowerCase()}`;
}

function submissionDigest(input: z.infer<typeof AgentIdentityChallengeSubmissionSchema>): string {
  return sha256Hex(canonicalJson(input));
}

function enforceSubmitterRate(submitterHashSha256: string, now: number): GuardRejection | undefined {
  pruneRateWindows(now);
  const window = submitterWindows.get(submitterHashSha256);
  if (window === undefined || window.expiresAt <= now) {
    submitterWindows.set(submitterHashSha256, { count: 1, expiresAt: now + SUBMITTER_RATE_WINDOW_MS });
    return undefined;
  }
  if (window.count >= MAX_SUBMISSIONS_PER_SUBMITTER_WINDOW) {
    return {
      statusCode: 429,
      error: "identity_submission_rate_limited",
      retryAfterSeconds: secondsUntil(window.expiresAt, now)
    };
  }
  window.count += 1;
  return undefined;
}

function enforceSubmissionReplayGuards(input: {
  readonly siteId: string;
  readonly submitterHashSha256: string;
  readonly submissionDigestSha256: string;
  readonly operatorClaimHashSha256: string;
  readonly now: number;
}): GuardRejection | undefined {
  pruneExpiringMap(contentReplayExpirations, input.now);
  pruneExpiringMap(operatorClaimExpirations, input.now);

  const contentKey = `${input.siteId}:${input.submissionDigestSha256}`;
  const contentExpiresAt = contentReplayExpirations.get(contentKey);
  if (contentExpiresAt !== undefined && contentExpiresAt > input.now) {
    return {
      statusCode: 429,
      error: "identity_submission_duplicate",
      retryAfterSeconds: secondsUntil(contentExpiresAt, input.now)
    };
  }

  const operatorClaimKey = `${input.submitterHashSha256}:${input.operatorClaimHashSha256}`;
  const operatorClaimExpiresAt = operatorClaimExpirations.get(operatorClaimKey);
  if (operatorClaimExpiresAt !== undefined && operatorClaimExpiresAt > input.now) {
    return {
      statusCode: 429,
      error: "identity_operator_claim_cooldown",
      retryAfterSeconds: secondsUntil(operatorClaimExpiresAt, input.now)
    };
  }

  contentReplayExpirations.set(contentKey, input.now + CONTENT_REPLAY_WINDOW_MS);
  operatorClaimExpirations.set(operatorClaimKey, input.now + OPERATOR_CLAIM_COOLDOWN_MS);
  return undefined;
}

function serializeAgentIdentitySubmission(record: AgentIdentitySubmissionRecord) {
  return {
    id: record.id,
    site_id: record.siteId,
    ...(record.requestId === undefined ? {} : { request_id: record.requestId }),
    purpose: record.purpose,
    requested_access_duration_seconds: record.requestedAccessDurationSeconds,
    requested_access_expires_at: record.requestedAccessExpiresAt,
    ...(record.purposeRationale === undefined ? {} : { purpose_rationale: record.purposeRationale }),
    provider_name: record.providerName,
    ...(record.operatorActorId === undefined ? {} : { operator_actor_id: record.operatorActorId }),
    contact_url: record.contactUrl,
    ...(record.jwksUrl === undefined ? {} : { jwks_url: record.jwksUrl }),
    ...(record.delegationAuthorityJwkThumbprintSha256 === undefined
      ? {}
      : { delegation_authority_jwk_thumbprint_sha256: record.delegationAuthorityJwkThumbprintSha256 }),
    cascade_attestation: record.cascadeAttestation,
    ...(record.declaration === undefined ? {} : { declaration: record.declaration }),
    status: record.status,
    submitted_at: record.submittedAt,
    ...(record.reviewedAt === undefined ? {} : { reviewed_at: record.reviewedAt }),
    ...(record.reviewDecision === undefined ? {} : { review_decision: record.reviewDecision }),
    ...(record.reviewerIdentityHashSha256 === undefined
      ? {}
      : { reviewer_identity_hash_sha256: record.reviewerIdentityHashSha256 }),
    ...(record.reviewReason === undefined ? {} : { review_reason: record.reviewReason }),
    ...(record.approvedOperatorActorId === undefined ? {} : { approved_operator_actor_id: record.approvedOperatorActorId }),
    ...(record.operatorReputationId === undefined ? {} : { operator_reputation_id: record.operatorReputationId }),
    ...(record.assignedTrustTier === undefined ? {} : { assigned_trust_tier: record.assignedTrustTier }),
    ...(record.assignedOperatorStatus === undefined ? {} : { assigned_operator_status: record.assignedOperatorStatus }),
    ...(record.assignedReputationScore === undefined ? {} : { assigned_reputation_score: record.assignedReputationScore })
  };
}

function serializeAgentIdentityReviewNotification(record: {
  readonly id: string;
  readonly siteId: string;
  readonly submissionId: string;
  readonly reviewDecision: "approve" | "reject";
  readonly providerName: string;
  readonly operatorActorId?: string | undefined;
  readonly contactUrl: string;
  readonly reviewerIdentityHashSha256: string;
  readonly reviewReason?: string | undefined;
  readonly status: "unread" | "read";
  readonly createdAt: string;
  readonly readAt?: string | undefined;
}) {
  return {
    id: record.id,
    site_id: record.siteId,
    submission_id: record.submissionId,
    review_decision: record.reviewDecision,
    provider_name: record.providerName,
    ...(record.operatorActorId === undefined ? {} : { operator_actor_id: record.operatorActorId }),
    contact_url: record.contactUrl,
    reviewer_identity_hash_sha256: record.reviewerIdentityHashSha256,
    ...(record.reviewReason === undefined ? {} : { review_reason: record.reviewReason }),
    status: record.status,
    created_at: record.createdAt,
    ...(record.readAt === undefined ? {} : { read_at: record.readAt })
  };
}

function defaultReputationScore(input: { readonly trustTier: "restricted" | "trusted"; readonly status: "active" | "watchlist" }): number {
  if (input.status === "watchlist") {
    return input.trustTier === "trusted" ? 75 : 55;
  }
  return input.trustTier === "trusted" ? 90 : 60;
}

function reputationNotes(input: {
  readonly submissionId: string;
  readonly notes?: string | undefined;
  readonly reviewReason?: string | undefined;
}): string {
  if (input.notes !== undefined) {
    return input.notes;
  }
  if (input.reviewReason !== undefined) {
    return `Approved from identity challenge ${input.submissionId}: ${input.reviewReason}`.slice(0, 1024);
  }
  return `Approved from identity challenge ${input.submissionId}`;
}

async function recordReviewNotification(
  app: FastifyInstance,
  services: ControlPlaneServices,
  submission: AgentIdentitySubmissionRecord,
  createdAt: string
): Promise<void> {
  if (submission.reviewDecision === undefined || submission.reviewerIdentityHashSha256 === undefined) {
    app.log.warn({ submissionId: submission.id }, "identity review notification skipped because review metadata is incomplete");
    return;
  }
  try {
    await services.store.recordAgentIdentityReviewNotification(
      {
        siteId: submission.siteId,
        submissionId: submission.id,
        reviewDecision: submission.reviewDecision,
        providerName: submission.providerName,
        operatorActorId: submission.approvedOperatorActorId ?? submission.operatorActorId,
        contactUrl: submission.contactUrl,
        reviewerIdentityHashSha256: submission.reviewerIdentityHashSha256,
        reviewReason: submission.reviewReason
      },
      createdAt
    );
  } catch (error) {
    app.log.warn({ error, submissionId: submission.id }, "identity review notification dispatch failed");
  }
}

export async function registerIdentityRoutes(app: FastifyInstance, services: ControlPlaneServices): Promise<void> {
  app.post("/v1/identities", { bodyLimit: MAX_IDENTITY_SUBMISSION_BODY_BYTES }, async (request, reply) => {
    if (jsonBodySizeBytes(request.body) > MAX_IDENTITY_SUBMISSION_BODY_BYTES) {
      return reply
        .code(413)
        .send({ error: "identity_submission_payload_too_large", max_bytes: MAX_IDENTITY_SUBMISSION_BODY_BYTES });
    }

    const nowMs = Date.now();
    const submitterHashSha256 = submitterFingerprint(request);
    const rateRejection = enforceSubmitterRate(submitterHashSha256, nowMs);
    if (rateRejection !== undefined) {
      if (rateRejection.retryAfterSeconds !== undefined) {
        reply.header("Retry-After", String(rateRejection.retryAfterSeconds));
      }
      return reply.code(rateRejection.statusCode).send({ error: rateRejection.error, retry_after_seconds: rateRejection.retryAfterSeconds });
    }

    const parsed = AgentIdentityChallengeSubmissionSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.code(400).send({ error: "invalid_identity_challenge_submission", details: parsed.error.issues });
    }

    const submissionDigestSha256 = submissionDigest(parsed.data);
    const operatorClaimHashSha256 = sha256Hex(claimKey(parsed.data));
    const replayRejection = enforceSubmissionReplayGuards({
      siteId: parsed.data.site_id,
      submitterHashSha256,
      submissionDigestSha256,
      operatorClaimHashSha256,
      now: nowMs
    });
    if (replayRejection !== undefined) {
      if (replayRejection.retryAfterSeconds !== undefined) {
        reply.header("Retry-After", String(replayRejection.retryAfterSeconds));
      }
      return reply.code(replayRejection.statusCode).send({ error: replayRejection.error, retry_after_seconds: replayRejection.retryAfterSeconds });
    }

    const submittedAt = new Date().toISOString();
    const submission = await services.store.recordAgentIdentitySubmission(
      {
        siteId: parsed.data.site_id,
        requestId: parsed.data.request_id,
        purpose: parsed.data.purpose,
        requestedAccessDurationSeconds: parsed.data.requested_access_duration_seconds,
        requestedAccessExpiresAt: computeRequestedAccessExpiresAt(submittedAt, parsed.data.requested_access_duration_seconds),
        purposeRationale: parsed.data.purpose_rationale,
        providerName: parsed.data.provider_name,
        operatorActorId: parsed.data.operator_actor_id,
        contactUrl: parsed.data.contact_url,
        jwksUrl: parsed.data.jwks_url,
        delegationAuthorityJwkThumbprintSha256: parsed.data.delegation_authority_jwk_thumbprint_sha256,
        cascadeAttestation: parsed.data.cascade_attestation,
        declaration: parsed.data.declaration,
        submitterHashSha256,
        submissionDigestSha256,
        operatorClaimHashSha256
      },
      submittedAt
    );

    return reply.code(202).send({
      submission: serializeAgentIdentitySubmission(submission),
      next_steps: [
        "operator_review_required",
        "register_http_signature_jwks",
        "exchange_for_proof_bound_session",
        "send_x_aidenid_purpose_on_purpose_gated_routes"
      ]
    });
  });

  app.get("/v1/identities/submissions", async (request, reply) => {
    const operator = requireOperatorRole(request, reply, "operator_reputation");
    if (operator === undefined) {
      return;
    }
    const parsed = AgentIdentitySubmissionQuerySchema.safeParse(request.query);
    if (!parsed.success) {
      return reply.code(400).send({ error: "invalid_identity_submission_query", details: parsed.error.issues });
    }
    const submissions = await services.store.listAgentIdentitySubmissions({
      siteId: parsed.data.site_id,
      status: parsed.data.status,
      limit: parsed.data.limit
    });
    return { submissions: submissions.map(serializeAgentIdentitySubmission) };
  });

  app.get("/v1/identities/review-notifications", async (request, reply) => {
    const operator = requireOperatorRole(request, reply, "operator_reputation");
    if (operator === undefined) {
      return;
    }
    const parsed = AgentIdentityReviewNotificationQuerySchema.safeParse(request.query);
    if (!parsed.success) {
      return reply.code(400).send({ error: "invalid_identity_review_notification_query", details: parsed.error.issues });
    }
    const notifications = await services.store.listAgentIdentityReviewNotifications({
      siteId: parsed.data.site_id,
      status: parsed.data.status,
      limit: parsed.data.limit
    });
    return { notifications: notifications.map(serializeAgentIdentityReviewNotification) };
  });

  app.patch("/v1/identities/review-notifications/:notificationId", async (request, reply) => {
    const operator = requireOperatorRole(request, reply, "operator_reputation");
    if (operator === undefined) {
      return;
    }
    const params = AgentIdentityReviewNotificationParamsSchema.safeParse(request.params);
    if (!params.success) {
      return reply.code(400).send({ error: "invalid_identity_review_notification_id", details: params.error.issues });
    }
    const parsed = AgentIdentityReviewNotificationReadSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.code(400).send({ error: "invalid_identity_review_notification_update", details: parsed.error.issues });
    }
    const notification = await services.store.markAgentIdentityReviewNotificationRead(
      params.data.notificationId,
      new Date().toISOString()
    );
    if (notification === undefined) {
      return reply.code(404).send({ error: "identity_review_notification_not_found" });
    }
    return { notification: serializeAgentIdentityReviewNotification(notification) };
  });

  app.patch("/v1/identities/submissions/:submissionId/review", async (request, reply) => {
    const operator = requireOperatorRole(request, reply, "operator_reputation");
    if (operator === undefined) {
      return;
    }
    const params = AgentIdentitySubmissionReviewParamsSchema.safeParse(request.params);
    if (!params.success) {
      return reply.code(400).send({ error: "invalid_identity_submission_id", details: params.error.issues });
    }
    const parsed = AgentIdentityChallengeReviewSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.code(400).send({ error: "invalid_identity_submission_review", details: parsed.error.issues });
    }

    const submission = await services.store.getAgentIdentitySubmission(params.data.submissionId);
    if (submission === undefined) {
      return reply.code(404).send({ error: "identity_submission_not_found" });
    }
    if (submission.status !== "pending_review") {
      return reply.code(409).send({
        error: "identity_submission_already_reviewed",
        submission: serializeAgentIdentitySubmission(submission)
      });
    }

    const reviewedAt = new Date().toISOString();
    const reviewerIdentityHashSha256 = reviewerIdentityHash(request, operator.actorId);
    if (parsed.data.action === "reject") {
      const reviewReason = parsed.data.review_reason;
      if (reviewReason === undefined) {
        return reply.code(400).send({ error: "identity_review_reason_required" });
      }
      const result = await services.store.reviewAgentIdentitySubmission(
        {
          submissionId: submission.id,
          action: "reject",
          reviewerIdentityHashSha256,
          reviewReason
        },
        reviewedAt
      );
      if (result.status === "not_found") {
        return reply.code(404).send({ error: "identity_submission_not_found" });
      }
      if (result.status === "already_reviewed") {
        return reply.code(409).send({
          error: "identity_submission_already_reviewed",
          submission: serializeAgentIdentitySubmission(result.submission)
        });
      }
      await recordReviewNotification(app, services, result.submission, reviewedAt);
      return {
        submission: serializeAgentIdentitySubmission(result.submission)
      };
    }

    const operatorActorId = parsed.data.operator_actor_id ?? submission.operatorActorId;
    if (operatorActorId === undefined) {
      return reply.code(400).send({ error: "identity_review_operator_actor_id_required" });
    }
    const approvalExpiry = reviewerApprovalExpiresAt({
      requestedAccessExpiresAt: submission.requestedAccessExpiresAt,
      reviewerSelectedExpiresAt: parsed.data.approval_expires_at,
      reviewedAt
    });
    if (!approvalExpiry.ok) {
      return reply.code(400).send({ error: approvalExpiry.error });
    }
    const result = await services.store.reviewAgentIdentitySubmission(
      {
        submissionId: submission.id,
        action: "approve",
        reviewerIdentityHashSha256,
        reviewReason: parsed.data.review_reason,
        approvedOperatorActorId: operatorActorId,
        operatorReputation: {
          siteId: submission.siteId,
          operatorActorId,
          displayName: parsed.data.display_name ?? submission.providerName,
          trustTier: parsed.data.trust_tier,
          status: parsed.data.operator_status,
          reputationScore:
            parsed.data.reputation_score ??
            defaultReputationScore({ trustTier: parsed.data.trust_tier, status: parsed.data.operator_status }),
          defaultAction: parsed.data.default_action,
          defaultScopeRoutes: parsed.data.default_scope_routes,
          defaultScopeRedirectPath: parsed.data.default_scope_redirect_path,
          notes: reputationNotes({
            submissionId: submission.id,
            notes: parsed.data.notes,
            reviewReason: parsed.data.review_reason
          }),
          lastReviewedAt: reviewedAt,
          expiresAt: approvalExpiry.expiresAt,
          updatedBy: reviewerIdentityHashSha256
        }
      },
      reviewedAt
    );
    if (result.status === "not_found") {
      return reply.code(404).send({ error: "identity_submission_not_found" });
    }
    if (result.status === "already_reviewed") {
      return reply.code(409).send({
        error: "identity_submission_already_reviewed",
        submission: serializeAgentIdentitySubmission(result.submission)
      });
    }
    await recordReviewNotification(app, services, result.submission, reviewedAt);
    return {
      submission: serializeAgentIdentitySubmission(result.submission),
      ...(result.operatorReputation === undefined ? {} : { operator: serializeOperatorReputation(result.operatorReputation) })
    };
  });
}
