import type { FastifyInstance } from "fastify";
import { ActorClassSchema, CascadeTraceSchema, DecisionActionSchema, OPERATOR_ACTIONS } from "@aidenid/common-schemas";
import { makeOutboxEvent } from "@aidenid/eventing";
import { z } from "zod";

import { prefixedId } from "../ids.js";
import { requireOperatorOrServiceRole, requireOperatorRole } from "../plugins/operatorAuth.js";
import { enqueuePersonaAudit } from "../services/personaAudit.js";
import { DECISION_OUTBOX_GENESIS_HASH, validateDecisionOutboxChain } from "../services/store.js";
import type { ControlPlaneServices, DecisionOutboxEvent, DecisionRecord } from "../types.js";

const DECISION_STREAM_BATCH_SIZE = 100;
const DECISION_STREAM_WAIT_MS = 200;
const DECISION_STREAM_KEEPALIVE_MS = 15_000;
const PurposeSlugSchema = z.string().trim().min(1).max(64).regex(/^[a-z][a-z0-9_-]{0,63}$/);

const DecisionQuerySchema = z
  .object({
    site_id: z.string().regex(/^sit_[A-Za-z0-9_-]+$/).optional(),
    limit: z.coerce.number().int().positive().max(500).default(100)
  })
  .strict();

const DecisionSearchQuerySchema = z
  .object({
    site_id: z.string().regex(/^sit_[A-Za-z0-9_-]+$/),
    decision: DecisionActionSchema.optional(),
    operator_actor_id: z.string().min(1).max(256).optional(),
    since: z.string().datetime().optional(),
    until: z.string().datetime().optional(),
    issuer: z.string().min(1).max(512).optional(),
    subject_handle: z.string().min(1).max(256).optional(),
    actor_class: ActorClassSchema.optional(),
    route_template: z.string().regex(/^\//).optional(),
    purpose: PurposeSlugSchema.optional(),
    limit: z.coerce.number().int().positive().max(1000).default(100)
  })
  .strict();

const QuarantinePinsQuerySchema = z
  .object({
    site_id: z.string().regex(/^sit_[A-Za-z0-9_-]+$/).optional(),
    limit: z.coerce.number().int().positive().max(500).default(100)
  })
  .strict();

const DecisionStreamQuerySchema = z
  .object({
    site_id: z.string().regex(/^sit_[A-Za-z0-9_-]+$/),
    once: z.enum(["1", "true", "yes"]).optional()
  })
  .strict();

const DecisionAwaitQuerySchema = z
  .object({
    timeout_ms: z.coerce.number().int().min(0).max(30_000).default(1_500)
  })
  .strict();

const DecisionChainSegmentQuerySchema = z
  .object({
    from_seq: z.coerce.number().int().positive().default(1),
    limit: z.coerce.number().int().positive().max(1_000).default(250),
    expected_previous_hash: z.string().regex(/^[a-f0-9]{64}$/).optional()
  })
  .strict();

const DecisionParamsSchema = z
  .object({
    id: z.string().regex(/^dec_[A-Za-z0-9_-]+$/)
  })
  .strict();

const OperatorDecisionActionSchema = z.enum(OPERATOR_ACTIONS);
const LlmBrandSchema = z.string().trim().min(1).max(32).regex(/^[a-z][a-z0-9_-]{0,31}$/);

const OperatorActionSchema = z
  .object({
    operator_action: OperatorDecisionActionSchema,
    operator_reason: z.string().min(1).max(512).optional(),
    operator_ttl_seconds: z.number().int().min(60).max(604_800).optional()
  })
  .strict();

const DecisionRecordRequestSchema = z
  .object({
    site_id: z.string().regex(/^sit_[A-Za-z0-9_-]+$/),
    request_id: z.string().min(1),
    actor_class: z.string().min(1),
    decision: z.string().min(1),
    recommended_decision: z.string().min(1).optional(),
    route_template: z.string().regex(/^\//),
    method: z.string().min(1),
    occurred_at: z.string().datetime().optional(),
    latency_us: z.number().int().nonnegative().optional(),
    subject_handle: z.string().min(8).max(256).optional(),
    issuer: z.string().min(1).max(512).optional(),
    llm_brand: LlmBrandSchema.optional(),
    purpose: PurposeSlugSchema.optional(),
    price_usd: z.number().nonnegative().optional(),
    suspicion_score: z.number().min(0).max(1).optional(),
    reason_codes: z.array(z.string().min(1)).max(32).optional(),
    cascade_trace: CascadeTraceSchema.optional()
  })
  .strict();

function serializeDecision(decision: DecisionRecord) {
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

function hasDecisionReceipt(decision: DecisionRecord): boolean {
  return (
    decision.receiptJws !== undefined &&
    decision.receiptKeyId !== undefined &&
    decision.receiptPublicJwk !== undefined &&
    decision.receiptPayloadSha256 !== undefined &&
    decision.receiptJwsSha256 !== undefined &&
    decision.transparencyLeafHash !== undefined &&
    decision.transparencyLeafIndex !== undefined &&
    decision.transparencyCheckpoint !== undefined &&
    decision.transparencyInclusionProof !== undefined
  );
}

function parseLastEventId(value: string | string[] | undefined): number {
  const raw = Array.isArray(value) ? value[0] : value;
  if (raw === undefined || raw.trim().length === 0) {
    return 0;
  }
  const parsed = Number(raw);
  return Number.isSafeInteger(parsed) && parsed >= 0 ? parsed : 0;
}

function decisionOutboxPayloadWithChain(event: DecisionOutboxEvent): Readonly<Record<string, unknown>> {
  return {
    ...event.payload,
    decision_outbox_chain: {
      previous_hash: event.previousHash,
      entry_hash: event.entryHash
    }
  };
}

function serializeDecisionOutboxEvent(event: DecisionOutboxEvent): Readonly<Record<string, unknown>> {
  return {
    seq: event.seq,
    decision_id: event.decisionId,
    occurred_at: event.occurredAt,
    event_type: event.eventType,
    previous_hash: event.previousHash,
    entry_hash: event.entryHash,
    payload: event.payload
  };
}

function encodeDecisionSse(event: DecisionOutboxEvent): string {
  return `id: ${event.seq}\nevent: ${event.eventType}\ndata: ${JSON.stringify(decisionOutboxPayloadWithChain(event))}\n\n`;
}

function encodeDecisionStreamError(): string {
  return `event: stream_error\ndata: ${JSON.stringify({ error: "decision_stream_unavailable" })}\n\n`;
}

async function publishQuarantineSideEffects(services: ControlPlaneServices, event: DecisionOutboxEvent, ttlSeconds: number | undefined): Promise<void> {
  const basePayload = {
    ...decisionOutboxPayloadWithChain(event),
    ...(ttlSeconds === undefined ? {} : { operator_action_ttl_seconds: ttlSeconds }),
    decision_outbox_seq: event.seq
  };
  await services.outbox.publish(makeOutboxEvent(prefixedId("evt"), "DECISION_QUARANTINE_APPLIED", basePayload));
  await services.outbox.publish(makeOutboxEvent(prefixedId("evt"), "OCSF_DECISION_EMIT_REQUESTED", basePayload));
  await services.outbox.publish(makeOutboxEvent(prefixedId("evt"), "WEBHOOK_DECISION_EMIT_REQUESTED", basePayload));
}

export async function registerDecisionRoutes(app: FastifyInstance, services: ControlPlaneServices): Promise<void> {
  app.post("/v1/decisions", async (request, reply) => {
    const parsed = DecisionRecordRequestSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.code(400).send({ error: "invalid_decision_record", details: parsed.error.issues });
    }
    const target = await services.store.getTargetBySiteId(parsed.data.site_id);
    const decision = {
      id: prefixedId("dec"),
      tenantId: target?.tenantId,
      siteId: parsed.data.site_id,
      requestId: parsed.data.request_id,
      actorClass: parsed.data.actor_class,
      decision: parsed.data.decision,
      recommendedDecision: parsed.data.recommended_decision,
      routeTemplate: parsed.data.route_template,
      method: parsed.data.method.toUpperCase(),
      occurredAt: parsed.data.occurred_at ?? new Date().toISOString(),
      latencyUs: parsed.data.latency_us,
      subjectHandle: parsed.data.subject_handle,
      issuer: parsed.data.issuer,
      llmBrand: parsed.data.llm_brand,
      purpose: parsed.data.purpose,
      priceUsd: parsed.data.price_usd,
      suspicionScore: parsed.data.suspicion_score,
      reasonCodes: parsed.data.reason_codes ?? [],
      cascadeTrace: parsed.data.cascade_trace
    };
    const writeResult = await services.store.recordDecisionWithTenantQuota({
      tenantId: target?.tenantId,
      issueDecision: async () => ({
        ...decision,
        ...(await services.decisionReceipts.issue(decision))
      })
    });
    if (writeResult.status === "quota_exceeded") {
      return reply
        .code(429)
        .send({ error: "tenant_decision_storage_quota_exceeded", stored_decision_limit: writeResult.storedDecisionLimit });
    }

    const signedDecision = writeResult.decision;
    await services.outbox.publish(
      makeOutboxEvent(prefixedId("evt"), "DECISION_RECORDED", {
        tenant_id: signedDecision.tenantId ?? signedDecision.siteId,
        site_id: signedDecision.siteId,
        decision_id: signedDecision.id,
        request_id: signedDecision.requestId,
        actor_class: signedDecision.actorClass,
        decision: signedDecision.decision,
        ...(signedDecision.purpose === undefined ? {} : { purpose: signedDecision.purpose }),
        occurred_at: signedDecision.occurredAt,
        receipt_jws_sha256: signedDecision.receiptJwsSha256,
        receipt_payload_sha256: signedDecision.receiptPayloadSha256,
        transparency_leaf_hash: signedDecision.transparencyLeafHash,
        transparency_leaf_index: signedDecision.transparencyLeafIndex
      })
    );
    const personaAudit =
      decision.suspicionScore !== undefined && decision.suspicionScore >= services.personaAudit.suspicionThreshold
        ? await enqueuePersonaAudit(services, {
            triggerType: "suspicion_threshold",
            siteId: signedDecision.siteId,
            requestId: signedDecision.requestId,
            actorClass: signedDecision.actorClass,
            decision: signedDecision.decision,
            suspicionScore: decision.suspicionScore,
            occurredAt: signedDecision.occurredAt
          })
        : undefined;

    return reply.code(201).send({
      decision: serializeDecision(signedDecision),
      ...(personaAudit === undefined ? {} : { persona_audit: { id: personaAudit.id, status: personaAudit.status } })
    });
  });

  app.get("/v1/decisions", async (request, reply) => {
    // Operator-gated: site_id is OPTIONAL on this query and listDecisions(undefined, limit) spans
    // every site, so ungated this returned up to 500 decision records across all tenants to an
    // anonymous caller — without needing to know a single id. Broader than the by-id receipt read.
    const operator = requireOperatorRole(request, reply, "decision_search");
    if (operator === undefined) {
      return;
    }
    const parsed = DecisionQuerySchema.safeParse(request.query);
    if (!parsed.success) {
      return reply.code(400).send({ error: "invalid_decision_query", details: parsed.error.issues });
    }
    return {
      decisions: (await services.store.listDecisions(parsed.data.site_id, parsed.data.limit)).map(serializeDecision)
    };
  });

  app.get("/v1/decisions/search", async (request, reply) => {
    const operator = requireOperatorRole(request, reply, "decision_search");
    if (operator === undefined) {
      return;
    }
    const parsed = DecisionSearchQuerySchema.safeParse(request.query);
    if (!parsed.success) {
      return reply.code(400).send({ error: "invalid_decision_search_query", details: parsed.error.issues });
    }
    const decisions = await services.store.searchDecisions({
      siteId: parsed.data.site_id,
      decision: parsed.data.decision,
      operatorActorId: parsed.data.operator_actor_id,
      since: parsed.data.since,
      until: parsed.data.until,
      issuer: parsed.data.issuer,
      subjectHandle: parsed.data.subject_handle,
      actorClass: parsed.data.actor_class,
      routeTemplate: parsed.data.route_template,
      purpose: parsed.data.purpose,
      limit: parsed.data.limit
    });
    return { decisions: decisions.map(serializeDecision) };
  });

  app.get("/v1/decisions/chain-segment", async (request, reply) => {
    const operator = requireOperatorRole(request, reply, "decision_search");
    if (operator === undefined) {
      return;
    }
    const parsed = DecisionChainSegmentQuerySchema.safeParse(request.query);
    if (!parsed.success) {
      return reply.code(400).send({ error: "invalid_decision_chain_segment_query", details: parsed.error.issues });
    }
    const events = await services.store.listDecisionOutboxAfter(parsed.data.from_seq - 1, parsed.data.limit);
    const validation = validateDecisionOutboxChain(events, { expectedPreviousHash: parsed.data.expected_previous_hash });
    return {
      chain: {
        version: "aidenid.decision_outbox.v1",
        genesis_hash: DECISION_OUTBOX_GENESIS_HASH,
        from_seq: validation.fromSeq,
        to_seq: validation.toSeq,
        count: validation.count,
        valid: validation.valid,
        ...(parsed.data.expected_previous_hash === undefined ? {} : { expected_previous_hash: parsed.data.expected_previous_hash }),
        ...(validation.anchorPreviousHash === undefined ? {} : { anchor_previous_hash: validation.anchorPreviousHash }),
        ...(validation.terminalEntryHash === undefined ? {} : { terminal_entry_hash: validation.terminalEntryHash }),
        findings: validation.findings
      },
      events: events.map(serializeDecisionOutboxEvent)
    };
  });

  app.get("/v1/decisions/:id/receipt", async (request, reply) => {
    // Operator-gated: a decision receipt is tenant-scoped evidence. Fetching by id alone
    // exposed any tenant's receipt to an anonymous caller who could guess or observe an id.
    const operator = requireOperatorRole(request, reply, "decision_search");
    if (operator === undefined) {
      return;
    }
    const params = DecisionParamsSchema.safeParse(request.params);
    if (!params.success) {
      return reply.code(400).send({ error: "invalid_decision_id", details: params.error.issues });
    }
    const decision = await services.store.getDecision(params.data.id);
    if (decision === undefined) {
      return reply.code(404).send({ error: "decision_not_found" });
    }
    if (!hasDecisionReceipt(decision)) {
      return reply.code(404).send({ error: "decision_receipt_not_found" });
    }
    return {
      decision_id: decision.id,
      receipt_jws: decision.receiptJws,
      receipt_key_id: decision.receiptKeyId,
      receipt_public_jwk: decision.receiptPublicJwk,
      receipt_payload_sha256: decision.receiptPayloadSha256,
      receipt_jws_sha256: decision.receiptJwsSha256,
      transparency: {
        leaf_hash: decision.transparencyLeafHash,
        leaf_index: decision.transparencyLeafIndex,
        checkpoint: decision.transparencyCheckpoint,
        inclusion_proof: decision.transparencyInclusionProof
      },
      verified: await services.decisionReceipts.verify(decision)
    };
  });

  app.patch("/v1/decisions/:id/operator-action", async (request, reply) => {
    const operator = requireOperatorRole(request, reply, "decision_operator");
    if (operator === undefined) {
      return;
    }
    const params = DecisionParamsSchema.safeParse(request.params);
    if (!params.success) {
      return reply.code(400).send({ error: "invalid_decision_id", details: params.error.issues });
    }
    const parsed = OperatorActionSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.code(400).send({ error: "invalid_operator_action", details: parsed.error.issues });
    }
    const occurredAt = new Date().toISOString();
    const event = await services.store.applyDecisionOperatorAction({
      decisionId: params.data.id,
      action: parsed.data.operator_action,
      actorId: operator.actorId,
      reason: parsed.data.operator_reason,
      occurredAt,
      ttlSeconds: parsed.data.operator_ttl_seconds
    });
    if (event === undefined) {
      return reply.code(404).send({ error: "decision_not_found" });
    }
    if (parsed.data.operator_action === "quarantine") {
      await publishQuarantineSideEffects(services, event, parsed.data.operator_ttl_seconds);
    }
    return reply.code(200).send({
      decision: event.payload,
      outbox: {
        seq: event.seq,
        event_type: event.eventType
      }
    });
  });

  app.get("/v1/decisions/:id/await", async (request, reply) => {
    // Gated for two reasons. It discloses a decision by id, the same class as the receipt read; and
    // it is a long poll that holds the connection for a caller-supplied timeout_ms while re-querying,
    // so ungated it was also a cheap way for anonymous callers to pin connections.
    //
    // ANY-OF, matching the route manifest: the verifier reaches this synchronously with
    // service:decision_status, and a human/dashboard caller with operator:decision_search. Gating it
    // with requireOperatorRole alone (as #284 originally did) rejects every service principal, which
    // passes today only because the live verifier credential is still an operator and would break the
    // moment it is re-scoped to a service principal -- i.e. exactly during the AUTH-1 migration the
    // WAF retirement depends on.
    const principal = requireOperatorOrServiceRole(request, reply, "decision_search", "decision_status");
    if (principal === undefined) {
      return;
    }
    const params = DecisionParamsSchema.safeParse(request.params);
    if (!params.success) {
      return reply.code(400).send({ error: "invalid_decision_id", details: params.error.issues });
    }
    const parsed = DecisionAwaitQuerySchema.safeParse(request.query);
    if (!parsed.success) {
      return reply.code(400).send({ error: "invalid_decision_await_query", details: parsed.error.issues });
    }

    const deadline = Date.now() + parsed.data.timeout_ms;
    while (true) {
      const cursor = await services.store.latestDecisionOutboxSeq();
      const decision = await services.store.getDecision(params.data.id);
      if (decision === undefined) {
        return reply.code(404).send({ error: "decision_not_found" });
      }
      if (decision.operatorAction !== undefined) {
        return reply.code(200).send({ status: "resolved", decision: serializeDecision(decision) });
      }
      const remaining = deadline - Date.now();
      if (remaining <= 0) {
        return reply.code(202).send({ status: "pending", decision: serializeDecision(decision) });
      }
      await services.store.waitForDecisionOutboxAfter(cursor, Math.min(remaining, DECISION_STREAM_WAIT_MS));
    }
  });

  app.get("/v1/quarantine/pins", async (request, reply) => {
    // Operator-gated: quarantine pins are tenant-scoped enforcement records. site_id is
    // caller-supplied, so without auth any site's pins were readable anonymously.
    const operator = requireOperatorRole(request, reply, "decision_search");
    if (operator === undefined) {
      return;
    }
    const parsed = QuarantinePinsQuerySchema.safeParse(request.query);
    if (!parsed.success) {
      return reply.code(400).send({ error: "invalid_quarantine_pins_query", details: parsed.error.issues });
    }
    return {
      pins: (await services.store.listQuarantinePins(parsed.data.site_id, parsed.data.limit)).map((pin) => ({
        id: pin.id,
        decision_id: pin.decisionId,
        site_id: pin.siteId,
        actor_class: pin.actorClass,
        ...(pin.issuer === undefined ? {} : { issuer: pin.issuer }),
        ...(pin.subjectHandle === undefined ? {} : { subject_handle: pin.subjectHandle }),
        request_id: pin.requestId,
        operator_actor_id: pin.operatorActorId,
        ...(pin.reason === undefined ? {} : { reason: pin.reason }),
        expires_at: pin.expiresAt,
        created_at: pin.createdAt
      }))
    };
  });

  app.get("/v1/decisions/stream", async (request, reply) => {
    const operator = requireOperatorRole(request, reply, "decision_search");
    if (operator === undefined) {
      return;
    }

    const parsed = DecisionStreamQuerySchema.safeParse(request.query);
    if (!parsed.success) {
      return reply.code(400).send({ error: "invalid_decision_stream_query", details: parsed.error.issues });
    }

    const requestedSiteId = parsed.data.site_id;
    let cursor = parseLastEventId(request.headers["last-event-id"]);
    const writeAvailable = async () => {
      const events = await services.store.listDecisionOutboxAfter(cursor, DECISION_STREAM_BATCH_SIZE);
      for (const event of events) {
        // Advance the cursor globally (preserving the append-only chain seq semantics),
        // but only emit events for the requested tenant/site. Fail closed: any event
        // whose site cannot be matched is never streamed to this subscriber.
        cursor = event.seq;
        if (event.payload.site_id !== requestedSiteId) {
          continue;
        }
        reply.raw.write(encodeDecisionSse(event));
      }
      return events.length;
    };

    reply.hijack();
    reply.raw.writeHead(200, {
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
      "Content-Type": "text/event-stream"
    });
    try {
      await writeAvailable();
    } catch (error) {
      app.log.error({ error }, "decision stream initial outbox read failed");
      reply.raw.write(encodeDecisionStreamError());
      reply.raw.end();
      return;
    }

    if (parsed.data.once !== undefined) {
      reply.raw.end();
      return;
    }

    let closed = false;
    const keepalive = setInterval(() => {
      if (!closed) {
        reply.raw.write(": ping\n\n");
      }
    }, DECISION_STREAM_KEEPALIVE_MS);
    const close = () => {
      closed = true;
      clearInterval(keepalive);
    };
    request.raw.on("close", close);

    const run = async () => {
      while (!closed) {
        try {
          const written = await writeAvailable();
          if (closed) {
            return;
          }
          if (written === 0) {
            await services.store.waitForDecisionOutboxAfter(cursor, DECISION_STREAM_WAIT_MS);
          }
        } catch (error) {
          close();
          app.log.error({ error }, "decision stream outbox poll failed");
          reply.raw.write(encodeDecisionStreamError());
          reply.raw.end();
          return;
        }
      }
    };
    void run();
  });
}
