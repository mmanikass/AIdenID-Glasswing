import type { FastifyInstance } from "fastify";
import { DecisionActionSchema, OperatorDefaultScopeRedirectPathSchema, OperatorDefaultScopeRoutesSchema } from "@aidenid/common-schemas";
import { z } from "zod";

import { requireOperatorRole } from "../plugins/operatorAuth.js";
import type { ControlPlaneServices, OperatorReputationRecord } from "../types.js";

const OperatorTrustTierSchema = z.enum(["unknown", "trusted", "restricted"]);
const OperatorReputationStatusSchema = z.enum(["active", "watchlist", "suspended", "expired"]);

const OperatorReputationParamsSchema = z
  .object({
    operatorActorId: z.string().trim().min(1).max(128)
  })
  .strict();

const OperatorReputationQuerySchema = z
  .object({
    site_id: z.string().regex(/^sit_[A-Za-z0-9_-]+$/),
    status: OperatorReputationStatusSchema.optional(),
    trust_tier: OperatorTrustTierSchema.optional(),
    limit: z.coerce.number().int().positive().max(1000).default(100)
  })
  .strict();

const OperatorReputationUpsertSchema = z
  .object({
    site_id: z.string().regex(/^sit_[A-Za-z0-9_-]+$/),
    display_name: z.string().trim().min(1).max(128).optional(),
    trust_tier: OperatorTrustTierSchema,
    status: OperatorReputationStatusSchema,
    reputation_score: z.number().int().min(0).max(100),
    default_action: DecisionActionSchema.default("allow"),
    default_scope_routes: OperatorDefaultScopeRoutesSchema.default([]),
    default_scope_redirect_path: OperatorDefaultScopeRedirectPathSchema.optional(),
    notes: z.string().trim().min(1).max(1024).optional(),
    last_reviewed_at: z.string().datetime().optional(),
    expires_at: z.string().datetime().nullable().optional()
  })
  .strict();

function objectHasOwn(value: unknown, key: string): boolean {
  return value !== null && typeof value === "object" && !Array.isArray(value) && Object.prototype.hasOwnProperty.call(value, key);
}

function expiryIsInvalidForStatus(input: {
  readonly expiresAt: string | undefined;
  readonly status: OperatorReputationRecord["status"];
  readonly now: string;
  readonly createdAt?: string | undefined;
}): boolean {
  if (input.expiresAt === undefined) {
    return false;
  }
  const expiresAtMs = Date.parse(input.expiresAt);
  const nowMs = Date.parse(input.now);
  const createdAtMs = Date.parse(input.createdAt ?? input.now);
  if (!Number.isFinite(expiresAtMs) || !Number.isFinite(nowMs) || !Number.isFinite(createdAtMs)) {
    return true;
  }
  if (expiresAtMs <= createdAtMs) {
    return true;
  }
  return expiresAtMs <= nowMs && input.status !== "expired";
}

export function serializeOperatorReputation(record: OperatorReputationRecord) {
  return {
    id: record.id,
    site_id: record.siteId,
    operator_actor_id: record.operatorActorId,
    ...(record.displayName === undefined ? {} : { display_name: record.displayName }),
    trust_tier: record.trustTier,
    status: record.status,
    reputation_score: record.reputationScore,
    default_action: record.defaultAction ?? "allow",
    default_scope_routes: record.defaultScopeRoutes ?? [],
    ...(record.defaultScopeRedirectPath === undefined ? {} : { default_scope_redirect_path: record.defaultScopeRedirectPath }),
    ...(record.notes === undefined ? {} : { notes: record.notes }),
    ...(record.lastReviewedAt === undefined ? {} : { last_reviewed_at: record.lastReviewedAt }),
    ...(record.expiresAt === undefined ? {} : { expires_at: record.expiresAt }),
    updated_by: record.updatedBy,
    created_at: record.createdAt,
    updated_at: record.updatedAt
  };
}

export async function registerOperatorRoutes(app: FastifyInstance, services: ControlPlaneServices): Promise<void> {
  app.get("/v1/operators/reputation", async (request, reply) => {
    const operator = requireOperatorRole(request, reply, "operator_reputation");
    if (operator === undefined) {
      return;
    }
    const parsed = OperatorReputationQuerySchema.safeParse(request.query);
    if (!parsed.success) {
      return reply.code(400).send({ error: "invalid_operator_reputation_query", details: parsed.error.issues });
    }
    const reputations = await services.store.listOperatorReputations({
      siteId: parsed.data.site_id,
      status: parsed.data.status,
      trustTier: parsed.data.trust_tier,
      limit: parsed.data.limit
    });
    return { operators: reputations.map(serializeOperatorReputation) };
  });

  app.get("/v1/operators/reputation/:operatorActorId", async (request, reply) => {
    const operator = requireOperatorRole(request, reply, "operator_reputation");
    if (operator === undefined) {
      return;
    }
    const params = OperatorReputationParamsSchema.safeParse(request.params);
    if (!params.success) {
      return reply.code(400).send({ error: "invalid_operator_actor_id", details: params.error.issues });
    }
    const parsed = OperatorReputationQuerySchema.pick({ site_id: true }).safeParse(request.query);
    if (!parsed.success) {
      return reply.code(400).send({ error: "invalid_operator_reputation_query", details: parsed.error.issues });
    }
    const reputation = await services.store.getOperatorReputation(parsed.data.site_id, params.data.operatorActorId);
    if (reputation === undefined) {
      return reply.code(404).send({ error: "operator_reputation_not_found" });
    }
    return { operator: serializeOperatorReputation(reputation) };
  });

  app.put("/v1/operators/reputation/:operatorActorId", async (request, reply) => {
    const operator = requireOperatorRole(request, reply, "operator_reputation");
    if (operator === undefined) {
      return;
    }
    const params = OperatorReputationParamsSchema.safeParse(request.params);
    if (!params.success) {
      return reply.code(400).send({ error: "invalid_operator_actor_id", details: params.error.issues });
    }
    const parsed = OperatorReputationUpsertSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.code(400).send({ error: "invalid_operator_reputation", details: parsed.error.issues });
    }
    const existing = await services.store.getOperatorReputation(parsed.data.site_id, params.data.operatorActorId);
    const now = new Date().toISOString();
    const expiresAtProvided = objectHasOwn(request.body, "expires_at");
    const expiresAt = expiresAtProvided ? parsed.data.expires_at ?? undefined : existing?.expiresAt;
    if (expiryIsInvalidForStatus({ expiresAt, status: parsed.data.status, now, createdAt: existing?.createdAt })) {
      return reply.code(400).send({ error: "operator_reputation_expiry_expired" });
    }
    const reputation = await services.store.upsertOperatorReputation(
      {
        siteId: parsed.data.site_id,
        operatorActorId: params.data.operatorActorId,
        displayName: parsed.data.display_name,
        trustTier: parsed.data.trust_tier,
        status: parsed.data.status,
        reputationScore: parsed.data.reputation_score,
        defaultAction: parsed.data.default_action,
        defaultScopeRoutes: parsed.data.default_scope_routes,
        defaultScopeRedirectPath: parsed.data.default_scope_redirect_path,
        notes: parsed.data.notes,
        lastReviewedAt: parsed.data.last_reviewed_at,
        expiresAt,
        updatedBy: operator.actorId
      },
      now
    );
    return reply.code(existing === undefined ? 201 : 200).send({ operator: serializeOperatorReputation(reputation) });
  });
}
