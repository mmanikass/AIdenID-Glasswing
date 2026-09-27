import type { FastifyInstance } from "fastify";
import { z } from "zod";

import { requireOperatorRole } from "../plugins/operatorAuth.js";
import type { ControlPlaneServices } from "../types.js";

const CreateTargetRequestSchema = z
  .object({
    tenant_id: z.string().regex(/^ten_[A-Za-z0-9_-]+$/).default("ten_demo"),
    site_id: z.string().regex(/^sit_[A-Za-z0-9_-]+$/),
    name: z.string().trim().min(1),
    origin: z.string().url()
  })
  .strict();

export async function registerTargetRoutes(app: FastifyInstance, services: ControlPlaneServices): Promise<void> {
  // Admin-gated: registering a target claims a site_id, and the store accepts a DUPLICATE
  // site_id, so ungated an anonymous caller could register an existing tenant's site under
  // an origin it controls. It is also step 1 of the targets -> grants -> sessions/exchange
  // chain. The route-access manifest has always classified this operator:admin; the handler
  // is catching up to that contract rather than introducing a new policy.
  app.post("/v1/targets", async (request, reply) => {
    const operator = requireOperatorRole(request, reply, "admin");
    if (operator === undefined) {
      return;
    }
    const parsed = CreateTargetRequestSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.code(400).send({ error: "invalid_target", details: parsed.error.issues });
    }
    const quota = await services.store.getTenantQuota(parsed.data.tenant_id);
    if (quota !== undefined && (await services.store.countTargets(parsed.data.tenant_id)) >= quota.targetLimit) {
      return reply.code(429).send({ error: "tenant_target_quota_exceeded", target_limit: quota.targetLimit });
    }
    const target = await services.store.createTarget({
      tenantId: parsed.data.tenant_id,
      siteId: parsed.data.site_id,
      name: parsed.data.name,
      origin: parsed.data.origin
    });
    return reply.code(201).send({
      id: target.id,
      tenant_id: target.tenantId,
      site_id: target.siteId,
      name: target.name,
      origin: target.origin,
      created_at: target.createdAt
    });
  });
}
