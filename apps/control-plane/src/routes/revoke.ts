import type { FastifyInstance } from "fastify";
import { z } from "zod";

import { operatorCanAccessSite, requireOperatorRole } from "../plugins/operatorAuth.js";
import { revokeChain } from "../services/revocation.js";
import type { ControlPlaneServices } from "../types.js";

const RevokeRequestSchema = z
  .object({
    chain_id: z.string().regex(/^chn_[A-Za-z0-9_-]+$/),
    reason: z.string().trim().min(1),
    actor_id: z.string().trim().min(1)
  })
  .strict();

export async function registerRevokeRoutes(app: FastifyInstance, services: ControlPlaneServices): Promise<void> {
  // Admin-gated: revocation takes a caller-named chain_id, so ungated it was a denial-of-service
  // primitive against any subject in the system.
  app.post("/v1/revoke", async (request, reply) => {
    const operator = requireOperatorRole(request, reply, "admin");
    if (operator === undefined) {
      return;
    }
    const parsed = RevokeRequestSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.code(400).send({ error: "invalid_revocation", details: parsed.error.issues });
    }
    // Bound to the authenticated principal: the revocation record is evidence of who cut a chain
    // off, and a body-supplied actor let that evidence name anyone.
    if (parsed.data.actor_id !== operator.actorId) {
      return reply.code(400).send({ error: "actor_id_mismatch", expected_actor_id: operator.actorId });
    }
    if (operator.sites !== undefined) {
      const grant = await services.store.getGrantByChainId(parsed.data.chain_id);
      if (grant === undefined || !operatorCanAccessSite(operator, grant.siteId)) {
        return reply.code(403).send({ error: "operator_forbidden" });
      }
    }
    const revocation = await revokeChain(services, {
      chainId: parsed.data.chain_id,
      reason: parsed.data.reason,
      actorId: operator.actorId
    });
    return reply.code(202).send({
      id: revocation.id,
      chain_id: revocation.chainId,
      revocation_epoch: revocation.epoch,
      reason: revocation.reason,
      actor_id: revocation.actorId,
      occurred_at: revocation.occurredAt
    });
  });
}
