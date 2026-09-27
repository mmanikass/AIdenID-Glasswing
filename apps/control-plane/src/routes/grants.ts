import { makeOutboxEvent } from "@aidenid/eventing";
import type { FastifyInstance } from "fastify";
import { z } from "zod";

import { prefixedId } from "../ids.js";
import { requireOperatorRole } from "../plugins/operatorAuth.js";
import type { ControlPlaneServices } from "../types.js";

const CreateGrantRequestSchema = z
  .object({
    target_id: z.string().regex(/^tgt_[A-Za-z0-9_-]+$/),
    subject: z.string().trim().min(1),
    resource: z.string().url().optional(),
    permissions: z.array(z.string().trim().min(1)).min(1).max(64),
    expires_in_seconds: z.number().int().positive().max(86_400).default(3_600)
  })
  .strict();

export async function registerGrantRoutes(app: FastifyInstance, services: ControlPlaneServices): Promise<void> {
  // Admin-gated: a grant mints delegation authority. Ungated, an anonymous caller could author
  // the very authority the session exchange later verifies.
  app.post("/v1/grants", async (request, reply) => {
    const operator = requireOperatorRole(request, reply, "admin");
    if (operator === undefined) {
      return;
    }
    const parsed = CreateGrantRequestSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.code(400).send({ error: "invalid_grant", details: parsed.error.issues });
    }
    const target = await services.store.getTarget(parsed.data.target_id);
    if (target === undefined) {
      return reply.code(404).send({ error: "target_not_found" });
    }
    const expiresAt = new Date(Date.now() + parsed.data.expires_in_seconds * 1000).toISOString();
    const grant = await services.store.createGrant({
      targetId: target.id,
      siteId: target.siteId,
      subject: parsed.data.subject,
      resource: parsed.data.resource ?? target.origin,
      permissions: parsed.data.permissions,
      expiresAt,
      // Bound from the AUTHENTICATED principal, never from the body. Unlike revoke and the
      // kill switch — which accept an actor_id and reject a disagreeing one — the request
      // schema here is .strict() and has no actor field at all, so a caller cannot even
      // propose an issuer. Attribution is not a claim the caller gets to make.
      issuerActorId: operator.actorId
    });
    await services.outbox.publish(
      makeOutboxEvent(prefixedId("evt"), "GRANT_ISSUED_HASH", {
        grant_id: grant.id,
        chain_id: grant.chainId,
        site_id: grant.siteId,
        // The transparency record of a grant issuance should say who issued it; an
        // unattributable authority event is weaker evidence than an attributable one.
        issuer_actor_id: grant.issuerActorId
      })
    );

    return reply.code(201).send({
      id: grant.id,
      target_id: grant.targetId,
      site_id: grant.siteId,
      subject: grant.subject,
      chain_id: grant.chainId,
      resource: grant.resource,
      permissions: grant.permissions,
      expires_at: grant.expiresAt,
      created_at: grant.createdAt,
      issuer_actor_id: grant.issuerActorId
    });
  });
}
