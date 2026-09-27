import type { FastifyInstance } from "fastify";
import { z } from "zod";

import type { ControlPlaneServices, PersonaAuditJob } from "../types.js";

const PersonaAuditQuerySchema = z
  .object({
    site_id: z.string().regex(/^sit_[A-Za-z0-9_-]+$/).optional(),
    limit: z.coerce.number().int().positive().max(100).default(50)
  })
  .strict();

function serializePersonaAudit(job: PersonaAuditJob) {
  return {
    id: job.id,
    trigger_type: job.triggerType,
    status: job.status,
    severity: job.severity,
    tool: job.tool,
    persona_pack: job.personaPack,
    ...(job.siteId === undefined ? {} : { site_id: job.siteId }),
    ...(job.chainId === undefined ? {} : { chain_id: job.chainId }),
    ...(job.requestId === undefined ? {} : { request_id: job.requestId }),
    ...(job.actorClass === undefined ? {} : { actor_class: job.actorClass }),
    ...(job.decision === undefined ? {} : { decision: job.decision }),
    ...(job.suspicionScore === undefined ? {} : { suspicion_score: job.suspicionScore }),
    ...(job.revocationEpoch === undefined ? {} : { revocation_epoch: job.revocationEpoch }),
    ...(job.reason === undefined ? {} : { reason: job.reason }),
    ...(job.actorId === undefined ? {} : { actor_id: job.actorId }),
    input_refs: job.inputRefs,
    narrative: {
      title: job.narrative.title,
      summary: job.narrative.summary,
      evidence_refs: job.narrative.evidenceRefs,
      recommended_actions: job.narrative.recommendedActions
    },
    created_at: job.createdAt
  };
}

export async function registerPersonaAuditRoutes(app: FastifyInstance, services: ControlPlaneServices): Promise<void> {
  app.get("/v1/persona-audits", async (request, reply) => {
    const parsed = PersonaAuditQuerySchema.safeParse(request.query);
    if (!parsed.success) {
      return reply.code(400).send({ error: "invalid_persona_audit_query", details: parsed.error.issues });
    }

    return {
      incidents: services.personaAudit.list(parsed.data.site_id, parsed.data.limit).map(serializePersonaAudit)
    };
  });
}
