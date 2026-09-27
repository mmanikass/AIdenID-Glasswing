import { makeOutboxEvent } from "@aidenid/eventing";

import { prefixedId } from "../ids.js";
import type { ControlPlaneServices, PersonaAuditController, PersonaAuditEnqueueInput, PersonaAuditJob, PersonaAuditNarrative } from "../types.js";

const PERSONA_TOOL = "create-sentinelayer" as const;
const PERSONA_PACK = "aidenid-post-incident-auditor" as const;
const DEFAULT_SUSPICION_THRESHOLD = 0.85;

function inputRefs(input: PersonaAuditEnqueueInput): readonly string[] {
  return [
    ...(input.siteId === undefined ? [] : [`decision_stream:${input.siteId}`]),
    ...(input.chainId === undefined ? [] : [`chain:${input.chainId}`]),
    ...(input.requestId === undefined ? [] : [`request:${input.requestId}`]),
    ...(input.revocationEpoch === undefined ? [] : [`revocation_epoch:${input.revocationEpoch}`])
  ];
}

function narrativeFor(input: PersonaAuditEnqueueInput, refs: readonly string[]): PersonaAuditNarrative {
  if (input.triggerType === "revocation_epoch") {
    return {
      title: "Revocation root-cause audit queued",
      summary: `Revocation epoch ${input.revocationEpoch ?? "n/a"} for ${input.chainId ?? "unknown chain"} requires post-incident narrative review.`,
      evidenceRefs: refs,
      recommendedActions: ["review-delegation-chain", "summarize-revocation-reason", "verify-downstream-session-denials"]
    };
  }

  return {
    title: "Suspicion spike audit queued",
    summary: `Suspicion score ${input.suspicionScore?.toFixed(2) ?? "n/a"} breached the audit threshold for ${input.requestId ?? "unknown request"}.`,
    evidenceRefs: refs,
    recommendedActions: ["review-recent-route-decisions", "compare-actor-classification-evidence", "recommend-policy-or-registry-followup"]
  };
}

export class InMemoryPersonaAuditController implements PersonaAuditController {
  readonly suspicionThreshold: number;
  readonly #jobs: PersonaAuditJob[] = [];

  constructor(suspicionThreshold = DEFAULT_SUSPICION_THRESHOLD) {
    this.suspicionThreshold = suspicionThreshold;
  }

  enqueue(input: PersonaAuditEnqueueInput): PersonaAuditJob {
    const refs = inputRefs(input);
    const job: PersonaAuditJob = {
      id: prefixedId("aud"),
      triggerType: input.triggerType,
      status: "queued",
      severity: input.triggerType === "revocation_epoch" ? "high" : "medium",
      tool: PERSONA_TOOL,
      personaPack: PERSONA_PACK,
      ...(input.siteId === undefined ? {} : { siteId: input.siteId }),
      ...(input.chainId === undefined ? {} : { chainId: input.chainId }),
      ...(input.requestId === undefined ? {} : { requestId: input.requestId }),
      ...(input.actorClass === undefined ? {} : { actorClass: input.actorClass }),
      ...(input.decision === undefined ? {} : { decision: input.decision }),
      ...(input.suspicionScore === undefined ? {} : { suspicionScore: input.suspicionScore }),
      ...(input.revocationEpoch === undefined ? {} : { revocationEpoch: input.revocationEpoch }),
      ...(input.reason === undefined ? {} : { reason: input.reason }),
      ...(input.actorId === undefined ? {} : { actorId: input.actorId }),
      inputRefs: refs,
      narrative: narrativeFor(input, refs),
      createdAt: input.occurredAt ?? new Date().toISOString()
    };
    this.#jobs.unshift(job);
    return job;
  }

  list(siteId?: string | undefined, limit = 100): readonly PersonaAuditJob[] {
    const filtered = siteId === undefined ? this.#jobs : this.#jobs.filter((job) => job.siteId === siteId);
    return filtered.slice(0, limit);
  }
}

export async function enqueuePersonaAudit(services: ControlPlaneServices, input: PersonaAuditEnqueueInput): Promise<PersonaAuditJob> {
  const job = services.personaAudit.enqueue(input);
  await services.outbox.publish(
    makeOutboxEvent(prefixedId("evt"), "PERSONA_AUDIT_REQUESTED", {
      job_id: job.id,
      trigger_type: job.triggerType,
      severity: job.severity,
      tool: job.tool,
      persona_pack: job.personaPack,
      input_refs: job.inputRefs,
      no_token_passthrough: true,
      oauth_resource: "sentinelayer://persona-audit",
      audience: "create-sentinelayer"
    })
  );
  return job;
}
