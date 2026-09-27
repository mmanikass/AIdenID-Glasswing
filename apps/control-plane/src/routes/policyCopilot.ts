import {
  ACTOR_CLASSES,
  DECISION_ACTIONS,
  suggestPolicyDiffs,
  type PolicyCopilotSuggestion
} from "@aidenid/policy-engine";
import type { FastifyInstance } from "fastify";
import { z } from "zod";

const PolicyCopilotDecisionSampleSchema = z
  .object({
    route_template: z.string().regex(/^\//),
    method: z.string().min(1),
    actor_class: z.enum(ACTOR_CLASSES),
    decision: z.enum(DECISION_ACTIONS),
    reason_codes: z.array(z.string().min(1)).optional(),
    occurred_at: z.string().datetime().optional()
  })
  .strict();

const PolicyCopilotSuggestionRequestSchema = z
  .object({
    policy_yaml: z.string().min(1),
    decision_samples: z.array(PolicyCopilotDecisionSampleSchema).default([]),
    prompt: z.string().min(1).optional(),
    input_refs: z.array(z.string().min(1)).default([]),
    suspicious_automation_threshold: z.number().int().positive().optional(),
    max_suggestions: z.number().int().positive().max(20).optional()
  })
  .strict();

function serializeSuggestion(suggestion: PolicyCopilotSuggestion) {
  return {
    id: suggestion.id,
    label: suggestion.label,
    approval_status: suggestion.approvalStatus,
    risk_level: suggestion.riskLevel,
    rationale: suggestion.rationale,
    metadata: {
      model: suggestion.metadata.model,
      tool: suggestion.metadata.tool,
      prompt_digest_sha256: suggestion.metadata.promptDigestSha256,
      input_refs: suggestion.metadata.inputRefs,
      generated_at: suggestion.metadata.generatedAt
    },
    policy_sha256: suggestion.policySha256,
    proposed_policy_sha256: suggestion.proposedPolicySha256,
    proposed_policy_yaml: suggestion.proposedPolicyYaml,
    output_diff: suggestion.outputDiff
  };
}

export async function registerPolicyCopilotRoutes(app: FastifyInstance): Promise<void> {
  app.post("/v1/policy-copilot/suggestions", async (request, reply) => {
    const parsed = PolicyCopilotSuggestionRequestSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.code(400).send({ error: "invalid_policy_copilot_request", details: parsed.error.issues });
    }

    try {
      const suggestions = suggestPolicyDiffs({
        policyYaml: parsed.data.policy_yaml,
        decisionSamples: parsed.data.decision_samples.map((sample) => ({
          routeTemplate: sample.route_template,
          method: sample.method,
          actorClass: sample.actor_class,
          decision: sample.decision,
          reasonCodes: sample.reason_codes,
          occurredAt: sample.occurred_at
        })),
        prompt: parsed.data.prompt,
        inputRefs: parsed.data.input_refs,
        suspiciousAutomationThreshold: parsed.data.suspicious_automation_threshold,
        maxSuggestions: parsed.data.max_suggestions
      });

      return reply.code(200).send({
        suggestions: suggestions.map(serializeSuggestion),
        apply_policy: false
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return reply.code(400).send({ error: "invalid_policy_copilot_policy", message });
    }
  });
}
