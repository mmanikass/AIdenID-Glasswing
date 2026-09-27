import { z } from "zod";

/**
 * The only shape a provider answer may take. Anything else is `inconclusive`.
 * There is deliberately no field through which a model could name permissions,
 * resources, or a decision: Jev classifies risk, it does not authorize.
 */
export const JEV_OUTPUT_SCHEMA = z
  .object({
    risk_class: z.enum(["low", "elevated", "high"]),
    confidence: z.number().min(0).max(1),
    evidence_coverage: z.enum(["none", "partial", "full"]),
    rationale: z.string().trim().min(1).max(600)
  })
  .strict();
