import { z } from "zod";

import { CascadeTraceSchema } from "./cascadeTrace.js";
import { ActorClassSchema, DecisionActionSchema, ReasonCodeSchema } from "./enums.js";

const IsoDateTimeSchema = z.string().datetime();
const LlmBrandSchema = z.string().trim().min(1).max(32).regex(/^[a-z][a-z0-9_-]{0,31}$/);
const PurposeSlugSchema = z.string().trim().min(1).max(64).regex(/^[a-z][a-z0-9_-]{0,63}$/);

export const EvidenceBlobReferenceSchema = z
  .object({
    uri: z.string().url(),
    sha256: z.string().regex(/^[a-f0-9]{64}$/),
    byte_size: z.number().int().nonnegative()
  })
  .strict();

export type EvidenceBlobReference = z.infer<typeof EvidenceBlobReferenceSchema>;

export const DecisionEventSchema = z
  .object({
    id: z.string().regex(/^dec_[A-Za-z0-9_-]+$/),
    request_id: z.string().min(1),
    site_id: z.string().regex(/^sit_[A-Za-z0-9_-]+$/),
    occurred_at: IsoDateTimeSchema,
    actor_class: ActorClassSchema,
    decision: DecisionActionSchema,
    reason_codes: z.array(ReasonCodeSchema).min(1),
    route_template: z.string().regex(/^\//),
    method: z.enum(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]),
    path_hash_sha256: z.string().regex(/^[a-f0-9]{64}$/),
    latency_us: z.number().int().nonnegative(),
    llm_brand: LlmBrandSchema.optional(),
    purpose: PurposeSlugSchema.optional(),
    cascade_trace: CascadeTraceSchema.optional(),
    evidence: EvidenceBlobReferenceSchema.optional()
  })
  .strict();

export type DecisionEvent = z.infer<typeof DecisionEventSchema>;

export const TransparencyEventTypeSchema = z.enum([
  "ISSUER_KEY_REGISTERED",
  "ISSUER_KEY_ROTATED",
  "POLICY_BUNDLE_VERSION",
  "REVOCATION_EPOCH_BUMP",
  "GRANT_ISSUED_HASH",
  "SESSION_ISSUED_HASH",
  "EVIDENCE_BUNDLE_ROOT",
  "SAMPLED_DECISION_BATCH_ROOT"
]);

export type TransparencyEventType = z.infer<typeof TransparencyEventTypeSchema>;
