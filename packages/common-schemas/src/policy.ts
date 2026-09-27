import { z } from "zod";

import { ActorClassSchema, DecisionActionSchema, ReasonCodeSchema, TofuStateSchema, VerifierModeSchema } from "./enums.js";

const IsoDateTimeSchema = z.string().datetime();
const IdentifierSchema = z.string().regex(/^[A-Za-z0-9_.:-]+$/);
const PathPatternSchema = z.string().regex(/^\/(?:[A-Za-z0-9._~!$&'()*+,;=:@%-]+|\*{1,2}|\/)*$/);
const PurposeSlugSchema = z.string().regex(/^[a-z][a-z0-9_-]{0,63}$/);

export const PriceMetadataSchema = z
  .object({
    unit: z.string().min(1),
    currency: z.literal("USD"),
    amount_micros: z.number().int().nonnegative()
  })
  .strict();

export const DecisionOutcomeSchema = z
  .object({
    decision: DecisionActionSchema,
    reason: ReasonCodeSchema.optional(),
    retry_after_seconds: z.number().int().positive().optional(),
    sandbox_origin: z.string().url().optional(),
    price_metadata: PriceMetadataSchema.optional()
  })
  .strict()
  .superRefine((outcome, ctx) => {
    if ((outcome.decision === "throttle" || outcome.decision === "queue") && outcome.retry_after_seconds === undefined) {
      ctx.addIssue({
        code: "custom",
        message: "throttle and queue outcomes require retry_after_seconds",
        path: ["retry_after_seconds"]
      });
    }
    if (outcome.decision === "sandbox" && outcome.sandbox_origin === undefined) {
      ctx.addIssue({
        code: "custom",
        message: "sandbox outcomes require sandbox_origin",
        path: ["sandbox_origin"]
      });
    }
    if (outcome.decision === "price_required" && outcome.price_metadata === undefined) {
      ctx.addIssue({
        code: "custom",
        message: "price_required outcomes require price_metadata",
        path: ["price_metadata"]
      });
    }
  });

export type DecisionOutcome = z.infer<typeof DecisionOutcomeSchema>;

export const RoutePolicySchema = z
  .object({
    route: PathPatternSchema,
    mode: VerifierModeSchema.default("observe"),
    strict: z.boolean().default(false),
    allowed_purposes: z.array(PurposeSlugSchema).min(1).max(32).optional(),
    required_permissions: z.array(z.string().trim().min(1)).min(1).max(64).optional(),
    default: DecisionOutcomeSchema,
    actors: z.partialRecord(ActorClassSchema, DecisionOutcomeSchema).default({})
  })
  .strict();

export type RoutePolicy = z.infer<typeof RoutePolicySchema>;

export const IssuerKeyLedgerEntrySchema = z
  .object({
    issuer: z.string().url(),
    kid: IdentifierSchema,
    jwk_thumbprint_sha256: z.string().regex(/^[a-f0-9]{64}$/),
    alg: z.enum(["EdDSA", "ES256"]),
    state: TofuStateSchema,
    first_seen_at: IsoDateTimeSchema,
    approved_at: IsoDateTimeSchema.optional(),
    previous_kid: IdentifierSchema.optional(),
    rotation_signed_by_kid: IdentifierSchema.optional(),
    transparency_checkpoint: z.string().min(1).optional()
  })
  .strict();

export type IssuerKeyLedgerEntry = z.infer<typeof IssuerKeyLedgerEntrySchema>;

export const PolicyBundleSchema = z
  .object({
    version: z.string().regex(/^pol_[A-Za-z0-9_-]+$/),
    site_id: z.string().regex(/^sit_[A-Za-z0-9_-]+$/),
    issued_at: IsoDateTimeSchema,
    routes: z.array(RoutePolicySchema).min(1),
    issuer_key_ledger: z.array(IssuerKeyLedgerEntrySchema).default([]),
    revocation_epoch: z.number().int().nonnegative(),
    transparency_log_events: z
      .array(z.enum(["ISSUER_KEY_REGISTERED", "ISSUER_KEY_ROTATED", "POLICY_BUNDLE_VERSION", "REVOCATION_EPOCH_BUMP"]))
      .default([])
  })
  .strict();

export type PolicyBundle = z.infer<typeof PolicyBundleSchema>;
