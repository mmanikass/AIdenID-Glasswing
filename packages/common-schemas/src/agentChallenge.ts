import { z } from "zod";

import { CASCADE_TRACE_LAYERS, CascadeTraceLayerSchema } from "./cascadeTrace.js";
import { ActorClassSchema, DecisionActionSchema, ReasonCodeSchema } from "./enums.js";

export const AGENT_IDENTITY_CHALLENGE_VERSION = "2026-05-18";
export const AGENT_IDENTITY_CHALLENGE_TYPE = "aidenid.agent_identity_challenge";

export const AGENT_IDENTITY_CHALLENGE_FIELDS = [
  "purpose",
  "requested_access_duration_seconds",
  "provider_name",
  "contact_url",
  "cascade_attestation"
] as const;

export const AGENT_IDENTITY_CHALLENGE_OPTIONAL_FIELDS = [
  "operator_actor_id",
  "purpose_rationale",
  "jwks_url",
  "delegation_authority_jwk_thumbprint_sha256",
  "declaration"
] as const;

export const AGENT_IDENTITY_PURPOSES = [
  "research",
  "commercial_crawl",
  "ai_training",
  "monitoring_uptime",
  "accessibility",
  "archival",
  "search_indexing",
  "competitive_intelligence",
  "fraud_detection",
  "other"
] as const;

export const AgentIdentityChallengeFieldSchema = z.enum(AGENT_IDENTITY_CHALLENGE_FIELDS);
export type AgentIdentityChallengeField = z.infer<typeof AgentIdentityChallengeFieldSchema>;
export const AgentIdentityChallengeOptionalFieldSchema = z.enum(AGENT_IDENTITY_CHALLENGE_OPTIONAL_FIELDS);
export type AgentIdentityChallengeOptionalField = z.infer<typeof AgentIdentityChallengeOptionalFieldSchema>;
export const AgentIdentityPurposeSchema = z.enum(AGENT_IDENTITY_PURPOSES);
export type AgentIdentityPurpose = z.infer<typeof AgentIdentityPurposeSchema>;

export const SiteIdSchema = z.string().max(128).regex(/^sit_[A-Za-z0-9_-]+$/);
export const RequestIdSchema = z.string().trim().min(1).max(128);
export const OperatorActorIdSchema = z.string().trim().min(1).max(128).regex(/^[A-Za-z0-9:_-]+$/);
export const ProviderNameSchema = z.string().trim().min(1).max(128);
export const Sha256HexSchema = z.string().regex(/^[a-f0-9]{64}$/);
export const ChallengeUrlSchema = z.string().max(2048).url();
export const AGENT_IDENTITY_ACCESS_DURATION_SECONDS_MIN = 60;
export const AGENT_IDENTITY_ACCESS_DURATION_SECONDS_MAX = 7_776_000;
export const RequestedAccessDurationSecondsSchema = z
  .number()
  .int()
  .min(AGENT_IDENTITY_ACCESS_DURATION_SECONDS_MIN)
  .max(AGENT_IDENTITY_ACCESS_DURATION_SECONDS_MAX);

export const AgentIdentityChallengeCascadePromptSchema = z
  .object({
    ordinal: z.number().int().min(1).max(4),
    layer: CascadeTraceLayerSchema,
    title: z.string().trim().min(1).max(64),
    prompt: z.string().trim().min(1).max(256)
  })
  .strict();

export type AgentIdentityChallengeCascadePrompt = z.infer<typeof AgentIdentityChallengeCascadePromptSchema>;

function enforceCascadeOrder(
  prompts: readonly { readonly ordinal: number; readonly layer: string }[],
  ctx: z.RefinementCtx
): void {
  for (let index = 0; index < CASCADE_TRACE_LAYERS.length; index += 1) {
    const prompt = prompts[index];
    if (prompt?.ordinal !== index + 1) {
      ctx.addIssue({
        code: "custom",
        message: `cascade challenge ordinal ${index + 1} is required at position ${index}`,
        path: [index, "ordinal"]
      });
    }
    if (prompt?.layer !== CASCADE_TRACE_LAYERS[index]) {
      ctx.addIssue({
        code: "custom",
        message: `cascade challenge layer ${CASCADE_TRACE_LAYERS[index]} is required at position ${index}`,
        path: [index, "layer"]
      });
    }
  }
}

export const AgentIdentityChallengeCascadePromptsSchema = z
  .array(AgentIdentityChallengeCascadePromptSchema)
  .length(CASCADE_TRACE_LAYERS.length)
  .superRefine(enforceCascadeOrder);

export const AgentIdentityChallengeSchema = z
  .object({
    type: z.literal(AGENT_IDENTITY_CHALLENGE_TYPE),
    version: z.literal(AGENT_IDENTITY_CHALLENGE_VERSION),
    site_id: SiteIdSchema,
    request_id: RequestIdSchema,
    actor_class: ActorClassSchema,
    decision: DecisionActionSchema,
    reason_codes: z.array(ReasonCodeSchema).min(1).max(16),
    challenge_url: ChallengeUrlSchema,
    register_url: ChallengeUrlSchema,
    docs_url: ChallengeUrlSchema,
    required_fields: z.array(AgentIdentityChallengeFieldSchema).length(AGENT_IDENTITY_CHALLENGE_FIELDS.length),
    optional_fields: z.array(AgentIdentityChallengeOptionalFieldSchema).max(AGENT_IDENTITY_CHALLENGE_OPTIONAL_FIELDS.length),
    allowed_purposes: z.array(AgentIdentityPurposeSchema).length(AGENT_IDENTITY_PURPOSES.length),
    cascade_layers: AgentIdentityChallengeCascadePromptsSchema,
    submit: z
      .object({
        method: z.literal("POST"),
        content_type: z.literal("application/json"),
        headers: z.array(z.string().trim().min(1).max(64)).max(8)
      })
      .strict()
  })
  .strict();

export type AgentIdentityChallenge = z.infer<typeof AgentIdentityChallengeSchema>;

export const AgentIdentitySubmissionStatusSchema = z.enum(["pending_review", "approved", "rejected"]);
export type AgentIdentitySubmissionStatus = z.infer<typeof AgentIdentitySubmissionStatusSchema>;

export const AgentIdentityChallengeReviewActionSchema = z.enum(["approve", "reject"]);
export type AgentIdentityChallengeReviewAction = z.infer<typeof AgentIdentityChallengeReviewActionSchema>;

export const AgentIdentityChallengeReviewTrustTierSchema = z.enum(["restricted", "trusted"]);
export type AgentIdentityChallengeReviewTrustTier = z.infer<typeof AgentIdentityChallengeReviewTrustTierSchema>;

export const AgentIdentityChallengeReviewOperatorStatusSchema = z.enum(["active", "watchlist"]);
export type AgentIdentityChallengeReviewOperatorStatus = z.infer<typeof AgentIdentityChallengeReviewOperatorStatusSchema>;

export const OperatorDefaultScopeRouteSchema = z
  .string()
  .trim()
  .min(1)
  .max(256)
  .regex(/^\/[A-Za-z0-9._~!$&'()*+,;=:@/%-]*(?:\/\*)?$/);
export type OperatorDefaultScopeRoute = z.infer<typeof OperatorDefaultScopeRouteSchema>;

export const OperatorDefaultScopeRoutesSchema = z.array(OperatorDefaultScopeRouteSchema).max(32);
export type OperatorDefaultScopeRoutes = z.infer<typeof OperatorDefaultScopeRoutesSchema>;

export const OperatorDefaultScopeRedirectPathSchema = z
  .string()
  .trim()
  .min(1)
  .max(256)
  .regex(/^\/[A-Za-z0-9._~!$&'()*+,;=:@/%-]*$/);
export type OperatorDefaultScopeRedirectPath = z.infer<typeof OperatorDefaultScopeRedirectPathSchema>;

export const AgentIdentityChallengeSubmissionSchema = z
  .object({
    site_id: SiteIdSchema,
    request_id: RequestIdSchema.optional(),
    purpose: AgentIdentityPurposeSchema,
    requested_access_duration_seconds: RequestedAccessDurationSecondsSchema,
    purpose_rationale: z.string().trim().min(1).max(1024).optional(),
    provider_name: ProviderNameSchema,
    operator_actor_id: OperatorActorIdSchema.optional(),
    contact_url: ChallengeUrlSchema,
    jwks_url: ChallengeUrlSchema.optional(),
    delegation_authority_jwk_thumbprint_sha256: Sha256HexSchema.optional(),
    cascade_attestation: z
      .array(CascadeTraceLayerSchema)
      .length(CASCADE_TRACE_LAYERS.length)
      .superRefine((layers, ctx) => enforceCascadeOrder(layers.map((layer, index) => ({ ordinal: index + 1, layer })), ctx)),
    declaration: z.string().trim().min(1).max(1024).optional()
  })
  .strict()
  .superRefine((submission, ctx) => {
    if (submission.purpose === "other" && submission.purpose_rationale === undefined) {
      ctx.addIssue({
        code: "custom",
        message: "purpose_rationale is required when purpose is other",
        path: ["purpose_rationale"]
      });
    }
  });

export type AgentIdentityChallengeSubmission = z.infer<typeof AgentIdentityChallengeSubmissionSchema>;

export const AgentIdentityChallengeReviewSchema = z
  .object({
    action: AgentIdentityChallengeReviewActionSchema,
    operator_actor_id: OperatorActorIdSchema.optional(),
    trust_tier: AgentIdentityChallengeReviewTrustTierSchema.default("restricted"),
    operator_status: AgentIdentityChallengeReviewOperatorStatusSchema.default("active"),
    reputation_score: z.number().int().min(0).max(100).optional(),
    default_action: DecisionActionSchema.default("allow"),
    default_scope_routes: OperatorDefaultScopeRoutesSchema.default([]),
    default_scope_redirect_path: OperatorDefaultScopeRedirectPathSchema.optional(),
    approval_expires_at: z.string().datetime().optional(),
    display_name: ProviderNameSchema.optional(),
    notes: z.string().trim().min(1).max(1024).optional(),
    review_reason: z.string().trim().min(1).max(1024).optional()
  })
  .strict()
  .superRefine((review, ctx) => {
    if (review.action === "reject" && review.review_reason === undefined) {
      ctx.addIssue({
        code: "custom",
        message: "review_reason is required when rejecting an identity challenge submission",
        path: ["review_reason"]
      });
    }
  });

export type AgentIdentityChallengeReview = z.infer<typeof AgentIdentityChallengeReviewSchema>;

export const DEFAULT_AGENT_IDENTITY_CHALLENGE_CASCADE_PROMPTS: readonly AgentIdentityChallengeCascadePrompt[] = [
  {
    ordinal: 1,
    layer: "crypto_identity",
    title: "Crypto Identity",
    prompt: "Bind this request to a registered issuer with HTTP Message Signatures, DPoP, and a proof-bound session."
  },
  {
    ordinal: 2,
    layer: "delegation_authorization",
    title: "Delegation Authorization",
    prompt: "Show the delegated grant or session scope that authorizes this action for the target site."
  },
  {
    ordinal: 3,
    layer: "fingerprint_sidecar",
    title: "Fingerprint Sidecar",
    prompt: "Expect server-visible automation evidence to be evaluated without relying on client-side scripts."
  },
  {
    ordinal: 4,
    layer: "operator_reputation",
    title: "Operator Reputation",
    prompt: "Identify the operator or provider so the site can apply its allowlist, watchlist, or suspension policy."
  }
];

export interface BuildAgentIdentityChallengeInput {
  readonly siteId: string;
  readonly requestId: string;
  readonly actorClass: z.infer<typeof ActorClassSchema>;
  readonly decision: z.infer<typeof DecisionActionSchema>;
  readonly reasonCodes: readonly z.infer<typeof ReasonCodeSchema>[];
  readonly challengeUrl: string;
  readonly registerUrl: string;
  readonly docsUrl: string;
}

export function buildAgentIdentityChallenge(input: BuildAgentIdentityChallengeInput): AgentIdentityChallenge {
  return AgentIdentityChallengeSchema.parse({
    type: AGENT_IDENTITY_CHALLENGE_TYPE,
    version: AGENT_IDENTITY_CHALLENGE_VERSION,
    site_id: input.siteId,
    request_id: input.requestId,
    actor_class: input.actorClass,
    decision: input.decision,
    reason_codes: input.reasonCodes.slice(0, 16),
    challenge_url: input.challengeUrl,
    register_url: input.registerUrl,
    docs_url: input.docsUrl,
    required_fields: [...AGENT_IDENTITY_CHALLENGE_FIELDS],
    optional_fields: [...AGENT_IDENTITY_CHALLENGE_OPTIONAL_FIELDS],
    allowed_purposes: [...AGENT_IDENTITY_PURPOSES],
    cascade_layers: DEFAULT_AGENT_IDENTITY_CHALLENGE_CASCADE_PROMPTS,
    submit: {
      method: "POST",
      content_type: "application/json",
      headers: ["X-AIdenID-Purpose", "Signature", "Signature-Input", "DPoP"]
    }
  });
}
