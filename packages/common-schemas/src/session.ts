import { z } from "zod";

const NumericDateSchema = z.number().int().positive();
const NonEmptyStringSchema = z.string().trim().min(1);
const LlmBrandSchema = z.string().trim().min(1).max(32).regex(/^[a-z][a-z0-9_-]{0,31}$/);
const UrlOrUrnSchema = z.union([z.string().url(), z.string().regex(/^urn:[a-z0-9][a-z0-9-]{0,31}:.+/i)]);

export const ConfirmationKeySchema = z
  .object({
    jkt: z.string().trim().min(16)
  })
  .strict();

export const SessionTokenClaimsSchema = z
  .object({
    iss: z.string().url(),
    sub: NonEmptyStringSchema,
    aud: NonEmptyStringSchema,
    resource: UrlOrUrnSchema,
    site_id: z.string().regex(/^sit_[A-Za-z0-9_-]+$/),
    grant_id: z.string().regex(/^grt_[A-Za-z0-9_-]+$/),
    chain_id: z.string().regex(/^chn_[A-Za-z0-9_-]+$/),
    permissions: z.array(NonEmptyStringSchema).min(1),
    llm_brand: LlmBrandSchema.optional(),
    cnf: ConfirmationKeySchema,
    revocation_epoch: z.number().int().nonnegative(),
    iat: NumericDateSchema,
    nbf: NumericDateSchema.optional(),
    exp: NumericDateSchema
  })
  .strict()
  .superRefine((claims, ctx) => {
    if (claims.exp <= claims.iat) {
      ctx.addIssue({
        code: "custom",
        message: "session token exp must be greater than iat",
        path: ["exp"]
      });
    }
    if (claims.nbf !== undefined && claims.nbf > claims.exp) {
      ctx.addIssue({
        code: "custom",
        message: "session token nbf must not be after exp",
        path: ["nbf"]
      });
    }
  });

export type SessionTokenClaims = z.infer<typeof SessionTokenClaimsSchema>;

export const SessionExchangeRequestSchema = z
  .object({
    grant_id: z.string().regex(/^grt_[A-Za-z0-9_-]+$/),
    audience: NonEmptyStringSchema,
    resource: UrlOrUrnSchema,
    proof_jkt: z.string().trim().min(16),
    requested_permissions: z.array(NonEmptyStringSchema).min(1).max(64),
    llm_brand: LlmBrandSchema.optional()
  })
  .strict();

export type SessionExchangeRequest = z.infer<typeof SessionExchangeRequestSchema>;

export const SessionExchangeResponseSchema = z
  .object({
    access_token: NonEmptyStringSchema,
    token_type: z.literal("DPoP"),
    expires_in: z.number().int().positive(),
    session_id: z.string().regex(/^ses_[A-Za-z0-9_-]+$/),
    revocation_epoch: z.number().int().nonnegative()
  })
  .strict();

export type SessionExchangeResponse = z.infer<typeof SessionExchangeResponseSchema>;
