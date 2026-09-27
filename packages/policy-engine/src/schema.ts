import { z } from "zod";

import { ACTOR_CLASSES, DECISION_ACTIONS, VERIFIER_MODES, type ActorClass, type ActorRoutePolicy, type CompiledPolicyBundle } from "./types.js";

const PathTemplateSchema = z.string().regex(/^\/(?:[A-Za-z0-9._~!$&'()*+,;=:@%-]+|:[A-Za-z][A-Za-z0-9_]*|\*{1,2}|\/)*$/);
const MethodSchema = z
  .string()
  .min(1)
  .transform((method) => method.toUpperCase());
const PurposeSlugSchema = z.string().regex(/^[a-z][a-z0-9_-]{0,63}$/);

export const RatePolicyInputSchema = z
  .object({
    capacity: z.number().int().positive(),
    refill_per_sec: z.number().positive(),
    cost: z.number().positive().default(1)
  })
  .strict();

export const PriceMetadataInputSchema = z
  .object({
    unit: z.string().min(1),
    currency: z.literal("USD"),
    amount_micros: z.number().int().nonnegative()
  })
  .strict();

export const ActorDecisionInputSchema = z
  .object({
    decision: z.union([z.enum(DECISION_ACTIONS), z.null()]).default(null),
    rate: RatePolicyInputSchema.optional(),
    strict: z.boolean().optional(),
    signature_required: z.array(z.string().min(1)).optional(),
    queue_retry_s: z.number().int().positive().optional(),
    retry_after_s: z.number().int().positive().optional(),
    price_usd: z.number().nonnegative().optional(),
    price_metadata: PriceMetadataInputSchema.optional(),
    sandbox_origin: z.string().url().optional()
  })
  .strict()
  .superRefine((value, ctx) => {
    if (value.decision === "price_required" && value.price_usd === undefined && value.price_metadata === undefined) {
      ctx.addIssue({ code: "custom", message: "price_required decisions require price_usd or price_metadata", path: ["price_metadata"] });
    }
    if (value.price_usd !== undefined && value.price_metadata !== undefined) {
      const priceMicros = Math.round(value.price_usd * 1_000_000);
      if (priceMicros !== value.price_metadata.amount_micros) {
        ctx.addIssue({ code: "custom", message: "price_usd must match price_metadata.amount_micros", path: ["price_metadata", "amount_micros"] });
      }
    }
    if (value.decision === "sandbox" && value.sandbox_origin === undefined) {
      ctx.addIssue({ code: "custom", message: "sandbox decisions require sandbox_origin", path: ["sandbox_origin"] });
    }
  });

export const PolicyRouteInputSchema = z
  .object({
    template: PathTemplateSchema,
    method: MethodSchema.default("*"),
    allowed_purposes: z.array(PurposeSlugSchema).min(1).max(32).optional(),
    required_permissions: z.array(z.string().trim().min(1)).min(1).max(64).optional(),
    route_bucket: z.string().min(1).optional(),
    strict: z.boolean().optional(),
    on_degraded: z.enum(["queue", "deny"]).optional(),
    signature_required: z.array(z.string().min(1)).default([]),
    rate: RatePolicyInputSchema.optional(),
    queue_retry_s: z.number().int().positive().optional(),
    retry_after_s: z.number().int().positive().optional(),
    sandbox_origin: z.string().url().optional(),
    per_actor_class: z.partialRecord(z.enum(ACTOR_CLASSES), ActorDecisionInputSchema).default({})
  })
  .strict();

export const PolicyDefaultsInputSchema = z.preprocess(
  (value) => value ?? {},
  z.object({
    strict: z.boolean().default(false),
    on_degraded: z.enum(["queue", "deny"]).default("queue"),
    sandbox_origin: z.string().url().optional(),
    suspicion_threshold: z.number().min(0).max(1).default(0.85),
    rate: RatePolicyInputSchema.default({ capacity: 60, refill_per_sec: 1, cost: 1 })
  })
    .strict()
);

export const PolicyDocumentInputSchema = z
  .object({
    version: z.union([z.string().min(1), z.number().int().positive()]).transform(String),
    site_id: z.string().regex(/^sit_[A-Za-z0-9_-]+$/),
    mode: z.enum(VERIFIER_MODES).default("observe"),
    defaults: PolicyDefaultsInputSchema,
    routes: z.array(PolicyRouteInputSchema).min(1),
    reporting: z.unknown().optional(),
    registry: z.unknown().optional()
  })
  .strict();

export type RatePolicyInput = z.output<typeof RatePolicyInputSchema>;
export type PriceMetadataInput = z.output<typeof PriceMetadataInputSchema>;
export type ActorDecisionInput = z.output<typeof ActorDecisionInputSchema>;
export type PolicyRouteInput = z.output<typeof PolicyRouteInputSchema>;
export type PolicyDocumentInput = z.input<typeof PolicyDocumentInputSchema>;
export type PolicyDocument = z.output<typeof PolicyDocumentInputSchema>;

function compileRate(rate: RatePolicyInput) {
  return {
    capacity: rate.capacity,
    refillPerSec: rate.refill_per_sec,
    cost: rate.cost
  };
}

function stableBucket(method: string, template: string): string {
  return `${method}:${template}`.replace(/[^A-Za-z0-9_.:-]+/g, "_");
}

function priceMetadataFromUsd(priceUsd: number) {
  return {
    unit: "request",
    currency: "USD" as const,
    amountMicros: Math.round(priceUsd * 1_000_000)
  };
}

function compilePriceMetadata(input: PriceMetadataInput | undefined, priceUsd: number | undefined) {
  if (input !== undefined) {
    return {
      unit: input.unit,
      currency: input.currency,
      amountMicros: input.amount_micros
    };
  }
  return priceUsd === undefined ? undefined : priceMetadataFromUsd(priceUsd);
}

export function compilePolicyDocument(input: unknown): CompiledPolicyBundle {
  const parsed = PolicyDocumentInputSchema.parse(input);
  const defaultRate = compileRate(parsed.defaults.rate);
  const defaults = {
    strict: parsed.defaults.strict,
    onDegraded: parsed.defaults.on_degraded,
    ...(parsed.defaults.sandbox_origin === undefined ? {} : { sandboxOrigin: parsed.defaults.sandbox_origin }),
    suspicionThreshold: parsed.defaults.suspicion_threshold,
    rate: defaultRate
  };

  const routes = parsed.routes.map((route, index) => {
    const routeRate = route.rate === undefined ? defaultRate : compileRate(route.rate);
    const strict = route.strict ?? defaults.strict;
    const routeSandboxOrigin = route.sandbox_origin ?? defaults.sandboxOrigin;
    const allowedPurposes = route.allowed_purposes;
    const requiredPermissions = route.required_permissions;
    const signatureRequired = route.signature_required;
    const queueRetrySeconds = route.queue_retry_s ?? 30;
    const retryAfterSeconds = route.retry_after_s ?? queueRetrySeconds;
    const routeBucket = route.route_bucket ?? stableBucket(route.method, route.template);
    const ruleId = `route-${index + 1}:${route.method}:${route.template}`;

    const defaultActorPolicy = {
      actorClass: "*" as const,
      decision: null,
      rate: routeRate,
      strict,
      signatureRequired,
      queueRetrySeconds,
      retryAfterSeconds,
      ...(routeSandboxOrigin === undefined ? {} : { sandboxOrigin: routeSandboxOrigin }),
      ruleId: `${ruleId}:*`
    };

    const perActorClass = new Map<ActorClass, ActorRoutePolicy>();
    for (const actorClass of ACTOR_CLASSES) {
      const actorInput = route.per_actor_class[actorClass];
      if (actorInput === undefined) {
        continue;
      }
      const actorRate = actorInput.rate === undefined ? routeRate : compileRate(actorInput.rate);
      const priceUsd = actorInput.price_usd ?? (actorInput.price_metadata === undefined ? undefined : actorInput.price_metadata.amount_micros / 1_000_000);
      const priceMetadata = compilePriceMetadata(actorInput.price_metadata, priceUsd);
      const actorPolicy = {
        actorClass,
        decision: actorInput.decision,
        rate: actorRate,
        strict: actorInput.strict ?? strict,
        signatureRequired: actorInput.signature_required ?? signatureRequired,
        queueRetrySeconds: actorInput.queue_retry_s ?? queueRetrySeconds,
        retryAfterSeconds: actorInput.retry_after_s ?? retryAfterSeconds,
        ...(priceUsd === undefined ? {} : { priceUsd }),
        ...(priceMetadata === undefined ? {} : { priceMetadata }),
        ...((actorInput.sandbox_origin ?? routeSandboxOrigin) === undefined ? {} : { sandboxOrigin: actorInput.sandbox_origin ?? routeSandboxOrigin }),
        ruleId: `${ruleId}:${actorClass}`
      };
      perActorClass.set(actorClass, actorPolicy);
    }

    return {
      ruleId,
      routeTemplate: route.template,
      method: route.method,
      ...(allowedPurposes === undefined ? {} : { allowedPurposes }),
      ...(requiredPermissions === undefined ? {} : { requiredPermissions }),
      routeBucket,
      mode: parsed.mode,
      strict,
      onDegraded: route.on_degraded ?? defaults.onDegraded,
      signatureRequired,
      rate: routeRate,
      queueRetrySeconds,
      retryAfterSeconds,
      ...(routeSandboxOrigin === undefined ? {} : { sandboxOrigin: routeSandboxOrigin }),
      defaultActorPolicy,
      perActorClass
    };
  });

  return {
    version: parsed.version,
    siteId: parsed.site_id,
    mode: parsed.mode,
    defaults,
    routes
  };
}
