import type { FastifyInstance } from "fastify";
import { buildMcpProtectedResourceMetadata, MCP_PROTECTED_RESOURCE_WELL_KNOWN_PATH } from "@aidenid/common-schemas";
import { createSignedWebhookEnvelope } from "@aidenid/eventing";
import { z } from "zod";

import {
  BILLING_EXPORT_PROVIDERS,
  billingExportDeliveryReceiptPayloadSha256,
  buildBillingExportRecord,
  buildBillingPeriodRollup,
  buildCounterfactualSummary,
  buildPriceRequiredBillingSummary,
  buildUsageMeter,
  defaultTenantPricingPlan,
  sha256Hex
} from "../services/adoption.js";
import { requireOperatorRole } from "../plugins/operatorAuth.js";
import {
  WebhookSecretResolutionError,
  type BillingExportRecord,
  type BillingPeriodRollupRecord,
  type ControlPlaneServices,
  type TenantPricingPlanRecord,
  type TenantQuotaRecord,
  type WebhookEndpointRecord
} from "../types.js";

const SiteQuerySchema = z
  .object({
    site_id: z.string().regex(/^sit_[A-Za-z0-9_-]+$/).optional(),
    tenant_id: z.string().regex(/^ten_[A-Za-z0-9_-]+$/).optional(),
    limit: z.coerce.number().int().positive().max(10_000).default(5_000)
  })
  .strict();

const CounterfactualQuerySchema = z
  .object({
    site_id: z.string().regex(/^sit_[A-Za-z0-9_-]+$/),
    route_template: z.string().regex(/^\//).optional(),
    limit: z.coerce.number().int().positive().max(10_000).default(5_000)
  })
  .strict();

const TenantQuotaBodySchema = z
  .object({
    monthly_decision_limit: z.number().int().positive(),
    stored_decision_limit: z.number().int().positive(),
    target_limit: z.number().int().positive()
  })
  .strict();

const TenantPricingPlanBodySchema = z
  .object({
    plan_tier: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9_-]{1,63}$/),
    unit_price_usd: z.number().nonnegative(),
    included_monthly_cleared_decisions: z.number().int().nonnegative(),
    effective_from: z.string().datetime().optional()
  })
  .strict();

const BillingPeriodSchema = z
  .object({
    tenant_id: z.string().regex(/^ten_[A-Za-z0-9_-]+$/),
    period_start: z.string().datetime(),
    period_end: z.string().datetime(),
    limit: z.coerce.number().int().positive().max(50_000).default(50_000)
  })
  .strict();

const BillingExportSchema = z
  .object({
    tenant_id: z.string().regex(/^ten_[A-Za-z0-9_-]+$/),
    period_start: z.string().datetime(),
    period_end: z.string().datetime(),
    provider: z.enum(BILLING_EXPORT_PROVIDERS),
    destination_ref: z.string().min(1).max(256)
  })
  .strict();

const BillingExportListSchema = z
  .object({
    tenant_id: z.string().regex(/^ten_[A-Za-z0-9_-]+$/).optional(),
    provider: z.enum(BILLING_EXPORT_PROVIDERS).optional(),
    status: z.enum(["prepared", "delivered"]).optional(),
    period_start: z.string().datetime().optional(),
    period_end: z.string().datetime().optional(),
    limit: z.coerce.number().int().positive().max(1_000).default(100)
  })
  .strict();

const BillingExportParamsSchema = z
  .object({
    exportId: z.string().regex(/^bex_[a-f0-9]{32}$/)
  })
  .strict();

const BillingExportDeliveryReceiptSchema = z
  .object({
    provider_receipt_id: z.string().min(1).max(256),
    provider_receipt_status: z.string().min(1).max(128),
    provider_response: z.record(z.string(), z.unknown()).optional(),
    delivered_at: z.string().datetime().optional()
  })
  .strict();

const PrivacyEraseSchema = z
  .object({
    site_id: z.string().regex(/^sit_[A-Za-z0-9_-]+$/),
    subject_handle: z.string().min(8).max(256),
    reason: z.string().min(1).max(256),
    actor_id: z.string().min(1).max(128)
  })
  .strict();

function isHttpsUrl(value: string): boolean {
  try {
    return new URL(value).protocol === "https:";
  } catch {
    return false;
  }
}

const WebhookEndpointSchema = z
  .object({
    tenant_id: z.string().regex(/^ten_[A-Za-z0-9_-]+$/),
    url: z.string().url().refine(isHttpsUrl, { message: "webhook endpoint URL must use https" }),
    event_types: z.array(z.string().min(1)).min(1).max(32),
    signing_secret_ref: z.string().min(3).max(256)
  })
  .strict();

const WebhookSignPreviewSchema = z
  .object({
    endpoint_id: z.string().regex(/^whk_[A-Za-z0-9_-]+$/),
    payload: z.record(z.string(), z.unknown())
  })
  .strict();

const McpProtectedResourceQuerySchema = z
  .object({
    resource: z.string().url().optional()
  })
  .strict();

const VERIFIER_SDK_TARBALLS = [
  "aidenid-verifier-node-0.0.0.tgz"
] as const;

const VERIFIER_SDK_INSTALL_COMMAND = `pnpm add ${VERIFIER_SDK_TARBALLS.map((tarball) => `./${tarball}`).join(" ")}`;

function serializeQuota(quota: TenantQuotaRecord) {
  return {
    tenant_id: quota.tenantId,
    monthly_decision_limit: quota.monthlyDecisionLimit,
    stored_decision_limit: quota.storedDecisionLimit,
    target_limit: quota.targetLimit,
    updated_at: quota.updatedAt
  };
}

function serializePricingPlan(plan: TenantPricingPlanRecord) {
  return {
    tenant_id: plan.tenantId,
    plan_tier: plan.planTier,
    currency: plan.currency,
    unit_price_usd: plan.unitPriceUsd,
    included_monthly_cleared_decisions: plan.includedMonthlyClearedDecisions,
    effective_from: plan.effectiveFrom,
    updated_at: plan.updatedAt
  };
}

function serializeBillingRollup(rollup: BillingPeriodRollupRecord) {
  return {
    id: rollup.id,
    tenant_id: rollup.tenantId,
    period_start: rollup.periodStart,
    period_end: rollup.periodEnd,
    plan_tier: rollup.planTier,
    currency: rollup.currency,
    unit_price_usd: rollup.unitPriceUsd,
    included_cleared_decisions: rollup.includedClearedDecisions,
    cleared_decision_count: rollup.clearedDecisionCount,
    billable_cleared_decision_count: rollup.billableClearedDecisionCount,
    overage_cleared_decision_count: rollup.overageClearedDecisionCount,
    estimated_cost_usd: rollup.estimatedCostUsd,
    price_required_gross_usd: rollup.priceRequiredGrossUsd,
    invoice_line_item_id: rollup.invoiceLineItemId,
    export_idempotency_key: rollup.exportIdempotencyKey,
    generated_at: rollup.generatedAt
  };
}

function serializeBillingExport(record: BillingExportRecord) {
  return {
    id: record.id,
    rollup_id: record.rollupId,
    tenant_id: record.tenantId,
    period_start: record.periodStart,
    period_end: record.periodEnd,
    provider: record.provider,
    destination_ref: record.destinationRef,
    idempotency_key: record.idempotencyKey,
    payload_sha256: record.payloadSha256,
    payload: record.payload,
    status: record.status,
    created_at: record.createdAt,
    updated_at: record.updatedAt,
    delivered_at: record.deliveredAt,
    provider_receipt_id: record.providerReceiptId,
    provider_receipt_status: record.providerReceiptStatus,
    provider_receipt_payload_sha256: record.providerReceiptPayloadSha256,
    provider_receipt_recorded_at: record.providerReceiptRecordedAt
  };
}

function serializeWebhook(endpoint: WebhookEndpointRecord) {
  return {
    id: endpoint.id,
    tenant_id: endpoint.tenantId,
    url: endpoint.url,
    event_types: endpoint.eventTypes,
    signing_secret_ref: endpoint.signingSecretRef,
    created_at: endpoint.createdAt,
    updated_at: endpoint.updatedAt
  };
}

function serializeUsage(input: ReturnType<typeof buildUsageMeter>) {
  return {
    site_id: input.siteId,
    tenant_id: input.tenantId,
    decision_count: input.decisionCount,
    cleared_decision_count: input.clearedDecisionCount,
    billable_cleared_decision_count: input.billableClearedDecisionCount,
    included_cleared_decision_count: input.includedClearedDecisionCount,
    overage_cleared_decision_count: input.overageClearedDecisionCount,
    pricing_plan_tier: input.pricingPlanTier,
    billing_currency: input.billingCurrency,
    billing_unit_price_usd: input.billingUnitPriceUsd,
    estimated_cost_usd: input.estimatedCostUsd,
    price_required_gross_usd: input.priceRequiredGrossUsd,
    p95_latency_us: input.p95LatencyUs,
    quota: input.quota === undefined ? undefined : serializeQuota(input.quota),
    quota_remaining: input.quotaRemaining,
    quota_status: input.quotaStatus
  };
}

function mcpProtectedResourceMetadata(services: ControlPlaneServices, resource?: string) {
  return buildMcpProtectedResourceMetadata({
    resource: resource ?? services.issuer,
    authorizationServers: [services.issuer]
  });
}

function serializePriceRequiredBilling(input: ReturnType<typeof buildPriceRequiredBillingSummary>) {
  return {
    site_id: input.siteId,
    tenant_id: input.tenantId,
    decision_count: input.decisionCount,
    priced_decision_count: input.pricedDecisionCount,
    estimated_gross_usd: input.estimatedGrossUsd,
    by_issuer: input.byIssuer.map((issuer) => ({
      issuer: issuer.issuer,
      decision_count: issuer.decisionCount,
      policy_decision_count: issuer.policyDecisionCount,
      operator_decision_count: issuer.operatorDecisionCount,
      priced_decision_count: issuer.pricedDecisionCount,
      estimated_gross_usd: issuer.estimatedGrossUsd,
      routes: issuer.routes.map((route) => ({
        route_template: route.routeTemplate,
        decision_count: route.decisionCount,
        estimated_gross_usd: route.estimatedGrossUsd
      }))
    }))
  };
}

export async function registerAdoptionRoutes(app: FastifyInstance, services: ControlPlaneServices): Promise<void> {
  app.get("/v1/usage/meter", async (request, reply) => {
    // Operator-gated: tenant-scoped usage metering.
    const operator = requireOperatorRole(request, reply, "decision_search");
    if (operator === undefined) {
      return;
    }
    const parsed = SiteQuerySchema.safeParse(request.query);
    if (!parsed.success) {
      return reply.code(400).send({ error: "invalid_usage_query", details: parsed.error.issues });
    }
    const decisions = await services.store.listDecisions(parsed.data.site_id, parsed.data.limit);
    const quota = parsed.data.tenant_id === undefined ? undefined : await services.store.getTenantQuota(parsed.data.tenant_id);
    const pricingPlan =
      parsed.data.tenant_id === undefined ? undefined : await services.store.getTenantPricingPlan(parsed.data.tenant_id);
    return {
      usage: serializeUsage(
        buildUsageMeter({
          siteId: parsed.data.site_id,
          tenantId: parsed.data.tenant_id,
          decisions,
          pricingPlan,
          quota
        })
      )
    };
  });

  app.get("/v1/usage/price-required", async (request, reply) => {
    // Operator-gated: tenant-scoped billing summary.
    const operator = requireOperatorRole(request, reply, "decision_search");
    if (operator === undefined) {
      return;
    }
    const parsed = SiteQuerySchema.safeParse(request.query);
    if (!parsed.success) {
      return reply.code(400).send({ error: "invalid_price_required_usage_query", details: parsed.error.issues });
    }
    const decisions = await services.store.listDecisions(parsed.data.site_id, parsed.data.limit);
    return {
      price_required_billing: serializePriceRequiredBilling(
        buildPriceRequiredBillingSummary({ siteId: parsed.data.site_id, tenantId: parsed.data.tenant_id, decisions })
      )
    };
  });

  app.get("/v1/counterfactuals/enforcement", async (request, reply) => {
    // Operator-gated: discloses what enforcement WOULD have done per route — an attacker-useful
    // map of where policy is permissive.
    const operator = requireOperatorRole(request, reply, "decision_search");
    if (operator === undefined) {
      return;
    }
    const parsed = CounterfactualQuerySchema.safeParse(request.query);
    if (!parsed.success) {
      return reply.code(400).send({ error: "invalid_counterfactual_query", details: parsed.error.issues });
    }
    const decisions = await services.store.listDecisions(parsed.data.site_id, parsed.data.limit);
    const summary = buildCounterfactualSummary({
      siteId: parsed.data.site_id,
      routeTemplate: parsed.data.route_template,
      decisions
    });
    return {
      counterfactual: {
        site_id: summary.siteId,
        route_template: summary.routeTemplate,
        sample_count: summary.sampleCount,
        currently_blocked: summary.currentlyBlocked,
        would_block_if_enforced: summary.wouldBlockIfEnforced,
        newly_blocked_if_enforced: summary.newlyBlockedIfEnforced,
        block_rate: summary.blockRate,
        by_actor_class: summary.byActorClass
      }
    };
  });

  app.put("/v1/tenants/:tenantId/quota", async (request, reply) => {
    // Admin-gated: the tenant is named in the path, so ungated this let anyone rewrite any
    // tenant's decision/storage/target limits — an enforcement control, not a preference.
    const operator = requireOperatorRole(request, reply, "admin");
    if (operator === undefined) {
      return;
    }
    const tenantId = String((request.params as { tenantId?: string }).tenantId ?? "");
    if (!/^ten_[A-Za-z0-9_-]+$/.test(tenantId)) {
      return reply.code(400).send({ error: "invalid_tenant_id" });
    }
    const parsed = TenantQuotaBodySchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.code(400).send({ error: "invalid_tenant_quota", details: parsed.error.issues });
    }
    const quota = await services.store.upsertTenantQuota(
      {
        tenantId,
        monthlyDecisionLimit: parsed.data.monthly_decision_limit,
        storedDecisionLimit: parsed.data.stored_decision_limit,
        targetLimit: parsed.data.target_limit
      },
      new Date().toISOString()
    );
    return { quota: serializeQuota(quota), target_count: await services.store.countTargets(tenantId) };
  });

  app.get("/v1/tenants/:tenantId/quota", async (request, reply) => {
    // Operator-gated: tenant enforcement limits, tenant named in the path.
    const operator = requireOperatorRole(request, reply, "decision_search");
    if (operator === undefined) {
      return;
    }
    const tenantId = String((request.params as { tenantId?: string }).tenantId ?? "");
    if (!/^ten_[A-Za-z0-9_-]+$/.test(tenantId)) {
      return reply.code(400).send({ error: "invalid_tenant_id" });
    }
    const quota = await services.store.getTenantQuota(tenantId);
    if (quota === undefined) {
      return reply.code(404).send({ error: "tenant_quota_not_found" });
    }
    return { quota: serializeQuota(quota), target_count: await services.store.countTargets(tenantId) };
  });

  app.put("/v1/tenants/:tenantId/pricing-plan", async (request, reply) => {
    // Admin-gated: billing configuration for a path-named tenant. Ungated, anyone could rewrite
    // any tenant's pricing plan.
    const operator = requireOperatorRole(request, reply, "admin");
    if (operator === undefined) {
      return;
    }
    const tenantId = String((request.params as { tenantId?: string }).tenantId ?? "");
    if (!/^ten_[A-Za-z0-9_-]+$/.test(tenantId)) {
      return reply.code(400).send({ error: "invalid_tenant_id" });
    }
    const parsed = TenantPricingPlanBodySchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.code(400).send({ error: "invalid_tenant_pricing_plan", details: parsed.error.issues });
    }
    const now = new Date().toISOString();
    const plan = await services.store.upsertTenantPricingPlan(
      {
        tenantId,
        planTier: parsed.data.plan_tier,
        currency: "USD",
        unitPriceUsd: parsed.data.unit_price_usd,
        includedMonthlyClearedDecisions: parsed.data.included_monthly_cleared_decisions,
        effectiveFrom: parsed.data.effective_from ?? now
      },
      now
    );
    return { pricing_plan: serializePricingPlan(plan) };
  });

  app.get("/v1/tenants/:tenantId/pricing-plan", async (request, reply) => {
    // Operator-gated: tenant billing configuration.
    const operator = requireOperatorRole(request, reply, "decision_search");
    if (operator === undefined) {
      return;
    }
    const tenantId = String((request.params as { tenantId?: string }).tenantId ?? "");
    if (!/^ten_[A-Za-z0-9_-]+$/.test(tenantId)) {
      return reply.code(400).send({ error: "invalid_tenant_id" });
    }
    const plan = await services.store.getTenantPricingPlan(tenantId);
    if (plan === undefined) {
      return { pricing_plan: serializePricingPlan(defaultTenantPricingPlan(tenantId)) };
    }
    return { pricing_plan: serializePricingPlan(plan) };
  });

  app.post("/v1/billing/rollups", async (request, reply) => {
    // Admin-gated: writes a billing period rollup for a caller-named tenant.
    const operator = requireOperatorRole(request, reply, "admin");
    if (operator === undefined) {
      return;
    }
    const parsed = BillingPeriodSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.code(400).send({ error: "invalid_billing_rollup_request", details: parsed.error.issues });
    }
    if (Date.parse(parsed.data.period_start) >= Date.parse(parsed.data.period_end)) {
      return reply.code(400).send({ error: "invalid_billing_period" });
    }
    if (Date.parse(parsed.data.period_end) > Date.now()) {
      return reply.code(400).send({ error: "billing_period_not_closed" });
    }
    const decisions = await services.store.listDecisionsForTenantPeriod(
      parsed.data.tenant_id,
      parsed.data.period_start,
      parsed.data.period_end,
      parsed.data.limit
    );
    const pricingPlan = await services.store.getTenantPricingPlan(parsed.data.tenant_id);
    const rollup = await services.store.upsertBillingPeriodRollup(
      buildBillingPeriodRollup({
        tenantId: parsed.data.tenant_id,
        periodStart: parsed.data.period_start,
        periodEnd: parsed.data.period_end,
        decisions,
        pricingPlan
      }),
      new Date().toISOString()
    );
    return reply.code(201).send({ billing_rollup: serializeBillingRollup(rollup) });
  });

  app.get("/v1/billing/rollups", async (request, reply) => {
    // Operator-gated: tenant billing records.
    const operator = requireOperatorRole(request, reply, "decision_search");
    if (operator === undefined) {
      return;
    }
    const parsed = BillingPeriodSchema.safeParse(request.query);
    if (!parsed.success) {
      return reply.code(400).send({ error: "invalid_billing_rollup_query", details: parsed.error.issues });
    }
    const rollup = await services.store.getBillingPeriodRollup(
      parsed.data.tenant_id,
      parsed.data.period_start,
      parsed.data.period_end
    );
    if (rollup === undefined) {
      return reply.code(404).send({ error: "billing_rollup_not_found" });
    }
    return { billing_rollup: serializeBillingRollup(rollup) };
  });

  app.post("/v1/billing/exports", async (request, reply) => {
    // Admin-gated: creates a billing export record for a caller-named tenant.
    const operator = requireOperatorRole(request, reply, "admin");
    if (operator === undefined) {
      return;
    }
    const parsed = BillingExportSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.code(400).send({ error: "invalid_billing_export_request", details: parsed.error.issues });
    }
    if (Date.parse(parsed.data.period_start) >= Date.parse(parsed.data.period_end)) {
      return reply.code(400).send({ error: "invalid_billing_period" });
    }
    const rollup = await services.store.getBillingPeriodRollup(
      parsed.data.tenant_id,
      parsed.data.period_start,
      parsed.data.period_end
    );
    if (rollup === undefined) {
      return reply.code(404).send({ error: "billing_rollup_not_found" });
    }
    const exportRecord = await services.store.upsertBillingExport(
      buildBillingExportRecord({
        rollup,
        provider: parsed.data.provider,
        destinationRef: parsed.data.destination_ref
      }),
      new Date().toISOString()
    );
    return reply.code(201).send({ billing_export: serializeBillingExport(exportRecord) });
  });

  app.get("/v1/billing/exports", async (request, reply) => {
    // Operator-gated: tenant billing exports incl. destination refs.
    const operator = requireOperatorRole(request, reply, "decision_search");
    if (operator === undefined) {
      return;
    }
    const parsed = BillingExportListSchema.safeParse(request.query);
    if (!parsed.success) {
      return reply.code(400).send({ error: "invalid_billing_export_query", details: parsed.error.issues });
    }
    return {
      billing_exports: (
        await services.store.listBillingExports({
          tenantId: parsed.data.tenant_id,
          provider: parsed.data.provider,
          status: parsed.data.status,
          periodStart: parsed.data.period_start,
          periodEnd: parsed.data.period_end,
          limit: parsed.data.limit
        })
      ).map(serializeBillingExport)
    };
  });

  app.post("/v1/billing/exports/:exportId/delivery-receipt", async (request, reply) => {
    // Admin-gated: attests delivery of a billing export. Ungated, delivery of another tenant's
    // export could be attested by anyone.
    const operator = requireOperatorRole(request, reply, "admin");
    if (operator === undefined) {
      return;
    }
    const params = BillingExportParamsSchema.safeParse(request.params);
    if (!params.success) {
      return reply.code(400).send({ error: "invalid_billing_export_id", details: params.error.issues });
    }
    const parsed = BillingExportDeliveryReceiptSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.code(400).send({ error: "invalid_billing_export_delivery_receipt", details: parsed.error.issues });
    }
    const now = new Date().toISOString();
    const deliveredAt = parsed.data.delivered_at ?? now;
    const exportRecord = await services.store.recordBillingExportDeliveryReceipt(
      {
        id: params.data.exportId,
        providerReceiptId: parsed.data.provider_receipt_id,
        providerReceiptStatus: parsed.data.provider_receipt_status,
        providerReceiptPayloadSha256: billingExportDeliveryReceiptPayloadSha256({
          providerReceiptId: parsed.data.provider_receipt_id,
          providerReceiptStatus: parsed.data.provider_receipt_status,
          providerResponse: parsed.data.provider_response
        }),
        deliveredAt
      },
      now
    );
    if (exportRecord === undefined) {
      return reply.code(404).send({ error: "billing_export_not_found" });
    }
    return { billing_export: serializeBillingExport(exportRecord) };
  });

  app.post("/v1/privacy/erase", async (request, reply) => {
    // Admin-gated: this destroys decision records for a caller-named site/subject. Ungated, any
    // anonymous caller could erase another tenant's decisions and — because the audit record's
    // actor also came from the body — choose the name the erasure log recorded as responsible.
    const operator = requireOperatorRole(request, reply, "admin");
    if (operator === undefined) {
      return;
    }
    const parsed = PrivacyEraseSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.code(400).send({ error: "invalid_privacy_erase_request", details: parsed.error.issues });
    }
    // The erasure record is the audit trail for a destructive operation, so the actor it names is
    // bound to the authenticated principal rather than to the body. Gating alone would still let an
    // authenticated caller stamp someone else's name on an erasure they performed. A body actor_id
    // that disagrees is rejected rather than silently discarded, so the caller never believes it
    // attributed the erasure to a party it did not.
    if (parsed.data.actor_id !== operator.actorId) {
      return reply.code(400).send({
        error: "actor_id_mismatch",
        expected_actor_id: operator.actorId
      });
    }
    const erasedDecisionCount = await services.store.eraseSubjectDecisions(parsed.data.site_id, parsed.data.subject_handle);
    const erasure = await services.store.recordPrivacyErasure(
      {
        siteId: parsed.data.site_id,
        subjectHandle: parsed.data.subject_handle,
        reason: parsed.data.reason,
        actorId: operator.actorId,
        erasedDecisionCount
      },
      new Date().toISOString()
    );
    return reply.code(202).send({
      erasure: {
        id: erasure.id,
        site_id: erasure.siteId,
        subject_handle: erasure.subjectHandle,
        erased_decision_count: erasure.erasedDecisionCount,
        occurred_at: erasure.occurredAt
      }
    });
  });

  app.get("/v1/privacy/erasures", async (request, reply) => {
    // Operator-gated: the erasure log names subjects and actors — GDPR-relevant evidence.
    const operator = requireOperatorRole(request, reply, "decision_search");
    if (operator === undefined) {
      return;
    }
    const parsed = SiteQuerySchema.safeParse(request.query);
    if (!parsed.success) {
      return reply.code(400).send({ error: "invalid_privacy_erasure_query", details: parsed.error.issues });
    }
    return {
      erasures: (await services.store.listPrivacyErasures(parsed.data.site_id, parsed.data.limit)).map((erasure) => ({
        id: erasure.id,
        site_id: erasure.siteId,
        subject_handle: erasure.subjectHandle,
        reason: erasure.reason,
        actor_id: erasure.actorId,
        erased_decision_count: erasure.erasedDecisionCount,
        occurred_at: erasure.occurredAt
      }))
    };
  });

  app.post("/v1/webhooks/endpoints", async (request, reply) => {
    // Admin-gated: tenant_id and url are both caller-supplied and this upserts, so an anonymous
    // caller could point any tenant's webhook delivery at a URL they control — including
    // overwriting an existing endpoint, which redirects a live event stream rather than adding one.
    const operator = requireOperatorRole(request, reply, "admin");
    if (operator === undefined) {
      return;
    }
    const parsed = WebhookEndpointSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.code(400).send({ error: "invalid_webhook_endpoint", details: parsed.error.issues });
    }
    const endpoint = await services.store.upsertWebhookEndpoint(
      {
        tenantId: parsed.data.tenant_id,
        url: parsed.data.url,
        eventTypes: parsed.data.event_types,
        signingSecretRef: parsed.data.signing_secret_ref
      },
      new Date().toISOString()
    );
    return reply.code(201).send({
      endpoint: serializeWebhook(endpoint),
      signature: {
        algorithm: "HMAC-SHA256",
        signing_input: "x-aidenid-webhook-timestamp + '.' + raw_body",
        header: "x-aidenid-webhook-signature"
      }
    });
  });

  app.get("/v1/webhooks/endpoints", async (request, reply) => {
    // Admin-gated: serializeWebhook emits signing_secret_ref alongside the delivery url, so this
    // listed every tenant's endpoints and their secret references to anonymous callers.
    const operator = requireOperatorRole(request, reply, "admin");
    if (operator === undefined) {
      return;
    }
    const parsed = SiteQuerySchema.safeParse(request.query);
    if (!parsed.success) {
      return reply.code(400).send({ error: "invalid_webhook_endpoint_query", details: parsed.error.issues });
    }
    return { endpoints: (await services.store.listWebhookEndpoints(parsed.data.tenant_id)).map(serializeWebhook) };
  });

  app.post("/v1/webhooks/signature-preview", async (request, reply) => {
    // Admin-gated, and this is NOT a read: it resolves the endpoint's real signing secret and
    // returns the HMAC headers for a caller-supplied payload. Ungated it was a signing oracle —
    // anyone could mint a valid signature for any tenant's webhook receiver.
    const operator = requireOperatorRole(request, reply, "admin");
    if (operator === undefined) {
      return;
    }
    const parsed = WebhookSignPreviewSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.code(400).send({ error: "invalid_webhook_signature_preview", details: parsed.error.issues });
    }
    const endpoint = (await services.store
      .listWebhookEndpoints())
      .find((candidate) => candidate.id === parsed.data.endpoint_id);
    if (endpoint === undefined) {
      return reply.code(404).send({ error: "webhook_endpoint_not_found" });
    }
    let signingSecret: string | Uint8Array;
    try {
      signingSecret = await services.webhookSecrets.resolve(endpoint.signingSecretRef);
    } catch (error) {
      if (error instanceof WebhookSecretResolutionError) {
        return reply.code(424).send({ error: "webhook_signing_secret_unresolved", signing_secret_ref: endpoint.signingSecretRef });
      }
      throw error;
    }
    const envelope = createSignedWebhookEnvelope({
      endpoint,
      payload: parsed.data.payload,
      signingSecret,
      timestamp: "2026-04-25T00:00:00.000Z"
    });
    return {
      payload_sha256: sha256Hex(envelope.payload),
      headers: envelope.headers
    };
  });

  app.get("/v1/onboarding/target-plan", async (request, reply) => {
    // Operator-gated: takes tenant_id and site_id and echoes a provisioning plan for them.
    const operator = requireOperatorRole(request, reply, "decision_search");
    if (operator === undefined) {
      return;
    }
    const parsed = z
      .object({
        tenant_id: z.string().regex(/^ten_[A-Za-z0-9_-]+$/),
        site_id: z.string().regex(/^sit_[A-Za-z0-9_-]+$/),
        name: z.string().min(1),
        origin: z.string().url()
      })
      .strict()
      .safeParse(request.query);
    if (!parsed.success) {
      return reply.code(400).send({ error: "invalid_onboarding_query", details: parsed.error.issues });
    }
    return {
      plan: {
        target_payload: {
          tenant_id: parsed.data.tenant_id,
          site_id: parsed.data.site_id,
          name: parsed.data.name,
          origin: parsed.data.origin
        },
        sdk_install: VERIFIER_SDK_INSTALL_COMMAND,
        sdk: {
          package_name: "@aidenid/verifier-node",
          delivery: "ci_tarball_bundle",
          artifact_name_pattern: "aidenid-verifier-node-sdk-<source_sha>",
          manifest: "aidenid-verifier-node-sdk-manifest.json",
          checksum_file: "aidenid-verifier-node-sdk.SHA256SUMS",
          verify_command: "node verify-verifier-sdk-pack.mjs aidenid-verifier-node-sdk-manifest.json",
          tarballs: VERIFIER_SDK_TARBALLS,
          bundled_internal_dependencies: [
            "@aidenid/common-schemas",
            "@aidenid/policy-engine",
            "@aidenid/crypto",
            "@aidenid/fingerprint-sidecar"
          ],
          install_command: VERIFIER_SDK_INSTALL_COMMAND,
          public_registry_available: false,
          public_registry_command_when_published: "pnpm add @aidenid/verifier-node"
        },
        env: {
          AIDENID_SITE_ID: parsed.data.site_id,
          AIDENID_MODE: "observe",
          AIDENID_REQUIRE_DISTRIBUTED_STORES: "true"
        },
        next_steps: ["POST /v1/targets", "install verifier middleware", "send observe-mode traffic", "review counterfactuals"]
      }
    };
  });

  app.get(MCP_PROTECTED_RESOURCE_WELL_KNOWN_PATH, async () => mcpProtectedResourceMetadata(services));

  app.get("/v1/mcp/protected-resource-metadata", async (request, reply) => {
    const parsed = McpProtectedResourceQuerySchema.safeParse(request.query);
    if (!parsed.success) {
      return reply.code(400).send({ error: "invalid_mcp_resource_metadata_query", details: parsed.error.issues });
    }
    try {
      return mcpProtectedResourceMetadata(services, parsed.data.resource);
    } catch (error) {
      if (error instanceof Error && /must use https/.test(error.message)) {
        return reply.code(400).send({ error: "invalid_mcp_resource_metadata_query", message: error.message });
      }
      throw error;
    }
  });

  app.get("/v1/mcp/front-door/roadmap", async () => ({
    roadmap: {
      product: "AidenID-as-MCP-authorization-server",
      hot_path: false,
      protected_resource_metadata: MCP_PROTECTED_RESOURCE_WELL_KNOWN_PATH,
      standards: ["RFC 9728", "RFC 8414", "RFC 8693", "RFC 9449"],
      phases: [
        "resource-bound MCP access tokens",
        "audience and resource validation shared with session-token verifier",
        "no-token-passthrough MCP proxy adapter",
        "persona-audit sidecar handoff for revoked or suspicious agents"
      ]
    }
  }));
}
