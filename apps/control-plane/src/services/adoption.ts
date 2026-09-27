import { createHash } from "node:crypto";

import { canonicalJson, type JsonValue } from "@aidenid/transparency";

import type {
  BillingExportProvider,
  BillingExportRecord,
  BillingExportStatus,
  BillingPeriodRollupRecord,
  DecisionRecord,
  TenantPricingPlanRecord,
  TenantQuotaRecord
} from "../types.js";

export const CLEARED_DECISION_UNIT_PRICE_USD = 0.00001;
export const DEFAULT_PRICING_PLAN_TIER = "internal-default";
export const BILLING_CURRENCY = "USD" as const;
export const BILLING_EXPORT_PROVIDERS = ["stripe_meter_event", "quickbooks_invoice"] as const;

export interface UsageMeter {
  readonly siteId?: string | undefined;
  readonly tenantId?: string | undefined;
  readonly decisionCount: number;
  readonly clearedDecisionCount: number;
  readonly billableClearedDecisionCount: number;
  readonly includedClearedDecisionCount: number;
  readonly overageClearedDecisionCount: number;
  readonly pricingPlanTier: string;
  readonly billingCurrency: "USD";
  readonly billingUnitPriceUsd: number;
  readonly estimatedCostUsd: number;
  readonly priceRequiredGrossUsd: number;
  readonly p95LatencyUs: number | null;
  readonly quota?: TenantQuotaRecord | undefined;
  readonly quotaRemaining?: number | undefined;
  readonly quotaStatus: "ok" | "warning" | "exceeded";
}

export interface CounterfactualSummary {
  readonly siteId: string;
  readonly routeTemplate?: string | undefined;
  readonly sampleCount: number;
  readonly currentlyBlocked: number;
  readonly wouldBlockIfEnforced: number;
  readonly newlyBlockedIfEnforced: number;
  readonly blockRate: number;
  readonly byActorClass: Readonly<Record<string, number>>;
}

export interface PriceRequiredIssuerAggregate {
  readonly issuer: string;
  readonly decisionCount: number;
  readonly policyDecisionCount: number;
  readonly operatorDecisionCount: number;
  readonly pricedDecisionCount: number;
  readonly estimatedGrossUsd: number;
  readonly routes: readonly {
    readonly routeTemplate: string;
    readonly decisionCount: number;
    readonly estimatedGrossUsd: number;
  }[];
}

export interface PriceRequiredBillingSummary {
  readonly siteId?: string | undefined;
  readonly tenantId?: string | undefined;
  readonly decisionCount: number;
  readonly pricedDecisionCount: number;
  readonly estimatedGrossUsd: number;
  readonly byIssuer: readonly PriceRequiredIssuerAggregate[];
}

function roundUsd(value: number): number {
  return Math.round(value * 1_000_000) / 1_000_000;
}

function jsonValue(value: unknown, path: string): JsonValue {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error(`${path} must be finite`);
    }
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item, index) => jsonValue(item, `${path}[${index}]`));
  }
  if (typeof value === "object") {
    const output: Record<string, JsonValue> = {};
    for (const [key, item] of Object.entries(value)) {
      if (item === undefined) {
        continue;
      }
      output[key] = jsonValue(item, `${path}.${key}`);
    }
    return output;
  }
  throw new Error(`${path} cannot be encoded as canonical JSON`);
}

function jsonObject(value: Readonly<Record<string, unknown>>, path: string): { readonly [key: string]: JsonValue } {
  const converted = jsonValue(value, path);
  if (converted === null || typeof converted !== "object" || Array.isArray(converted)) {
    throw new Error(`${path} must be a JSON object`);
  }
  return converted as { readonly [key: string]: JsonValue };
}

function canonicalPayloadSha256(payload: Readonly<Record<string, unknown>>): string {
  return sha256Hex(canonicalJson(jsonObject(payload, "billing_export.payload")));
}

export function billingExportDeliveryReceiptPayloadSha256(input: {
  readonly providerReceiptId: string;
  readonly providerReceiptStatus: string;
  readonly providerResponse?: Readonly<Record<string, unknown>> | undefined;
}): string {
  return sha256Hex(
    canonicalJson(
      jsonObject(
        {
          version: "aidenid.billing_export.delivery_receipt.v1",
          provider_receipt_id: input.providerReceiptId,
          provider_receipt_status: input.providerReceiptStatus,
          provider_response: input.providerResponse ?? null
        },
        "billing_export.delivery_receipt"
      )
    )
  );
}

function p95(values: readonly number[]): number | null {
  const sorted = values.filter((value) => Number.isFinite(value) && value >= 0).sort((left, right) => left - right);
  if (sorted.length === 0) {
    return null;
  }
  return sorted[Math.min(sorted.length - 1, Math.ceil(sorted.length * 0.95) - 1)] ?? null;
}

function nonAllow(decision: string): boolean {
  return decision !== "allow";
}

function isPriceRequiredDecision(decision: DecisionRecord): boolean {
  return decision.decision === "price_required" || decision.operatorAction === "price_required";
}

function effectiveDecision(decision: DecisionRecord): string {
  return decision.operatorActionEffectiveDecision ?? decision.decision;
}

export function isBillableClearedDecision(decision: DecisionRecord): boolean {
  return effectiveDecision(decision) !== "deny";
}

function scopeDecisions(input: {
  readonly decisions: readonly DecisionRecord[];
  readonly siteId?: string | undefined;
  readonly tenantId?: string | undefined;
}): readonly DecisionRecord[] {
  return input.decisions.filter((decision) => {
    if (input.siteId !== undefined && decision.siteId !== input.siteId) {
      return false;
    }
    if (input.tenantId !== undefined && decision.tenantId !== input.tenantId) {
      return false;
    }
    return true;
  });
}

function periodDecisions(input: {
  readonly decisions: readonly DecisionRecord[];
  readonly periodStart: string;
  readonly periodEnd: string;
}): readonly DecisionRecord[] {
  return input.decisions.filter((decision) => decision.occurredAt >= input.periodStart && decision.occurredAt < input.periodEnd);
}

export function defaultTenantPricingPlan(tenantId?: string | undefined, effectiveFrom = "1970-01-01T00:00:00.000Z"): TenantPricingPlanRecord {
  return {
    tenantId: tenantId ?? "ten_unscoped",
    planTier: DEFAULT_PRICING_PLAN_TIER,
    currency: BILLING_CURRENCY,
    unitPriceUsd: CLEARED_DECISION_UNIT_PRICE_USD,
    includedMonthlyClearedDecisions: 0,
    effectiveFrom,
    updatedAt: effectiveFrom
  };
}

function priceRequiredGrossUsd(decisions: readonly DecisionRecord[]): number {
  return roundUsd(decisions.filter(isPriceRequiredDecision).reduce((sum, decision) => sum + (decision.priceUsd ?? 0), 0));
}

export function buildUsageMeter(input: {
  readonly siteId?: string | undefined;
  readonly tenantId?: string | undefined;
  readonly decisions: readonly DecisionRecord[];
  readonly pricingPlan?: TenantPricingPlanRecord | undefined;
  readonly quota?: TenantQuotaRecord | undefined;
}): UsageMeter {
  const decisions = scopeDecisions(input);
  const pricingPlan = input.pricingPlan ?? defaultTenantPricingPlan(input.tenantId);
  const clearedDecisionCount = decisions.filter(isBillableClearedDecision).length;
  const includedClearedDecisionCount = Math.min(clearedDecisionCount, pricingPlan.includedMonthlyClearedDecisions);
  const overageClearedDecisionCount = Math.max(0, clearedDecisionCount - pricingPlan.includedMonthlyClearedDecisions);
  const p95LatencyUs = p95(decisions.map((decision) => decision.latencyUs ?? Number.NaN));
  const quotaRemaining =
    input.quota === undefined ? undefined : Math.max(0, input.quota.monthlyDecisionLimit - decisions.length);
  const quotaStatus =
    input.quota === undefined || decisions.length < input.quota.monthlyDecisionLimit * 0.8
      ? "ok"
      : decisions.length <= input.quota.monthlyDecisionLimit
        ? "warning"
        : "exceeded";
  return {
    siteId: input.siteId,
    tenantId: input.tenantId,
    decisionCount: decisions.length,
    clearedDecisionCount,
    billableClearedDecisionCount: clearedDecisionCount,
    includedClearedDecisionCount,
    overageClearedDecisionCount,
    pricingPlanTier: pricingPlan.planTier,
    billingCurrency: pricingPlan.currency,
    billingUnitPriceUsd: pricingPlan.unitPriceUsd,
    estimatedCostUsd: roundUsd(overageClearedDecisionCount * pricingPlan.unitPriceUsd),
    priceRequiredGrossUsd: priceRequiredGrossUsd(decisions),
    p95LatencyUs,
    quota: input.quota,
    quotaRemaining,
    quotaStatus
  };
}

export function buildCounterfactualSummary(input: {
  readonly siteId: string;
  readonly routeTemplate?: string | undefined;
  readonly decisions: readonly DecisionRecord[];
}): CounterfactualSummary {
  const scoped = input.routeTemplate === undefined ? input.decisions : input.decisions.filter((item) => item.routeTemplate === input.routeTemplate);
  const byActorClass: Record<string, number> = {};
  for (const decision of scoped) {
    byActorClass[decision.actorClass] = (byActorClass[decision.actorClass] ?? 0) + 1;
  }
  const currentlyBlocked = scoped.filter((decision) => nonAllow(decision.decision)).length;
  const wouldBlockIfEnforced = scoped.filter((decision) => nonAllow(decision.recommendedDecision ?? decision.decision)).length;
  const newlyBlockedIfEnforced = scoped.filter(
    (decision) => decision.decision === "allow" && nonAllow(decision.recommendedDecision ?? decision.decision)
  ).length;
  return {
    siteId: input.siteId,
    routeTemplate: input.routeTemplate,
    sampleCount: scoped.length,
    currentlyBlocked,
    wouldBlockIfEnforced,
    newlyBlockedIfEnforced,
    blockRate: scoped.length === 0 ? 0 : wouldBlockIfEnforced / scoped.length,
    byActorClass
  };
}

export function buildPriceRequiredBillingSummary(input: {
  readonly siteId?: string | undefined;
  readonly tenantId?: string | undefined;
  readonly decisions: readonly DecisionRecord[];
}): PriceRequiredBillingSummary {
  const scoped = scopeDecisions(input).filter(isPriceRequiredDecision);
  const byIssuer = new Map<string, DecisionRecord[]>();
  for (const decision of scoped) {
    const issuer = decision.issuer ?? "unknown_issuer";
    const bucket = byIssuer.get(issuer) ?? [];
    bucket.push(decision);
    byIssuer.set(issuer, bucket);
  }

  const aggregates = [...byIssuer.entries()]
    .map(([issuer, decisions]) => {
      const byRoute = new Map<string, DecisionRecord[]>();
      for (const decision of decisions) {
        const bucket = byRoute.get(decision.routeTemplate) ?? [];
        bucket.push(decision);
        byRoute.set(decision.routeTemplate, bucket);
      }
      const estimatedGrossUsd = roundUsd(decisions.reduce((sum, decision) => sum + (decision.priceUsd ?? 0), 0));
      return {
        issuer,
        decisionCount: decisions.length,
        policyDecisionCount: decisions.filter((decision) => decision.decision === "price_required").length,
        operatorDecisionCount: decisions.filter((decision) => decision.operatorAction === "price_required").length,
        pricedDecisionCount: decisions.filter((decision) => decision.priceUsd !== undefined).length,
        estimatedGrossUsd,
        routes: [...byRoute.entries()]
          .map(([routeTemplate, routeDecisions]) => ({
            routeTemplate,
            decisionCount: routeDecisions.length,
            estimatedGrossUsd: roundUsd(routeDecisions.reduce((sum, decision) => sum + (decision.priceUsd ?? 0), 0))
          }))
          .sort((left, right) => right.estimatedGrossUsd - left.estimatedGrossUsd || right.decisionCount - left.decisionCount)
      };
    })
    .sort((left, right) => right.estimatedGrossUsd - left.estimatedGrossUsd || right.decisionCount - left.decisionCount);

  return {
    siteId: input.siteId,
    tenantId: input.tenantId,
    decisionCount: scoped.length,
    pricedDecisionCount: scoped.filter((decision) => decision.priceUsd !== undefined).length,
    estimatedGrossUsd: roundUsd(scoped.reduce((sum, decision) => sum + (decision.priceUsd ?? 0), 0)),
    byIssuer: aggregates
  };
}

export function billingRollupId(tenantId: string, periodStart: string, periodEnd: string): string {
  return `bil_${sha256Hex(`billing-rollup:v1:${tenantId}:${periodStart}:${periodEnd}`).slice(0, 32)}`;
}

export function invoiceLineItemId(tenantId: string, periodStart: string, periodEnd: string): string {
  return `ili_${sha256Hex(`invoice-line-item:v1:${tenantId}:${periodStart}:${periodEnd}`).slice(0, 32)}`;
}

export function exportIdempotencyKey(input: {
  readonly tenantId: string;
  readonly periodStart: string;
  readonly periodEnd: string;
  readonly clearedDecisionCount: number;
  readonly estimatedCostUsd: number;
}): string {
  return sha256Hex(
    [
      "billing-export:v1",
      input.tenantId,
      input.periodStart,
      input.periodEnd,
      String(input.clearedDecisionCount),
      input.estimatedCostUsd.toFixed(6)
    ].join(":")
  );
}

export function billingExportId(input: {
  readonly rollupId: string;
  readonly provider: BillingExportProvider;
  readonly destinationRef: string;
}): string {
  return `bex_${sha256Hex(["billing-export-record:v1", input.rollupId, input.provider, input.destinationRef].join(":")).slice(0, 32)}`;
}

export function billingExportProviderIdempotencyKey(input: {
  readonly rollup: BillingPeriodRollupRecord;
  readonly provider: BillingExportProvider;
  readonly destinationRef: string;
}): string {
  return sha256Hex(
    [
      "billing-export-provider:v1",
      input.rollup.exportIdempotencyKey,
      input.rollup.id,
      input.provider,
      input.destinationRef
    ].join(":")
  );
}

function periodEndUnixSeconds(periodEnd: string): number {
  const timestampMs = Date.parse(periodEnd);
  if (!Number.isFinite(timestampMs)) {
    throw new Error("billing export period_end is invalid");
  }
  return Math.floor(timestampMs / 1_000);
}

function isoDate(value: string): string {
  const timestampMs = Date.parse(value);
  if (!Number.isFinite(timestampMs)) {
    throw new Error("billing export date is invalid");
  }
  return new Date(timestampMs).toISOString().slice(0, 10);
}

function billingExportMetadata(rollup: BillingPeriodRollupRecord) {
  return {
    rollup_id: rollup.id,
    tenant_id: rollup.tenantId,
    period_start: rollup.periodStart,
    period_end: rollup.periodEnd,
    plan_tier: rollup.planTier,
    currency: rollup.currency,
    billable_cleared_decision_count: rollup.billableClearedDecisionCount,
    overage_cleared_decision_count: rollup.overageClearedDecisionCount,
    estimated_cost_usd: rollup.estimatedCostUsd,
    price_required_gross_usd: rollup.priceRequiredGrossUsd,
    rollup_export_idempotency_key: rollup.exportIdempotencyKey,
    invoice_line_item_id: rollup.invoiceLineItemId
  };
}

export function buildBillingExportPayload(input: {
  readonly rollup: BillingPeriodRollupRecord;
  readonly provider: BillingExportProvider;
  readonly destinationRef: string;
  readonly idempotencyKey: string;
}): Readonly<Record<string, unknown>> {
  const metadata = billingExportMetadata(input.rollup);
  if (input.provider === "stripe_meter_event") {
    return {
      adapter: "stripe_meter_event",
      version: "aidenid.billing_export.v1",
      method: "POST",
      path: "/v1/billing/meter_events",
      idempotency_key: input.idempotencyKey,
      body: {
        event_name: "aidenid_cleared_agent_action",
        identifier: input.idempotencyKey,
        timestamp: periodEndUnixSeconds(input.rollup.periodEnd),
        payload: {
          stripe_customer_id: input.destinationRef,
          value: String(input.rollup.billableClearedDecisionCount)
        }
      },
      metadata
    };
  }

  return {
    adapter: "quickbooks_invoice",
    version: "aidenid.billing_export.v1",
    method: "POST",
    path: "/v3/company/{realmId}/invoice",
    idempotency_key: input.idempotencyKey,
    body: {
      DocNumber: input.rollup.invoiceLineItemId,
      CustomerRef: { value: input.destinationRef },
      TxnDate: isoDate(input.rollup.periodEnd),
      PrivateNote: `AIdenID cleared agent actions ${input.rollup.periodStart} to ${input.rollup.periodEnd}`,
      Line: [
        {
          DetailType: "SalesItemLineDetail",
          Amount: input.rollup.estimatedCostUsd,
          Description: "AIdenID cleared agent action overage",
          SalesItemLineDetail: {
            Qty: input.rollup.overageClearedDecisionCount,
            UnitPrice: input.rollup.unitPriceUsd,
            ItemRef: {
              value: "AIDENID_CLEARED_ACTION",
              name: "AIdenID cleared agent action"
            }
          }
        }
      ]
    },
    metadata
  };
}

export function buildBillingExportRecord(input: {
  readonly rollup: BillingPeriodRollupRecord;
  readonly provider: BillingExportProvider;
  readonly destinationRef: string;
  readonly status?: BillingExportStatus | undefined;
  readonly deliveredAt?: string | undefined;
}): Omit<BillingExportRecord, "createdAt" | "updatedAt"> {
  const idempotencyKey = billingExportProviderIdempotencyKey(input);
  const payload = buildBillingExportPayload({
    rollup: input.rollup,
    provider: input.provider,
    destinationRef: input.destinationRef,
    idempotencyKey
  });
  return {
    id: billingExportId({
      rollupId: input.rollup.id,
      provider: input.provider,
      destinationRef: input.destinationRef
    }),
    rollupId: input.rollup.id,
    tenantId: input.rollup.tenantId,
    periodStart: input.rollup.periodStart,
    periodEnd: input.rollup.periodEnd,
    provider: input.provider,
    destinationRef: input.destinationRef,
    idempotencyKey,
    payloadSha256: canonicalPayloadSha256(payload),
    payload,
    status: input.status ?? "prepared",
    deliveredAt: input.deliveredAt
  };
}

export function buildBillingPeriodRollup(input: {
  readonly tenantId: string;
  readonly periodStart: string;
  readonly periodEnd: string;
  readonly decisions: readonly DecisionRecord[];
  readonly pricingPlan?: TenantPricingPlanRecord | undefined;
}): Omit<BillingPeriodRollupRecord, "id" | "generatedAt"> {
  const pricingPlan = input.pricingPlan ?? defaultTenantPricingPlan(input.tenantId, input.periodStart);
  const scoped = periodDecisions({
    decisions: scopeDecisions({ decisions: input.decisions, tenantId: input.tenantId }),
    periodStart: input.periodStart,
    periodEnd: input.periodEnd
  });
  const usage = buildUsageMeter({
    tenantId: input.tenantId,
    decisions: scoped,
    pricingPlan
  });
  return {
    tenantId: input.tenantId,
    periodStart: input.periodStart,
    periodEnd: input.periodEnd,
    planTier: pricingPlan.planTier,
    currency: pricingPlan.currency,
    unitPriceUsd: pricingPlan.unitPriceUsd,
    includedClearedDecisions: pricingPlan.includedMonthlyClearedDecisions,
    clearedDecisionCount: usage.clearedDecisionCount,
    billableClearedDecisionCount: usage.billableClearedDecisionCount,
    overageClearedDecisionCount: usage.overageClearedDecisionCount,
    estimatedCostUsd: usage.estimatedCostUsd,
    priceRequiredGrossUsd: usage.priceRequiredGrossUsd,
    invoiceLineItemId: invoiceLineItemId(input.tenantId, input.periodStart, input.periodEnd),
    exportIdempotencyKey: exportIdempotencyKey({
      tenantId: input.tenantId,
      periodStart: input.periodStart,
      periodEnd: input.periodEnd,
      clearedDecisionCount: usage.clearedDecisionCount,
      estimatedCostUsd: usage.estimatedCostUsd
    })
  };
}

export function sha256Hex(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}
