import { parsePolicyYaml } from "@aidenid/policy-engine";

import type { DashboardDecisionEvent } from "./dashboardLiveModel.js";

export type {
  ActorClass,
  DashboardCascadeTraceEntry,
  DashboardDecisionEvent,
  DecisionAction,
  OperatorAction,
  ProviderReputationRisk,
  ProviderReputationSummary,
  TrafficClassificationBucket,
  TrafficClassificationBucketKey
} from "./dashboardLiveModel.js";
export { dashboardDecisionEventFromPayload, dashboardStreamErrorFromPayload, filterDecisionEvents, providerReputationFromEvents, trafficClassificationFromEvents } from "./dashboardLiveModel.js";

export interface RouteMetric {
  readonly routeTemplate: string;
  readonly count: number;
  readonly p95LatencyMs: number;
  readonly denyRate: number;
}

export interface CounterfactualImpact {
  readonly routeTemplate: string;
  readonly sampleCount: number;
  readonly wouldBlockIfEnforced: number;
  readonly newlyBlockedIfEnforced: number;
  readonly blockRate: number;
}

export interface PriceRequiredIssuerBilling {
  readonly issuer: string;
  readonly decisionCount: number;
  readonly pricedDecisionCount: number;
  readonly estimatedGrossUsd: number;
}

export interface PersonaAuditIncident {
  readonly id: string;
  readonly triggerType: "revocation_epoch" | "suspicion_threshold";
  readonly status: "queued" | "completed";
  readonly severity: "medium" | "high";
  readonly tool: "create-sentinelayer";
  readonly title: string;
  readonly summary: string;
  readonly evidenceRefs: readonly string[];
  readonly recommendedActions: readonly string[];
  readonly createdAt: string;
}

export interface CascadeLatencyStats {
  readonly count: number;
  readonly minMs: number;
  readonly avgMs: number;
  readonly p50Ms: number;
  readonly p95Ms: number;
  readonly p99Ms: number;
  readonly maxMs: number;
}

export interface CascadeLatencyProfile {
  readonly name: string;
  readonly timeoutMs: number;
  readonly description: string;
}

export interface CascadeLatencyBenchmarkArtifact {
  readonly generatedAt: string;
  readonly decisions: number;
  readonly concurrency: number;
  readonly seed: number;
  readonly cascade: {
    readonly mode: string;
    readonly shortCircuiting: boolean;
    readonly layerOrder: readonly string[];
  };
  readonly profiles: readonly CascadeLatencyProfile[];
  readonly overall: CascadeLatencyStats;
  readonly layers: Readonly<Record<string, CascadeLatencyStats>>;
}

export interface CascadeLayerTelemetry {
  readonly name: string;
  readonly label: string;
  readonly description: string;
  readonly count: number;
  readonly avgMs: number;
  readonly p50Ms: number;
  readonly p95Ms: number;
  readonly p99Ms: number;
  readonly maxMs: number;
  readonly timeoutMs: number | undefined;
  readonly p95Share: number;
  readonly exceededTimeout: boolean;
}

export interface CascadeTelemetrySummary {
  readonly generatedAt: string;
  readonly decisions: number;
  readonly concurrency: number;
  readonly seed: number;
  readonly mode: string;
  readonly shortCircuiting: boolean;
  readonly sloBudgetMs: number;
  readonly sloStatus: "within_budget" | "over_budget";
  readonly overall: CascadeLatencyStats;
  readonly layers: readonly CascadeLayerTelemetry[];
  readonly slowestLayer: CascadeLayerTelemetry | undefined;
}

export interface PolicyValidationResult {
  readonly ok: boolean;
  readonly routeCount: number;
  readonly errors: readonly string[];
}

export const DEFAULT_CASCADE_SLO_BUDGET_MS = 200;

const CASCADE_LAYER_LABELS: Readonly<Record<string, string>> = {
  web_bot_auth_verify: "Web Bot Auth",
  delegation_lookup: "Delegation",
  fingerprint_stub: "Fingerprint",
  operator_reputation_lookup: "Reputation"
};

export function routeMetricsFromEvents(events: readonly DashboardDecisionEvent[]): readonly RouteMetric[] {
  const grouped = new Map<string, DashboardDecisionEvent[]>();
  for (const event of events) {
    const bucket = grouped.get(event.routeTemplate) ?? [];
    bucket.push(event);
    grouped.set(event.routeTemplate, bucket);
  }

  return [...grouped.entries()]
    .map(([routeTemplate, routeEvents]) => {
      const sortedLatency = routeEvents.map((event) => event.latencyMs).sort((left, right) => left - right);
      const p95Index = Math.max(0, Math.ceil(sortedLatency.length * 0.95) - 1);
      const p95LatencyMs = sortedLatency[p95Index] ?? 0;
      const denied = routeEvents.filter((event) => event.decision === "deny" || event.decision === "throttle").length;
      return {
        routeTemplate,
        count: routeEvents.length,
        p95LatencyMs,
        denyRate: denied / routeEvents.length
      };
    })
    .sort((left, right) => right.count - left.count);
}

export function counterfactualImpactFromEvents(events: readonly DashboardDecisionEvent[]): readonly CounterfactualImpact[] {
  const grouped = new Map<string, DashboardDecisionEvent[]>();
  for (const event of events) {
    const bucket = grouped.get(event.routeTemplate) ?? [];
    bucket.push(event);
    grouped.set(event.routeTemplate, bucket);
  }

  return [...grouped.entries()]
    .map(([routeTemplate, routeEvents]) => {
      const wouldBlockIfEnforced = routeEvents.filter((event) => (event.recommendedDecision ?? event.decision) !== "allow").length;
      const newlyBlockedIfEnforced = routeEvents.filter(
        (event) => event.decision === "allow" && (event.recommendedDecision ?? event.decision) !== "allow"
      ).length;
      return {
        routeTemplate,
        sampleCount: routeEvents.length,
        wouldBlockIfEnforced,
        newlyBlockedIfEnforced,
        blockRate: routeEvents.length === 0 ? 0 : wouldBlockIfEnforced / routeEvents.length
      };
    })
    .sort((left, right) => right.newlyBlockedIfEnforced - left.newlyBlockedIfEnforced);
}

export function priceRequiredBillingFromEvents(events: readonly DashboardDecisionEvent[]): readonly PriceRequiredIssuerBilling[] {
  const priceRequiredEvents = events.filter((event) => event.decision === "price_required" || event.operatorAction === "price_required");
  const grouped = new Map<string, DashboardDecisionEvent[]>();
  for (const event of priceRequiredEvents) {
    const issuer = event.issuer ?? "unknown_issuer";
    const bucket = grouped.get(issuer) ?? [];
    bucket.push(event);
    grouped.set(issuer, bucket);
  }
  return [...grouped.entries()]
    .map(([issuer, issuerEvents]) => ({
      issuer,
      decisionCount: issuerEvents.length,
      pricedDecisionCount: issuerEvents.filter((event) => event.priceUsd !== undefined).length,
      estimatedGrossUsd: Math.round(issuerEvents.reduce((sum, event) => sum + (event.priceUsd ?? 0), 0) * 1_000_000) / 1_000_000
    }))
    .sort((left, right) => right.estimatedGrossUsd - left.estimatedGrossUsd || right.decisionCount - left.decisionCount);
}

export function cascadeTelemetryFromBenchmarkArtifact(
  artifact: CascadeLatencyBenchmarkArtifact,
  options: { readonly sloBudgetMs?: number } = {}
): CascadeTelemetrySummary {
  const sloBudgetMs = options.sloBudgetMs ?? DEFAULT_CASCADE_SLO_BUDGET_MS;
  const profileByName = new Map(artifact.profiles.map((profile) => [profile.name, profile]));
  const layers = artifact.cascade.layerOrder.map((name) => {
    const stats = artifact.layers[name];
    if (stats === undefined) {
      throw new Error(`missing cascade layer stats: ${name}`);
    }
    const profile = profileByName.get(name);
    return {
      name,
      label: CASCADE_LAYER_LABELS[name] ?? name,
      description: profile?.description ?? "",
      count: stats.count,
      avgMs: stats.avgMs,
      p50Ms: stats.p50Ms,
      p95Ms: stats.p95Ms,
      p99Ms: stats.p99Ms,
      maxMs: stats.maxMs,
      timeoutMs: profile?.timeoutMs,
      p95Share: artifact.overall.p95Ms === 0 ? 0 : stats.p95Ms / artifact.overall.p95Ms,
      exceededTimeout: profile?.timeoutMs === undefined ? false : stats.maxMs > profile.timeoutMs
    };
  });
  const slowestLayer = layers.reduce<CascadeLayerTelemetry | undefined>(
    (current, layer) => (current === undefined || layer.p95Ms > current.p95Ms ? layer : current),
    undefined
  );

  return {
    generatedAt: artifact.generatedAt,
    decisions: artifact.decisions,
    concurrency: artifact.concurrency,
    seed: artifact.seed,
    mode: artifact.cascade.mode,
    shortCircuiting: artifact.cascade.shortCircuiting,
    sloBudgetMs,
    sloStatus: artifact.overall.p95Ms <= sloBudgetMs ? "within_budget" : "over_budget",
    overall: artifact.overall,
    layers,
    slowestLayer
  };
}

export function validatePolicyText(policyText: string): PolicyValidationResult {
  try {
    const loaded = parsePolicyYaml(policyText);
    return { ok: true, routeCount: loaded.bundle.routes.length, errors: [] };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return { ok: false, routeCount: 0, errors: [message] };
  }
}

export function dashboardLayoutForWidth(width: number): "mobile" | "tablet" | "desktop" {
  if (width < 720) {
    return "mobile";
  }
  if (width < 1100) {
    return "tablet";
  }
  return "desktop";
}

export function personaAuditSeverityCounts(incidents: readonly PersonaAuditIncident[]): Readonly<Record<PersonaAuditIncident["severity"], number>> {
  return incidents.reduce(
    (counts, incident) => ({
      ...counts,
      [incident.severity]: counts[incident.severity] + 1
    }),
    { medium: 0, high: 0 }
  );
}
