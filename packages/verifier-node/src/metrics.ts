import type { CascadeTraceEntry } from "@aidenid/common-schemas";

import type { DecisionResult, VerifierMetricsSink } from "./types.js";

export interface DecisionMetricKey {
  readonly siteId: string;
  readonly action: string;
  readonly actorClass: string;
  readonly mode: string;
  readonly routeTemplate: string;
}

export interface DecisionMetricSample extends DecisionMetricKey {
  readonly count: number;
  readonly latencyUsSum: number;
  readonly latencyUsP95: number;
}

export interface ProviderMetricKey {
  readonly siteId: string;
  readonly layer: "fingerprint_sidecar" | "operator_reputation";
  readonly provider: string;
  readonly status: string;
  readonly reason: string;
  readonly routeTemplate: string;
}

export interface ProviderMetricObservation extends ProviderMetricKey {
  readonly latencyUs: number;
}

export interface ProviderMetricSample extends ProviderMetricKey {
  readonly count: number;
  readonly latencyUsSum: number;
  readonly latencyUsP95: number;
}

export interface ScopeMismatchMetricKey {
  readonly siteId: string;
  readonly actorClass: string;
  readonly mode: string;
  readonly routeTemplate: string;
}

export interface ScopeMismatchMetricSample extends ScopeMismatchMetricKey {
  readonly count: number;
}

export interface SandboxRouteMetricKey {
  readonly siteId: string;
  readonly actorClass: string;
  readonly mode: string;
  readonly routeTemplate: string;
}

export interface SandboxRouteMetricSample extends SandboxRouteMetricKey {
  readonly count: number;
}

function keyFor(decision: DecisionResult): string {
  return JSON.stringify({
    siteId: decision.siteId,
    action: decision.decision,
    actorClass: decision.actorClass,
    mode: decision.mode,
    routeTemplate: decision.routeTemplate
  });
}

function parseKey(key: string): DecisionMetricKey {
  return JSON.parse(key) as DecisionMetricKey;
}

function providerKeyFor(observation: ProviderMetricKey): string {
  return JSON.stringify({
    siteId: observation.siteId,
    layer: observation.layer,
    provider: observation.provider,
    status: observation.status,
    reason: observation.reason,
    routeTemplate: observation.routeTemplate
  });
}

function parseProviderKey(key: string): ProviderMetricKey {
  return JSON.parse(key) as ProviderMetricKey;
}

function scopeMismatchKeyFor(decision: DecisionResult): string {
  return JSON.stringify(scopeMismatchMetricAttributes(decision));
}

function parseScopeMismatchKey(key: string): ScopeMismatchMetricKey {
  return JSON.parse(key) as ScopeMismatchMetricKey;
}

function sandboxRouteKeyFor(decision: DecisionResult): string {
  return JSON.stringify(sandboxRouteMetricAttributes(decision));
}

function parseSandboxRouteKey(key: string): SandboxRouteMetricKey {
  return JSON.parse(key) as SandboxRouteMetricKey;
}

function prometheusLabels(labels: Readonly<Record<string, string>>): string {
  return Object.entries(labels)
    .map(([key, value]) => `${key}=${JSON.stringify(value)}`)
    .join(",");
}

function p95(values: readonly number[]): number {
  const sorted = [...values].sort((left, right) => left - right);
  if (sorted.length === 0) {
    return 0;
  }
  return sorted[Math.min(sorted.length - 1, Math.ceil(sorted.length * 0.95) - 1)] ?? 0;
}

export function decisionMetricAttributes(decision: DecisionResult): DecisionMetricKey {
  return {
    siteId: decision.siteId,
    action: decision.decision,
    actorClass: decision.actorClass,
    mode: decision.mode,
    routeTemplate: decision.routeTemplate
  };
}

export function scopeMismatchMetricAttributes(decision: DecisionResult): ScopeMismatchMetricKey {
  return {
    siteId: decision.siteId,
    actorClass: decision.actorClass,
    mode: decision.mode,
    routeTemplate: decision.routeTemplate
  };
}

export function sandboxRouteMetricAttributes(decision: DecisionResult): SandboxRouteMetricKey {
  return {
    siteId: decision.siteId,
    actorClass: decision.actorClass,
    mode: decision.mode,
    routeTemplate: decision.routeTemplate
  };
}

function providerLabelFromTraceEntry(entry: CascadeTraceEntry): string {
  const providerEvidence = entry.evidence?.find((item) => item.startsWith("provider:"));
  const provider = providerEvidence?.slice("provider:".length).trim();
  if (provider !== undefined && provider.length > 0) {
    return provider.slice(0, 64);
  }
  return entry.status === "not_configured" ? "not_configured" : "unknown";
}

function isProviderTraceEntry(entry: CascadeTraceEntry): entry is CascadeTraceEntry & ProviderMetricKey {
  return entry.layer === "fingerprint_sidecar" || entry.layer === "operator_reputation";
}

export function providerMetricAttributes(decision: DecisionResult): readonly ProviderMetricObservation[] {
  return (decision.cascadeTrace ?? []).filter(isProviderTraceEntry).map((entry) => ({
    siteId: decision.siteId,
    layer: entry.layer,
    provider: providerLabelFromTraceEntry(entry),
    status: entry.status,
    reason: entry.reason,
    routeTemplate: decision.routeTemplate,
    latencyUs: entry.latency_us
  }));
}

export class InMemoryVerifierMetricsSink implements VerifierMetricsSink {
  readonly #latenciesByKey = new Map<string, number[]>();
  readonly #providerLatenciesByKey = new Map<string, number[]>();
  readonly #scopeMismatchesByKey = new Map<string, number>();
  readonly #sandboxRoutesByKey = new Map<string, number>();

  recordDecision(decision: DecisionResult): void {
    const key = keyFor(decision);
    const latencies = this.#latenciesByKey.get(key) ?? [];
    latencies.push(decision.latencyUs);
    this.#latenciesByKey.set(key, latencies);
    if (decision.reasons.includes("operator_scope_mismatch")) {
      const scopeKey = scopeMismatchKeyFor(decision);
      this.#scopeMismatchesByKey.set(scopeKey, (this.#scopeMismatchesByKey.get(scopeKey) ?? 0) + 1);
    }
    if (decision.decision === "sandbox") {
      const sandboxKey = sandboxRouteKeyFor(decision);
      this.#sandboxRoutesByKey.set(sandboxKey, (this.#sandboxRoutesByKey.get(sandboxKey) ?? 0) + 1);
    }
    for (const observation of providerMetricAttributes(decision)) {
      const providerKey = providerKeyFor(observation);
      const providerLatencies = this.#providerLatenciesByKey.get(providerKey) ?? [];
      providerLatencies.push(observation.latencyUs);
      this.#providerLatenciesByKey.set(providerKey, providerLatencies);
    }
  }

  snapshot(): readonly DecisionMetricSample[] {
    return [...this.#latenciesByKey.entries()].map(([key, latencies]) => {
      const parsed = parseKey(key);
      return {
        ...parsed,
        count: latencies.length,
        latencyUsSum: latencies.reduce((sum, value) => sum + value, 0),
        latencyUsP95: p95(latencies)
      };
    });
  }

  providerSnapshot(): readonly ProviderMetricSample[] {
    return [...this.#providerLatenciesByKey.entries()].map(([key, latencies]) => {
      const parsed = parseProviderKey(key);
      return {
        ...parsed,
        count: latencies.length,
        latencyUsSum: latencies.reduce((sum, value) => sum + value, 0),
        latencyUsP95: p95(latencies)
      };
    });
  }

  scopeMismatchSnapshot(): readonly ScopeMismatchMetricSample[] {
    return [...this.#scopeMismatchesByKey.entries()].map(([key, count]) => ({
      ...parseScopeMismatchKey(key),
      count
    }));
  }

  sandboxRouteSnapshot(): readonly SandboxRouteMetricSample[] {
    return [...this.#sandboxRoutesByKey.entries()].map(([key, count]) => ({
      ...parseSandboxRouteKey(key),
      count
    }));
  }

  renderPrometheus(): string {
    const lines = [
      "# HELP aidenid_decision_total Total verifier decisions by action, actor class, mode, and route.",
      "# TYPE aidenid_decision_total counter",
      "# HELP aidenid_decision_latency_us_sum Sum of verifier hot-path latency in microseconds.",
      "# TYPE aidenid_decision_latency_us_sum counter",
      "# HELP aidenid_decision_latency_us_p95 Current in-process p95 verifier latency in microseconds.",
      "# TYPE aidenid_decision_latency_us_p95 gauge",
      "# HELP aidenid_provider_layer_total Total verifier provider-layer observations by layer, provider, status, reason, and route.",
      "# TYPE aidenid_provider_layer_total counter",
      "# HELP aidenid_provider_layer_latency_us_sum Sum of verifier provider-layer latency in microseconds.",
      "# TYPE aidenid_provider_layer_latency_us_sum counter",
      "# HELP aidenid_provider_layer_latency_us_p95 Current in-process p95 provider-layer latency in microseconds.",
      "# TYPE aidenid_provider_layer_latency_us_p95 gauge",
      "# HELP aidenid_operator_scope_mismatch_total Total operator-reputation scoped-route denials by actor class, mode, and route.",
      "# TYPE aidenid_operator_scope_mismatch_total counter",
      "# HELP aidenid_sandbox_route_total Total sandbox-routed decisions by actor class, mode, and route.",
      "# TYPE aidenid_sandbox_route_total counter"
    ];
    for (const sample of this.snapshot()) {
      const labels = prometheusLabels({
        site_id: sample.siteId,
        action: sample.action,
        actor_class: sample.actorClass,
        mode: sample.mode,
        route_template: sample.routeTemplate
      });
      lines.push(`aidenid_decision_total{${labels}} ${sample.count}`);
      lines.push(`aidenid_decision_latency_us_sum{${labels}} ${sample.latencyUsSum}`);
      lines.push(`aidenid_decision_latency_us_p95{${labels}} ${sample.latencyUsP95}`);
    }
    for (const sample of this.providerSnapshot()) {
      const labels = prometheusLabels({
        site_id: sample.siteId,
        layer: sample.layer,
        provider: sample.provider,
        status: sample.status,
        reason: sample.reason,
        route_template: sample.routeTemplate
      });
      lines.push(`aidenid_provider_layer_total{${labels}} ${sample.count}`);
      lines.push(`aidenid_provider_layer_latency_us_sum{${labels}} ${sample.latencyUsSum}`);
      lines.push(`aidenid_provider_layer_latency_us_p95{${labels}} ${sample.latencyUsP95}`);
    }
    for (const sample of this.scopeMismatchSnapshot()) {
      const labels = prometheusLabels({
        site_id: sample.siteId,
        actor_class: sample.actorClass,
        mode: sample.mode,
        route_template: sample.routeTemplate
      });
      lines.push(`aidenid_operator_scope_mismatch_total{${labels}} ${sample.count}`);
    }
    for (const sample of this.sandboxRouteSnapshot()) {
      const labels = prometheusLabels({
        site_id: sample.siteId,
        actor_class: sample.actorClass,
        mode: sample.mode,
        route_template: sample.routeTemplate
      });
      lines.push(`aidenid_sandbox_route_total{${labels}} ${sample.count}`);
    }
    return `${lines.join("\n")}\n`;
  }
}
