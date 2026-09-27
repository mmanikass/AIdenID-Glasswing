export type ActorClass = "verified_agent" | "signed_agent" | "likely_human" | "suspicious_automation" | "unknown";
export type DecisionAction = "allow" | "throttle" | "queue" | "sandbox" | "deny" | "price_required";
export type OperatorAction = DecisionAction | "quarantine";
export type CascadeTraceLayer = "crypto_identity" | "delegation_authorization" | "fingerprint_sidecar" | "operator_reputation";
export type CascadeTraceStatus = "pass" | "fail" | "skipped" | "not_configured";
export type ProviderReputationRisk = "trusted" | "review" | "restricted" | "unknown";

export interface DashboardCascadeTraceEntry {
  readonly ordinal: number;
  readonly layer: CascadeTraceLayer;
  readonly status: CascadeTraceStatus;
  readonly reason: string;
  readonly latencyUs: number;
  readonly evidence: readonly string[];
}

export interface DashboardDecisionEvent {
  readonly id: string;
  readonly occurredAt: string;
  readonly requestId: string;
  readonly siteId: string;
  readonly actorClass: ActorClass;
  readonly issuer?: string | undefined;
  readonly llmBrand?: string | undefined;
  readonly purpose?: string | undefined;
  readonly decision: DecisionAction;
  readonly recommendedDecision?: DecisionAction | undefined;
  readonly routeTemplate: string;
  readonly method: string;
  readonly latencyMs: number;
  readonly priceUsd?: number | undefined;
  readonly reasonCodes: readonly string[];
  readonly cascadeTrace?: readonly DashboardCascadeTraceEntry[] | undefined;
  readonly operatorAction?: OperatorAction | undefined;
  readonly operatorActionActorId?: string | undefined;
  readonly operatorActionReason?: string | undefined;
  readonly operatorActionAt?: string | undefined;
  readonly operatorActionEffectiveDecision?: DecisionAction | undefined;
  readonly operatorActionExpiresAt?: string | undefined;
  readonly operatorActionEffects?: readonly string[] | undefined;
}

export type TrafficClassificationBucketKey = "agents" | "humans" | "automation" | "unknown";

export interface TrafficClassificationBucket {
  readonly key: TrafficClassificationBucketKey;
  readonly label: string;
  readonly count: number;
  readonly percentage: number;
}

export interface ProviderReputationSummary {
  readonly providerId: string;
  readonly displayName: string;
  readonly eventCount: number;
  readonly passCount: number;
  readonly failCount: number;
  readonly skippedCount: number;
  readonly notConfiguredCount: number;
  readonly latestScore?: number | undefined;
  readonly latestStatus?: CascadeTraceStatus | undefined;
  readonly latestReason?: string | undefined;
  readonly latestDecisionId?: string | undefined;
  readonly latestRouteTemplate?: string | undefined;
  readonly recommendedAction: OperatorAction;
  readonly risk: ProviderReputationRisk;
}

export interface DashboardStreamError {
  readonly error: string;
  readonly status?: number | undefined;
}

const TRAFFIC_CLASSIFICATION_BUCKETS: readonly Omit<TrafficClassificationBucket, "count" | "percentage">[] = [
  { key: "agents", label: "Agents" },
  { key: "humans", label: "Humans" },
  { key: "automation", label: "Automation" },
  { key: "unknown", label: "Unknown" }
];

export function trafficClassificationFromEvents(events: readonly DashboardDecisionEvent[]): readonly TrafficClassificationBucket[] {
  const counts: Record<TrafficClassificationBucketKey, number> = {
    agents: 0,
    humans: 0,
    automation: 0,
    unknown: 0
  };
  for (const event of events) {
    if (event.actorClass === "verified_agent" || event.actorClass === "signed_agent") {
      counts.agents += 1;
    } else if (event.actorClass === "likely_human") {
      counts.humans += 1;
    } else if (event.actorClass === "suspicious_automation") {
      counts.automation += 1;
    } else {
      counts.unknown += 1;
    }
  }
  const total = events.length;
  return TRAFFIC_CLASSIFICATION_BUCKETS.map((bucket) => ({
    ...bucket,
    count: counts[bucket.key],
    percentage: total === 0 ? 0 : Math.round((counts[bucket.key] / total) * 100)
  }));
}

function operatorReputationTrace(event: DashboardDecisionEvent): DashboardCascadeTraceEntry | undefined {
  return event.cascadeTrace?.find((entry) => entry.layer === "operator_reputation");
}

function normalizedProviderId(value: string | undefined): string | undefined {
  const normalized = value?.trim().toLowerCase();
  return normalized === undefined || normalized.length === 0 ? undefined : normalized;
}

function providerIdFromEvidence(evidence: readonly string[]): string | undefined {
  for (const item of evidence) {
    const operatorMatch = /^operator:([^:]+):score=\d+$/u.exec(item);
    if (operatorMatch?.[1] !== undefined) {
      return normalizedProviderId(operatorMatch[1]);
    }
    const providerMatch = /^provider:([^:]+)$/u.exec(item);
    if (providerMatch?.[1] !== undefined) {
      return normalizedProviderId(providerMatch[1]);
    }
  }
  return undefined;
}

function reputationScoreFromEvidence(evidence: readonly string[]): number | undefined {
  for (const item of evidence) {
    const scoreMatch = /(?:^operator:[^:]+:score=|^reputation_score:)(\d{1,3})$/u.exec(item);
    if (scoreMatch?.[1] === undefined) {
      continue;
    }
    const score = Number.parseInt(scoreMatch[1], 10);
    if (Number.isInteger(score) && score >= 0 && score <= 100) {
      return score;
    }
  }
  return undefined;
}

function providerDisplayName(providerId: string): string {
  const known: Readonly<Record<string, string>> = {
    anthropic: "Claude / Anthropic",
    openai: "ChatGPT / OpenAI",
    unknown: "Unknown operator"
  };
  return (
    known[providerId] ??
    providerId
      .split(/[-_]/u)
      .filter((part) => part.length > 0)
      .map((part) => part.slice(0, 1).toUpperCase() + part.slice(1))
      .join(" ")
  );
}

function recommendedProviderAction(status: CascadeTraceStatus | undefined, reason: string | undefined, score: number | undefined): OperatorAction {
  if (status === "fail") {
    if (reason?.includes("suspended") === true || reason?.includes("untrusted") === true || (score !== undefined && score < 30)) {
      return "deny";
    }
    if (score !== undefined && score < 60) {
      return "queue";
    }
    return "sandbox";
  }
  if (status === "skipped" || status === "not_configured") {
    return "throttle";
  }
  if (score !== undefined && score < 50) {
    return "sandbox";
  }
  return "allow";
}

function riskFromProviderAction(action: OperatorAction, status: CascadeTraceStatus | undefined): ProviderReputationRisk {
  if (status === undefined) {
    return "unknown";
  }
  if (action === "allow") {
    return "trusted";
  }
  if (action === "deny" || action === "quarantine") {
    return "restricted";
  }
  return "review";
}

export function providerReputationFromEvents(events: readonly DashboardDecisionEvent[]): readonly ProviderReputationSummary[] {
  const grouped = new Map<
    string,
    {
      eventCount: number;
      passCount: number;
      failCount: number;
      skippedCount: number;
      notConfiguredCount: number;
      latestAt: number;
      latestScore: number | undefined;
      latestStatus: CascadeTraceStatus | undefined;
      latestReason: string | undefined;
      latestDecisionId: string | undefined;
      latestRouteTemplate: string | undefined;
    }
  >();

  for (const event of events) {
    const reputationTrace = operatorReputationTrace(event);
    const providerId = normalizedProviderId(event.llmBrand) ?? providerIdFromEvidence(reputationTrace?.evidence ?? []);
    if (providerId === undefined) {
      continue;
    }
    const current = grouped.get(providerId) ?? {
      eventCount: 0,
      passCount: 0,
      failCount: 0,
      skippedCount: 0,
      notConfiguredCount: 0,
      latestAt: Number.NEGATIVE_INFINITY,
      latestScore: undefined,
      latestStatus: undefined,
      latestReason: undefined,
      latestDecisionId: undefined,
      latestRouteTemplate: undefined
    };
    current.eventCount += 1;
    if (reputationTrace?.status === "pass") {
      current.passCount += 1;
    } else if (reputationTrace?.status === "fail") {
      current.failCount += 1;
    } else if (reputationTrace?.status === "skipped") {
      current.skippedCount += 1;
    } else if (reputationTrace?.status === "not_configured") {
      current.notConfiguredCount += 1;
    }

    const occurredAtMs = Date.parse(event.occurredAt);
    const sortableTime = Number.isFinite(occurredAtMs) ? occurredAtMs : Number.NEGATIVE_INFINITY;
    if (sortableTime >= current.latestAt) {
      current.latestAt = sortableTime;
      current.latestScore = reputationScoreFromEvidence(reputationTrace?.evidence ?? []);
      current.latestStatus = reputationTrace?.status;
      current.latestReason = reputationTrace?.reason;
      current.latestDecisionId = event.id;
      current.latestRouteTemplate = event.routeTemplate;
    }
    grouped.set(providerId, current);
  }

  return [...grouped.entries()]
    .map(([providerId, summary]) => {
      const recommendedAction = recommendedProviderAction(summary.latestStatus, summary.latestReason, summary.latestScore);
      return {
        providerId,
        displayName: providerDisplayName(providerId),
        eventCount: summary.eventCount,
        passCount: summary.passCount,
        failCount: summary.failCount,
        skippedCount: summary.skippedCount,
        notConfiguredCount: summary.notConfiguredCount,
        latestScore: summary.latestScore,
        latestStatus: summary.latestStatus,
        latestReason: summary.latestReason,
        latestDecisionId: summary.latestDecisionId,
        latestRouteTemplate: summary.latestRouteTemplate,
        recommendedAction,
        risk: riskFromProviderAction(recommendedAction, summary.latestStatus)
      };
    })
    .sort((left, right) => right.eventCount - left.eventCount || left.displayName.localeCompare(right.displayName));
}

export function filterDecisionEvents(events: readonly DashboardDecisionEvent[], query: string): readonly DashboardDecisionEvent[] {
  const normalized = query.trim().toLowerCase();
  if (normalized.length === 0) {
    return events;
  }
  return events.filter((event) =>
    [
      event.requestId,
      event.actorClass,
      event.decision,
      event.operatorAction ?? "",
      event.llmBrand ?? "",
      event.purpose ?? "",
      event.routeTemplate,
      event.method,
      ...(event.cascadeTrace ?? []).flatMap((entry) => [entry.layer, entry.status, entry.reason, ...entry.evidence])
    ]
      .join(" ")
      .toLowerCase()
      .includes(normalized)
  );
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function numberValue(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function actorClassValue(value: unknown): ActorClass {
  const raw = stringValue(value);
  return raw === "verified_agent" || raw === "signed_agent" || raw === "likely_human" || raw === "suspicious_automation" || raw === "unknown"
    ? raw
    : "unknown";
}

function decisionActionValue(value: unknown): DecisionAction | undefined {
  const raw = stringValue(value);
  return raw === "allow" || raw === "throttle" || raw === "queue" || raw === "sandbox" || raw === "deny" || raw === "price_required"
    ? raw
    : undefined;
}

function operatorActionValue(value: unknown): OperatorAction | undefined {
  const decision = decisionActionValue(value);
  if (decision !== undefined) {
    return decision;
  }
  return stringValue(value) === "quarantine" ? "quarantine" : undefined;
}

function stringArrayValue(value: unknown): readonly string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

function cascadeTraceLayerValue(value: unknown): CascadeTraceLayer | undefined {
  const raw = stringValue(value);
  return raw === "crypto_identity" || raw === "delegation_authorization" || raw === "fingerprint_sidecar" || raw === "operator_reputation"
    ? raw
    : undefined;
}

function cascadeTraceStatusValue(value: unknown): CascadeTraceStatus | undefined {
  const raw = stringValue(value);
  return raw === "pass" || raw === "fail" || raw === "skipped" || raw === "not_configured" ? raw : undefined;
}

function cascadeTraceValue(value: unknown): readonly DashboardCascadeTraceEntry[] | undefined {
  if (!Array.isArray(value)) {
    return undefined;
  }
  const entries: DashboardCascadeTraceEntry[] = [];
  for (const item of value) {
    if (item === null || typeof item !== "object" || Array.isArray(item)) {
      continue;
    }
    const source = item as Readonly<Record<string, unknown>>;
    const layer = cascadeTraceLayerValue(source.layer);
    const status = cascadeTraceStatusValue(source.status);
    const reason = stringValue(source.reason);
    const ordinal = numberValue(source.ordinal);
    if (layer === undefined || status === undefined || reason === undefined || ordinal === undefined) {
      continue;
    }
    entries.push({
      ordinal,
      layer,
      status,
      reason,
      latencyUs: numberValue(field(source, "latency_us", "latencyUs")) ?? 0,
      evidence: stringArrayValue(source.evidence)
    });
  }
  return entries.length === 0 ? undefined : entries.sort((left, right) => left.ordinal - right.ordinal);
}

function field(source: Readonly<Record<string, unknown>>, snakeCase: string, camelCase: string): unknown {
  return source[snakeCase] ?? source[camelCase];
}

export function dashboardStreamErrorFromPayload(payload: unknown): DashboardStreamError | undefined {
  if (payload === null || typeof payload !== "object" || Array.isArray(payload)) {
    return undefined;
  }
  const source = payload as Readonly<Record<string, unknown>>;
  const error = stringValue(source.error);
  if (error === undefined) {
    return undefined;
  }
  const status = numberValue(source.status);
  return {
    error,
    ...(status === undefined ? {} : { status })
  };
}

export function dashboardDecisionEventFromPayload(payload: unknown): DashboardDecisionEvent | undefined {
  if (payload === null || typeof payload !== "object" || Array.isArray(payload)) {
    return undefined;
  }
  const source = payload as Readonly<Record<string, unknown>>;
  const id = stringValue(field(source, "id", "id"));
  const occurredAt = stringValue(field(source, "occurred_at", "occurredAt"));
  const requestId = stringValue(field(source, "request_id", "requestId"));
  const siteId = stringValue(field(source, "site_id", "siteId"));
  const routeTemplate = stringValue(field(source, "route_template", "routeTemplate"));
  const method = stringValue(field(source, "method", "method"));
  const decision = decisionActionValue(field(source, "decision", "decision"));
  if (
    id === undefined ||
    occurredAt === undefined ||
    requestId === undefined ||
    siteId === undefined ||
    routeTemplate === undefined ||
    method === undefined ||
    decision === undefined
  ) {
    return undefined;
  }

  const latencyMs = numberValue(field(source, "latency_ms", "latencyMs")) ?? (numberValue(field(source, "latency_us", "latencyUs")) ?? 0) / 1_000;
  return {
    id,
    occurredAt,
    requestId,
    siteId,
    actorClass: actorClassValue(field(source, "actor_class", "actorClass")),
    issuer: stringValue(field(source, "issuer", "issuer")),
    llmBrand: stringValue(field(source, "llm_brand", "llmBrand")),
    purpose: stringValue(field(source, "purpose", "purpose")),
    decision,
    recommendedDecision: decisionActionValue(field(source, "recommended_decision", "recommendedDecision")),
    routeTemplate,
    method: method.toUpperCase(),
    latencyMs,
    priceUsd: numberValue(field(source, "price_usd", "priceUsd")),
    reasonCodes: stringArrayValue(field(source, "reason_codes", "reasonCodes")),
    cascadeTrace: cascadeTraceValue(field(source, "cascade_trace", "cascadeTrace")),
    operatorAction: operatorActionValue(field(source, "operator_action", "operatorAction")),
    operatorActionActorId: stringValue(field(source, "operator_action_actor_id", "operatorActionActorId")),
    operatorActionReason: stringValue(field(source, "operator_action_reason", "operatorActionReason")),
    operatorActionAt: stringValue(field(source, "operator_action_at", "operatorActionAt")),
    operatorActionEffectiveDecision: decisionActionValue(field(source, "operator_action_effective_decision", "operatorActionEffectiveDecision")),
    operatorActionExpiresAt: stringValue(field(source, "operator_action_expires_at", "operatorActionExpiresAt")),
    operatorActionEffects: stringArrayValue(field(source, "operator_action_effects", "operatorActionEffects"))
  };
}
