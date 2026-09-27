import type { DecisionAction, DecisionResult, OperatorAction, ReasonCode } from "./types.js";

export interface ControlPlaneDecisionPayload {
  readonly site_id: string;
  readonly request_id: string;
  readonly actor_class: string;
  readonly decision: string;
  readonly recommended_decision: string;
  readonly route_template: string;
  readonly method: string;
  readonly occurred_at: string;
  readonly latency_us: number;
  readonly issuer?: string | undefined;
  readonly subject_handle?: string | undefined;
  readonly llm_brand?: string | undefined;
  readonly purpose?: string | undefined;
  readonly price_usd?: number | undefined;
  readonly reason_codes: readonly string[];
  readonly cascade_trace?: DecisionResult["cascadeTrace"] | undefined;
}

export interface DecisionEmitterFetchResponse {
  readonly ok: boolean;
  readonly status: number;
  text(): Promise<string>;
}

export type DecisionEmitterFetch = (
  input: string,
  init: {
    readonly method: "GET" | "POST";
    readonly headers: Readonly<Record<string, string>>;
    readonly body?: string | undefined;
    readonly signal: AbortSignal;
  }
) => Promise<DecisionEmitterFetchResponse>;

export interface ControlPlaneDecisionEmitterOptions {
  readonly controlPlaneUrl: string;
  readonly apiKey?: string | undefined;
  readonly fetcher?: DecisionEmitterFetch | undefined;
  readonly timeoutMs?: number | undefined;
  readonly flushIntervalMs?: number | undefined;
  readonly maxBatchSize?: number | undefined;
  readonly maxQueueSize?: number | undefined;
  readonly failClosed?: boolean | undefined;
  readonly now?: (() => Date) | undefined;
  readonly onError?: ((error: Error, decision: DecisionResult) => void | Promise<void>) | undefined;
}

export interface ControlPlaneDecisionOverrideOptions extends ControlPlaneDecisionEmitterOptions {
  readonly awaitTimeoutMs?: number | undefined;
}

const DEFAULT_EMIT_TIMEOUT_MS = 1_500;
const DEFAULT_EMIT_FLUSH_INTERVAL_MS = 250;
const DEFAULT_EMIT_MAX_BATCH_SIZE = 100;
const DEFAULT_EMIT_MAX_QUEUE_SIZE = 10_000;

function decisionEndpoint(controlPlaneUrl: string): string {
  const normalized = controlPlaneUrl.endsWith("/") ? controlPlaneUrl : `${controlPlaneUrl}/`;
  return new URL("v1/decisions", normalized).toString();
}

function decisionAwaitEndpoint(controlPlaneUrl: string, decisionId: string, timeoutMs: number): string {
  const normalized = controlPlaneUrl.endsWith("/") ? controlPlaneUrl : `${controlPlaneUrl}/`;
  const endpoint = new URL(`v1/decisions/${encodeURIComponent(decisionId)}/await`, normalized);
  endpoint.searchParams.set("timeout_ms", String(timeoutMs));
  return endpoint.toString();
}

function errorFromResponse(status: number, body: string): Error {
  const suffix = body.trim().length === 0 ? "" : `: ${body.trim().slice(0, 300)}`;
  return new Error(`control-plane decision emit failed with HTTP ${status}${suffix}`);
}

async function reportError(
  error: Error,
  decision: DecisionResult,
  options: ControlPlaneDecisionEmitterOptions
): Promise<void> {
  await options.onError?.(error, decision);
  if (options.failClosed === true) {
    throw error;
  }
}

function integerOption(value: number | undefined, fallback: number, name: string, min: number): number {
  const resolved = value ?? fallback;
  if (!Number.isInteger(resolved) || resolved < min) {
    throw new Error(`${name} must be an integer >= ${min}`);
  }
  return resolved;
}

function stringField(source: unknown, name: string): string | undefined {
  if (source === null || typeof source !== "object" || Array.isArray(source)) {
    return undefined;
  }
  const value = (source as Readonly<Record<string, unknown>>)[name];
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function decisionAction(value: unknown): DecisionAction | undefined {
  return value === "allow" || value === "throttle" || value === "queue" || value === "sandbox" || value === "deny" || value === "price_required"
    ? value
    : undefined;
}

function operatorAction(value: unknown): OperatorAction | undefined {
  const decision = decisionAction(value);
  if (decision !== undefined) {
    return decision;
  }
  return value === "quarantine" ? "quarantine" : undefined;
}

function decisionIdFromRecordResponse(payload: unknown): string | undefined {
  if (payload === null || typeof payload !== "object" || Array.isArray(payload)) {
    return undefined;
  }
  return stringField((payload as Readonly<Record<string, unknown>>).decision, "id");
}

function operatorActionFromAwaitResponse(payload: unknown): OperatorAction | undefined {
  if (payload === null || typeof payload !== "object" || Array.isArray(payload)) {
    return undefined;
  }
  return operatorAction(stringField((payload as Readonly<Record<string, unknown>>).decision, "operator_action"));
}

function priceUsdFromHeaders(headers: Readonly<Record<string, string>> | undefined): number | undefined {
  const raw = headers?.["X-AIdenID-Price-USD"] ?? headers?.["x-aidenid-price-usd"];
  if (raw === undefined) {
    return undefined;
  }
  const parsed = Number(raw);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : undefined;
}

function purposeFromHeaders(headers: Readonly<Record<string, string>> | undefined): string | undefined {
  const raw = headers?.["X-AIdenID-Purpose"] ?? headers?.["x-aidenid-purpose"];
  return raw === undefined || raw.trim().length === 0 ? undefined : raw.trim().toLowerCase();
}

function withOperatorAction(decision: DecisionResult, action: OperatorAction): DecisionResult {
  const reasons: ReasonCode[] = [...decision.reasons];
  if (!reasons.includes("operator_override")) {
    reasons.push("operator_override");
  }
  if (action === "quarantine" && !reasons.includes("quarantine")) {
    reasons.push("quarantine");
  }
  const effectiveDecision: DecisionAction = action === "quarantine" ? "deny" : action;
  const responseHeaders = {
    ...decision.responseHeaders,
    "X-AIdenID-Operator-Action": action,
    "X-AIdenID-Operator-Effective-Decision": effectiveDecision
  };
  return {
    ...decision,
    decision: effectiveDecision,
    reasons,
    responseHeaders
  };
}

export function controlPlaneDecisionPayloadFromResult(
  decision: DecisionResult,
  options: Pick<ControlPlaneDecisionEmitterOptions, "now"> = {}
): ControlPlaneDecisionPayload {
  const priceUsd = decision.priceUsd ?? priceUsdFromHeaders(decision.responseHeaders);
  const purpose = decision.purpose ?? purposeFromHeaders(decision.responseHeaders);
  return {
    site_id: decision.siteId,
    request_id: decision.requestId,
    actor_class: decision.actorClass,
    decision: decision.decision,
    recommended_decision: decision.recommendedDecision,
    route_template: decision.routeTemplate,
    method: decision.method.toUpperCase(),
    occurred_at: (options.now ?? (() => new Date()))().toISOString(),
    latency_us: decision.latencyUs,
    ...(decision.issuer === undefined ? {} : { issuer: decision.issuer }),
    ...(decision.subjectHandle === undefined ? {} : { subject_handle: decision.subjectHandle }),
    ...(decision.llmBrand === undefined ? {} : { llm_brand: decision.llmBrand }),
    ...(purpose === undefined ? {} : { purpose }),
    ...(priceUsd === undefined ? {} : { price_usd: priceUsd }),
    ...(decision.cascadeTrace === undefined ? {} : { cascade_trace: decision.cascadeTrace }),
    reason_codes: decision.reasons
  };
}

export function createControlPlaneDecisionEmitter(
  options: ControlPlaneDecisionEmitterOptions
): (decision: DecisionResult) => Promise<void> {
  const endpoint = decisionEndpoint(options.controlPlaneUrl);
  const fetcher = options.fetcher ?? (globalThis.fetch as unknown as DecisionEmitterFetch);
  const timeoutMs = integerOption(options.timeoutMs, DEFAULT_EMIT_TIMEOUT_MS, "timeoutMs", 1);
  const flushIntervalMs = integerOption(options.flushIntervalMs, DEFAULT_EMIT_FLUSH_INTERVAL_MS, "flushIntervalMs", 0);
  const maxBatchSize = integerOption(options.maxBatchSize, DEFAULT_EMIT_MAX_BATCH_SIZE, "maxBatchSize", 1);
  const maxQueueSize = integerOption(options.maxQueueSize, DEFAULT_EMIT_MAX_QUEUE_SIZE, "maxQueueSize", 1);
  const queue: DecisionResult[] = [];
  let flushing = false;
  let flushScheduled = false;
  let droppedCount = 0;

  const emitOne = async (decision: DecisionResult): Promise<void> => {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const payload = controlPlaneDecisionPayloadFromResult(decision, options);
      const response = await fetcher(endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(options.apiKey === undefined ? {} : { Authorization: `Bearer ${options.apiKey}` })
        },
        body: JSON.stringify(payload),
        signal: controller.signal
      });
      if (!response.ok) {
        throw errorFromResponse(response.status, await response.text());
      }
    } catch (error) {
      await reportError(error instanceof Error ? error : new Error(String(error)), decision, options);
    } finally {
      clearTimeout(timeout);
    }
  };

  const flushQueue = async (): Promise<void> => {
    if (flushing) {
      return;
    }
    flushing = true;
    try {
      while (queue.length > 0) {
        const batch = queue.splice(0, maxBatchSize);
        await Promise.all(batch.map((decision) => emitOne(decision).catch(() => undefined)));
      }
    } finally {
      flushing = false;
      if (queue.length > 0) {
        scheduleFlush();
      }
    }
  };

  function scheduleFlush(): void {
    if (flushScheduled) {
      return;
    }
    flushScheduled = true;
    const run = () => {
      flushScheduled = false;
      void flushQueue().catch(() => undefined);
    };
    if (flushIntervalMs === 0) {
      queueMicrotask(run);
    } else {
      setTimeout(run, flushIntervalMs);
    }
  }

  return async (decision: DecisionResult) => {
    if (options.failClosed === true) {
      await emitOne(decision);
      return;
    }
    if (queue.length >= maxQueueSize) {
      const dropped = queue.shift();
      droppedCount += 1;
      if (dropped !== undefined) {
        void reportError(
          new Error(`control-plane decision emitter queue full; dropped oldest decision (dropped=${droppedCount})`),
          dropped,
          options
        ).catch(() => undefined);
      }
    }
    queue.push(decision);
    scheduleFlush();
  };
}

export function createControlPlaneDecisionOverride(
  options: ControlPlaneDecisionOverrideOptions
): (decision: DecisionResult) => Promise<DecisionResult | undefined> {
  const endpoint = decisionEndpoint(options.controlPlaneUrl);
  const fetcher = options.fetcher ?? (globalThis.fetch as unknown as DecisionEmitterFetch);
  const timeoutMs = options.timeoutMs ?? DEFAULT_EMIT_TIMEOUT_MS;
  const awaitTimeoutMs = options.awaitTimeoutMs ?? 1_500;

  return async (decision: DecisionResult) => {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs + awaitTimeoutMs);
    try {
      const payload = controlPlaneDecisionPayloadFromResult(decision, options);
      const recordResponse = await fetcher(endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(options.apiKey === undefined ? {} : { Authorization: `Bearer ${options.apiKey}` })
        },
        body: JSON.stringify(payload),
        signal: controller.signal
      });
      const recordBody = await recordResponse.text();
      if (!recordResponse.ok) {
        throw errorFromResponse(recordResponse.status, recordBody);
      }
      if (awaitTimeoutMs <= 0) {
        return undefined;
      }
      const decisionId = decisionIdFromRecordResponse(JSON.parse(recordBody) as unknown);
      if (decisionId === undefined) {
        return undefined;
      }
      const awaitResponse = await fetcher(decisionAwaitEndpoint(options.controlPlaneUrl, decisionId, awaitTimeoutMs), {
        method: "GET",
        headers: {
          Accept: "application/json",
          ...(options.apiKey === undefined ? {} : { Authorization: `Bearer ${options.apiKey}` })
        },
        signal: controller.signal
      });
      const awaitBody = await awaitResponse.text();
      if (!awaitResponse.ok && awaitResponse.status !== 202) {
        throw errorFromResponse(awaitResponse.status, awaitBody);
      }
      const operatorAction = operatorActionFromAwaitResponse(JSON.parse(awaitBody) as unknown);
      return operatorAction === undefined ? undefined : withOperatorAction(decision, operatorAction);
    } catch (error) {
      await reportError(error instanceof Error ? error : new Error(String(error)), decision, options);
      return undefined;
    } finally {
      clearTimeout(timeout);
    }
  };
}
