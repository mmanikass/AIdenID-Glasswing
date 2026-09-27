export const DEFAULT_LIVE_OPERATOR_ACTION_TIMEOUT_MS = 5_000;
export const DEFAULT_LIVE_OPERATOR_ACTION_CIRCUIT_FAILURE_THRESHOLD = 3;
export const DEFAULT_LIVE_OPERATOR_ACTION_CIRCUIT_OPEN_MS = 30_000;

export interface LiveOperatorActionCircuitOptions {
  readonly failureThreshold?: number | undefined;
  readonly openMs?: number | undefined;
  readonly now?: (() => number) | undefined;
}

export interface LiveOperatorActionFetchOptions {
  readonly timeoutMs?: number | undefined;
  readonly circuitBreaker?: LiveOperatorActionCircuitBreaker | undefined;
  readonly fetchImpl?: typeof fetch | undefined;
}

function positiveInteger(value: number | undefined, fallback: number): number {
  if (value === undefined || !Number.isInteger(value) || value <= 0) {
    return fallback;
  }
  return value;
}

function errorName(error: unknown): string | undefined {
  return error instanceof Error ? error.name : undefined;
}

export class LiveOperatorActionCircuitBreaker {
  private failureCount = 0;
  private openUntilMs: number | undefined;
  private readonly failureThreshold: number;
  private readonly openMs: number;
  private readonly now: () => number;

  constructor(options: LiveOperatorActionCircuitOptions = {}) {
    this.failureThreshold = positiveInteger(
      options.failureThreshold,
      DEFAULT_LIVE_OPERATOR_ACTION_CIRCUIT_FAILURE_THRESHOLD,
    );
    this.openMs = positiveInteger(
      options.openMs,
      DEFAULT_LIVE_OPERATOR_ACTION_CIRCUIT_OPEN_MS,
    );
    this.now = options.now ?? Date.now;
  }

  currentOpenUntilMs(): number | undefined {
    if (this.openUntilMs === undefined) {
      return undefined;
    }
    if (this.now() < this.openUntilMs) {
      return this.openUntilMs;
    }
    this.failureCount = 0;
    this.openUntilMs = undefined;
    return undefined;
  }

  recordSuccess(): void {
    this.failureCount = 0;
    this.openUntilMs = undefined;
  }

  recordFailure(): number | undefined {
    this.failureCount += 1;
    if (this.failureCount >= this.failureThreshold) {
      this.openUntilMs = this.now() + this.openMs;
    }
    return this.openUntilMs;
  }
}

const sharedLiveOperatorActionCircuit = new LiveOperatorActionCircuitBreaker();

export async function fetchLiveOperatorAction(
  input: Parameters<typeof fetch>[0],
  init: RequestInit,
  options: LiveOperatorActionFetchOptions = {},
): Promise<Response> {
  const {
    timeoutMs,
    circuitBreaker = sharedLiveOperatorActionCircuit,
    fetchImpl = fetch,
  } = options;
  const openUntilMs = circuitBreaker.currentOpenUntilMs();
  if (openUntilMs !== undefined) {
    throw new Error(`operator action circuit open until ${openUntilMs}`);
  }

  const boundedTimeoutMs = positiveInteger(
    timeoutMs,
    DEFAULT_LIVE_OPERATOR_ACTION_TIMEOUT_MS,
  );
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), boundedTimeoutMs);
  try {
    const response = await fetchImpl(input, {
      ...init,
      signal: controller.signal,
    });
    if (response.status >= 500) {
      circuitBreaker.recordFailure();
    } else {
      circuitBreaker.recordSuccess();
    }
    return response;
  } catch (error) {
    circuitBreaker.recordFailure();
    if (
      errorName(error) === "AbortError" ||
      errorName(error) === "TimeoutError"
    ) {
      throw new Error(`operator action timed out after ${boundedTimeoutMs}ms`);
    }
    throw error;
  } finally {
    clearTimeout(timer);
  }
}
