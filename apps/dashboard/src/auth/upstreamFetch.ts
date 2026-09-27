export interface DashboardAuthFetchEnvironment extends Readonly<
  Record<string, string | undefined>
> {
  readonly AIDENID_DASHBOARD_AUTH_TIMEOUT_MS?: string | undefined;
}

export type DashboardAuthJsonFetchOptions = Omit<RequestInit, "redirect"> & {
  readonly fetchImpl?: typeof fetch | undefined;
  readonly maxResponseBytes?: number | undefined;
  readonly timeoutMs?: number | undefined;
};

export interface DashboardAuthJsonResponse {
  readonly body: unknown;
  readonly ok: boolean;
  readonly status: number;
}

const DEFAULT_DASHBOARD_AUTH_TIMEOUT_MS = 5_000;
const MIN_DASHBOARD_AUTH_TIMEOUT_MS = 250;
const MAX_DASHBOARD_AUTH_TIMEOUT_MS = 30_000;
const DEFAULT_DASHBOARD_AUTH_MAX_RESPONSE_BYTES = 64 * 1024;
const MAX_DASHBOARD_AUTH_MAX_RESPONSE_BYTES = 1024 * 1024;

function boundedInteger(
  value: number,
  defaultValue: number,
  minimum: number,
  maximum: number,
): number {
  if (!Number.isFinite(value)) {
    return defaultValue;
  }
  return Math.min(maximum, Math.max(minimum, Math.trunc(value)));
}

export function dashboardAuthTimeoutMs(
  env: DashboardAuthFetchEnvironment = process.env,
): number {
  const raw = env.AIDENID_DASHBOARD_AUTH_TIMEOUT_MS;
  if (raw === undefined || raw.trim().length === 0) {
    return DEFAULT_DASHBOARD_AUTH_TIMEOUT_MS;
  }
  return boundedInteger(
    Number(raw),
    DEFAULT_DASHBOARD_AUTH_TIMEOUT_MS,
    MIN_DASHBOARD_AUTH_TIMEOUT_MS,
    MAX_DASHBOARD_AUTH_TIMEOUT_MS,
  );
}

function dashboardAuthMaxResponseBytes(value: number | undefined): number {
  if (value === undefined) {
    return DEFAULT_DASHBOARD_AUTH_MAX_RESPONSE_BYTES;
  }
  return boundedInteger(
    value,
    DEFAULT_DASHBOARD_AUTH_MAX_RESPONSE_BYTES,
    1,
    MAX_DASHBOARD_AUTH_MAX_RESPONSE_BYTES,
  );
}

function abortError(signal: AbortSignal): unknown {
  return (
    signal.reason ?? new DOMException("The request was aborted.", "AbortError")
  );
}

async function readWithAbort(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  signal: AbortSignal,
): Promise<{
  readonly done: boolean;
  readonly value: Uint8Array | undefined;
}> {
  if (signal.aborted) {
    throw abortError(signal);
  }

  return await new Promise((resolve, reject) => {
    const onAbort = (): void => reject(abortError(signal));
    signal.addEventListener("abort", onAbort, { once: true });
    reader
      .read()
      .then(resolve, reject)
      .finally(() => {
        signal.removeEventListener("abort", onAbort);
      });
  });
}

function cancelBody(response: Response, reason: unknown): void {
  if (response.body === null) return;
  response.body.cancel(reason).catch(() => undefined);
}

async function readBoundedJsonBody(
  response: Response,
  maxResponseBytes: number,
  signal: AbortSignal,
): Promise<unknown> {
  const contentType = response.headers
    .get("content-type")
    ?.split(";", 1)[0]
    ?.trim()
    .toLowerCase();
  if (
    contentType !== "application/json" &&
    contentType?.endsWith("+json") !== true
  ) {
    cancelBody(response, "dashboard auth response was not JSON");
    throw new Error(
      "Dashboard authentication upstream returned non-JSON data.",
    );
  }

  const contentLength = response.headers.get("content-length");
  if (contentLength !== null) {
    if (!/^\d+$/.test(contentLength)) {
      cancelBody(response, "invalid content-length");
      throw new Error(
        "Dashboard authentication upstream returned an invalid Content-Length.",
      );
    }
    const declaredBytes = Number(contentLength);
    if (
      !Number.isSafeInteger(declaredBytes) ||
      declaredBytes > maxResponseBytes
    ) {
      cancelBody(response, "dashboard auth response exceeded byte limit");
      throw new Error(
        "Dashboard authentication upstream response exceeded the byte limit.",
      );
    }
  }

  if (response.body === null) {
    throw new Error(
      "Dashboard authentication upstream returned an empty body.",
    );
  }

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;
  try {
    for (;;) {
      const { done, value } = await readWithAbort(reader, signal);
      if (done) break;
      if (value === undefined) continue;
      totalBytes += value.byteLength;
      if (totalBytes > maxResponseBytes) {
        reader
          .cancel("dashboard auth response exceeded byte limit")
          .catch(() => undefined);
        throw new Error(
          "Dashboard authentication upstream response exceeded the byte limit.",
        );
      }
      chunks.push(value);
    }
  } catch (error) {
    reader.cancel(error).catch(() => undefined);
    throw error;
  } finally {
    try {
      reader.releaseLock();
    } catch {
      // Cancellation may still be settling after a deadline or caller abort.
    }
  }

  const bytes = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  return JSON.parse(text) as unknown;
}

export async function fetchDashboardAuthJson(
  input: Parameters<typeof fetch>[0],
  options: DashboardAuthJsonFetchOptions = {},
): Promise<DashboardAuthJsonResponse> {
  const {
    fetchImpl = fetch,
    maxResponseBytes: requestedMaxResponseBytes,
    timeoutMs: requestedTimeoutMs,
    ...init
  } = options;
  const timeoutMs =
    requestedTimeoutMs === undefined
      ? dashboardAuthTimeoutMs()
      : boundedInteger(
          requestedTimeoutMs,
          DEFAULT_DASHBOARD_AUTH_TIMEOUT_MS,
          MIN_DASHBOARD_AUTH_TIMEOUT_MS,
          MAX_DASHBOARD_AUTH_TIMEOUT_MS,
        );
  const maxResponseBytes = dashboardAuthMaxResponseBytes(
    requestedMaxResponseBytes,
  );
  const controller = new AbortController();
  const callerSignal = init.signal;
  const abortFromCaller = (): void => controller.abort(callerSignal?.reason);
  if (callerSignal?.aborted === true) {
    abortFromCaller();
  } else {
    callerSignal?.addEventListener("abort", abortFromCaller, { once: true });
  }
  const timeout = globalThis.setTimeout(() => {
    controller.abort(
      new DOMException(
        "Dashboard authentication upstream request timed out.",
        "TimeoutError",
      ),
    );
  }, timeoutMs);

  try {
    const response = await fetchImpl(input, {
      ...init,
      redirect: "error",
      signal: controller.signal,
    });
    if (!response.ok) {
      cancelBody(response, `dashboard auth upstream HTTP ${response.status}`);
      return { body: undefined, ok: false, status: response.status };
    }
    const body = await readBoundedJsonBody(
      response,
      maxResponseBytes,
      controller.signal,
    );
    return { body, ok: true, status: response.status };
  } finally {
    globalThis.clearTimeout(timeout);
    callerSignal?.removeEventListener("abort", abortFromCaller);
  }
}
