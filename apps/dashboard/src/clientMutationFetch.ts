export const DASHBOARD_CLIENT_MUTATION_TIMEOUT_MS = 10_000;

function isAbortError(error: unknown): boolean {
  return error instanceof Error && error.name === "AbortError";
}

export async function fetchWithDashboardMutationTimeout(
  input: Parameters<typeof fetch>[0],
  init: RequestInit = {},
  timeoutMs = DASHBOARD_CLIENT_MUTATION_TIMEOUT_MS,
): Promise<Response> {
  if (!Number.isFinite(timeoutMs) || timeoutMs < 1) {
    throw new Error("Dashboard mutation timeout must be a positive integer.");
  }

  const controller = new AbortController();
  const callerSignal = init.signal;
  const abortFromCaller = (): void => controller.abort(callerSignal?.reason);
  if (callerSignal?.aborted === true) {
    abortFromCaller();
  } else {
    callerSignal?.addEventListener("abort", abortFromCaller, { once: true });
  }
  const timeout = globalThis.setTimeout(() => controller.abort(), timeoutMs);

  try {
    return await fetch(input, { ...init, signal: controller.signal });
  } catch (error) {
    if (isAbortError(error)) {
      throw new Error(`Dashboard request timed out after ${timeoutMs}ms.`);
    }
    throw error;
  } finally {
    callerSignal?.removeEventListener("abort", abortFromCaller);
    globalThis.clearTimeout(timeout);
  }
}
