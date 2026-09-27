export type ControlPlaneHealthState = "connected" | "unavailable";

export interface ControlPlaneHealthEnvironment {
  readonly AIDENID_CONTROL_PLANE_URL?: string | undefined;
}

function healthEndpoint(value: string): URL | undefined {
  try {
    const base = new URL(value);
    if (
      (base.protocol !== "http:" && base.protocol !== "https:") ||
      base.username.length > 0 ||
      base.password.length > 0 ||
      base.search.length > 0 ||
      base.hash.length > 0
    ) {
      return undefined;
    }
    return new URL("/healthz", base);
  } catch {
    return undefined;
  }
}

export async function checkControlPlaneHealth(
  env: ControlPlaneHealthEnvironment,
  fetchImpl: typeof fetch = fetch,
  timeoutMs = 1_500,
): Promise<ControlPlaneHealthState> {
  const configuredUrl = env.AIDENID_CONTROL_PLANE_URL?.trim();
  if (!configuredUrl) {
    return "unavailable";
  }
  const endpoint = healthEndpoint(configuredUrl);
  if (endpoint === undefined) {
    return "unavailable";
  }

  const boundedTimeoutMs =
    Number.isInteger(timeoutMs) && timeoutMs > 0
      ? Math.min(timeoutMs, 5_000)
      : 1_500;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), boundedTimeoutMs);
  try {
    const response = await fetchImpl(endpoint, {
      method: "GET",
      cache: "no-store",
      signal: controller.signal,
    });
    if (!response.ok) {
      return "unavailable";
    }
    const body: unknown = await response.json();
    if (
      body !== null &&
      typeof body === "object" &&
      !Array.isArray(body) &&
      (body as Readonly<Record<string, unknown>>).ok === true &&
      (body as Readonly<Record<string, unknown>>).service ===
        "aidenid-control-plane"
    ) {
      return "connected";
    }
    return "unavailable";
  } catch {
    return "unavailable";
  } finally {
    clearTimeout(timer);
  }
}
