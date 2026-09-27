import type { RequestHeaders } from "./types.js";

export function readHeader(headers: RequestHeaders | undefined, name: string): string | undefined {
  if (headers === undefined) {
    return undefined;
  }

  const get = "get" in headers && typeof headers.get === "function" ? headers.get.bind(headers) : null;
  if (get !== null) {
    return get(name) ?? undefined;
  }

  const wanted = name.toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() !== wanted || value === undefined) {
      continue;
    }
    return Array.isArray(value) ? value.join(", ") : value;
  }

  return undefined;
}

export function hasHeader(headers: RequestHeaders | undefined, name: string): boolean {
  return readHeader(headers, name) !== undefined;
}
