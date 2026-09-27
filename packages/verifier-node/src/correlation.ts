import { randomUUID } from "node:crypto";

import { readHeader } from "./headers.js";
import type { RequestHeaders } from "./types.js";

export function resolveRequestId(headers: RequestHeaders | undefined): string {
  return readHeader(headers, "x-request-id") ?? readHeader(headers, "x-correlation-id") ?? `req_${randomUUID()}`;
}
