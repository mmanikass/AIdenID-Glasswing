import { hasHeader, readHeader } from "./headers.js";
import type { ClassificationResult, RequestHeaders } from "./types.js";

const SUSPICIOUS_UA_PARTS = ["curl", "python-requests", "headless", "playwright", "selenium", "bot"];
const BROWSER_UA_PARTS = ["mozilla", "chrome", "safari", "firefox", "edg/"];

export function classifyRequest(headers: RequestHeaders | undefined): ClassificationResult {
  const evidence: string[] = [];
  const authorization = readHeader(headers, "authorization") ?? "";

  if (
    hasHeader(headers, "signature") ||
    hasHeader(headers, "signature-input") ||
    hasHeader(headers, "dpop") ||
    authorization.trim().toLowerCase().startsWith("dpop ")
  ) {
    evidence.push("signed-request-material-present");
    return { actorClass: "signed_agent", evidence };
  }

  const userAgent = (readHeader(headers, "user-agent") ?? "").toLowerCase();
  if (SUSPICIOUS_UA_PARTS.some((part) => userAgent.includes(part))) {
    evidence.push("automation-user-agent");
    return { actorClass: "suspicious_automation", evidence };
  }

  const accept = (readHeader(headers, "accept") ?? "").toLowerCase();
  if (BROWSER_UA_PARTS.some((part) => userAgent.includes(part)) && accept.includes("text/html")) {
    evidence.push("browser-shaped-headers");
    return { actorClass: "likely_human", evidence };
  }

  evidence.push("insufficient-signal");
  return { actorClass: "unknown", evidence };
}
