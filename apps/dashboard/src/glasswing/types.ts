/**
 * Glasswing operator API contract (implemented by apps/protected-site under /glasswing/*,
 * proxied by this dashboard under /api/glasswing/*). Frozen in the build room on
 * 2026-09-27; change here only together with the protected site.
 */
import type { ActorClass, DecisionAction } from "../dashboardModel.js";

export type GlasswingTask = "catalog" | "reserve" | "export" | "bulk-report";

export const GLASSWING_TASKS: readonly { readonly task: GlasswingTask; readonly label: string; readonly hint: string }[] = [
  { task: "catalog", label: "Read catalog", hint: "In scope: catalog:read" },
  { task: "reserve", label: "Reserve item", hint: "State change, in scope, parameters in the path" },
  { task: "export", label: "Export customers", hint: "Out of scope: expected deny" },
  { task: "bulk-report", label: "Bulk report", hint: "Ambiguous: purpose required, Jev review" }
];

export interface GlasswingAgent {
  readonly id: string;
  readonly keyId: string;
  readonly thumbprint: string;
  readonly publicJwk: Readonly<Record<string, unknown>>;
  readonly createdAt: string;
}

export interface GlasswingGrant {
  readonly id: string;
  readonly chainId: string;
  readonly siteId: string;
  readonly resource: string;
  readonly permissions: readonly string[];
  readonly expiresAt: string;
}

export interface GlasswingJevAssessment {
  readonly verificationStatus: "evaluated" | "not_evaluated" | "unavailable" | "inconclusive";
  readonly riskClass: "low" | "elevated" | "high" | null;
  readonly modelConfidence: number | null;
  readonly evidenceCoverage: "none" | "partial" | "full";
  readonly rationale: string | null;
  readonly obligation: "none" | "review_required";
  readonly unavailableReason: "no_provider" | "timeout" | "provider_error" | "malformed_output" | null;
  readonly modelVersion: string | null;
  readonly latencyMs: number;
}

export interface GlasswingRunResult {
  readonly request: { readonly method: string; readonly url: string };
  readonly session: { readonly sessionId: string; readonly revocationEpoch: number } | null;
  readonly decision: {
    readonly requestId: string;
    readonly decisionId: string | null;
    readonly action: DecisionAction;
    readonly reasonCodes: readonly string[];
    readonly actorClass: ActorClass;
  } | null;
  readonly effect: { readonly ok: boolean; readonly reason?: string | undefined; readonly value?: unknown } | null;
  readonly jev: GlasswingJevAssessment | null;
  readonly error?: { readonly code: string; readonly message: string } | undefined;
}

export interface GlasswingReview {
  readonly id: string;
  readonly requestId: string;
  readonly agentId: string;
  readonly task: GlasswingTask;
  readonly purpose: string;
  readonly assessment: GlasswingJevAssessment;
  readonly status: "pending" | "approved" | "denied";
}

export interface GlasswingRevocation {
  readonly id: string;
  readonly chainId: string;
  readonly epoch: number;
}
