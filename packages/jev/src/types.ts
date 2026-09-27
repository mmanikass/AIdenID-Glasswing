import type { z } from "zod";

import type { JEV_OUTPUT_SCHEMA } from "./schema.js";

/** Semantic risk class produced by an evaluated rubric. */
export type JevRiskClass = "low" | "elevated" | "high";

/**
 * Whether a semantic check actually ran. Only `evaluated` carries a risk class.
 * `unavailable` = provider absent, timed out, or errored. `inconclusive` = the provider
 * answered but the answer did not satisfy the output contract. `not_evaluated` = the
 * caller chose not to run the check (recorded for completeness, never inferred as safe).
 */
export type JevVerificationStatus = "evaluated" | "not_evaluated" | "unavailable" | "inconclusive";

export type JevEvidenceCoverage = "none" | "partial" | "full";

/** The only thing Jev can add to a decision: a review obligation. It never grants authority. */
export type JevObligation = "none" | "review_required";

/** One bounded question. The rubric is versioned so cached results are bound to it. */
export interface JevRubric {
  readonly id: string;
  readonly version: string;
  /** The single question the model answers about the action. */
  readonly question: string;
  /** Hard cap on untrusted purpose text characters included in the prompt. */
  readonly maxPurposeChars: number;
  /** Below this confidence an evaluated `low` still requires review. */
  readonly minConfidenceForClear: number;
}

/** Structured, trusted facts about the action. Produced by the server, never by the caller's text. */
export interface JevActionScope {
  readonly tenantId: string;
  readonly siteId: string;
  readonly subject: string;
  readonly grantId: string;
  readonly policyVersion: string;
  readonly action: string;
  readonly resource: string;
  readonly permissions: readonly string[];
}

export interface JevAssessmentInput {
  readonly rubric: JevRubric;
  readonly scope: JevActionScope;
  /** Untrusted free text supplied by the agent (purpose / intent). Data, never instructions. */
  readonly purposeText: string;
  /** Digest of the normalized business operation; binds the result to exactly this action. */
  readonly actionDigest: string;
  /** Mandatory checks leave the action non-executable when Jev cannot answer. Optional ones do not. */
  readonly mandatory: boolean;
}

export type JevProviderOutput = z.infer<typeof JEV_OUTPUT_SCHEMA>;

export interface JevProviderRequest {
  /** Fixed rubric instructions. Contains no caller-controlled text. */
  readonly system: string;
  /** Structured scope plus the delimited untrusted purpose block. */
  readonly user: string;
  readonly signal: AbortSignal;
}

/** A model provider. The core never depends on a vendor SDK; adapters implement this. */
export interface JevProvider {
  readonly modelVersion: string;
  /** Returns the model's answer as parsed JSON (any shape; the core validates it). */
  assess(request: JevProviderRequest): Promise<unknown>;
}

export interface JevAssessment {
  readonly verificationStatus: JevVerificationStatus;
  /** Present only when `verificationStatus === "evaluated"`. */
  readonly riskClass: JevRiskClass | null;
  /** Model self-reported confidence in [0, 1]; present only when evaluated. Never a permission. */
  readonly modelConfidence: number | null;
  readonly evidenceCoverage: JevEvidenceCoverage;
  readonly rationale: string | null;
  readonly obligation: JevObligation;
  /** Why the check did not evaluate, when it did not. */
  readonly unavailableReason: "no_provider" | "timeout" | "provider_error" | "malformed_output" | null;
  readonly modelVersion: string | null;
  readonly rubricId: string;
  readonly rubricVersion: string;
  readonly actionDigest: string;
  readonly cacheKey: string;
  readonly fromCache: boolean;
  readonly purposeTruncated: boolean;
  readonly evaluatedAt: string;
  readonly latencyMs: number;
}

export interface JevOptions {
  readonly provider?: JevProvider | undefined;
  /** Provider deadline. Default 4000 ms. A late answer is `unavailable`, never applied retroactively. */
  readonly timeoutMs?: number | undefined;
  /** Result cache keyed by the bound cache key. Only evaluated results are cached. */
  readonly cache?: Map<string, JevAssessment> | undefined;
  readonly now?: (() => Date) | undefined;
}
