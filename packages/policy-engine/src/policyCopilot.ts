import { createHash } from "node:crypto";

import { parse, stringify } from "yaml";

import { parsePolicyYaml } from "./policyLoader.js";
import { PolicyDocumentInputSchema, type ActorDecisionInput, type PolicyDocument, type RatePolicyInput } from "./schema.js";
import type { ActorClass, DecisionAction } from "./types.js";

export type PolicyCopilotLabel = "ai_proposed";
export type PolicyCopilotApprovalStatus = "pending" | "approved" | "rejected";
export type PolicyCopilotRiskLevel = "low" | "medium";

export interface PolicyCopilotDecisionSample {
  readonly routeTemplate: string;
  readonly method: string;
  readonly actorClass: ActorClass;
  readonly decision: DecisionAction;
  readonly reasonCodes?: readonly string[] | undefined;
  readonly occurredAt?: string | undefined;
}

export interface PolicyCopilotInput {
  readonly policyYaml: string;
  readonly decisionSamples: readonly PolicyCopilotDecisionSample[];
  readonly prompt?: string | undefined;
  readonly inputRefs?: readonly string[] | undefined;
  readonly generatedAt?: string | undefined;
  readonly suspiciousAutomationThreshold?: number | undefined;
  readonly maxSuggestions?: number | undefined;
}

export interface PolicyCopilotDiffOperation {
  readonly op: "add" | "replace";
  readonly path: string;
  readonly before?: unknown;
  readonly after: unknown;
}

export interface PolicyCopilotOutputDiff {
  readonly format: "aidenid.policy.diff.v1";
  readonly operations: readonly PolicyCopilotDiffOperation[];
  readonly summary: string;
}

export interface PolicyCopilotMetadata {
  readonly model: "offline-policy-copilot-rules-v1";
  readonly tool: "aidenid-policy-copilot";
  readonly promptDigestSha256: string;
  readonly inputRefs: readonly string[];
  readonly generatedAt: string;
}

export interface PolicyCopilotSuggestion {
  readonly id: string;
  readonly label: PolicyCopilotLabel;
  readonly approvalStatus: PolicyCopilotApprovalStatus;
  readonly riskLevel: PolicyCopilotRiskLevel;
  readonly rationale: string;
  readonly metadata: PolicyCopilotMetadata;
  readonly policySha256: string;
  readonly proposedPolicySha256: string;
  readonly proposedPolicyYaml: string;
  readonly outputDiff: PolicyCopilotOutputDiff;
  readonly reviewer?: string | undefined;
  readonly reviewedAt?: string | undefined;
  readonly reviewComment?: string | undefined;
}

export interface PolicyCopilotReview {
  readonly reviewer: string;
  readonly reviewedAt: string;
  readonly comment?: string | undefined;
}

export interface PolicyCopilotGoldenVector {
  readonly method: string;
  readonly path: string;
  readonly actorClass: ActorClass;
  readonly expectedDecision: DecisionAction;
}

export interface PolicyCopilotGoldenFailure {
  readonly vector: PolicyCopilotGoldenVector;
  readonly actualDecision: DecisionAction;
}

export interface PolicyCopilotGoldenVerification {
  readonly ok: boolean;
  readonly failures: readonly PolicyCopilotGoldenFailure[];
}

const DEFAULT_PROMPT = "AIdenID offline Policy Copilot proposes review-gated policy diffs only.";
const DEFAULT_SUSPICIOUS_AUTOMATION_THRESHOLD = 3;
const DEFAULT_MAX_SUGGESTIONS = 5;
const DEFAULT_THROTTLE_RATE: RatePolicyInput = { capacity: 10, refill_per_sec: 1, cost: 1 };
const DEFENSIVE_DECISIONS = new Set<DecisionAction>(["throttle", "deny", "sandbox"]);

function sha256Hex(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function parsePolicyDocument(policyYaml: string): PolicyDocument {
  return PolicyDocumentInputSchema.parse(parse(policyYaml));
}

function cloneRate(rate: RatePolicyInput): RatePolicyInput {
  return { capacity: rate.capacity, refill_per_sec: rate.refill_per_sec, cost: rate.cost };
}

function cloneActorDecision(input: ActorDecisionInput): ActorDecisionInput {
  return {
    decision: input.decision,
    ...(input.rate === undefined ? {} : { rate: cloneRate(input.rate) }),
    ...(input.strict === undefined ? {} : { strict: input.strict }),
    ...(input.signature_required === undefined ? {} : { signature_required: [...input.signature_required] }),
    ...(input.queue_retry_s === undefined ? {} : { queue_retry_s: input.queue_retry_s }),
    ...(input.retry_after_s === undefined ? {} : { retry_after_s: input.retry_after_s }),
    ...(input.price_usd === undefined ? {} : { price_usd: input.price_usd }),
    ...(input.sandbox_origin === undefined ? {} : { sandbox_origin: input.sandbox_origin })
  };
}

function clonePolicyDocument(document: PolicyDocument): PolicyDocument {
  return {
    version: document.version,
    site_id: document.site_id,
    mode: document.mode,
    defaults: {
      strict: document.defaults.strict,
      on_degraded: document.defaults.on_degraded,
      ...(document.defaults.sandbox_origin === undefined ? {} : { sandbox_origin: document.defaults.sandbox_origin }),
      suspicion_threshold: document.defaults.suspicion_threshold,
      rate: cloneRate(document.defaults.rate)
    },
    routes: document.routes.map((route) => ({
      template: route.template,
      method: route.method,
      ...(route.route_bucket === undefined ? {} : { route_bucket: route.route_bucket }),
      ...(route.strict === undefined ? {} : { strict: route.strict }),
      ...(route.on_degraded === undefined ? {} : { on_degraded: route.on_degraded }),
      signature_required: [...route.signature_required],
      ...(route.rate === undefined ? {} : { rate: cloneRate(route.rate) }),
      ...(route.queue_retry_s === undefined ? {} : { queue_retry_s: route.queue_retry_s }),
      ...(route.retry_after_s === undefined ? {} : { retry_after_s: route.retry_after_s }),
      ...(route.sandbox_origin === undefined ? {} : { sandbox_origin: route.sandbox_origin }),
      per_actor_class: Object.fromEntries(
        Object.entries(route.per_actor_class).map(([actorClass, actorDecision]) => [actorClass, cloneActorDecision(actorDecision)])
      )
    }))
  };
}

function diffOperation(op: "add" | "replace", path: string, before: unknown, after: unknown): PolicyCopilotDiffOperation {
  return {
    op,
    path,
    ...(before === undefined ? {} : { before }),
    after
  };
}

function stringifyAndValidatePolicy(document: PolicyDocument): string {
  const policyYaml = stringify(document);
  parsePolicyYaml(policyYaml);
  return policyYaml;
}

function createSuggestion(
  input: PolicyCopilotInput,
  basePolicyYaml: string,
  nextDocument: PolicyDocument,
  operations: readonly PolicyCopilotDiffOperation[],
  rationale: string,
  riskLevel: PolicyCopilotRiskLevel,
  stableSuffix: string
): PolicyCopilotSuggestion {
  const proposedPolicyYaml = stringifyAndValidatePolicy(nextDocument);
  const policySha256 = sha256Hex(basePolicyYaml);
  const proposedPolicySha256 = sha256Hex(proposedPolicyYaml);
  const promptDigestSha256 = sha256Hex(input.prompt ?? DEFAULT_PROMPT);
  const id = `pcs_${sha256Hex(`${policySha256}:${proposedPolicySha256}:${stableSuffix}`).slice(0, 20)}`;

  return {
    id,
    label: "ai_proposed",
    approvalStatus: "pending",
    riskLevel,
    rationale,
    metadata: {
      model: "offline-policy-copilot-rules-v1",
      tool: "aidenid-policy-copilot",
      promptDigestSha256,
      inputRefs: input.inputRefs ?? [],
      generatedAt: input.generatedAt ?? new Date().toISOString()
    },
    policySha256,
    proposedPolicySha256,
    proposedPolicyYaml,
    outputDiff: {
      format: "aidenid.policy.diff.v1",
      operations,
      summary: operations.map((operation) => `${operation.op} ${operation.path}`).join("; ")
    }
  };
}

function routeMatchesSample(route: PolicyDocument["routes"][number], sample: PolicyCopilotDecisionSample): boolean {
  return route.template === sample.routeTemplate && (route.method === "*" || route.method === sample.method.toUpperCase());
}

function suspiciousAutomationCount(route: PolicyDocument["routes"][number], samples: readonly PolicyCopilotDecisionSample[]): number {
  return samples.filter((sample) => sample.actorClass === "suspicious_automation" && routeMatchesSample(route, sample)).length;
}

export function suggestPolicyDiffs(input: PolicyCopilotInput): readonly PolicyCopilotSuggestion[] {
  const document = parsePolicyDocument(input.policyYaml);
  const suggestions: PolicyCopilotSuggestion[] = [];
  const suspiciousThreshold = input.suspiciousAutomationThreshold ?? DEFAULT_SUSPICIOUS_AUTOMATION_THRESHOLD;

  document.routes.forEach((route, index) => {
    if (route.signature_required.length > 0 && (route.strict !== true || route.on_degraded !== "deny")) {
      const next = clonePolicyDocument(document);
      const nextRoute = next.routes[index];
      if (nextRoute === undefined) {
        throw new Error("policy route index disappeared during clone");
      }
      const operations: PolicyCopilotDiffOperation[] = [];
      if (nextRoute.strict !== true) {
        operations.push(diffOperation(nextRoute.strict === undefined ? "add" : "replace", `/routes/${index}/strict`, nextRoute.strict, true));
        nextRoute.strict = true;
      }
      if (nextRoute.on_degraded !== "deny") {
        operations.push(
          diffOperation(nextRoute.on_degraded === undefined ? "add" : "replace", `/routes/${index}/on_degraded`, nextRoute.on_degraded, "deny")
        );
        nextRoute.on_degraded = "deny";
      }
      suggestions.push(
        createSuggestion(
          input,
          input.policyYaml,
          next,
          operations,
          `Route ${route.method} ${route.template} requires signatures and should fail closed when dependencies degrade.`,
          "medium",
          `strict:${index}:${route.method}:${route.template}`
        )
      );
    }

    const suspiciousCount = suspiciousAutomationCount(route, input.decisionSamples);
    const suspiciousPolicy = route.per_actor_class.suspicious_automation;
    if (suspiciousCount >= suspiciousThreshold && !DEFENSIVE_DECISIONS.has(suspiciousPolicy?.decision ?? "allow")) {
      const next = clonePolicyDocument(document);
      const nextRoute = next.routes[index];
      if (nextRoute === undefined) {
        throw new Error("policy route index disappeared during clone");
      }
      const before = nextRoute.per_actor_class.suspicious_automation;
      nextRoute.per_actor_class.suspicious_automation = {
        ...(before === undefined ? {} : before),
        decision: "throttle",
        rate: before?.rate === undefined ? DEFAULT_THROTTLE_RATE : before.rate
      };
      suggestions.push(
        createSuggestion(
          input,
          input.policyYaml,
          next,
          [
            diffOperation(
              before === undefined ? "add" : "replace",
              `/routes/${index}/per_actor_class/suspicious_automation`,
              before,
              nextRoute.per_actor_class.suspicious_automation
            )
          ],
          `Route ${route.method} ${route.template} saw ${suspiciousCount} suspicious automation samples without a defensive actor policy.`,
          "low",
          `suspicious:${index}:${route.method}:${route.template}:${suspiciousCount}`
        )
      );
    }
  });

  return suggestions.slice(0, input.maxSuggestions ?? DEFAULT_MAX_SUGGESTIONS);
}

function assertReviewer(review: PolicyCopilotReview): void {
  if (!review.reviewer.trim()) {
    throw new Error("policy copilot approval requires a human reviewer");
  }
}

export function approvePolicySuggestion(suggestion: PolicyCopilotSuggestion, review: PolicyCopilotReview): PolicyCopilotSuggestion {
  assertReviewer(review);
  return {
    ...suggestion,
    approvalStatus: "approved",
    reviewer: review.reviewer,
    reviewedAt: review.reviewedAt,
    ...(review.comment === undefined ? {} : { reviewComment: review.comment })
  };
}

export function rejectPolicySuggestion(suggestion: PolicyCopilotSuggestion, review: PolicyCopilotReview): PolicyCopilotSuggestion {
  assertReviewer(review);
  return {
    ...suggestion,
    approvalStatus: "rejected",
    reviewer: review.reviewer,
    reviewedAt: review.reviewedAt,
    ...(review.comment === undefined ? {} : { reviewComment: review.comment })
  };
}

export function verifyPolicySuggestionAgainstGoldenVectors(
  suggestion: PolicyCopilotSuggestion,
  vectors: readonly PolicyCopilotGoldenVector[]
): PolicyCopilotGoldenVerification {
  const loaded = parsePolicyYaml(suggestion.proposedPolicyYaml);
  const failures = vectors.flatMap((vector): PolicyCopilotGoldenFailure[] => {
    const match = loaded.trie.match(vector.method, vector.path, vector.actorClass);
    const actualDecision = match.actorPolicy.decision ?? "allow";
    return actualDecision === vector.expectedDecision ? [] : [{ vector, actualDecision }];
  });

  return {
    ok: failures.length === 0,
    failures
  };
}
