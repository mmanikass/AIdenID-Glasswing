export type PolicyDiffStatus = "unchanged" | "added" | "removed";

export interface PolicyDiffLine {
  readonly index: number;
  readonly status: PolicyDiffStatus;
  readonly currentLineNumber?: number | undefined;
  readonly proposedLineNumber?: number | undefined;
  readonly current: string;
  readonly proposed: string;
}

export interface PolicyPreviewDiffOperation {
  readonly op: string;
  readonly path: string;
}

export interface PolicyPreviewSuggestion {
  readonly id: string;
  readonly label: string;
  readonly approvalStatus: string;
  readonly riskLevel: string;
  readonly rationale: string;
  readonly outputSummary: string;
  readonly operationCount: number;
  readonly operations: readonly PolicyPreviewDiffOperation[];
}

export interface PolicyPreviewResponse {
  readonly applyPolicy: false;
  readonly changedLineCount: number;
  readonly diffLines: readonly PolicyDiffLine[];
  readonly suggestions: readonly PolicyPreviewSuggestion[];
}

export interface PolicyPreviewDecisionSample {
  readonly route_template: string;
  readonly method: string;
  readonly actor_class: string;
  readonly decision: string;
  readonly reason_codes?: readonly string[] | undefined;
  readonly occurred_at?: string | undefined;
}

export interface PolicyPreviewProxyOptions {
  readonly controlPlaneUrl?: string | undefined;
  readonly apiKey?: string | undefined;
  readonly proposedPolicyYaml: string;
  readonly prompt?: string | undefined;
  readonly inputRefs?: readonly string[] | undefined;
  readonly decisionSamples?: readonly PolicyPreviewDecisionSample[] | undefined;
  readonly maxSuggestions?: number | undefined;
}

export interface PolicyPreviewProxyRequest {
  readonly url: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: string;
}

export interface PolicyPreviewResponseOptions {
  readonly currentPolicyYaml: string;
  readonly proposedPolicyYaml: string;
  readonly copilotPayload: unknown;
}

function controlPlaneBaseUrl(controlPlaneUrl: string | undefined): string | undefined {
  if (controlPlaneUrl === undefined || controlPlaneUrl.trim().length === 0) {
    return undefined;
  }
  return controlPlaneUrl.endsWith("/") ? controlPlaneUrl : `${controlPlaneUrl}/`;
}

function splitPolicyLines(policyYaml: string): readonly string[] {
  const normalized = policyYaml.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  if (normalized.length === 0) {
    return [""];
  }
  return normalized.endsWith("\n") ? normalized.slice(0, -1).split("\n") : normalized.split("\n");
}

export function buildSideBySidePolicyDiff(currentPolicyYaml: string, proposedPolicyYaml: string): readonly PolicyDiffLine[] {
  const current = splitPolicyLines(currentPolicyYaml);
  const proposed = splitPolicyLines(proposedPolicyYaml);
  const lcs = Array.from({ length: current.length + 1 }, () => Array<number>(proposed.length + 1).fill(0));

  for (let left = current.length - 1; left >= 0; left -= 1) {
    for (let right = proposed.length - 1; right >= 0; right -= 1) {
      const row = lcs[left];
      if (row === undefined) {
        throw new Error("policy diff row index out of bounds");
      }
      row[right] =
        current[left] === proposed[right]
          ? 1 + (lcs[left + 1]?.[right + 1] ?? 0)
          : Math.max(lcs[left + 1]?.[right] ?? 0, lcs[left]?.[right + 1] ?? 0);
    }
  }

  const lines: PolicyDiffLine[] = [];
  let left = 0;
  let right = 0;
  let currentLineNumber = 1;
  let proposedLineNumber = 1;

  const pushLine = (line: Omit<PolicyDiffLine, "index">) => {
    lines.push({ index: lines.length + 1, ...line });
  };

  while (left < current.length && right < proposed.length) {
    if (current[left] === proposed[right]) {
      pushLine({
        status: "unchanged",
        currentLineNumber,
        proposedLineNumber,
        current: current[left] ?? "",
        proposed: proposed[right] ?? ""
      });
      left += 1;
      right += 1;
      currentLineNumber += 1;
      proposedLineNumber += 1;
    } else if ((lcs[left + 1]?.[right] ?? 0) >= (lcs[left]?.[right + 1] ?? 0)) {
      pushLine({
        status: "removed",
        currentLineNumber,
        current: current[left] ?? "",
        proposed: ""
      });
      left += 1;
      currentLineNumber += 1;
    } else {
      pushLine({
        status: "added",
        proposedLineNumber,
        current: "",
        proposed: proposed[right] ?? ""
      });
      right += 1;
      proposedLineNumber += 1;
    }
  }

  while (left < current.length) {
    pushLine({
      status: "removed",
      currentLineNumber,
      current: current[left] ?? "",
      proposed: ""
    });
    left += 1;
    currentLineNumber += 1;
  }

  while (right < proposed.length) {
    pushLine({
      status: "added",
      proposedLineNumber,
      current: "",
      proposed: proposed[right] ?? ""
    });
    right += 1;
    proposedLineNumber += 1;
  }

  return lines;
}

function recordFromUnknown(value: unknown): Readonly<Record<string, unknown>> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? (value as Readonly<Record<string, unknown>>) : undefined;
}

function stringFromUnknown(value: unknown): string | undefined {
  return typeof value === "string" && value.trim().length > 0 ? value : undefined;
}

function normalizeOperations(value: unknown): readonly PolicyPreviewDiffOperation[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.flatMap((operation): PolicyPreviewDiffOperation[] => {
    const source = recordFromUnknown(operation);
    const op = stringFromUnknown(source?.op);
    const path = stringFromUnknown(source?.path);
    return op === undefined || path === undefined ? [] : [{ op, path }];
  });
}

function normalizeSuggestion(value: unknown): PolicyPreviewSuggestion | undefined {
  const source = recordFromUnknown(value);
  if (source === undefined) {
    return undefined;
  }
  const outputDiff = recordFromUnknown(source.output_diff) ?? recordFromUnknown(source.outputDiff);
  const operations = normalizeOperations(outputDiff?.operations);
  return {
    id: stringFromUnknown(source.id) ?? "pcs_unknown",
    label: stringFromUnknown(source.label) ?? "ai_proposed",
    approvalStatus: stringFromUnknown(source.approval_status) ?? stringFromUnknown(source.approvalStatus) ?? "pending",
    riskLevel: stringFromUnknown(source.risk_level) ?? stringFromUnknown(source.riskLevel) ?? "low",
    rationale: stringFromUnknown(source.rationale) ?? "Policy Copilot returned a preview suggestion.",
    outputSummary: stringFromUnknown(outputDiff?.summary) ?? "",
    operationCount: operations.length,
    operations
  };
}

export function buildPolicyPreviewResponse(options: PolicyPreviewResponseOptions): PolicyPreviewResponse {
  const diffLines = buildSideBySidePolicyDiff(options.currentPolicyYaml, options.proposedPolicyYaml);
  const payload = recordFromUnknown(options.copilotPayload);
  const suggestions = Array.isArray(payload?.suggestions)
    ? payload.suggestions.flatMap((suggestion): PolicyPreviewSuggestion[] => {
        const normalized = normalizeSuggestion(suggestion);
        return normalized === undefined ? [] : [normalized];
      })
    : [];

  return {
    applyPolicy: false,
    changedLineCount: diffLines.filter((line) => line.status !== "unchanged").length,
    diffLines,
    suggestions
  };
}

export function buildPolicyPreviewProxyRequest(options: PolicyPreviewProxyOptions): PolicyPreviewProxyRequest | undefined {
  const base = controlPlaneBaseUrl(options.controlPlaneUrl);
  if (base === undefined) {
    return undefined;
  }

  return {
    url: new URL("v1/policy-copilot/suggestions", base).toString(),
    headers: {
      "Content-Type": "application/json",
      ...(options.apiKey === undefined || options.apiKey.trim().length === 0 ? {} : { Authorization: `Bearer ${options.apiKey}` })
    },
    body: JSON.stringify({
      policy_yaml: options.proposedPolicyYaml,
      decision_samples: options.decisionSamples ?? [],
      prompt: options.prompt ?? "dashboard read-only policy diff preview",
      input_refs: options.inputRefs ?? ["dashboard:policy-preview"],
      max_suggestions: options.maxSuggestions ?? 5
    })
  };
}
