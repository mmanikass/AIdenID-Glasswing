export const OMAR_GATE_ACTION_REF = "mrrCarter/sentinelayer-v1-action@1eed812b92b9463a5fd51b6c906c8988b7c1bd3f";
export const AIDENID_VERIFIER_GATE_WORKFLOW_REF =
  "mrrCarter/aidenid-clearance/.github/workflows/aidenid-verifier-gate.yml@v0";

export const OMAR_GATE_REQUIRED_SECRETS = ["SENTINELAYER_TOKEN", "OPENAI_API_KEY"] as const;
export const OMAR_GATE_REQUIRED_VARIABLES = ["SENTINELAYER_SPEC_ID"] as const;

export interface AidenIdVerifierGateJobOptions {
  readonly workflowRef?: string | undefined;
  readonly sentinelayerSpecVariable?: string | undefined;
  readonly scanMode?: "deep" | "nightly" | undefined;
  readonly severityGate?: "P0" | "P1" | "P2" | "none" | undefined;
}

function safeVariableName(name: string): string {
  if (!/^[A-Z][A-Z0-9_]*$/.test(name)) {
    throw new Error(`invalid GitHub variable name: ${name}`);
  }
  return name;
}

export function renderAidenIdVerifierGateJob(options: AidenIdVerifierGateJobOptions = {}): string {
  const workflowRef = options.workflowRef ?? AIDENID_VERIFIER_GATE_WORKFLOW_REF;
  const specVariable = safeVariableName(options.sentinelayerSpecVariable ?? "SENTINELAYER_SPEC_ID");
  const scanMode = options.scanMode ?? "deep";
  const severityGate = options.severityGate ?? "P1";

  return [
    "aidenid-verifier-gate:",
    `  uses: ${workflowRef}`,
    "  secrets: inherit",
    "  with:",
    `    sentinelayer_spec_id: \${{ vars.${specVariable} }}`,
    `    scan_mode: ${scanMode}`,
    `    severity_gate: ${severityGate}`
  ].join("\n");
}
