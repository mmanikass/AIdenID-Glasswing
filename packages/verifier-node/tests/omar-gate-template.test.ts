import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  AIDENID_VERIFIER_GATE_WORKFLOW_REF,
  OMAR_GATE_ACTION_REF,
  OMAR_GATE_REQUIRED_SECRETS,
  OMAR_GATE_REQUIRED_VARIABLES,
  renderAidenIdVerifierGateJob
} from "../src/omarGateTemplate.js";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const reusableWorkflowPath = path.join(repoRoot, ".github", "workflows", "aidenid-verifier-gate.yml");
const packageTemplatePath = path.join(
  repoRoot,
  "packages",
  "verifier-node",
  "templates",
  "github",
  "aidenid-omar-gate.yml"
);
const packageJsonPath = path.join(repoRoot, "packages", "verifier-node", "package.json");
const evidencePath = path.join(repoRoot, "docs", "dd", "artifacts", "omar-gate-integration-2026-04-24.json");

const readRepoFile = (filePath: string): string => readFileSync(filePath, "utf8");

describe("verifier Omar Gate customer template", () => {
  it("packages a one-job customer workflow template", () => {
    const template = readRepoFile(packageTemplatePath);

    expect(template).toContain(`uses: ${AIDENID_VERIFIER_GATE_WORKFLOW_REF}`);
    expect(template).toContain("secrets: inherit");
    expect(template).toContain("sentinelayer_spec_id: ${{ vars.SENTINELAYER_SPEC_ID }}");
    expect(template).toContain("severity_gate: P1");
    expect(template).not.toMatch(/sk-[A-Za-z0-9]/);
    expect(template).not.toMatch(/sentinelayer_token:\s+['"]?[A-Za-z0-9_-]{12,}/i);
  });

  it("renders safe workflow job snippets for generators", () => {
    expect(renderAidenIdVerifierGateJob()).toBe(
      [
        "aidenid-verifier-gate:",
        `  uses: ${AIDENID_VERIFIER_GATE_WORKFLOW_REF}`,
        "  secrets: inherit",
        "  with:",
        "    sentinelayer_spec_id: ${{ vars.SENTINELAYER_SPEC_ID }}",
        "    scan_mode: deep",
        "    severity_gate: P1"
      ].join("\n")
    );

    expect(
      renderAidenIdVerifierGateJob({
        sentinelayerSpecVariable: "AIDENID_SENTINELAYER_SPEC_ID",
        scanMode: "nightly",
        severityGate: "P2"
      })
    ).toContain("sentinelayer_spec_id: ${{ vars.AIDENID_SENTINELAYER_SPEC_ID }}");
    expect(() => renderAidenIdVerifierGateJob({ sentinelayerSpecVariable: "SENTINELAYER_SPEC_ID }} # injected" })).toThrow(
      /invalid GitHub variable name/
    );
  });

  it("keeps the reusable workflow pinned and fail-closed", () => {
    const workflow = readRepoFile(reusableWorkflowPath);

    expect(workflow).toContain("workflow_call:");
    expect(workflow).toContain("pull-requests: write");
    expect(workflow).toMatch(/actions\/checkout@[0-9a-f]{40}/);
    expect(workflow).toContain(`uses: ${OMAR_GATE_ACTION_REF}`);
    expect(workflow).toContain("severity_gate:");
    expect(workflow).toContain("default: P1");
    expect(workflow).toContain("SENTINELAYER_SPEC_ID is required");
    expect(workflow).toContain("OPENAI_API_KEY:");
    expect(workflow).toContain("github_token: ${{ github.token }}");
    expect(workflow).toContain("openai_api_key: ${{ secrets.OPENAI_API_KEY }}");
    expect(workflow).toContain('sentinelayer_managed_llm: "false"');
    expect(workflow).toContain("llm_provider: openai");
    expect(workflow).toContain("llm_failure_policy: block");
    expect(workflow).toContain('if [ "${p0}" -gt 0 ] || [ "${p1}" -gt 0 ]; then');
    expect(workflow).toContain("Omar Gate blocked");
    expect(workflow).not.toContain("id-token: write");
  });

  it("exports templates and documents required caller configuration", () => {
    const packageJson = JSON.parse(readRepoFile(packageJsonPath)) as {
      files?: string[];
      exports?: Record<string, unknown>;
    };
    const evidence = JSON.parse(readRepoFile(evidencePath)) as {
      reusable_workflow?: string;
      packaged_template?: string;
      default_scan_mode?: string;
      default_severity_gate?: string;
      fail_closed_assertions?: string[];
    };

    expect(packageJson.files).toEqual(expect.arrayContaining(["dist", "templates", "README.md"]));
    expect(packageJson.exports).toHaveProperty("./templates/github/aidenid-omar-gate.yml");
    expect(existsSync(packageTemplatePath)).toBe(true);
    expect(OMAR_GATE_REQUIRED_SECRETS).toEqual(["SENTINELAYER_TOKEN", "OPENAI_API_KEY"]);
    expect(OMAR_GATE_REQUIRED_VARIABLES).toEqual(["SENTINELAYER_SPEC_ID"]);
    expect(evidence).toMatchObject({
      reusable_workflow: ".github/workflows/aidenid-verifier-gate.yml",
      packaged_template: "packages/verifier-node/templates/github/aidenid-omar-gate.yml",
      default_scan_mode: "deep",
      default_severity_gate: "P1"
    });
    expect(evidence.fail_closed_assertions).toEqual(
      expect.arrayContaining([
        "p0_p1_threshold_enforced",
        "actions_pinned_by_commit_sha",
        "byo_openai_managed_llm_disabled"
      ])
    );
  });
});
