import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../..",
);
const workflowsRoot = path.join(repoRoot, ".github", "workflows");
const actionsRoot = path.join(repoRoot, ".github", "actions");

const readRepoFile = (file: string): string =>
  readFileSync(path.join(repoRoot, file), "utf8");
const readWorkflow = (file: string): string =>
  readFileSync(path.join(workflowsRoot, file), "utf8");
const readAction = (file: string): string =>
  readFileSync(path.join(actionsRoot, file), "utf8");
const listFiles = (root: string): string[] =>
  readdirSync(root, { withFileTypes: true }).flatMap((entry) => {
    const resolved = path.join(root, entry.name);
    return entry.isDirectory() ? listFiles(resolved) : [resolved];
  });
const readGithubFiles = (): readonly {
  readonly path: string;
  readonly content: string;
}[] =>
  listFiles(path.join(repoRoot, ".github")).map((file) => ({
    path: path.relative(repoRoot, file).replaceAll("\\", "/"),
    content: readFileSync(file, "utf8"),
  }));

describe("workflow hardening", () => {
  it("serializes CI and publishes an immutable build artifact", () => {
    const ci = readWorkflow("ci.yml");
    const retryAction = readAction(path.join("retry-command", "action.yml"));

    expect(ci).toContain("concurrency:");
    expect(ci).toContain(
      "group: ci-${{ github.workflow }}-${{ github.event.pull_request.head.sha || github.sha }}",
    );
    expect(ci).toContain(
      "cancel-in-progress: ${{ github.event_name == 'pull_request' }}",
    );
    const topPermissions = ci.slice(
      ci.indexOf("permissions:"),
      ci.indexOf("env:"),
    );
    const buildBlock = ci.slice(
      ci.indexOf("  build:"),
      ci.indexOf("  quality:"),
    );
    const jobNames = [
      "prepare",
      "lint",
      "python_wheelhouse",
      "test",
      "security",
      "build",
      "quality",
    ];
    for (const job of ["prepare", "lint", "test", "security", "quality"]) {
      const start = ci.indexOf(`  ${job}:`);
      const next = jobNames
        .map((candidate) => ci.indexOf(`\n  ${candidate}:`, start + 1))
        .filter((index) => index > start)
        .sort((left, right) => left - right)[0];
      const block = ci.slice(start, next === -1 ? undefined : next);
      expect(block).toContain("permissions:");
      expect(block).toContain("actions: read");
      expect(block).toContain("contents: read");
      expect(block).not.toContain("id-token: write");
      expect(block).not.toContain("attestations: write");
    }
    expect(topPermissions).toContain("contents: read");
    expect(topPermissions).not.toContain("id-token: write");
    expect(topPermissions).not.toContain("attestations: write");
    expect(buildBlock).toContain("permissions:");
    expect(buildBlock).toContain("id-token: write");
    expect(buildBlock).toContain("attestations: write");
    const pythonWheelhouseBlock = ci.slice(
      ci.indexOf("  python_wheelhouse:"),
      ci.indexOf("  test:"),
    );
    expect(pythonWheelhouseBlock).toContain("permissions:");
    expect(pythonWheelhouseBlock).toContain("id-token: write");
    expect(pythonWheelhouseBlock).toContain("attestations: write");
    expect(ci).toContain("runs-on: ubuntu-22.04");
    expect(ci).toContain('CI_WORKFLOW_TIMEOUT_BUDGET_MINUTES: "75"');
    expect(ci).toContain('CI_RETRY_MAX_ELAPSED_SECONDS: "900"');
    expect(ci).toContain("Record CI workflow timeout budget");
    expect(ci).toContain("ci_workflow_timeout_budget");
    expect(ci).toContain("top_level_workflow_timeout_emulated: true");
    expect(ci).toContain("retry_command_global_elapsed_budget_required: true");
    expect(ci).toMatch(/actions\/setup-python@[0-9a-f]{40}/);
    expect(ci).toContain('python-version: "3.12"');
    expect(ci).toContain(
      "packages/verifier-python/requirements-ci-linux-py312.txt",
    );
    expect(ci).toContain("pip download --require-hashes");
    expect(ci).toContain(
      "python -m pip install --no-index --find-links python-wheelhouse-input/python-wheelhouse --require-hashes",
    );
    expect(ci).toContain("python -m pip install --no-deps -e");
    expect(ci).toContain('PNPM_VERSION: "10.28.0"');
    expect(ci).toContain('corepack prepare "pnpm@${PNPM_VERSION}" --activate');
    expect(ci).toContain('test "$(pnpm --version)" = "${PNPM_VERSION}"');
    expect(ci).toContain("pnpm install --ignore-scripts --frozen-lockfile");
    expect(ci).toContain("uses: ./.github/actions/retry-command");
    expect(retryAction).toContain(
      "retry-command failed after ${RETRY_ATTEMPTS} attempts",
    );
    expect(retryAction).toContain(
      "retry-command attempt ${attempt}/${RETRY_ATTEMPTS} failed",
    );
    expect(retryAction).toContain("RETRY_MAX_ELAPSED_SECONDS");
    expect(retryAction).toContain("retry-command global elapsed budget");
    expect(retryAction).toContain('timeout --kill-after=30s "${remaining}s"');
    expect(ci).toContain("name: python wheelhouse");
    expect(ci).toContain("python-wheelhouse-pip-version.txt");
    expect(ci).toContain("python-wheelhouse-provenance.json");
    expect(ci).toContain("python_wheelhouse_provenance");
    expect(ci).toContain(
      "Generate signed Python wheelhouse provenance attestation",
    );
    expect(ci).toContain("subject-path: python-wheelhouse-manifest.sha256");
    expect(ci).toContain(
      "signed Python wheelhouse provenance attestation verification failed before artifact upload",
    );
    expect(ci).toContain(
      "python_wheelhouse_provenance_required_for_attestation: true",
    );
    expect(ci).toContain(
      "retry_with_backoff_timeout 600s python -m pip download --require-hashes",
    );
    expect(ci).toContain("built_in_dedicated_ci_job: true");
    expect(ci).toContain("network_resolution_isolated_from_tests: true");
    expect(ci).toContain("python-wheelhouse-input");
    expect(ci).toContain(
      "timeout --kill-after=30s 600s python -m pip install --no-index --find-links python-wheelhouse-input/python-wheelhouse --require-hashes",
    );
    expect(ci).toContain("timeout --kill-after=30s");
    expect(ci).not.toContain("python -m pip install --upgrade pip");
    expect(ci).toContain("command: pnpm audit:high");
    expect(ci).toContain("command: pnpm audit:critical");
    expect(ci).not.toContain("pnpm install --frozen-lockfile");
    expect(ci).toContain("prepare immutable ci inputs");
    expect(ci).toContain("ci-immutable-inputs-${GITHUB_SHA}");
    expect(ci).toContain("Verify promoted immutable CI input artifact");
    expect(ci).toContain(
      "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
    );
    expect(ci).not.toContain('gh run download "${GITHUB_RUN_ID}"');
    expect(ci).toContain("artifact_promotion");
    expect(ci).toContain("immutable_inputs: true");
    expect(ci).toContain("node scripts/write-ci-input-manifest.mjs");
    expect(ci).toContain("ci-inputs-files.txt");
    expect(ci).toContain("bound_input_manifest: true");
    expect(ci).toContain("Verify repository-wide pinned action policy");
    expect(ci).toContain("node scripts/verify-workflow-action-pins.mjs");
    expect(ci).toContain("workflow-action-pins.json");
    expect(ci).toContain("repository-wide full-SHA GitHub Actions pin policy");
    expect(ci).toContain("workspace package manifests");
    expect(ci).toContain("package, app, and lab source/test files");
    expect(ci).toContain("workflow and composite action definitions");
    expect(ci).toContain("deployment drill evidence artifacts");
    expect(ci).toContain("Terraform runtime and environment inputs");
    expect(ci).toContain("diff -u .ci-immutable-inputs/ci-inputs.sha256");
    expect(ci).toContain(
      "diff -u .ci-immutable-inputs/ci-inputs-files.txt ci-inputs.current.txt",
    );
    expect(ci).toContain("  lint:");
    expect(ci).toContain("    needs: [prepare]");
    expect(ci).toContain("  test:");
    expect(ci).toContain("    needs: [prepare, lint, python_wheelhouse]");
    expect(ci).toContain("  security:");
    expect(ci).toContain("    needs: [prepare, lint, test]");
    expect(ci).toContain("  build:");
    expect(ci).toContain("    needs: [prepare, security]");
    expect(ci).toContain("  sbom:");
    expect(ci).toContain("    needs: [prepare, build]");
    expect(ci).toContain("ci-sbom-gate-contract-${{ github.sha }}");
    expect(ci).toContain("  quality:");
    expect(ci).toContain(
      "    needs: [prepare, lint, test, security, build, sbom]",
    );
    expect(ci).toContain("aidenid-clearance-build-${{ github.sha }}");
    expect(ci).toContain("Pack verifier-node SDK tarball bundle");
    expect(ci).toContain("node scripts/pack-verifier-sdk.mjs");
    expect(ci).toContain("node scripts/verify-verifier-sdk-pack.mjs");
    expect(ci).toContain("aidenid-verifier-node-sdk-${{ github.sha }}");
    expect(ci).toContain("verifier-node-sdk-pack/**");
    expect(ci).toContain("Record canonical build artifact digest");
    expect(ci).toContain("canonical_artifact_name");
    expect(ci).toContain("single canonical compiled artifact recorded");
    expect(ci).toContain("single_canonical_compiled_artifact: true");
    expect(ci).toContain("build_once_promote_many: true");
    expect(ci).toContain("downstream_rebuild_forbidden: true");
    expect(ci).toContain(
      "downstream_gates_consume_canonical_artifact_digest: true",
    );
    expect(ci).toContain("retention-days: 30");
    expect(ci).toContain("ci-artifact-manifest.txt");
    expect(ci).toContain(
      "node scripts/list-ci-artifact-files.mjs --output ci-artifact-manifest.txt",
    );
    expect(ci).not.toContain("build_output_roots=(");
    expect(ci).toContain("--sort=name");
    expect(ci).toContain('--mtime="UTC 1970-01-01"');
    expect(ci).toContain("--numeric-owner");
    expect(ci).toContain("gzip -n -9");
    expect(ci).toContain("sha256sum aidenid-clearance-build.tgz");
    expect(ci).toContain("--files-from=ci-artifact-manifest.txt");
    expect(ci).toContain("name: Static security scan");
    expect(ci).toContain("pnpm security:sast");
    expect(ci).toContain("name: Dependency vulnerability audit");
    expect(ci).toContain("pnpm audit:high");
    expect(ci).toContain("name: Secret scan");
    expect(ci).toContain("pnpm security:secrets");
    expect(ci).toContain("name: IaC security scan");
    expect(ci).toContain("pnpm security:iac");
    expect(ci).toContain("name: Generate CI SBOM");
    expect(ci).toContain("pnpm security:sbom --");
    expect(ci).toContain("--artifact-sha256");
    expect(ci).toContain("name: Verify CI SBOM");
    expect(ci).toContain("pnpm security:sbom:verify -- ci-sbom.spdx.json");
    expect(ci).toContain("ci-sbom.spdx.json");
    expect(ci).toContain("ci-artifact-manifest.sha256");
    expect(ci).toContain("Record CI artifact provenance");
    expect(ci).toContain("ci-artifact-provenance.json");
    expect(ci).toContain("name: Verify artifact trust policy");
    expect(ci).toContain("artifact_retention");
    expect(ci).toContain("release_minimum_remaining_days");
    expect(ci).toContain(
      "retention_days >= .artifact_retention.release_minimum_remaining_days",
    );
    expect(ci).toContain("jq -e");
    expect(ci).toContain(".source.repository == $repository");
    expect(ci).toContain('image: "ubuntu-22.04"');
    expect(ci).toContain("ci-runner-image-governance/v1");
    expect(ci).toContain("floating_latest_forbidden");
    expect(ci).toContain("self_hosted_forbidden");
    expect(ci).not.toContain("RUNNER_NAME");
    expect(ci).not.toContain("runner_name");
    expect(ci).toContain("Record CI native attestation support");
    expect(ci).toContain("ci-native-attestation-support.json");
    expect(ci).toContain(
      "Generate signed build-time provenance attestation before upload",
    );
    expect(ci).toContain(
      "Verify signed build-time provenance attestation before upload",
    );
    expect(ci).toContain("ci-native-attestation-verify.json");
    expect(ci).toContain(
      "signed build-time provenance attestation verification failed before artifact upload",
    );
    expect(ci).toContain(
      "Require build-time provenance boundary before upload",
    );
    expect(ci).toContain("private_repo_ci_provenance_manifest");
    expect(ci).toContain(
      "workflow_run_release_promotion_allowed_without_native_attestation",
    );
    expect(ci).toContain("workflow_run_release_promotion_controls");
    expect(ci).toContain("ci_gate_contract_exact_run");
    expect(ci).toContain("Record CI gate contract");
    expect(ci).toContain("ci-gate-contract/v1");
    expect(ci).toContain("ci-gate-contract-${{ github.sha }}");
    expect(ci).toContain("python-wheelhouse-${{ github.sha }}");
    expect(ci).toContain("python_wheelhouse_promotion_contract");
    expect(ci).toContain("pip download --require-hashes");
    expect(ci).toContain("--no-index --find-links python-wheelhouse");
    expect(ci).toContain("release_requires_exact_run_id: true");
    expect(ci).toContain("job_name_matching_is_not_the_release_contract");
    expect(ci).toMatch(/actions\/attest-build-provenance@[0-9a-f]{40}/);
    expect(ci).toContain("github.event.repository.private == false");
    expect(ci).toContain(
      "github.event_name == 'pull_request' && github.event.pull_request.head.repo.full_name == github.repository",
    );
    expect(ci).toContain("subject-path: aidenid-clearance-build.tgz");
    expect(ci).toContain("Redis restore drill evidence gate");
    expect(ci).toContain("verify-redis-restore-drill.mjs");
    expect(ci).toContain("AIDENID_REDIS_RESTORE_DRILL_MAX_AGE_DAYS");
    expect(ci).toContain("verify-redis-restore-drill.mjs --latest");
    expect(ci).toContain("timeout-minutes: 15");
    expect(ci).toContain("timeout-minutes: 20");
    expect(ci).toContain("timeout-minutes: 25");
    expect(ci).toContain("timeout-minutes: 30");
    expect(ci).toContain("timeout-minutes: 35");
    expect(ci).toMatch(/actions\/upload-artifact@[0-9a-f]{40}/);

    const sastIndex = ci.indexOf("name: Static security scan");
    const dependencyAuditIndex = ci.indexOf(
      "name: Dependency vulnerability audit",
    );
    const secretIndex = ci.indexOf("name: Secret scan");
    const iacIndex = ci.indexOf("name: IaC security scan");
    const testIndex = ci.indexOf("name: Test");
    const pythonIndex = ci.indexOf("name: Python verifier tests");
    const loadSmokeIndex = ci.indexOf("name: Load-smoke latency SLO");
    const auditIndex = ci.indexOf("name: Critical dependency audit");
    const buildIndex = ci.indexOf("name: Build", ci.indexOf("  build:"));
    const sdkPackIndex = ci.indexOf(
      "name: Pack verifier-node SDK tarball bundle",
    );
    const packIndex = ci.indexOf("name: Pack build artifact");
    const sbomIndex = ci.indexOf("name: Generate CI SBOM");
    const verifySbomIndex = ci.indexOf("name: Verify CI SBOM");
    const trustPolicyIndex = ci.indexOf("name: Verify artifact trust policy");
    const supportIndex = ci.indexOf(
      "name: Record CI native attestation support",
    );
    const nativeAttestationIndex = ci.indexOf(
      "name: Generate signed build-time provenance attestation before upload",
    );
    const nativeAttestationVerifyIndex = ci.indexOf(
      "name: Verify signed build-time provenance attestation before upload",
    );
    const uploadIndex = ci.indexOf(
      "actions/upload-artifact@",
      nativeAttestationIndex,
    );
    expect(dependencyAuditIndex).toBeGreaterThan(0);
    expect(sastIndex).toBeGreaterThan(0);
    expect(testIndex).toBeGreaterThan(0);
    expect(testIndex).toBeLessThan(dependencyAuditIndex);
    expect(pythonIndex).toBeGreaterThan(testIndex);
    expect(pythonIndex).toBeLessThan(dependencyAuditIndex);
    expect(loadSmokeIndex).toBeGreaterThan(pythonIndex);
    expect(loadSmokeIndex).toBeLessThan(dependencyAuditIndex);
    expect(dependencyAuditIndex).toBeLessThan(buildIndex);
    expect(dependencyAuditIndex).toBeLessThan(sastIndex);
    expect(dependencyAuditIndex).toBeLessThan(uploadIndex);
    expect(secretIndex).toBeGreaterThan(sastIndex);
    expect(iacIndex).toBeGreaterThan(secretIndex);
    expect(auditIndex).toBeGreaterThan(0);
    expect(auditIndex).toBeLessThan(buildIndex);
    expect(auditIndex).toBeLessThan(sdkPackIndex);
    expect(auditIndex).toBeLessThan(packIndex);
    expect(auditIndex).toBeLessThan(uploadIndex);
    expect(sastIndex).toBeLessThan(buildIndex);
    expect(secretIndex).toBeLessThan(buildIndex);
    expect(iacIndex).toBeLessThan(buildIndex);
    expect(sdkPackIndex).toBeGreaterThan(buildIndex);
    expect(sdkPackIndex).toBeLessThan(packIndex);
    expect(sbomIndex).toBeGreaterThan(packIndex);
    expect(verifySbomIndex).toBeGreaterThan(sbomIndex);
    expect(verifySbomIndex).toBeLessThan(uploadIndex);
    expect(trustPolicyIndex).toBeGreaterThan(verifySbomIndex);
    expect(trustPolicyIndex).toBeLessThan(supportIndex);
    expect(supportIndex).toBeLessThan(nativeAttestationIndex);
    expect(nativeAttestationVerifyIndex).toBeGreaterThan(
      nativeAttestationIndex,
    );
    expect(nativeAttestationVerifyIndex).toBeLessThan(uploadIndex);
    expect(nativeAttestationIndex).toBeLessThan(uploadIndex);
  });

  it("keeps workflow action-pin scanning anchored to uses keys", () => {
    const deploy = readWorkflow("deploy-dashboard.yml");
    const runSast = (cwd: string) =>
      spawnSync(process.execPath, ["scripts/security-scan.mjs", "sast"], {
        cwd,
        encoding: "utf8",
      });

    expect(deploy).toContain("member_statuses: members");

    const result = runSast(repoRoot);

    expect(`${result.stdout}\n${result.stderr}`).not.toContain(
      "workflow action must be pinned to a 40-character commit SHA (members,)",
    );
    expect(result.status, result.stderr || result.stdout).toBe(0);

    const tempRoot = mkdtempSync(path.join(tmpdir(), "aidenid-sast-"));
    try {
      mkdirSync(path.join(tempRoot, ".github", "workflows"), {
        recursive: true,
      });
      mkdirSync(path.join(tempRoot, "scripts"), { recursive: true });
      writeFileSync(
        path.join(tempRoot, "scripts", "security-scan.mjs"),
        readRepoFile("scripts/security-scan.mjs"),
      );
      writeFileSync(
        path.join(tempRoot, ".github", "workflows", "scan.yml"),
        [
          "name: scan",
          "on: workflow_dispatch",
          "jobs:",
          "  scan:",
          "    runs-on: ubuntu-latest",
          "    steps:",
          "      - uses: actions/checkout@v4",
          "      - run: node - <<'NODE'",
          "          const receipt = { member_statuses: members, members: [] };",
          "          console.log(receipt);",
          "NODE",
        ].join("\n"),
      );

      for (const args of [["init"], ["add", "."]]) {
        const gitResult = spawnSync("git", args, {
          cwd: tempRoot,
          encoding: "utf8",
        });
        expect(gitResult.status, gitResult.stderr || gitResult.stdout).toBe(0);
      }

      const unpinnedResult = runSast(tempRoot);
      const output = `${unpinnedResult.stdout}\n${unpinnedResult.stderr}`;

      expect(output).not.toContain(
        "workflow action must be pinned to a 40-character commit SHA (members,)",
      );
      expect(output).toContain(
        "workflow action must be pinned to a 40-character commit SHA (actions/checkout@v4)",
      );
      expect(unpinnedResult.status).toBe(1);
    } finally {
      rmSync(tempRoot, { recursive: true, force: true });
    }
  });

  it("pins hosted JavaScript actions to Node 24-ready SHAs", () => {
    const workflowAndActionText = [
      readWorkflow("ci.yml"),
      readWorkflow("release.yml"),
      readWorkflow("deploy-dashboard.yml"),
      readWorkflow("dashboard-rollback-drill.yml"),
      readWorkflow("dashboard-base-image-refresh.yml"),
      readAction(path.join("attest-artifact", "action.yml")),
    ].join("\n");

    expect(workflowAndActionText).toContain(
      "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
    );
    expect(workflowAndActionText).toContain(
      "actions/setup-python@a309ff8b426b58ec0e2a45f0f869d46889d02405",
    );
    expect(workflowAndActionText).toContain(
      "aws-actions/configure-aws-credentials@ec61189d14ec14c8efccab744f656cffd0e33f37",
    );
    expect(workflowAndActionText).not.toContain(
      "d3f86a106a0bac45b974a628896c90dbdf5c8093",
    );
    expect(workflowAndActionText).not.toContain(
      "a26af69be951a213d495a4c3e4e4022e16d87065",
    );
    expect(workflowAndActionText).not.toContain(
      "7474bc4690e29a8392af63c5b98e7449536d5c3a",
    );
  });

  it("keeps workflow Node heredoc terminators at shell column zero", () => {
    for (const workflow of ["release.yml", "deploy-dashboard.yml"]) {
      const lines = readWorkflow(workflow).split(/\r?\n/);

      for (const [index, line] of lines.entries()) {
        const opener = line.match(/<<'(?<delimiter>NODE)'/);
        if (!opener?.groups?.delimiter) {
          continue;
        }

        const previousLines = lines.slice(0, index);
        const runLineOffset = previousLines.findLastIndex((candidate) =>
          /^\s+run:\s*\|/.test(candidate),
        );
        expect(
          runLineOffset,
          `${workflow}:${index + 1} has no containing run block`,
        ).toBeGreaterThanOrEqual(0);
        const runLine = previousLines[runLineOffset] ?? "";
        const shellBaseIndent = (runLine.match(/^ */)?.[0].length ?? 0) + 2;
        const closeIndex =
          index +
          1 +
          lines
            .slice(index + 1)
            .findIndex(
              (candidate) => candidate.trim() === opener.groups?.delimiter,
            );
        expect(
          closeIndex,
          `${workflow}:${index + 1} has no ${opener.groups.delimiter} close`,
        ).toBeGreaterThan(index);
        const closeLine = lines[closeIndex] ?? "";
        const closeIndent = closeLine.match(/^ */)?.[0].length ?? 0;
        expect(
          closeIndent,
          `${workflow}:${closeIndex + 1} ${opener.groups.delimiter} must be at the run-block shell base indent`,
        ).toBe(shellBaseIndent);
      }
    }
  });

  it("discovers CI artifact generated outputs from workspace metadata", () => {
    const manifestScript = readRepoFile("scripts/list-ci-artifact-files.mjs");

    expect(manifestScript).toContain("pnpm-workspace.yaml");
    expect(manifestScript).toContain("turbo.json");
    expect(manifestScript).toContain("git ls-files");
    expect(manifestScript).toContain("scripts?.build");
    expect(manifestScript).toContain("next build");
    expect(manifestScript).toContain(".next/cache");
    expect(manifestScript).toContain("turboOutputRoots");
  });

  it("prebuilds workspace package exports before the root test suite", () => {
    const rootPackage = readRepoFile("package.json");

    for (const packageName of [
      "@aidenid/common-schemas",
      "@aidenid/eventing",
      "@aidenid/policy-engine",
      "@aidenid/crypto",
      "@aidenid/fingerprint-sidecar",
      "@aidenid/transparency",
      "@aidenid/verifier-node",
      "@aidenid/control-plane",
      "@aidenid/registry",
      "@aidenid/authorized-benchmark",
    ]) {
      expect(rootPackage).toContain(`pnpm --filter ${packageName} build`);
    }
  });

  it("emits the CI artifact manifest in tar-compatible byte order", () => {
    const result = spawnSync(
      process.execPath,
      ["scripts/list-ci-artifact-files.mjs"],
      {
        cwd: repoRoot,
        encoding: "utf8",
        maxBuffer: 16 * 1024 * 1024,
      },
    );
    const byteCompare = (left: string, right: string): number =>
      Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
    const lines = result.stdout.trim().split(/\r?\n/);

    expect(result.status, result.stderr).toBe(0);
    expect(lines.length).toBeGreaterThan(0);
    expect(lines).toEqual([...lines].sort(byteCompare));
    expect(lines.some((line) => line.includes("/.next/cache/"))).toBe(false);
  }, 15_000);

  it("runs OpenSSF Scorecard on PRs, main pushes, and the weekly schedule", () => {
    const scorecard = readWorkflow("scorecard.yml");

    expect(scorecard).toContain("pull_request:");
    expect(scorecard).toContain("push:");
    expect(scorecard).toContain("branches: [main]");
    expect(scorecard).toContain("schedule:");
    expect(scorecard).toContain("actions: read");
    expect(scorecard).toContain("security-events: write");
    expect(scorecard).toMatch(
      /permissions:\s+actions: read\s+contents: read\s+concurrency:/,
    );
    expect(scorecard).toContain(
      "group: scorecard-${{ github.workflow }}-${{ github.event.pull_request.head.sha || github.sha || github.ref }}",
    );
    expect(scorecard).toContain(
      "cancel-in-progress: ${{ github.event_name == 'pull_request' }}",
    );
    expect(scorecard).toMatch(
      /scorecard:[\s\S]*?permissions:[\s\S]*?security-events: write/,
    );
    expect(scorecard).toMatch(
      /scorecard:[\s\S]*?permissions:[\s\S]*?checks: read/,
    );
    expect(scorecard).toMatch(
      /scorecard:[\s\S]*?permissions:[\s\S]*?issues: read/,
    );
    expect(scorecard).toMatch(
      /scorecard:[\s\S]*?permissions:[\s\S]*?pull-requests: read/,
    );
    expect(scorecard).toContain("runs-on: ubuntu-22.04");
    expect(scorecard).toContain("timeout-minutes: 15");
    expect(scorecard).toContain("ossf/scorecard-action@");
    expect(scorecard).toMatch(/ossf\/scorecard-action@[0-9a-f]{40}/);
    expect(scorecard).toContain("results_format: sarif");
    expect(scorecard).toContain("github/codeql-action/upload-sarif@");
    expect(scorecard).toMatch(
      /github\/codeql-action\/upload-sarif@[0-9a-f]{40}/,
    );
    expect(scorecard).toContain("Detect code scanning SARIF upload support");
    expect(scorecard).toContain("code-scanning/alerts?per_page=1");
    expect(scorecard).toContain("code-scanning/default-setup");
    expect(scorecard).toContain(
      "SCORECARD_CAPABILITY_GLOBAL_ELAPSED_BUDGET_SECONDS=180",
    );
    expect(scorecard).toContain("scorecard_timeout_budget");
    expect(scorecard).toContain("scorecard_bounded_sleep");
    expect(scorecard).toContain("code scanning capability API probe");
    expect(scorecard).toContain("code-scanning-capability.err");
    expect(scorecard).toContain("Fail closed for untrusted pull requests");
    expect(scorecard).toContain(
      "Scorecard is a required security context and must fail closed for untrusted pull requests",
    );
    expect(scorecard).toContain("response_body_logged: false");
    expect(scorecard).not.toContain("cat code-scanning-capability.json");
    expect(scorecard).not.toContain("curl ");
    expect(scorecard).toContain("code_scanning_alerts_api_network_error");
    expect(scorecard).toContain(
      "trusted Scorecard contexts fail closed instead of marking upload_required=false",
    );
    expect(scorecard).toContain("allow_sarif_fallback_break_glass");
    expect(scorecard).toContain("aidenid-clearance-scorecard-break-glass");
    expect(scorecard).toContain(
      "Code scanning is not enabled for this release-evidence Scorecard context",
    );
    expect(scorecard).toContain(
      "RELEASE_EVIDENCE_SCORECARD_CONTEXT: ${{ (github.event_name == 'push' && github.ref == 'refs/heads/main') || github.event_name == 'workflow_dispatch' }}",
    );
    expect(scorecard).toContain(
      'release_evidence_scorecard_context: ($release_evidence_scorecard_context == "true")',
    );
    expect(scorecard).toContain("release_evidence_scorecard_sarif_break_glass");
    expect(scorecard).toContain(
      "release_evidence_scorecard_code_scanning_platform_unavailable",
    );
    expect(scorecard).toContain("protected_environment_break_glass_approved");
    expect(scorecard).toContain("continue-on-error: true");
    expect(scorecard).toContain("Fail required Scorecard SARIF upload misses");
    expect(scorecard).toContain(
      "steps.code_scanning_capability.outputs.upload_required == 'true'",
    );
    expect(scorecard).not.toContain("github.event.repository.private == false");
    expect(scorecard).toContain(
      "Scorecard SARIF upload must succeed for release-evidence contexts whenever upload_required=true",
    );
    expect(scorecard).toContain(
      "Release-evidence Scorecard context requires successful SARIF upload when upload_required=true unless aidenid-clearance-scorecard-break-glass approved artifact-only fallback",
    );
    expect(scorecard).toContain("sarif_file: scorecard.sarif");
    expect(scorecard).toContain("scorecard-upload-fallback.json");
    expect(scorecard).toContain(
      "Verify Scorecard publication-equivalent evidence",
    );
    expect(scorecard).toContain(
      "code_scanning_upload_capability_checked_unavailable_or_untrusted",
    );
    expect(scorecard).toContain("actions/upload-artifact@");
    expect(scorecard).toMatch(/actions\/upload-artifact@[0-9a-f]{40}/);
    expect(scorecard).toContain("scorecard-sarif-${{ github.sha }}");
    expect(scorecard).toContain(
      'workflow_artifact_fallback: ($upload_outcome != "success")',
    );
    expect(scorecard).toContain(
      'publication_equivalent_evidence: ($upload_outcome == "success")',
    );
    expect(scorecard).toContain("advisory_only_artifact_fallback");
    expect(scorecard).toContain("platform_capability_artifact_fallback");
    expect(scorecard).toContain(
      "required_scorecard_publication_evidence: true",
    );
    expect(scorecard).toContain("code_scanning_capability_checked: true");
    expect(scorecard).toContain(
      'code_scanning_upload_required: ($code_scanning_upload_required == "true")',
    );
    expect(scorecard).toContain(".code_scanning_upload_required == false");
    expect(scorecard).toContain(".publication_equivalent_evidence == false");
    expect(scorecard).not.toContain("private_repo_fallback_allowed" + ": true");
  });

  it("codifies main branch required-check governance", () => {
    const governance = readWorkflow("branch-protection-governance.yml");

    expect(governance).toContain("name: Branch Protection Governance");
    expect(governance).toContain("push:");
    expect(governance).toContain("branches: [main]");
    expect(governance).toContain("schedule:");
    expect(governance).toContain("GH_BRANCH_PROTECTION_AUDIT_APP_ID");
    expect(governance).toContain("AIDENID_GITHUB_APP_TOKEN_BROKER_URL");
    expect(governance).toContain("AIDENID_GITHUB_APP_TOKEN_BROKER_AUDIENCE");
    expect(governance).toContain("github_oidc_required: true");
    expect(governance).toContain("static_private_key_forbidden: true");
    expect(governance).toContain('credential_kind: "github_app_installation"');
    expect(governance).toContain(
      'credential_source: "github_oidc_token_broker"',
    );
    expect(governance).toContain("token_ttl_seconds_max: 3600");
    expect(governance).toContain("ACTIONS_ID_TOKEN_REQUEST_URL");
    expect(governance).toContain("ACTIONS_ID_TOKEN_REQUEST_TOKEN");
    expect(governance).toContain("broker_idempotency_key=");
    expect(governance).toContain("Idempotency-Key: ${broker_idempotency_key}");
    expect(governance).not.toContain(
      "GH_BRANCH_PROTECTION_AUDIT_APP_PRIVATE_KEY",
    );
    expect(governance).not.toContain("private-key:");
    expect(governance).toContain('metadata: "read"');
    expect(governance).not.toContain('administration: "read"');
    expect(governance).not.toContain('administration: "write"');
    expect(governance).toContain("aidenid-clearance-branch-governance");
    expect(governance).toContain(
      "Branch governance token broker did not return a GitHub App installation token",
    );
    expect(governance).toContain(
      "Branch governance audit must use an ephemeral GitHub App installation token",
    );
    expect(governance).toContain("branch-governance-audit-${{ github.sha }}");
    expect(governance).toContain(
      "branch-governance-readiness-${{ github.sha }}",
    );
    expect(governance).toContain("real_audit_required_before_promotion: true");
    expect(governance).toContain("config-ready=false");
    expect(governance).toContain("actions/attest-build-provenance@");
    expect(governance).toContain("github.event.repository.private == false");
    expect(governance).toContain(
      "branch-governance-native-attestation-support.json",
    );
    expect(governance).toContain("private_repo_branch_governance_manifest");
    expect(governance).toContain(
      "private_repo_branch_governance_fallback_supported",
    );
    expect(governance).toContain("required_before_release_promotion: true");
    expect(governance).toContain("required_before_deploy_apply: true");
    expect(governance).toContain("promotion_contract");
    expect(governance).not.toContain("GH_BRANCH_PROTECTION_AUDIT_TOKEN");
    expect(governance).not.toContain("/branches/main/protection");
    expect(governance).toContain(
      'gh api "repos/${GITHUB_REPOSITORY}/rulesets?targets=branch"',
    );
    expect(governance).toContain("GH_ACTIONS_APP_ID");
    expect(governance).toContain("integration_id");
    expect(governance).toContain("required_status_checks");
    expect(governance).toContain("strict_required_status_checks_policy");
    expect(governance).toContain("legacy status contexts alone are spoofable");
    expect(governance).toContain("required_review_thread_resolution");
    expect(governance).toContain('select(.type == "required_linear_history")');
    expect(governance).toContain(
      "main ruleset must block force pushes through non-fast-forward protection",
    );
    expect(governance).toContain('source: "github_repository_rulesets"');
    expect(governance).toContain("legacy_branch_protection_checked: false");
    expect(governance).toContain(
      "legacy_branch_protection_admin_read_required: false",
    );
    expect(governance).toContain("required_review_thread_resolution: true");
    expect(governance).toContain("required_linear_history: true");
    expect(governance).toContain("force_pushes_blocked: true");
    expect(governance).toContain("deletions_blocked: true");
    expect(governance).toContain("ruleset_bypass_actors_empty: true");
    const branchGovernanceVerifier = readRepoFile(
      "scripts/verify-branch-governance-audit.mjs",
    );
    expect(branchGovernanceVerifier).toContain("github_oidc_token_broker");
    expect(branchGovernanceVerifier).toContain("token_ttl_seconds_max");
    expect(branchGovernanceVerifier).toContain(
      "required_review_thread_resolution",
    );
    for (const requiredCheck of [
      "lint",
      "test",
      "security",
      "build",
      "quality",
      "gate",
      "scorecard",
      "sbom",
      "attestation contract check",
    ]) {
      expect(governance).toContain(`"${requiredCheck}"`);
    }
    expect(governance).not.toContain('"attest artifact"');
    expect(governance).toContain("required_approving_review_count");
    expect(governance).toContain("strict_required_status_checks_policy");
    expect(governance).toContain("fail_closed_signed_audit");
    expect(governance).toContain("fail_closed_exact_run_audit");
    expect(governance).toContain(
      "branch_protection_admin_read_permissions_requested: false",
    );
    expect(governance).toContain(
      "branch_protection_admin_write_permissions_requested: false",
    );
    expect(governance).toContain(
      "workflow_repository_mutation_forbidden: true",
    );
    expect(branchGovernanceVerifier).toContain(
      "fail-closed signed-audit or exact-run enforcement",
    );
    expect(branchGovernanceVerifier).toContain(
      "private-repo exact-run fallback contract",
    );
    expect(branchGovernanceVerifier).toContain(
      "repo-admin or policy-as-code repair outside the audit workflow",
    );
    expect(branchGovernanceVerifier).toContain(
      "GitHub repository rulesets as source of truth",
    );
  });

  it("promotes immutable dashboard release manifests before production deploy", () => {
    const release = readWorkflow("release.yml");

    expect(release).toContain("name: Promote Clearance Dashboard Release");
    expect(release).toContain("workflow_run:");
    expect(release).toContain("workflows: [Artifact Attestation]");
    expect(release).toContain("workflow_dispatch:");
    expect(release).toContain("pull-requests: read");
    expect(release).toContain("break_glass:");
    expect(release).toContain("break_glass_reason:");
    expect(release).toContain("break_glass_approved_until:");
    expect(release).toContain("break_glass_incident_ticket:");
    expect(release).toContain("NATIVE_ATTESTATION_BREAK_GLASS");
    expect(release).toContain("break_glass_review:");
    expect(release).toContain("review native-attestation break-glass");
    expect(release).toContain("aidenid-clearance-release-break-glass");
    expect(release).toContain("production_break_glass_review:");
    expect(release).toContain("aidenid-clearance-production-break-glass");
    expect(release).toContain(
      "production native attestation fallback requires a second protected production break-glass environment approval",
    );
    expect(release).toContain("native_attestation_policy:");
    expect(release).toContain("native attestation promotion policy");
    expect(release).toContain("manual_release_approval,");
    expect(release).toContain("MANUAL_RELEASE_APPROVAL_RESULT");
    expect(release).toContain("promotion_authorized");
    expect(release).toContain(
      "workflow_dispatch release promotion requires protected manual_release_approval before the centralized promotion policy authorizes release",
    );
    expect(release).toContain("manual_release_approval:");
    expect(release).toContain("manual release promotion approval");
    expect(release).toContain(
      "Manual release promotion approval job passed after GitHub Environment reviewer gate",
    );
    expect(release).toContain("fallback_authorized");
    expect(release).toContain(
      "Native attestation verification is mandatory; fallback is fail-closed without protected break-glass",
    );
    expect(release).toContain(
      "needs.native_attestation_policy.outputs.promotion_authorized == 'true'",
    );
    expect(release).toContain("BREAK_GLASS_REVIEW_RESULT");
    expect(release).toContain("PRODUCTION_BREAK_GLASS_REVIEW_RESULT");
    expect(release).toContain('"${BREAK_GLASS_REVIEW_RESULT}" != "success"');
    expect(release).toContain(
      "needs.native_attestation_policy.outputs.policy_ready == 'true'",
    );
    expect(release).toContain("NATIVE_ATTESTATION_FALLBACK_AUTHORIZED");
    expect(release).toContain(
      "aidenid-clearance-release-break-glass must require GitHub Environment reviewers",
    );
    expect(release).toContain(
      "group: release-dashboard-${{ github.event_name == 'workflow_dispatch' && inputs.environment || format('attestation-run-{0}', github.event.workflow_run.id) }}-${{ github.event.workflow_run.head_sha || github.sha }}",
    );
    expect(release).toContain("cancel-in-progress: false");
    expect(release).toContain("runs-on: ubuntu-22.04");
    expect(release).toContain("timeout-minutes: 30");
    expect(release).toMatch(
      /manual_release_approval:[\s\S]*?timeout-minutes: 10/,
    );
    expect(release).toMatch(
      /native_attestation_policy:[\s\S]*?timeout-minutes: 10/,
    );
    expect(release).toContain("ci-runner-image-governance/v1");
    expect(release).toContain(
      "provide an exact run-id path instead of relying on latest-run matching",
    );
    expect(release).toContain("environment:");
    expect(release).toContain(
      "name: aidenid-clearance-${{ inputs.environment || 'production' }}",
    );
    expect(release).toContain(
      "github.event.workflow_run.conclusion == 'success'",
    );
    expect(release).not.toContain("vars.AIDENID_DASHBOARD_IMAGE != ''");
    expect(release).not.toContain("vars.AIDENID_CONTROL_PLANE_IMAGE != ''");
    expect(release).not.toContain("vars.AIDENID_VERIFIER_IMAGE != ''");
    expect(release).not.toContain("vars.AIDENID_OTEL_COLLECTOR_IMAGE != ''");
    expect(release).toContain(
      "dashboard-release-manifest-${{ inputs.environment || 'production' }}-${{ github.event.workflow_run.head_sha || github.sha }}",
    );
    expect(release).toContain('artifact_type: "dashboard_release_manifest"');
    expect(release).toContain("format_version: 1");
    expect(release).toContain("must require GitHub Environment reviewers");
    expect(release).toContain(
      "must require GitHub Environment reviewers before release promotion",
    );
    expect(release).toContain("AIDENID_RELEASE_PLAN_AWARE_AUTOPROMOTE");
    expect(release).toContain(
      "AIDENID_RELEASE_PLAN_AWARE_AUTOPROMOTE_APPROVED_BY",
    );
    expect(release).toContain(
      "AIDENID_RELEASE_PLAN_AWARE_AUTOPROMOTE_APPROVED_UNTIL",
    );
    expect(release).toContain(
      "AIDENID_RELEASE_PLAN_AWARE_AUTOPROMOTE_APPROVAL_TICKET",
    );
    expect(release).toContain("github_environment_required_reviewers");
    expect(release).toContain("plan_limited_branch_protection_strict_checks");
    expect(release).toContain(
      'if [ "${GITHUB_EVENT_NAME}" != "workflow_run" ] || [ "${RELEASE_ENVIRONMENT}" != "production" ] || [ "${AIDENID_RELEASE_PLAN_AWARE_AUTOPROMOTE}" != "true" ]; then',
    );
    expect(release).toContain(
      "plan-aware production workflow_run promotion requires AIDENID_RELEASE_PLAN_AWARE_AUTOPROMOTE_APPROVED_BY",
    );
    expect(release).toContain(
      "plan-aware production workflow_run promotion approval window cannot exceed four hours",
    );
    expect(release).toContain(
      "repos/${GITHUB_REPOSITORY}/commits/${SOURCE_SHA}/pulls",
    );
    expect(release).toContain("direct pushes cannot use this fallback");
    expect(release).toContain(
      "Plan-aware production workflow_run promotion verified branch governance evidence",
    );
    expect(release).toContain(
      "plan-aware production workflow_run promotion requires native-signed or private exact-run branch governance evidence",
    );
    expect(release).toContain(
      '.ruleset_governance.source == "github_repository_rulesets"',
    );
    expect(release).toContain(
      ".ruleset_governance.legacy_branch_protection_checked == false",
    );
    expect(release).toContain(
      ".ruleset_governance.required_review_thread_resolution == true",
    );
    expect(release).toContain(
      ".ruleset_governance.required_linear_history == true",
    );
    expect(release).toContain(
      ".ruleset_governance.force_pushes_blocked == true",
    );
    expect(release).toContain(".ruleset_governance.deletions_blocked == true");
    expect(release).toContain(
      ".ruleset_governance.ruleset_bypass_actors_empty == true",
    );
    expect(release).toContain("fail_closed_exact_run_audit");
    expect(release).toContain(
      ".enforcement_model.workflow_repository_mutation_forbidden == true",
    );
    expect(release).toContain(
      '((.ruleset_governance.required_contexts // []) | index("gate") != null)',
    );
    expect(release).toContain("release_promotion_policy");
    expect(release).toContain("approval_control_source");
    expect(release).toContain("plan_aware_autopromote");
    expect(release).toContain(
      'admin_controlled_repository_variable: "AIDENID_RELEASE_PLAN_AWARE_AUTOPROMOTE"',
    );
    expect(release).toContain(
      'approval_provenance: "repository_variables_admin_controlled_outside_workflow"',
    );
    expect(release).toContain("github_token_can_set_opt_in: false");
    expect(release).toContain("source_pull_request_number");
    expect(release).toContain("direct_push_forbidden: true");
    expect(release).toContain("workflow_dispatch_forbidden: true");
    expect(release).toContain("fail_closed_signed_audit");
    expect(release).toContain(
      "repository_admin_or_policy_as_code_mutation_required_for_repairs: true",
    );
    expect(release).toContain(
      "manual_and_break_glass_paths_require_protected_environments: true",
    );
    expect(release).toContain(
      "workflow_dispatch production release promotion is disabled in this generic workflow",
    );
    expect(release).toContain(
      "production release must be chained from the successful Artifact Attestation workflow_run path",
    );
    expect(release).not.toContain(
      "must require GitHub Environment reviewers before production release promotion",
    );
    expect(release).toContain("Validate provenance AWS role");
    expect(release).toContain(
      "vars.AIDENID_PROVENANCE_ROLE_ARN || vars.AWS_ROLE_TO_ASSUME",
    );
    expect(release).not.toContain("secrets.AWS_ROLE_TO_ASSUME");
    expect(release).toContain("timeout 30s gh");
    expect(release).toContain("commits/main");
    expect(release).toContain("refusing stale dashboard release manifest");
    expect(release).toContain("timeout 180s gh run download");
    expect(release).toContain("download_ci_artifact()");
    expect(release).toContain(
      "CI artifact download failed after 3 timeout-bounded attempts",
    );
    expect(release).toContain("AIDENID_CONTROL_PLANE_IMAGE");
    expect(release).toContain("AIDENID_VERIFIER_IMAGE");
    expect(release).toContain("AIDENID_OTEL_COLLECTOR_IMAGE");
    expect(release).toContain("require_service_image_artifact()");
    expect(release).toContain("Build and Push Clearance Images");
    expect(release).toContain("aidenid-clearance-service-images-${SOURCE_SHA}");
    expect(release).toContain("service-images.sha256");
    expect(release).toContain("aidenid-clearance-service-images.json");
    expect(release).toContain(
      '.source.workflow == "Build and Push Clearance Images"',
    );
    expect(release).toContain('.tag_policy.sha_tag == ("sha-" + $source_sha)');
    expect(release).toContain(".tag_policy.immutable_ecr_tags == true");
    expect(release).toContain(".tag_policy.rerun_idempotent == true");
    expect(release).toContain(".terraform_tfvars.control_plane_image");
    expect(release).toContain(".terraform_tfvars.dashboard_image");
    expect(release).toContain(".terraform_tfvars.verifier_image");
    expect(release).toContain(".terraform_tfvars.otel_collector_image");
    expect(release).toContain(
      "Service image artifact ${service_images_artifact} verified",
    );
    expect(release).toContain("service_images");
    expect(release).toContain("image_subject");
    expect(release).toContain("service_image_digests");
    expect(release).toContain("ci_artifact_sha256");
    expect(release).toContain("github_artifact_id");
    expect(release).toContain("github_artifact_archive_digest");
    expect(release).toContain("immutable_promotion");
    expect(release).toContain("artifact_archive_digest");
    expect(release).toContain("require_ci_gate_contract()");
    expect(release).toContain("ci-gate-contract-${SOURCE_SHA}");
    expect(release).toContain("ci-gate-contract/v1");
    expect(release).toContain("require_python_wheelhouse_contract()");
    expect(release).toContain("python-wheelhouse-${SOURCE_SHA}");
    expect(release).toContain("python_wheelhouse_promotion_contract");
    expect(release).toContain("python-wheelhouse-provenance.sha256");
    expect(release).toContain("python_wheelhouse_provenance");
    expect(release).toContain("immutable_wheelhouse_required_for_release");
    expect(release).toContain("AIDENID_RELEASE_READINESS_EVIDENCE_URI");
    expect(release).toContain("verify-dashboard-release-readiness.mjs");
    expect(release).toContain(
      "dashboard-release-readiness/${RELEASE_ENVIRONMENT}/latest.json",
    );
    expect(release).toContain("required_before_release_promotion: true");
    expect(release).toContain(
      'require_successful_workflow "CI" "ci_run_id" \'["lint","test","security","build","sbom","quality"]\'',
    );
    expect(release).toContain(
      'require_successful_workflow_run_id "CI" "${CI_ARTIFACT_RUN_ID}" "ci_run_id" \'["lint","test","security","build","sbom","quality"]\'',
    );
    expect(release).toContain("omar_gate_run_id:");
    expect(release).toContain("attestation_contract_run_id:");
    expect(release).toContain("scorecard_run_id:");
    expect(release).toContain("sbom_run_id:");
    expect(release).toContain(
      "workflow_dispatch release promotion requires exact numeric",
    );
    expect(release).toContain("implicit latest-run discovery is forbidden");
    expect(release).toContain(
      'require_successful_workflow_run_id "Omar Gate" "${OMAR_GATE_RUN_ID_INPUT}" "omar_run_id" \'["gate"]\'',
    );
    expect(release).toContain(
      'require_successful_workflow_run_id "Attestation Contract Check" "${ATTESTATION_CONTRACT_RUN_ID_INPUT}" "attestation_contract_run_id" \'["attestation contract check"]\'',
    );
    expect(release).toContain(
      'require_successful_workflow "Attestation Contract Check" "attestation_contract_run_id" \'["attestation contract check"]\'',
    );
    expect(release).toContain("def successful_by_name($name):");
    expect(release).toContain("release_requires_exact_run_id");
    expect(release).toContain("release_uses_gate_contract");
    expect(release).toContain("job_name_matching_is_not_the_release_contract");
    expect(release).toContain("ci_gate_contract_sha256");
    const releaseManifestJq =
      release.match(
        /jq -n \\\n[\s\S]*?> release-output\/dashboard-release-manifest\.json/,
      )?.[0] ?? "";
    expect(releaseManifestJq).toContain(
      '--arg ci_gate_contract_sha256 "${ci_gate_contract_sha256}"',
    );
    expect(releaseManifestJq).toContain(
      "gate_contract_sha256: $ci_gate_contract_sha256",
    );
    expect(release).toContain("ci_gate_contract_canonical_artifact_sha256");
    expect(release).toContain(
      ".promotion_contract.canonical_build_artifact_required == true",
    );
    expect(release).toContain(
      "Release promotion must consume the single canonical CI build artifact digest from ci-gate-contract",
    );
    expect(release).toContain("RELEASE_GATE_MIN_CREATED_AT");
    expect(release).toContain("refusing stale release gate lookup");
    expect(release).toContain("requires_immutable_artifact_tuple: true");
    expect(release).toContain("requires_python_wheelhouse_promotion: true");
    expect(release).toContain("requires_release_readiness: true");
    expect(release).toContain("release_manifest_only: true");
    expect(release).toContain(
      "requires_post_deploy_smoke_in_deploy_workflow: true",
    );
    expect(release).toContain(
      "rollback_execution_encoded_in_deploy_workflow: true",
    );
    expect(release).toContain(
      "canary_readiness_required_before_release_promotion: true",
    );
    expect(release).toContain(
      'deploy_workflow_path: ".github/workflows/deploy-dashboard.yml"',
    );
    expect(release).toContain("require_branch_governance_audit");
    expect(release).toContain("branch-governance-audit-${SOURCE_SHA}");
    expect(release).toContain("verify-branch-governance-audit.mjs");
    expect(release).toContain("branch_governance");
    expect(release).toContain("branch_governance_native_attestation_status");
    expect(release).toContain("requires_branch_governance_audit: true");
    expect(release).toContain("allows_private_repo_branch_governance_fallback");
    expect(release).toContain("private_repo_branch_governance_manifest");
    expect(release).toContain(
      "blocks_unresolved_native_attestation_exceptions: true",
    );
    expect(release).toContain("deploy_intent");
    expect(release).toContain("workflow_run_apply: true");
    expect(release).toContain(
      "cloudflare_proxied: $release_cloudflare_proxied",
    );
    expect(release).toContain("binds_terraform_plan_digest_before_apply: true");
    expect(release).toContain("missing a stable GitHub artifact id");
    expect(release).toContain(".gates.ci.artifact.archive_sha256");
    expect(release).toContain("provenance_manifest_sha256");
    expect(release).toContain(".github/workflows/ci.yml");
    expect(release).toContain("github_native_ci_verified");
    expect(release).toContain("ci-native-attestation-verify.json");
    expect(release).toContain(
      "GitHub-native CI artifact attestation verification failed",
    );
    expect(release).toContain(
      "workflow_run exact-run private-repo CI provenance controls",
    );
    expect(release).toContain(
      "workflow_run_private_repo_ci_provenance_fallback",
    );
    expect(release).toContain("private_repo_workflow_run_fallback_verified");
    expect(release).toContain("allows_private_repo_ci_workflow_run_fallback");
    expect(release).toContain(
      "native_attestation_policy fallback_authorized=true",
    );
    expect(release).toContain("break_glass_durable_private_repo_fallback");
    expect(release).toContain("AIDENID_RELEASE_EXCEPTION_KMS_SIGNING_KEY_ID");
    expect(release).toContain("native-attestation-break-glass-exception.json");
    expect(release).toContain("aws kms sign");
    expect(release).toContain("aws kms verify");
    expect(release).toContain("SignatureValid == true");
    expect(release).toContain("native-attestation-break-glass/v1");
    expect(release).toContain("signed_exception_sha256");
    expect(release).toContain("incident_ticket: $incident_ticket");
    expect(release).toContain(
      "native attestation fallback requires break_glass_incident_ticket",
    );
    expect(release).toContain(
      "future_promotions_blocked_while_unresolved: true",
    );
    expect(release).toContain(
      "dashboard-release-exceptions/${RELEASE_ENVIRONMENT}/open/latest.json",
    );
    expect(release).toContain("ensure_no_unresolved_release_exception");
    expect(release).toContain("durable_storage_uri");
    expect(release).toContain(
      "native attestation fallback approval window cannot exceed four hours",
    );
    expect(release).toContain(
      'required_gates: ["lint", "test", "security", "build", "sbom", "quality"]',
    );
    expect(release).toContain("attestation_contract_run_id");
    expect(release).toContain("required_before_release_promotion: true");
    expect(release).toContain("requires_release_manifest: true");
    expect(release).toContain("requires_release_manifest_for_all_apply: true");
    expect(release).toContain("requires_ci_artifact_binding: true");
    expect(release).toContain("expires too soon for release promotion");
    expect(release).toContain("sha256sum -c ci-artifact-provenance.sha256");
    expect(release).toContain("node scripts/verify-ci-sbom.mjs");
    expect(release).toContain('require_successful_workflow "SBOM"');
    expect(release).toContain(
      'sbom: {run_id: ($sbom_run_id | tonumber), required_jobs: ["sbom"]}',
    );
    expect(release).toContain(
      "aidenid-clearance-provenance-durable-receipt.json",
    );
    expect(release).toContain("verify_downloaded_sha256()");
    expect(release).toContain("downloaded sha file target mismatch");
    expect(release).toContain(
      "verify_downloaded_sha256 aidenid-clearance-provenance.sha256 aidenid-clearance-provenance.json",
    );

    for (const [, ref] of release.matchAll(/uses:\s+[^\s@]+@([^\s]+)/g)) {
      expect(ref).toMatch(/^[0-9a-f]{40}$/);
    }
  });

  it("runs the real deep Omar Gate path with the pinned protected action", () => {
    const omar = readWorkflow("omar-gate.yml");
    const reusable = readWorkflow("aidenid-verifier-gate.yml");

    expect(omar).not.toContain("uses: ./.github/actions/omar-gate");
    expect(omar).toContain(
      "uses: mrrCarter/sentinelayer-v1-action@1eed812b92b9463a5fd51b6c906c8988b7c1bd3f",
    );
    expect(omar).toContain(
      "sentinelayer_token: ${{ secrets.SENTINELAYER_TOKEN }}",
    );
    expect(omar).toContain("github_token: ${{ github.token }}");
    expect(omar).toContain("sentinelayer_spec_id: ${{ env.OMAR_SPEC_ID }}");
    expect(omar).toContain("openai_api_key: ${{ secrets.OPENAI_API_KEY }}");
    expect(omar).toContain("llm_provider: openai");
    expect(omar).not.toContain("status_poll_token:");
    expect(omar).not.toContain("sentinelayer_spec_hash:");
    expect(omar).not.toContain("spec_binding_mode: explicit");
    expect(omar).toContain("model: gpt-5.3-codex");
    expect(omar).toContain("codex_model: gpt-5.3-codex");
    expect(omar).toContain("model_fallback: gpt-4.1-mini");
    expect(omar).toContain("llm_failure_policy: block");
    expect(omar).toContain('sentinelayer_managed_llm: "false"');
    expect(omar).not.toContain('local_gates_enabled: "false"');
    expect(omar).toContain("push:");
    expect(omar).toContain("branches: [main]");
    expect(omar).toContain("pull_request_target:");
    expect(omar).not.toContain("pull_request:");
    expect(omar).toContain("github.event_name == 'pull_request_target'");
    expect(omar).not.toContain("github.event_name == 'pull_request'");
    expect(omar).toContain(
      "Assert trusted Omar execution context before checkout or scanner secrets",
    );
    expect(omar).toContain("Checkout scan subject");
    expect(omar).toContain(
      "ref: ${{ github.event_name == 'pull_request_target' && github.event.pull_request.head.sha || github.sha }}",
    );
    expect(omar).toContain(
      "repository: ${{ github.event_name == 'pull_request_target' && github.event.pull_request.head.repo.full_name || github.repository }}",
    );
    expect(omar).toContain("persist-credentials: false");
    expect(omar).toContain("Resolve Omar scan pull request");
    expect(omar).toContain(
      "repos/${GITHUB_REPOSITORY}/commits/${SCAN_SUBJECT_SHA}/pulls",
    );
    expect(omar).toContain("for attempt in $(seq 1 12)");
    expect(omar).toContain("retrying after GitHub association propagation");
    expect(omar).toContain("sleep 5");
    expect(omar).toContain("Run Omar Gate with resolved pull request");
    expect(omar).toContain(
      "pr_number: ${{ steps.omar_context.outputs.pr_number }}",
    );
    expect(omar).toContain(
      "SCAN_SUBJECT_SHA: ${{ github.event_name == 'pull_request_target' && github.event.pull_request.head.sha || github.sha }}",
    );
    expect(omar).toContain("workflow_sha: $workflow_sha");
    expect(omar).toContain("concurrency:");
    const scannerJob = omar.slice(omar.indexOf("  gate:"), omar.length);
    const scannerInvocation = omar.slice(
      omar.indexOf("      - name: Run Omar Gate"),
      omar.indexOf("\n      - name: Recover Omar output contract"),
    );
    expect(scannerJob).toContain(
      "permissions:\n      contents: read\n      checks: write\n      pull-requests: write",
    );
    expect(scannerJob).not.toContain("id-token: write");
    expect(
      scannerJob.indexOf(
        "Assert trusted Omar execution context before checkout or scanner secrets",
      ),
    ).toBeLessThan(scannerJob.indexOf("Checkout scan subject"));
    expect(
      scannerJob.indexOf(
        "Assert trusted Omar execution context before checkout or scanner secrets",
      ),
    ).toBeLessThan(scannerJob.indexOf("Validate Omar Gate configuration"));
    expect(omar).not.toContain("issues: write");
    expect(omar).toContain("GH_TOKEN: ${{ github.token }}");
    expect(scannerInvocation).toContain("github_token: ${{ github.token }}");
    expect(omar).toContain("continue-on-error: true");
    expect(omar).toContain("severity_gate: none");
    expect(omar).toContain("Recover Omar output contract");
    expect(omar).toContain("steps.omar_recovery.outputs.run_id");
    expect(omar).toContain("steps.omar_recovery.outputs.pack_summary_artifact");
    expect(omar).toContain("latest_by_name");
    expect(omar).toContain("synthesize_recovery_artifacts");
    expect(omar).toContain("pack_summary_has_recovery_contract");
    expect(omar).toContain("sentinelayer_backend_bridge_missing_pack_summary");
    expect(omar).toContain("sentinelayer_backend_bridge_missing_findings");
    expect(omar).toContain("sentinelayer_backend_bridge_invalid_pack_summary");
    expect(omar).toContain('if [ "${block_merge}" = "true" ]; then');
    expect(omar).toContain('gate_status="blocked"');
    expect(omar).toContain('elif [ -z "${gate_status}" ]; then');
    expect(omar.indexOf('if [ "${block_merge}" = "true" ]; then')).toBeLessThan(
      omar.indexOf('pack_summary_has_recovery_contract "${pack_summary}"'),
    );
    expect(omar).toContain("writer_complete == true");
    expect(omar).toContain("findings_file_sha256");
    expect(omar).toContain("omar_recovery_contract");
    expect(omar).toContain("omar-recovery-contract.json");
    expect(omar).toContain("omar-recovery-contract.sha256");
    expect(omar).toContain("scanner_publish_fallback_allowed");
    expect(omar).toContain("publish_failure_isolated");
    expect(omar).toContain("sha256sum -c");
    expect(omar).toContain(
      "Pinned Omar scanner publish failed after packaging; using validated cryptographically bound recovery artifact contract",
    );
    expect(omar).not.toContain(
      "failing closed instead of recovering from a partial local artifact contract",
    );
    expect(omar).toContain("Invalid Omar run_id output");
    expect(omar).toContain("SEVERITY_GATE");
    expect(omar).toContain("P2_COUNT");
    expect(omar).toContain("threshold=${SEVERITY_GATE}");
    expect(omar).not.toContain(
      "Report Omar Gate summary without scanner secrets",
    );
    expect(omar).not.toContain("--method POST");
    expect(omar).not.toContain("gh_api_retry");
    expect(omar).not.toContain("omar-report-publish-fallback.json");
    expect(omar).not.toContain("hosted_omar_artifacts_authoritative");
    expect(omar).not.toContain(
      '"repos/${GITHUB_REPOSITORY}/issues/${PR_NUMBER}/comments"',
    );
    expect(omar).toContain("default: deep");
    expect(omar).toContain("pr_number:");
    expect(omar).toContain(
      "Pull request number to scan when manually dispatching Omar Gate.",
    );
    expect(omar).toContain("inputs.scan_mode || 'deep'");
    const staleOpenAiRequiredMessage =
      "legacy provider key is required for the deep LLM Omar scan";
    const staleForkSecretList =
      "SENTINELAYER_TOKEN, legacy provider key, and SENTINELAYER_SPEC_ID";
    expect(omar).not.toContain(staleOpenAiRequiredMessage);
    expect(omar).toContain(
      "Omar Gate deep scans require trusted repository context with scanner credentials and explicit spec binding",
    );
    expect(omar).not.toContain(
      "Omar Gate deep scans require trusted repository context with SENTINELAYER_TOKEN",
    );
    expect(omar).not.toContain("SENTINELAYER_TOKEN is required");
    expect(omar).not.toContain(staleForkSecretList);
    expect(omar).toContain(
      "Explicit Omar spec binding must be configured as a 64-character lowercase hex digest",
    );
    expect(omar).toContain("sentinelayer_backend_bridge");
    expect(omar).toContain(
      "Omar action did not expose complete numeric severity counts for backend recovery.",
    );
    expect(omar).toContain(
      "Omar action exposed counts without a recoverable FINDINGS.jsonl",
    );
    expect(omar).toContain(
      "Recovered PACK_SUMMARY.json is missing required recovery contract fields",
    );
    expect(omar).toContain(
      "actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd",
    );
    expect(omar).toContain(
      "actions/upload-artifact@50769540e7f4bd5e21e526ee35c689e35e0d6874",
    );
    expect(omar).not.toContain("Post Omar Gate summary comment");
    expect(omar).not.toContain("<!-- aidenid-omar-gate-summary -->");
    expect(omar).not.toContain(
      "Collapse auxiliary Sentinelayer App Omar comments",
    );

    expect(reusable).toContain(
      "uses: mrrCarter/sentinelayer-v1-action@1eed812b92b9463a5fd51b6c906c8988b7c1bd3f",
    );
    expect(reusable).toContain("github_token: ${{ github.token }}");
    expect(reusable).toContain("openai_api_key: ${{ secrets.OPENAI_API_KEY }}");
    expect(reusable).toContain("llm_provider: openai");
    expect(reusable).toContain('sentinelayer_managed_llm: "false"');
    expect(reusable).toContain("llm_failure_policy: block");
    expect(reusable).not.toContain("id-token: write");
  });

  it("keeps .github clean of auxiliary Sentinelayer App Omar bridge artifacts", () => {
    const githubFiles = readGithubFiles();
    const paths = new Set(githubFiles.map((file) => file.path));
    const backendWorkflow = path.join(workflowsRoot, "omar-gate-backend.yml");
    const backendAction = path.join(actionsRoot, "run-omar-gate");
    const localOmarAction = path.join(actionsRoot, "omar-gate");

    expect(existsSync(backendWorkflow)).toBe(false);
    expect(existsSync(backendAction)).toBe(false);
    expect(existsSync(localOmarAction)).toBe(false);
    expect(paths.has(".github/workflows/omar-gate-backend.yml")).toBe(false);
    expect(paths.has(".github/actions/run-omar-gate/action.yml")).toBe(false);
    expect(paths.has(".github/actions/omar-gate/action.yml")).toBe(false);
    if (existsSync(backendAction)) {
      expect(statSync(backendAction).isDirectory()).toBe(false);
    }

    for (const file of githubFiles) {
      expect(file.content).not.toContain("Omar Multi-Agent Review");
      expect(file.content).not.toContain("Omar Gate Wrapper");
      expect(file.content).not.toContain("sentinelayer-app");
      expect(file.content).not.toContain(
        "829921e2fc09279fab5f6f084be3f77fe6236b6a",
      );
      expect(file.content).not.toContain(
        "721bc7efe1402fcce416becea3d247b838119ed2",
      );
      expect(file.content).not.toContain('sentinelayer_managed_llm: "true"');
      expect(file.content).not.toContain("status_poll_token:");
      expect(file.content).not.toContain("sentinelayer_spec_hash:");
      expect(file.content).not.toContain(
        "uses: ./.github/actions/run-omar-gate",
      );
      expect(file.content).not.toContain("uses: ./.github/actions/omar-gate");
      expect(file.content).not.toContain("omar-gate-backend");
    }

    const recoverySourceReferences = githubFiles
      .filter((file) => file.content.includes("sentinelayer_backend_bridge"))
      .map((file) => file.path)
      .sort();
    expect(recoverySourceReferences).toEqual([
      ".github/workflows/omar-gate.yml",
    ]);
  });

  it("attests only CI-produced artifacts after Omar Gate succeeds for the same SHA", () => {
    const attestationWorkflow = readWorkflow("attestation.yml");
    const contractWorkflow = readWorkflow("attestation-contract-check.yml");
    const attestAction = readAction(path.join("attest-artifact", "action.yml"));
    const attestation = `${attestationWorkflow}\n${attestAction}\n${contractWorkflow}`;
    const attestCiBlock = attestationWorkflow.slice(
      attestationWorkflow.indexOf("  attest_ci:"),
      attestationWorkflow.indexOf("  attest_manual:"),
    );
    const contractBlock = contractWorkflow.slice(
      contractWorkflow.indexOf("\n  contract_check:"),
    );

    expect(attestation).toContain("workflow_run:");
    expect(attestationWorkflow).toContain("cancel-in-progress: false");
    expect(attestationWorkflow).not.toContain("pull_request:");
    expect(contractWorkflow).toContain("name: Attestation Contract Check");
    expect(contractWorkflow).toContain("pull_request:");
    expect(contractWorkflow).toContain("workflow_run:");
    expect(contractWorkflow).toContain("workflows: [CI]");
    expect(contractWorkflow).toContain("branches: [main]");
    expect(contractWorkflow).toContain("github.event.workflow_run.id");
    expect(contractWorkflow).toContain("github.event.workflow_run.head_branch");
    expect(contractWorkflow).toContain(
      "github.event.workflow_run.conclusion == 'success'",
    );
    expect(contractWorkflow).toContain('CI_HEAD_BRANCH}" != "main"');
    expect(attestCiBlock).toContain('GITHUB_SHA}" != "${CI_HEAD_SHA}"');
    expect(attestCiBlock).toContain(
      "refusing stale Artifact Attestation workflow_run after main advanced",
    );
    expect(contractWorkflow).toContain('GITHUB_SHA}" != "${PR_HEAD_SHA}"');
    expect(contractWorkflow).toContain(
      "refusing stale Attestation Contract Check workflow_run after main advanced",
    );
    expect(contractWorkflow).toContain("name: attestation contract check");
    expect(contractWorkflow).toContain("Validate PR attestation contract");
    expect(contractWorkflow).toContain(
      "aidenid-clearance-build-${PR_HEAD_SHA}",
    );
    expect(contractBlock).toContain("timeout-minutes: 25");
    expect(contractBlock).toContain(
      "Validate PR attestation contract against real CI artifact",
    );
    expect(contractBlock).toContain("CI_RUN_ID");
    expect(contractBlock).toContain("authoritative workflow_run");
    expect(contractBlock).not.toContain("gh run list");
    expect(contractBlock).toContain("gh run download");
    expect(contractBlock).toContain("ci-artifact-provenance.json");
    expect(contractBlock).toContain("ci-native-attestation-verify.json");
    expect(contractBlock).toContain(
      "0000000000000000000000000000000000000000000000000000000000000000",
    );
    expect(contractBlock).not.toContain("sleep_with_backoff_jitter");
    expect(contractBlock).not.toContain("id-token: write");
    expect(contractBlock).not.toContain("attestations: write");
    expect(attestation).toContain("workflows: [CI]");
    expect(attestation).not.toContain(
      "workflows: [CI, Omar Gate, OpenSSF Scorecard]",
    );
    expect(attestation).toContain("runs-on: ubuntu-22.04");
    expect(attestation).toContain("break_glass:");
    expect(attestation).toContain("break_glass_reason:");
    expect(attestation).toContain("break_glass_approved_until:");
    expect(attestation).toContain("aidenid-clearance-attestation-break-glass");
    expect(attestation).toContain(
      "Manual attestation requires break_glass=true",
    );
    expect(attestation).toContain("must require GitHub Environment reviewers");
    expect(attestation).toContain(
      "Manual attestation break_glass_approved_until is expired",
    );
    expect(attestation).toContain(
      "Manual attestation approval window cannot exceed four hours",
    );
    expect(attestationWorkflow).toContain("attest_ci:");
    expect(attestationWorkflow).toContain(
      "Verify attestation CI release gates",
    );
    expect(attestationWorkflow).toContain("TRIGGER_WORKFLOW_NAME");
    expect(attestationWorkflow).toContain("TRIGGER_CREATED_AT");
    expect(attestationWorkflow).toContain(
      "ATTESTATION_GLOBAL_ELAPSED_BUDGET_SECONDS=1200",
    );
    expect(attestationWorkflow).toContain("global_deadline_epoch");
    expect(attestationWorkflow).toContain("timeout_budget");
    expect(attestationWorkflow).toContain("bounded_sleep");
    expect(attestationWorkflow).toContain("resolve_ci_run_id");
    expect(attestationWorkflow).toContain(
      "Attestation retry trigger ${TRIGGER_WORKFLOW_NAME}",
    );
    expect(attestationWorkflow).toContain("refusing ambiguous CI binding");
    expect(attestationWorkflow).toContain(
      "attestation requires an exact workflow_run trigger or a single unambiguous gate run",
    );
    expect(attestationWorkflow).toContain(
      'require_exact_or_unique_successful_workflow "Omar Gate" "gate"',
    );
    expect(attestationWorkflow).toContain(
      'require_exact_or_unique_successful_workflow "OpenSSF Scorecard" "scorecard"',
    );
    expect(attestCiBlock).toContain("CI_RUN_ID");
    expect(attestCiBlock).toContain("steps.verify_gates.outputs.ci_run_id");
    expect(attestCiBlock).toContain(
      'require_successful_job "CI" "${CI_RUN_ID}" "build"',
    );
    expect(attestCiBlock).toContain(
      'require_successful_job "CI" "${CI_RUN_ID}" "sbom"',
    );
    expect(attestCiBlock).toContain(
      'require_successful_job "CI" "${CI_RUN_ID}" "quality"',
    );
    expect(attestCiBlock).toContain("CI_RUN_CREATED_AT");
    expect(attestCiBlock).toContain("createdAt >= env.CI_RUN_CREATED_AT");
    expect(attestCiBlock).toContain("run_count");
    expect(attestCiBlock).toContain("refusing stale gate lookup");
    expect(attestCiBlock).toContain("verify_ci_gate_contract_artifact");
    expect(attestCiBlock).toContain("verify_gate_artifact_contract");
    expect(attestCiBlock).toContain("github-artifact-metadata.json");
    expect(attestCiBlock).toContain("actions/artifacts/${artifact_id}/zip");
    expect(attestCiBlock).toContain("actual_archive_digest");
    expect(attestCiBlock).toContain("ci-gate-contract-${CI_HEAD_SHA}");
    expect(attestCiBlock).toContain(
      ".promotion_contract.canonical_build_artifact_required == true",
    );
    expect(attestCiBlock).toContain(
      ".canonical_build_artifact.single_canonical_compiled_artifact == true",
    );
    expect(attestCiBlock).toContain(
      "verify_python_wheelhouse_contract_artifact",
    );
    expect(attestCiBlock).toContain("python-wheelhouse-${source_sha}");
    expect(attestCiBlock).toContain("python_wheelhouse_promotion_contract");
    expect(attestCiBlock).toContain("python-wheelhouse-provenance.sha256");
    expect(attestCiBlock).toContain("python_wheelhouse_provenance");
    expect(attestCiBlock).toContain("omar-gate-artifacts");
    expect(attestCiBlock).toContain("omar-recovery-contract.json");
    expect(attestCiBlock).toContain("omar-recovery-contract.sha256");
    expect(attestCiBlock).toContain('test -f "${gate_dir}/FINDINGS.jsonl"');
    expect(attestCiBlock).not.toContain('test -s "${gate_dir}/FINDINGS.jsonl"');
    expect(attestCiBlock).toContain('.policy_pack == "omar"');
    expect(attestCiBlock).toContain('.scan_mode == "deep"');
    expect(attestCiBlock).toContain("(.error == null)");
    expect(attestCiBlock).toContain("((.errors // []) | length == 0)");
    expect(attestCiBlock).toContain("(.counts.P0 // 1) == 0");
    expect(attestCiBlock).toContain("(.counts.P1 // 1) == 0");
    expect(attestCiBlock).not.toContain("(.counts.P2 // 1) == 0");
    expect(attestCiBlock).not.toContain("(.counts.P3 // 1) == 0");
    expect(attestCiBlock).not.toContain(
      '.source == "sentinelayer_backend_bridge"',
    );
    expect(attestCiBlock).not.toContain(
      '((.stages_completed // []) | index("backend_trigger"))',
    );
    expect(attestCiBlock).toContain(
      '((.workflow_threshold // "") == "P0" or (.workflow_threshold // "") == "P1")',
    );
    expect(attestCiBlock).toContain(".hashes.pack_summary_sha256");
    expect(attestCiBlock).toContain("scorecard-sarif-${CI_HEAD_SHA}");
    expect(attestationWorkflow).toContain(
      "Timed out waiting for ${workflow} to pass",
    );
    expect(attestationWorkflow).toContain(
      "github.event_name == 'workflow_run' && github.event.workflow_run.conclusion == 'success'",
    );
    expect(attestationWorkflow).toMatch(
      /attest_ci:[\s\S]*?uses: \.\/\.github\/actions\/attest-artifact/,
    );
    expect(attestCiBlock).toContain("permissions:");
    expect(attestCiBlock).toContain("id-token: write");
    expect(attestCiBlock).toContain("attestations: write");
    expect(attestCiBlock).not.toContain("needs: [break_glass]");
    expect(attestationWorkflow).toContain("attest_manual:");
    expect(attestationWorkflow).toContain("needs: [break_glass]");
    expect(attestationWorkflow).toContain(
      "Verify manual attestation CI input binding",
    );
    expect(attestationWorkflow).toContain("MANUAL_CI_RUN_ID");
    expect(attestationWorkflow).toContain("MANUAL_ARTIFACT_SHA");
    expect(attestationWorkflow).toContain(
      "MANUAL_ATTESTATION_GLOBAL_ELAPSED_BUDGET_SECONDS=900",
    );
    expect(attestationWorkflow).toContain("manual_timeout_budget");
    expect(attestationWorkflow).toContain("manual_bounded_sleep");
    expect(attestationWorkflow).toContain("MANUAL_CI_RUN_CREATED_AT");
    expect(attestationWorkflow).toContain(
      "createdAt >= env.MANUAL_CI_RUN_CREATED_AT",
    );
    expect(attestationWorkflow).toContain(
      "Manual attestation CI/Omar/Scorecard input binding verified",
    );
    expect(attestationWorkflow).toContain(
      'require_unique_successful_workflow "Omar Gate" "gate"',
    );
    expect(attestationWorkflow).toContain(
      'require_unique_successful_workflow "OpenSSF Scorecard" "scorecard"',
    );
    expect(attestationWorkflow).toContain(
      "verify_manual_ci_gate_contract_artifact",
    );
    expect(attestationWorkflow).toContain("python-wheelhouse-provenance.json");
    expect(attestationWorkflow).toContain(
      "verify_manual_python_wheelhouse_contract_artifact",
    );
    expect(attestationWorkflow).toContain(
      "verify_manual_gate_artifact_contract",
    );
    expect(attestAction).toContain("using: composite");
    expect(attestAction).toContain("shell: bash");
    expect(attestAction).not.toContain("${{ vars.");
    expect(attestAction).toContain("ci_max_age_days:");
    expect(attestAction).toContain("provenance_bucket:");
    expect(attestAction).toContain("provenance_role_arn:");
    expect(attestAction).toContain("aws_region:");
    expect(attestAction).toContain("provenance_prefix:");
    expect(attestationWorkflow).toContain(
      "provenance_role_arn: ${{ vars.AIDENID_PROVENANCE_ROLE_ARN || vars.AWS_ROLE_TO_ASSUME }}",
    );
    expect(attestation).not.toContain("tags:");
    expect(attestation).not.toContain("pnpm build");
    expect(attestation).toContain("Verify CI run succeeded for artifact SHA");
    expect(attestation).toContain('workflow}" != "CI"');
    expect(attestation).toContain('"${conclusion}" != "success"');
    expect(attestation).toContain('"${head_sha}" != "${ARTIFACT_SHA}"');
    expect(attestation).toContain("AIDENID_ATTESTATION_CI_MAX_AGE_DAYS");
    expect(attestation).toContain(
      "CI run is missing createdAt/updatedAt freshness metadata",
    );
    expect(attestation).toContain("cannot be attested");
    expect(attestation).toContain(
      "CI_CONCLUSION: ${{ steps.ci_run.outputs.conclusion }}",
    );
    expect(attestation).not.toContain(
      "CI_CONCLUSION: ${{ github.event.workflow_run.conclusion || 'success' }}",
    );
    expect(attestation).toContain('--workflow "Omar Gate"');
    expect(attestation).toContain('--commit "${ARTIFACT_SHA}"');
    expect(attestation).toContain(
      "Retryable timeout-bounded gh run list failure while polling Omar Gate",
    );
    expect(attestation).toContain("timeout 30s gh run list");
    expect(attestation).toContain("poll_started_at");
    expect(attestation).toContain("expires too soon for attestation");
    expect(attestation).toContain("timeout 180s gh run download");
    expect(attestation).toContain("sort_by(.createdAt) | reverse");
    expect(attestation).toContain("Verify immutable artifact metadata");
    expect(attestation).toContain(
      "expected exactly one matching immutable artifact",
    );
    expect(attestation).toContain("CI_ARTIFACT_DIGEST");
    expect(attestation).toContain("gh run download");
    expect(attestation).toContain(
      "sha256sum -c aidenid-clearance-build.sha256",
    );
    expect(attestation).toContain("sha256sum -c ci-artifact-manifest.sha256");
    expect(attestation).toContain("sha256sum -c ci-artifact-provenance.sha256");
    expect(attestation).toContain("ci-artifact-provenance.json");
    expect(attestation).toContain("ci-artifact-manifest.actual");
    expect(attestation).toContain(
      "diff -u ci-artifact-manifest.txt ci-artifact-manifest.actual",
    );
    expect(attestation).toContain("manifest_sha256");
    expect(attestation).toContain("private-repo-release-binding/v1");
    expect(attestation).toContain("provenance_manifest_sha256");
    expect(attestation).toContain("AIDENID_PROVENANCE_BUCKET");
    expect(attestation).toContain("AIDENID_PROVENANCE_ROLE_ARN");
    expect(attestation).toContain("get-object-lock-configuration");
    expect(attestation).toContain("s3_object_lock");
    expect(attestation).toContain("manual_dispatch");
    expect(attestation).toContain("approved_until");
    expect(attestation).toContain("max_age_days");
    expect(attestation).toContain(
      "aidenid-clearance-provenance-durable-receipt.json",
    );
    expect(attestation).toContain("aws s3 cp");
    expect(attestation).toContain(
      "aidenid-clearance-provenance-release-binding.sha256",
    );
    expect(attestation).toMatch(
      /aws-actions\/configure-aws-credentials@[0-9a-f]{40}/,
    );
    expect(attestation).toMatch(
      /actions\/attest-build-provenance@[0-9a-f]{40}/,
    );
  });

  it("bounds dashboard deploy network calls and requires green release gates before apply", () => {
    const deploy = readWorkflow("deploy-dashboard.yml");
    const publicSmoke = readWorkflow("dashboard-public-smoke.yml");
    const liveDeployDoc = readRepoFile(
      "docs/dd/dashboard-public-live-deploy.md",
    );
    const liveHotfixArtifact = readRepoFile(
      "docs/dd/artifacts/dashboard-public-hotfix-2026-05-25.json",
    );
    const verifyReleaseRun = readRepoFile(
      "scripts/verify-release-workflow-run.sh",
    );
    const terraformAlb = readRepoFile("infra/terraform/alb.tf");
    const terraformMain = readRepoFile("infra/terraform/main.tf");
    const terraformCloudflare = readRepoFile("infra/terraform/cloudflare.tf");

    expect(deploy).toContain("workflow_run:");
    expect(deploy).toContain(
      "workflows: [Promote Clearance Dashboard Release]",
    );
    expect(deploy).toContain("cancel-in-progress");
    expect(deploy).toContain("release-promotion");
    expect(deploy).toContain(
      "Revalidate deploy freshness immediately before apply",
    );
    expect(deploy).toContain("dashboard-pre-apply-freshness-gate.json");
    expect(deploy).toContain("stale_queued_deploy_rejected: true");
    expect(deploy).not.toContain("break_glass:");
    expect(deploy).not.toContain("break_glass_reason:");
    expect(deploy).not.toContain("break_glass_approved_until:");
    expect(deploy).toContain("Resolve release-manifest workflow_run dispatch");
    expect(deploy).toContain("scripts/verify-release-workflow-run.sh");
    expect(deploy).not.toContain("verify_release_workflow_required_jobs");
    expect(deploy).toContain("AIDENID_RELEASE_EVENT_APPLY=${release_apply}");
    expect(deploy).toContain(
      "AIDENID_RELEASE_EVENT_CLOUDFLARE_PROXIED=${release_cloudflare_proxied}",
    );
    expect(deploy).toContain("deploy_intent.workflow_run_apply");
    expect(deploy).toContain("deploy_intent.cloudflare_proxied");
    expect(deploy).toContain(
      "Release manifest deploy_intent.cloudflare_proxied must be boolean",
    );
    expect(deploy).toContain(
      "CLOUDFLARE_PROXIED: ${{ needs.resolve_deploy_context.outputs.cloudflare_proxied }}",
    );
    expect(deploy).not.toMatch(
      /\n\s+CLOUDFLARE_PROXIED: \$\{\{ inputs\.cloudflare_proxied \}\}/,
    );
    expect(deploy).toContain(
      "workflow_run apply will bind the generated Terraform plan digest before apply",
    );
    expect(verifyReleaseRun).toContain(
      "Triggering Promote Clearance Dashboard Release run verified before deploy",
    );
    expect(verifyReleaseRun).toContain("promote dashboard release manifest");
    expect(deploy).toContain("dashboard-release-manifest-");
    expect(deploy).toContain("artifact_count");
    expect(deploy).toContain("published no dashboard release manifest");
    expect(deploy).toContain("release_manifest_present=false");
    expect(deploy).toContain("checks_verified=false");
    expect(deploy).toContain("AIDENID_RELEASE_EVENT_DASHBOARD_IMAGE");
    expect(deploy).toContain("AIDENID_RELEASE_EVENT_CONTROL_PLANE_IMAGE");
    expect(deploy).toContain("AIDENID_RELEASE_EVENT_VERIFIER_IMAGE");
    expect(deploy).toContain("AIDENID_RELEASE_EVENT_OTEL_COLLECTOR_IMAGE");
    expect(deploy).toContain("AIDENID_EFFECTIVE_CONTROL_PLANE_IMAGE");
    expect(deploy).toContain("AIDENID_EFFECTIVE_VERIFIER_IMAGE");
    expect(deploy).toContain("AIDENID_EFFECTIVE_OTEL_COLLECTOR_IMAGE");
    expect(deploy).not.toContain(
      "Production release manifest dashboard image must match repository variable AIDENID_DASHBOARD_IMAGE",
    );
    expect(deploy).toContain("AIDENID_RELEASE_EVENT_CI_RUN_ID");
    expect(deploy).toContain("AIDENID_RELEASE_EVENT_OMAR_RUN_ID");
    expect(deploy).toContain("AIDENID_RELEASE_EVENT_ATTESTATION_RUN_ID");
    expect(deploy).toContain(
      'CI_RUN_ID="${CI_RUN_ID:-${AIDENID_RELEASE_EVENT_CI_RUN_ID:-}}"',
    );
    expect(deploy).toContain(
      "live dashboard canary requires numeric CI run id from workflow_dispatch input or release manifest",
    );
    expect(deploy).toContain(
      'ci_artifact_run_id="${AIDENID_RELEASE_EVENT_CI_RUN_ID:-${CI_ARTIFACT_RUN_ID:-}}"',
    );
    expect(deploy).toContain(
      'OMAR_RUN_ID="${OMAR_RUN_ID:-${AIDENID_RELEASE_EVENT_OMAR_RUN_ID:-}}"',
    );
    expect(deploy).toContain(
      'ATTESTATION_RUN_ID="${ATTESTATION_RUN_ID:-${AIDENID_RELEASE_EVENT_ATTESTATION_RUN_ID:-}}"',
    );
    expect(deploy).toContain(
      "apply=true deploy requires numeric Omar Gate run id from workflow_dispatch input or release manifest",
    );
    expect(deploy).not.toContain("AIDENID_RELEASE_EVENT_APPLY=false");
    expect(deploy).toContain("actions: read");
    expect(deploy).toContain("runs-on: ubuntu-22.04");
    expect(deploy).toContain("AIDENID_DASHBOARD_IMAGE");
    expect(deploy).toContain("MANUAL_DASHBOARD_IMAGE");
    expect(deploy).toContain("RELEASE_EVENT_DASHBOARD_IMAGE");
    expect(deploy).not.toContain("secrets.AWS_ROLE_TO_ASSUME");
    expect(deploy).toContain(
      "dashboard_image input is disabled for production",
    );
    expect(deploy).toContain(
      "Production deploys require a release manifest dashboard image or repository variable AIDENID_DASHBOARD_IMAGE",
    );
    expect(deploy).toContain("ci_artifact_run_id");
    expect(deploy).toContain("omar_gate_run_id");
    expect(deploy).toContain("artifact_attestation_run_id");
    expect(deploy).toContain("attestation_contract_run_id");
    expect(deploy).toContain("scorecard_run_id");
    expect(deploy).toContain("release_manifest_run_id");
    expect(deploy).toContain(
      "workflow_dispatch deploy requires exact numeric ci_artifact_run_id",
    );
    expect(deploy).toContain(
      "workflow_dispatch deploy requires exact numeric release_manifest_run_id",
    );
    expect(deploy).toContain(
      "apply=true deploy requires numeric release_manifest_run_id",
    );
    expect(deploy).toContain("AIDENID_ENABLE_NAT_EGRESS");
    expect(deploy).toContain("AIDENID_ENABLE_PRIVATE_VPC_ENDPOINTS");
    expect(deploy).toContain("AIDENID_ENABLE_CLOUDFLARE_INGRESS_PREFIX_LISTS");
    expect(deploy).toContain("TF_VAR_enable_nat_egress");
    expect(deploy).toContain("TF_VAR_enable_private_vpc_endpoints");
    expect(deploy).toContain("TF_VAR_enable_cloudflare_ingress_prefix_lists");
    expect(deploy).toContain("Terraform-managed Cloudflare prefix lists");
    expect(terraformMain).toContain(
      'variable "enable_cloudflare_ingress_prefix_lists"',
    );
    expect(terraformMain).toContain("cloudflare_ingress_ipv4_cidrs");
    expect(terraformMain).toContain("https://www.cloudflare.com/ips-v4");
    expect(terraformMain).toContain("https://www.cloudflare.com/ips-v6");
    expect(terraformCloudflare).toContain(
      'resource "aws_ec2_managed_prefix_list" "cloudflare_ipv4"',
    );
    expect(terraformCloudflare).toContain(
      'resource "aws_ec2_managed_prefix_list" "cloudflare_ipv6"',
    );
    expect(terraformCloudflare).toContain('address_family = "IPv4"');
    expect(terraformCloudflare).toContain('address_family = "IPv6"');
    expect(terraformAlb).toContain("cloudflare_ingress_prefix_list_ids");
    expect(terraformAlb).toContain("effective_ingress_prefix_list_ids");
    expect(terraformAlb).toContain(
      "aws_ec2_managed_prefix_list.cloudflare_ipv4[0].id",
    );
    expect(terraformAlb).toContain(
      "aws_ec2_managed_prefix_list.cloudflare_ipv6[0].id",
    );
    expect(deploy).toContain("must be a ${workflow} run");
    expect(deploy).toContain("must be completed/success");
    expect(deploy).toContain("require_successful_workflow_jobs");
    expect(deploy).toContain("def successful_by_name($name):");
    expect(deploy).toContain("Required ${workflow} jobs verified");
    expect(deploy).toContain("sort_by(.createdAt) | reverse");
    expect(deploy).toContain(
      "workflow_dispatch deploy requires immutable release-manifest provenance and exact CI/Omar/Scorecard/Attestation run IDs",
    );
    expect(deploy).toContain("rollback_artifact_run_id");
    expect(deploy).toContain("rollback_source_sha");
    expect(deploy).toContain("rollback_incident_ticket");
    expect(deploy).toContain(
      "AIDENID_DASHBOARD_ROLLBACK_ARTIFACT_MAX_AGE_HOURS",
    );
    expect(deploy).toContain("rollback artifact run is stale: created_at=");
    expect(deploy).toContain("production_rollback_approval");
    expect(deploy).toContain("production rollback-specific protected approval");
    expect(deploy).toContain("aidenid-clearance-production-rollback");
    expect(deploy).toContain(
      "inputs.environment == 'production' && 'aidenid-clearance-production-rollback'",
    );
    expect(deploy).toContain(
      "production rollback-specific approval requires rollback_incident_ticket before any rollback artifact download or script execution",
    );
    expect(deploy).toContain(
      "needs.production_rollback_approval.outputs.approved == 'true'",
    );
    expect(deploy).toContain(
      "rollback-specific protected environment approval verified before rollback artifact download",
    );
    expect(deploy).toContain("execute saved dashboard rollback");
    expect(deploy).toContain("dashboard-manual-rollback-summary");
    expect(deploy).toContain("dashboard-manual-rollback-verification");
    expect(deploy).toContain("dashboard_rollback_provenance_decision");
    expect(deploy).toContain("dashboard-rollback-provenance-decision.json");
    expect(deploy).toContain("dashboard-ecs-rollback.sha256");
    expect(deploy).toContain("dashboard-rollback-artifact-provenance.json");
    expect(deploy).toContain(
      "attestation_statement_subject_match_required: true",
    );
    expect(deploy).toContain(
      "Saved rollback script path is outside the allowlist",
    );
    expect(deploy).toContain(
      "rollback deploy-summary artifact ${rollback_artifact_id} is missing a GitHub archive digest",
    );
    expect(deploy).toContain("incident_ticket_bound: true");
    expect(deploy).toContain("artifact_freshness_verified: true");
    expect(deploy).toContain("artifact_metadata_digest_verified: true");
    expect(deploy).toContain("rollback_script_checksum_verified: true");
    expect(deploy).toContain("rollback_artifact_kms_signature_verified: true");
    expect(deploy).toContain("matching_service_image_lineage_verified: true");
    expect(deploy).toContain("current_environment_state_parity_verified: true");
    expect(deploy).toContain("rollback-current-environment-state.json");
    expect(deploy).toContain("AIDENID_ROLLBACK_DECISION_KMS_SIGNING_KEY_ID");
    expect(deploy).toContain("aws kms sign");
    expect(deploy).toContain("aws kms verify");
    expect(deploy).toContain(
      "Saved deploy artifact did not include dashboard-deploy-summary.json for provenance verification",
    );
    expect(deploy).toContain("services_stable: true");
    expect(deploy).toContain("post-rollback canary");
    expect(deploy).toContain("expected_terraform_plan_sha256");
    expect(deploy).toContain(
      "apply=true requires expected_terraform_plan_sha256 from a reviewed apply=false plan-approval artifact",
    );
    expect(deploy).toContain(
      "workflow_dispatch apply for any environment requires expected_terraform_plan_sha256 from a prior apply=false plan-approval artifact for the same SHA/environment",
    );
    expect(deploy).toContain("repository@sha256:<64-hex-digest>");
    expect(deploy).toContain("@sha256:[0-9a-f]{64}");
    expect(deploy).not.toContain("docker build");
    expect(deploy).not.toContain("docker push");
    const deployArtifactBindingIndex = deploy.indexOf(
      "Verify deploy artifact, SBOM, and image binding",
    );
    const dashboardImageAttestationIndex = deploy.indexOf(
      "Verify dashboard image signing attestation",
    );
    const ecrLoginIndex = deploy.indexOf("aws ecr get-login-password");
    const ecrConfigPermissionIndex = deploy.indexOf(
      'chmod 0644 "${cosign_docker_config}/config.json"',
    );
    expect(dashboardImageAttestationIndex).toBeGreaterThan(
      deployArtifactBindingIndex,
    );
    expect(ecrLoginIndex).toBeGreaterThan(dashboardImageAttestationIndex);
    expect(ecrConfigPermissionIndex).toBeGreaterThan(ecrLoginIndex);
    expect(deploy).toContain(
      "Verify CI/Omar/Scorecard/Attestation gates for every workflow_dispatch deploy SHA",
    );
    expect(deploy).toContain(
      "Resolve workflow_dispatch release gates before deploy job",
    );
    expect(deploy).toContain("gates_verified");
    expect(deploy).toContain(
      "needs.resolve_deploy_context.outputs.gates_verified == 'true'",
    );
    expect(deploy).toContain(
      "workflow_dispatch deploy exact-run gate resolution completed before deploy job starts",
    );
    expect(deploy).toContain(
      "if: ${{ github.event_name == 'workflow_dispatch' }}",
    );
    expect(deploy).toContain("required_for_all_workflow_dispatch_apply: true");
    expect(deploy).toContain(
      "required_for_all_workflow_dispatch_deploys: true",
    );
    expect(deploy).toContain("exact_run_ids_required: true");
    expect(deploy).toContain("enforced_for_non_production_apply: true");
    expect(deploy).toContain("workflow-dispatch-release-gates.json");
    expect(deploy).toContain(
      "workflow_dispatch deploy requires exact numeric ci_artifact_run_id before deploy gate resolution",
    );
    expect(deploy).toContain(
      "workflow_dispatch deploy requires exact numeric omar_gate_run_id before deploy gate resolution",
    );
    expect(deploy).toContain("latest-run discovery is forbidden");
    expect(deploy).toContain(
      "workflow_dispatch apply requires numeric terraform_plan_approval_run_id before deploy gate resolution",
    );
    expect(deploy).toContain("guard manual deploy dispatch ref");
    expect(deploy).toContain(
      "workflow_dispatch deploy ref and current-main SHA guard passed before downstream deploy jobs",
    );
    expect(deploy).toContain(
      "workflow_dispatch deploy SHA ${GITHUB_SHA} must equal current main ${current_main_sha} before any deploy job resolves context",
    );
    expect(deploy).toContain(
      "workflow_dispatch production deploys are disabled outside rollback",
    );
    expect(deploy).toContain(
      "production deploy must use the signed release-manifest workflow_run promotion path",
    );
    expect(deploy).toContain("needs: [manual_dispatch_ref_guard]");
    expect(deploy).toContain(
      "workflow_dispatch deploys must be dispatched from refs/heads/main before Terraform plan/apply",
    );
    expect(deploy).toContain(
      "workflow_dispatch deploys must be dispatched from refs/heads/main before rollback",
    );
    expect(deploy).toContain("Assert production environment review gate");
    expect(deploy).toContain("production_deploy_approval");
    expect(deploy).toContain("apply_deploy_approval");
    expect(deploy).toContain(
      "needs.apply_deploy_approval.outputs.approved == 'true'",
    );
    expect(deploy).toContain(
      "has no required_reviewers protection rule; validating bounded repo-admin apply approval fallback",
    );
    expect(deploy).toContain(
      "Apply deploy approval job passed after GitHub Environment reviewer gate",
    );
    expect(deploy).toContain(
      "Apply deploy approval job passed with bounded repo-admin fallback",
    );
    expect(deploy).toContain("AIDENID_DEPLOY_APPLY_APPROVED_BY");
    expect(deploy).toContain("AIDENID_DEPLOY_APPLY_APPROVED_UNTIL");
    expect(deploy).toContain("AIDENID_DEPLOY_APPLY_APPROVAL_TICKET");
    expect(deploy).toContain(
      "apply=true deploy fallback approval window cannot exceed four hours",
    );
    expect(deploy).toContain(
      "needs.production_deploy_approval.outputs.approved == 'true'",
    );
    expect(deploy).toContain(
      "Production deploy approval job passed after GitHub Environment reviewer gate",
    );
    expect(deploy).toContain(
      "Production apply reviewer assertion passed with bounded repo-admin fallback",
    );
    expect(deploy).toContain("workflow_dispatch production apply is disabled");
    expect(deploy).toContain(
      'require_successful_workflow_run_id "CI" "${CI_ARTIFACT_RUN_ID}"',
    );
    expect(deploy).toContain(
      '\'["lint","test","security","build","sbom","quality"]\'',
    );
    expect(deploy).toContain(
      'require_successful_workflow_run_id "Omar Gate" "${OMAR_GATE_RUN_ID}"',
    );
    expect(deploy).toContain("'[\"gate\"]'");
    expect(deploy).toContain(
      'require_successful_workflow_run_id "Artifact Attestation" "${ARTIFACT_ATTESTATION_RUN_ID}"',
    );
    expect(deploy).toContain(
      'require_successful_workflow_run_id "Attestation Contract Check" "${ATTESTATION_CONTRACT_RUN_ID}"',
    );
    expect(deploy).toContain("'[\"attest artifact\"]'");
    expect(deploy).toContain(
      'require_successful_workflow_run_id "OpenSSF Scorecard" "${SCORECARD_RUN_ID}"',
    );
    expect(deploy).toContain("'[\"scorecard\"]'");
    expect(deploy).toContain(
      "Require branch governance audit before deploy apply",
    );
    expect(deploy).toContain("branch-governance-audit-${DEPLOY_SHA}");
    expect(deploy).toContain("verify-branch-governance-audit.mjs");
    expect(deploy).toContain(
      "Branch Protection Governance must have a completed successful native-signed or private exact-run audit",
    );
    expect(deploy).toContain(
      ".gates.branch_governance.required_before_deploy_apply == true",
    );
    expect(deploy).toContain(
      ".production_deploy_policy.requires_branch_governance_audit == true",
    );
    expect(deploy).toContain(
      ".production_deploy_policy.allows_private_repo_branch_governance_fallback == true",
    );
    expect(deploy).toContain(
      "Sync Redis AUTH token secret outside Terraform state",
    );
    expect(deploy).toContain("redis-auth-token-secret-sync-receipt.json");
    expect(deploy).toContain("get-secret-value");
    expect(deploy).toContain('--secret-id "${secret_name}"');
    expect(deploy).toContain(".auth_token == $auth_token");
    expect(deploy).toContain("credential_sync_action");
    expect(deploy).toContain("credential_material_unchanged");
    expect(deploy).toContain(
      "Redis AUTH credential metadata is missing an AWSCURRENT version",
    );
    expect(deploy).toContain("credential_sync_status");
    expect(deploy).toContain("idempotent_credential_sync");
    expect(deploy).toContain("credential_value_matches_deploy_input");
    expect(deploy).toContain("terraform_state_secret_version: false");
    expect(deploy).toContain(
      "Verify Redis AUTH token rotation age before apply",
    );
    expect(deploy).toContain("redis-auth-token-rotation-gate.json");
    expect(deploy).toContain("rotation_epoch");
    expect(deploy).toContain("AIDENID_REDIS_AUTH_TOKEN_ROTATION_EPOCH");
    expect(deploy).toContain("TF_VAR_redis_auth_token_rotation_epoch");
    expect(deploy).toContain("redis-auth-token-preapply-state.json");
    expect(deploy).toContain("redis_auth_token_preapply_rotation_evidence");
    expect(deploy).toContain("redis_auth_required");
    expect(deploy).toContain("terraform_rotation_epoch_plan_visibility");
    expect(deploy).toContain("rotation_age_gate");
    expect(deploy).toContain("redis-auth-token-live-epoch-alignment.json");
    expect(deploy).toContain("redis_auth_token_live_epoch_alignment");
    expect(deploy).toContain(
      "live_auth_last_modified_date_matches_rotation_epoch",
    );
    expect(deploy).toContain("live_auth_epoch_alignment_mode");
    expect(deploy).toContain("already_configured_noop_credential_sync");
    expect(deploy).toContain(
      "already_configured_noop_credential_sync_accepted",
    );
    expect(deploy).toContain("elasticache_modify_noop_response");
    expect(deploy).toContain("already_configured_live_state_validated");
    expect(deploy).toContain("live_auth_epoch_alignment_gate_passed");
    expect(deploy).not.toContain("already.*auth");
    expect(deploy).toContain(
      "auth_last_modified_not_older_than_secrets_manager_awscurrent",
    );
    expect(deploy).toContain(
      "Block deploy completion unless live Redis AUTH is enabled and epoch-aligned",
    );
    expect(deploy).toContain("auth_enabled_live_gate");
    expect(deploy).toContain(
      "deployment_completion_blocked_until_auth_enabled",
    );
    expect(deploy).toContain("terraform_auth_material_absent_by_design");
    expect(deploy).toContain(
      "production Redis AUTH deploys must use ROTATE strategy",
    );
    expect(deploy).toContain("AIDENID_OTEL_OTLP_AUTH_TOKEN");
    expect(deploy).toContain("AIDENID_SERVICE_DISCOVERY_DNS_TTL_SECONDS");
    expect(deploy).toContain("TF_VAR_service_discovery_dns_ttl_seconds");
    expect(deploy).toContain("TF_VAR_redis_final_snapshot_identifier_suffix");
    expect(deploy).toContain(
      "${DEPLOY_ENVIRONMENT}-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}",
    );
    expect(deploy).toContain("Validate Redis AUTH token secret shape");
    expect(deploy).toContain("Validate OTel OTLP auth token secret shape");
    expect(deploy).toContain("Validate Cloudflare DNS token secret presence");
    expect(deploy).toContain(
      "AIDENID_OTEL_OTLP_AUTH_TOKEN must be 32-256 characters",
    );
    expect(deploy).toContain(
      "Sync OTel OTLP auth secret outside Terraform state",
    );
    expect(deploy).toContain("otel-otlp-auth-secret-sync-receipt.json");
    expect(deploy).toContain("receiver_requires_bearer_token: true");
    expect(deploy).toContain(
      "Configure Redis AUTH token outside Terraform state",
    );
    expect(deploy).toContain("modify-replication-group");
    expect(deploy).toContain(
      "redis-auth-token-out-of-state-activation-receipt.json",
    );
    expect(deploy).toContain("describe-replication-groups");
    expect(deploy).toContain("describe-cache-clusters");
    expect(deploy).toContain("redis-auth-token-postapply-availability.json");
    expect(deploy).toContain("redis_auth_token_postapply_availability_probe");
    expect(deploy).toContain("member_statuses: members");
    expect(deploy).toContain("cache_cluster_describe_required: true");
    expect(deploy).toContain("all_member_clusters_available");
    expect(deploy).toContain("ready_for_auth_token_modify");
    expect(deploy).toContain("required_before_auth_token_modify");
    expect(deploy).toContain("retry_on_invalid_cache_cluster_state");
    expect(deploy).toContain('wait_for_redis_available "before_auth_modify"');
    expect(deploy).toContain("InvalidCacheClusterState");
    expect(deploy).toContain("postapply_availability_artifact");
    expect(deploy).toContain("modify_attempts");
    expect(deploy).toContain("redis-auth-token-elasticache-readiness.json");
    expect(deploy).toContain("redis_auth_token_elasticache_readiness");
    expect(deploy).toContain("redis_auth_required: true");
    expect(deploy).toContain("expected_credential_update_strategy");
    expect(deploy).toContain("credential_last_modified_date");
    expect(deploy).toContain("AuthTokenEnabled=true");
    expect(deploy).toContain("rotation-age gate must pass");
    expect(deploy).toContain("terraform_state_plaintext_value: false");
    expect(deploy).toContain("credential_source");
    expect(deploy).toContain(
      "Require post-deploy automated health canary success",
    );
    expect(publicSmoke).toContain("name: Dashboard Public Smoke");
    expect(publicSmoke).toContain('workflows: ["Deploy Clearance Dashboard"]');
    expect(publicSmoke).toContain(
      "github.event.workflow_run.head_branch == 'main'",
    );
    expect(publicSmoke).toContain("AIDENID_DASHBOARD_PUBLIC_URL");
    expect(publicSmoke).toContain("AIDENID_DASHBOARD_HOSTNAME");
    expect(publicSmoke).toContain('canary_args=("${target}")');
    expect(publicSmoke).not.toContain("--emit-probe");
    expect(publicSmoke).not.toContain(
      "AIDENID_DASHBOARD_OPERATOR_REQUEST_TOKEN",
    );
    expect(publicSmoke).not.toContain("AIDENID_CONTROL_PLANE_API_KEY");
    expect(publicSmoke).toContain(
      'timeout 120s node scripts/check-dashboard-live.mjs "${canary_args[@]}"',
    );
    expect(publicSmoke).toContain("dashboard-public-smoke-verdict.json");
    expect(publicSmoke).toContain("dashboard_public_smoke_verdict");
    expect(publicSmoke).toContain("Public dashboard live canary failed");
    expect(liveDeployDoc).toContain("dashboard-public-hotfix-2026-05-25.json");
    expect(liveDeployDoc).toContain("26419867359");
    expect(liveDeployDoc).toContain("26420365788");
    expect(liveDeployDoc).toContain("26421146263");
    expect(liveDeployDoc).toContain("Cloudflare record");
    expect(liveDeployDoc).toContain("ALB listener still has the older");
    expect(liveHotfixArtifact).toContain("dashboard_public_hotfix_receipt");
    expect(liveHotfixArtifact).toContain(
      "aidenid-clearance-production-alb-599873594.us-east-1.elb.amazonaws.com",
    );
    expect(liveHotfixArtifact).toContain(
      "default_repo_variable_success_run_id",
    );
    expect(liveHotfixArtifact).toContain(
      "post_merge_default_repo_variable_success_run_id",
    );
    expect(deploy).toContain("required_for_apply_success: true");
    expect(deploy).toContain("dashboard-post-deploy-health-canary-gate.json");
    expect(deploy).toContain(
      "curl_args=(-fsS --connect-timeout 5 --max-time 30 --retry 3 --retry-delay 2 --retry-all-errors)",
    );
    expect(deploy).toContain('curl "${curl_args[@]}"');
    expect(deploy).toContain("refs/heads/main");
    expect(deploy).toContain("must equal current main");
    expect(deploy).toContain("guard exact SHA required checks");
    expect(deploy).toContain("REQUIRED_RELEASE_CHECK_WORKFLOWS");
    expect(deploy).toContain("verify_generic_required_status_checks");
    expect(deploy).toContain(
      "commits/${REQUIRED_CHECKS_SHA}/check-runs?per_page=100",
    );
    expect(deploy).toContain("require_exact_authoritative_run_id");
    expect(deploy).toContain("verify_manifest_authoritative_run_ids");
    expect(deploy).toContain(
      "RELEASE_WORKFLOW_CONCLUSION: ${{ github.event.workflow_run.conclusion }}",
    );
    expect(deploy).toContain(
      'if [ "${RELEASE_WORKFLOW_CONCLUSION}" != "success" ]; then',
    );
    expect(deploy).toContain(
      "Release workflow_run deploy trigger requires a successful release workflow before required-check verification",
    );
    expect(deploy).toContain(
      "workflow_run deploy uses the signed release manifest's exact run IDs",
    );
    expect(deploy).toContain(
      "workflow_dispatch deploy uses explicit exact run IDs",
    );
    expect(deploy).toContain(
      "Release-manifest authoritative gate run IDs verified",
    );
    expect(deploy).toContain(
      "Required release/deploy status check ${workflow} is missing or non-success",
    );
    expect(deploy).toContain(
      "needs.required_status_check_guard.outputs.checks_verified == 'true'",
    );
    expect(deploy).toContain('gh run download "${CI_RUN_ID}"');
    const deployRunDownloadBlocks =
      deploy.match(
        /(?:timeout 180s )?gh run download "\$\{[^}]+\}" \\\n(?:.*\n){0,4}/g,
      ) ?? [];
    expect(deployRunDownloadBlocks.length).toBeGreaterThanOrEqual(10);
    for (const block of deployRunDownloadBlocks) {
      expect(block).toContain('--repo "${GITHUB_REPOSITORY}"');
    }
    expect(deploy).toContain("sha256sum -c aidenid-clearance-build.sha256");
    expect(deploy).toContain("sha256sum -c ci-artifact-manifest.sha256");
    expect(deploy).toContain("Verify deploy artifact, SBOM, and image binding");
    expect(deploy).toContain("node scripts/verify-ci-sbom.mjs");
    expect(deploy).toContain("gh attestation verify");
    expect(deploy).toContain(
      '--signer-workflow "github.com/${GITHUB_REPOSITORY}/.github/workflows/ci.yml"',
    );
    expect(deploy).toContain("github_native_ci_verified");
    expect(deploy).toContain("Verify dashboard image signing attestation");
    expect(deploy).toContain("AIDENID_COSIGN_IMAGE");
    expect(deploy).toContain(
      "AIDENID_COSIGN_IMAGE is required for apply=true image attestation verification",
    );
    expect(deploy).toContain("verify-attestation");
    expect(deploy).toContain("--certificate-identity-regexp");
    expect(deploy).toContain("build-and-push-images.yml@refs/heads/main");
    expect(deploy).toContain("dashboard-image-cosign-attestation.json");
    expect(deploy).toContain('dashboard_registry="${DASHBOARD_IMAGE%%/*}"');
    expect(deploy).toContain(
      'cosign_docker_config="${RUNNER_TEMP}/cosign-docker-config"',
    );
    expect(deploy).toContain(
      'aws ecr get-login-password --region "${ecr_region}"',
    );
    expect(deploy).toContain(
      'docker --config "${cosign_docker_config}" login --username AWS --password-stdin "${dashboard_registry}"',
    );
    expect(deploy).toContain('chmod 0755 "${cosign_docker_config}"');
    expect(deploy).toContain(
      'chmod 0644 "${cosign_docker_config}/config.json"',
    );
    expect(deploy).toContain("DOCKER_CONFIG=/tmp/cosign-docker-config");
    expect(deploy).toContain(
      '"${cosign_docker_config}:/tmp/cosign-docker-config:ro"',
    );
    expect(deploy).toContain(
      '--signer-workflow "github.com/${GITHUB_REPOSITORY}/.github/workflows/attestation.yml"',
    );
    expect(deploy).toContain('--source-ref "refs/heads/main"');
    expect(deploy).toContain("AIDENID_PROVENANCE_BUCKET");
    expect(deploy).toContain("durable private-repo provenance fallback");
    expect(deploy).toContain("dashboard-provenance");
    expect(deploy).toContain("verify_downloaded_provenance_sha256()");
    expect(deploy).toContain(
      'checksum_basename="$(basename "${checksum_path}")"',
    );
    expect(deploy).toContain(
      "verify_downloaded_provenance_sha256 aidenid-clearance-provenance.sha256 aidenid-clearance-provenance.json",
    );
    expect(deploy).toContain(
      "verify_downloaded_provenance_sha256 aidenid-clearance-provenance-release-binding.sha256 aidenid-clearance-provenance-release-binding.json",
    );
    expect(deploy).toContain(
      "verify_downloaded_provenance_sha256 aidenid-clearance-provenance-durable-receipt.sha256 aidenid-clearance-provenance-durable-receipt.json",
    );
    expect(deploy).toContain("dashboard_image_release_binding");
    expect(deploy).toContain("dashboard_release_manifest");
    expect(deploy).toContain(
      "dashboard-release-manifest-${DEPLOY_ENVIRONMENT}-${DEPLOY_SHA}",
    );
    expect(deploy).toContain("image_subject.dashboard_image_digest");
    expect(deploy).toContain("image_subject.ci_artifact_sha256");
    expect(deploy).toContain("github_artifact_id");
    expect(deploy).toContain("github_artifact_archive_digest");
    expect(deploy).toContain("immutable_promotion.artifact_id");
    expect(deploy).toContain("requires_immutable_artifact_tuple == true");
    expect(deploy).toContain(".gates.ci.artifact.archive_sha256");
    expect(deploy).toContain("service_images.control_plane.image");
    expect(deploy).toContain("service_images.verifier.image");
    expect(deploy).toContain("service_images.otel_collector.image");
    expect(deploy).toContain(
      'CONTROL_PLANE_IMAGE="${AIDENID_EFFECTIVE_CONTROL_PLANE_IMAGE:-${AIDENID_RELEASE_EVENT_CONTROL_PLANE_IMAGE:-${REPOSITORY_CONTROL_PLANE_IMAGE:-}}}"',
    );
    expect(deploy).toContain(
      'VERIFIER_IMAGE="${AIDENID_EFFECTIVE_VERIFIER_IMAGE:-${AIDENID_RELEASE_EVENT_VERIFIER_IMAGE:-${REPOSITORY_VERIFIER_IMAGE:-}}}"',
    );
    expect(deploy).toContain(
      'OTEL_COLLECTOR_IMAGE="${AIDENID_EFFECTIVE_OTEL_COLLECTOR_IMAGE:-${AIDENID_RELEASE_EVENT_OTEL_COLLECTOR_IMAGE:-${REPOSITORY_OTEL_COLLECTOR_IMAGE:-}}}"',
    );
    expect(deploy).toContain(
      "TF_VAR_control_plane_image=${CONTROL_PLANE_IMAGE}",
    );
    expect(deploy).toContain("TF_VAR_verifier_image=${VERIFIER_IMAGE}");
    expect(deploy).toContain(
      "TF_VAR_otel_collector_image=${OTEL_COLLECTOR_IMAGE}",
    );
    expect(deploy).toContain("service_image_digests.control_plane");
    expect(deploy).toContain("requires_release_manifest_for_all_apply == true");
    expect(deploy).toContain("requires_ci_artifact_binding == true");
    expect(deploy).toContain("native_attestation_status");
    expect(deploy).toContain("provenance_storage_uri");
    expect(deploy).toContain("release_manifest_sha256");
    expect(deploy).toContain("dashboard-image-release-binding.sha256");
    expect(deploy).toContain("release_binding_sha256");
    expect(deploy).toContain("ci_sbom_sha256");
    expect(deploy).toContain(
      "diff -u ci-artifact-manifest.txt ci-artifact-manifest.actual",
    );
    expect(deploy).toContain("AIDENID_TF_STATE_KMS_KEY_ID");
    expect(deploy).toContain(
      '-backend-config="kms_key_id=${AIDENID_TF_STATE_KMS_KEY_ID}"',
    );
    expect(deploy).toContain("Terraform policy security gate");
    expect(deploy).toContain("node scripts/security-scan.mjs iac");
    expect(deploy).toContain("plan -lock-timeout=5m");
    expect(deploy).toContain("apply -lock-timeout=5m");
    expect(deploy).toContain("dashboard-terraform-plan.txt");
    expect(deploy).toContain("dashboard-terraform-plan-approval.json");
    expect(deploy).toContain("dashboard-terraform-plan-approval.sha256");
    expect(deploy).toContain("terraform_plan_approval_run_id");
    expect(deploy).toContain(
      "workflow_dispatch apply requires numeric terraform_plan_approval_run_id",
    );
    expect(deploy).toContain("approved_at");
    expect(deploy).toContain("expires_at");
    expect(deploy).toContain("dashboard-terraform-plan-approval-reviewed.json");
    expect(deploy).toContain("dashboard-terraform-vars.sha256");
    expect(deploy).toContain("apply_rejects_expired_plan_approval");
    expect(deploy).toContain(
      "apply_binds_source_sha_environment_and_tfvars_digest",
    );
    expect(deploy).toContain("write-dashboard-terraform-plan-approval.mjs");
    expect(deploy).toContain("dashboard-preapply-readiness.json");
    expect(deploy).toContain("write-dashboard-preapply-readiness.mjs");
    expect(deploy).toContain("sbom_run_id:");
    expect(deploy).toContain(
      "required for every workflow_dispatch deploy and rollback",
    );
    expect(deploy).toContain("deploy-output/dashboard-ecs-rollback.sh");
    expect(deploy).toContain("deploy-output/ecs-preapply/*.json");
    expect(deploy).toContain("describe-task-definition");
    expect(deploy).toContain("taskDefinition.status");
    expect(deploy).toContain(
      'if [ "\\${task_definition_status}" = "ACTIVE" ]; then',
    );
    expect(deploy).toContain("skipping update-service");
    expect(deploy).toContain(
      "relying on ECS circuit breaker/service stability evidence",
    );
    expect(deploy).toContain("bash deploy-output/dashboard-ecs-rollback.sh");
    expect(deploy).toContain(
      "does not match reviewed expected_terraform_plan_sha256",
    );
    expect(deploy).toContain("cloudflare-dashboard-cname-plan.json");
    expect(deploy).toContain("Cloudflare dashboard CNAME verified");
    expect(deploy).toContain("Upsert Cloudflare control-plane CNAME");
    expect(deploy).toContain("cloudflare-control-plane-cname-plan.json");
    expect(deploy).toContain("control_plane_cloudflare_cname_plan");
    expect(deploy).toContain("Cloudflare control-plane CNAME verified");
    expect(deploy).toContain("Upsert Cloudflare verifier CNAME");
    expect(deploy).toContain("cloudflare-verifier-cname-plan.json");
    expect(deploy).toContain("verifier_cloudflare_cname_plan");
    expect(deploy).toContain("Cloudflare verifier CNAME verified");
    expect(deploy).toContain(
      "configure_dns requires AIDENID_VERIFIER_HOSTNAME so the public verifier endpoint can be smoke-tested",
    );
    expect(deploy).toContain(
      "Run rollback readiness after failed apply or canary",
    );
    expect(deploy).toContain("aws ecs wait services-stable");
    expect(deploy).toContain("write-dashboard-rollback-readiness.mjs");
    expect(deploy).toContain(
      "Require recent rollback drill evidence before apply",
    );
    expect(deploy).toContain(
      "Require recent rollback drill evidence before rollback",
    );
    expect(deploy).toContain("verify-dashboard-rollback-drill.mjs");
    expect(deploy).toContain(
      "dashboard-rollback-drills/${DEPLOY_ENVIRONMENT}/latest.json",
    );
    expect(deploy).toContain("dashboard-rollback-drill-evidence.json");
    expect(deploy).toMatch(
      /resolve_deploy_context:[\s\S]*?timeout-minutes: 20/,
    );
    expect(deploy).toMatch(/deploy:[\s\S]*?timeout-minutes: 60/);
    expect(deploy).toMatch(/rollback:[\s\S]*?timeout-minutes: 30/);
    expect(deploy).toContain("production_rollback_approval:");
    expect(deploy).toContain("aidenid-clearance-production-rollback");
    expect(deploy).toMatch(
      /rollback:[\s\S]*?environment:\s*\n\s*name: \$\{\{ inputs\.environment == 'production' && 'aidenid-clearance-production-rollback'/,
    );
    expect(deploy).toContain(
      "Record rollback execution protected environment binding",
    );
    expect(deploy).toContain(
      "Rollback execution job is bound to ${ROLLBACK_EXECUTION_ENVIRONMENT} before saved rollback artifact download or script execution.",
    );
    expect(deploy).toContain("Require post-rollback verification evidence");
    expect(deploy).toContain(
      "rollback_source_sha before authoritative gate verification",
    );
    expect(deploy).toContain('REQUIRED_CHECKS_SHA="${ROLLBACK_SOURCE_SHA}"');
    expect(deploy).toContain(
      "rollback=true uses explicit exact run IDs for rollback_source_sha",
    );
    expect(deploy).toContain(
      "rollback=true authoritative gate run IDs verified for rollback source SHA",
    );
    expect(deploy).toContain("required checks SHA ${REQUIRED_CHECKS_SHA}");
    expect(deploy).toContain("required_for_rollback_success");
    expect(deploy).toContain("timeout-minutes: 8");
    expect(deploy).toContain("AIDENID_CONTROL_PLANE_HOSTNAME");
    expect(deploy).toContain("AIDENID_VERIFIER_HOSTNAME");
    expect(deploy).toContain(
      'canary_args=("${target}" "--site-id" "${dashboard_site_id}")',
    );
    expect(deploy).toContain(
      'dashboard_operator_secret_name="${AIDENID_CLEARANCE_PROJECT}-${DEPLOY_ENVIRONMENT}/dashboard/operator-token"',
    );
    expect(deploy).toContain("aws secretsmanager get-secret-value");
    expect(deploy).toContain('echo "::add-mask::${dashboard_operator_token}"');
    expect(deploy).toContain(
      'verifier_operator_secret_name="${AIDENID_CLEARANCE_PROJECT}-${DEPLOY_ENVIRONMENT}/control-plane/operator-tokens"',
    );
    expect(
      deploy.match(/select\(\.name == "AIDENID_CONTROL_PLANE_API_KEY"\)/g) ??
        [],
    ).toHaveLength(2);
    expect(deploy).toContain(
      'verifier_secret_selector_prefix="${verifier_operator_secret_arn}:"',
    );
    expect(deploy).toContain(
      "Running verifier control-plane key must reference the environment operator-token secret",
    );
    expect(deploy).toContain(
      "Running verifier control-plane key must use one bounded Secrets Manager JSON selector",
    );
    expect(deploy).toContain(
      "'.SecretString | fromjson | .[$key] | select(type == \"string\")'",
    );
    expect(
      deploy.match(/echo "::add-mask::\$\{control_plane_api_key\}"/g) ?? [],
    ).toHaveLength(2);
    expect(
      deploy.match(
        /control_plane_key_env_name="AIDENID_CONTROL_PLANE_API_KEY"/g,
      ) ?? [],
    ).toHaveLength(2);
    expect(
      deploy.match(
        /printf -v "\$\{control_plane_key_env_name\}" '%s' "\$\{control_plane_api_key\}"/g,
      ) ?? [],
    ).toHaveLength(2);
    expect(
      deploy.match(/export "\$\{control_plane_key_env_name\}"/g) ?? [],
    ).toHaveLength(2);
    expect(deploy.match(/unset verifier_operator_secret/g) ?? []).toHaveLength(
      2,
    );
    expect(deploy).toContain(
      'dashboard_token_env_name="AIDENID_DASHBOARD_OPERATOR_REQUEST_TOKEN"',
    );
    expect(deploy).toContain('select(.name == "AIDENID_DASHBOARD_SITE_ID")');
    expect(deploy).toContain(
      'canary_args+=("--emit-probe" "--control-plane-url" "https://${AIDENID_CONTROL_PLANE_HOSTNAME}")',
    );
    expect(deploy).toContain(
      'check_public_endpoint "control-plane health" "https://${AIDENID_CONTROL_PLANE_HOSTNAME}/healthz"',
    );
    expect(deploy).toContain(
      'check_public_endpoint "control-plane readiness" "https://${AIDENID_CONTROL_PLANE_HOSTNAME}/readyz"',
    );
    expect(deploy).toContain(
      'check_public_endpoint "verifier health" "https://${AIDENID_VERIFIER_HOSTNAME}/healthz"',
    );
    expect(deploy).toContain(
      'check_public_endpoint "verifier readiness" "https://${AIDENID_VERIFIER_HOSTNAME}/readyz"',
    );
    expect(deploy).toContain(
      "AIdenID dashboard and public host canaries passed",
    );
    expect(deploy).toContain(
      'timeout 25s node "${canary_src}/scripts/check-dashboard-live.mjs" "${canary_args[@]}"',
    );
    expect(deploy).not.toContain("pnpm install --frozen-lockfile");
    const dashboardCanary = readRepoFile("scripts/check-dashboard-live.mjs");
    expect(dashboardCanary).toContain("status.fallbackDataEnabled === true");
    expect(dashboardCanary).toContain(
      "status.controlPlaneStreamConfigured !== true",
    );
    expect(dashboardCanary).toContain(
      'streamDataSource !== "live" && !allowSample',
    );
    expect(dashboardCanary).toContain("event:\\s*stream_error");
    expect(dashboardCanary).toContain("decision_stream_unavailable");
    expect(dashboardCanary).toContain("live_control_plane_required");
    expect(dashboardCanary).toContain("emitSyntheticDecision");
    expect(dashboardCanary).toContain("observeContinuousProbe");
    expect(dashboardCanary).toContain('new URL("api/decisions/stream", base)');
    expect(dashboardCanary).toContain("observedProbe");
    expect(dashboardCanary).toContain("Last-Event-ID");
    expect(dashboardCanary).toContain("verifyAnonymousStreamBoundary");
    expect(dashboardCanary).toContain("operator_auth_required");
    expect(dashboardCanary).toContain("anonymousStreamDenied");
    expect(dashboardCanary).toContain("authenticatedStreamObserved");
    expect(dashboardCanary).toContain(
      "AIDENID_DASHBOARD_OPERATOR_REQUEST_TOKEN",
    );
    expect(dashboardCanary).toContain("AIDENID_CONTROL_PLANE_API_KEY");
    expect(dashboardCanary).toContain(
      "authenticated emit probes require AIDENID_CONTROL_PLANE_API_KEY",
    );
    expect(dashboardCanary).toContain("site_id: siteId");
  });

  it("provides a bounded dashboard DNS repair workflow with live canary proof", () => {
    const repair = readWorkflow("dashboard-dns-repair.yml");

    expect(repair).toContain("name: Dashboard DNS Repair");
    expect(repair).toContain("workflow_dispatch:");
    expect(repair).toContain("expected_cname:");
    expect(repair).toContain("permissions:");
    expect(repair).toContain("contents: read");
    expect(repair).toContain("concurrency:");
    expect(repair).toContain("cancel-in-progress: false");
    expect(repair).toContain(
      "CLOUDFLARE_API_TOKEN: ${{ secrets.CLOUDFLARE_API_TOKEN }}",
    );
    expect(repair).toContain(
      "CLOUDFLARE_ZONE_ID: ${{ vars.CLOUDFLARE_ZONE_ID }}",
    );
    expect(repair).toContain("dashboard.aidenid.com) ;;");
    expect(repair).toContain(
      "api.aidenid.com|swarm.aidenid.com|swarmbots.aidenid.com|aidenid.com|www.aidenid.com",
    );
    expect(repair).toContain(
      "Dashboard DNS repair is intentionally scoped to dashboard.aidenid.com",
    );
    expect(repair).toContain(
      "aidenid-clearance-production-alb-*.us-east-1.elb.amazonaws.com",
    );
    expect(repair).toContain("Refusing ambiguous repair");
    expect(repair).toContain("expected CNAME repair only");
    expect(repair).toContain("dashboard_dns_repair_plan");
    expect(repair).toContain("dashboard_dns_repair_verdict");
    expect(repair).toContain("cloudflare_api_state_verified: true");
    expect(repair).toContain("bounded_to_clearance_dashboard: true");
    expect(repair).toContain(
      "api.cloudflare.com/client/v4/zones/${CLOUDFLARE_ZONE_ID}/dns_records",
    );
    expect(repair).toContain(
      "curl_args=(-fsS --connect-timeout 5 --max-time 30 --retry 3 --retry-delay 2 --retry-all-errors)",
    );
    expect(repair).toContain("node scripts/check-dashboard-live.mjs");
    expect(repair).toContain("required_before_release_readiness: true");
    expect(repair).toContain(
      "Dashboard DNS repair completed but live canary did not pass",
    );
    expect(repair).toContain(
      "dashboard-dns-repair-${{ inputs.hostname || vars.AIDENID_DASHBOARD_HOSTNAME || 'dashboard.aidenid.com' }}-${{ github.sha }}",
    );

    for (const [, ref] of repair.matchAll(/uses:\s+[^\s@]+@([^\s]+)/g)) {
      expect(ref).toMatch(/^[0-9a-f]{40}$/);
    }
  });

  it("runs a scheduled continuous dashboard rollback drill verification workflow", () => {
    const drill = readWorkflow("dashboard-rollback-drill.yml");

    expect(drill).toContain("name: Dashboard Rollback Drill");
    expect(drill).toContain("schedule:");
    expect(drill).toContain("workflow_dispatch:");
    expect(drill).toContain("concurrency:");
    expect(drill).toContain("cancel-in-progress: false");
    expect(drill).toContain("attestations: write");
    expect(drill).toContain("id-token: write");
    expect(drill).toContain("timeout-minutes: 20");
    expect(drill).toContain("aws-actions/configure-aws-credentials@");
    expect(drill).toMatch(
      /aws-actions\/configure-aws-credentials@[0-9a-f]{40}/,
    );
    expect(drill).toContain("scripts/verify-dashboard-rollback-drill.mjs");
    expect(drill).toContain("scheduled_continuous_rollback_drill: true");
    expect(drill).toContain("required_before_apply: true");
    expect(drill).toContain("required_before_rollback: true");
    expect(drill).toContain("safe_non_production_environment");
    expect(drill).toContain(
      "dashboard-rollback-drill-continuous-evidence.json",
    );
    expect(drill).toContain(
      "Record scheduled rollback drill native-attestation support",
    );
    expect(drill).toContain(
      "dashboard_rollback_drill_native_attestation_support",
    );
    expect(drill).toContain(
      "github_native_attestation_unavailable_for_user_owned_private_repository",
    );
    expect(drill).toContain("publication_equivalent_evidence: false");
    expect(drill).toContain(
      "dashboard-rollback-drill-native-attestation-support.json",
    );
    expect(drill).toContain("actions/attest-build-provenance@");
    expect(drill).toContain(
      "if: ${{ github.event.repository.private == false }}",
    );
    expect(drill).toMatch(/actions\/attest-build-provenance@[0-9a-f]{40}/);

    for (const [, ref] of drill.matchAll(/uses:\s+[^\s@]+@([^\s]+)/g)) {
      expect(ref).toMatch(/^[0-9a-f]{40}$/);
    }
  });

  it("publishes service images through the least-privilege ECR role", () => {
    const workflow = readWorkflow("build-and-push-images.yml");
    const spec = readRepoFile("SPEC.md");
    const terraformReadme = readRepoFile("infra/terraform/README.md");
    const imageContentVerifier = readRepoFile(
      "scripts/verify-service-image-content.mjs",
    );

    expect(workflow).toContain("name: Build and Push Clearance Images");
    expect(workflow).toContain("pull_request:");
    expect(workflow).toContain("branches: [main]");
    expect(workflow).toContain("tags:");
    expect(workflow).toContain('"release-*"');
    expect(workflow).toContain("workflow_dispatch:");
    expect(workflow).toContain(
      "cancel-in-progress: ${{ github.event_name == 'pull_request' }}",
    );
    expect(workflow).toContain("permissions:");
    expect(workflow).toContain("contents: read");
    const topPermissions = workflow.slice(
      workflow.indexOf("permissions:"),
      workflow.indexOf("env:"),
    );
    expect(topPermissions).not.toContain("id-token: write");
    expect(topPermissions).not.toContain("contents: write");

    const validateBlock = workflow.slice(
      workflow.indexOf("  validate:"),
      workflow.indexOf("  publish:"),
    );
    expect(validateBlock).toContain("permissions:");
    expect(validateBlock).toContain("contents: read");
    expect(validateBlock).not.toContain("id-token: write");
    expect(validateBlock).toContain(
      "github_oidc_role_required_outside_pull_requests: true",
    );
    expect(validateBlock).toContain("AIDENID_COSIGN_IMAGE");
    expect(validateBlock).toContain(
      'cosign_image_attestation_required_outside_pull_requests: ($event_name != "pull_request")',
    );
    expect(validateBlock).toContain("cosign_image_digest_pinned");
    expect(validateBlock).toContain(
      "AIDENID_COSIGN_IMAGE is required so published service images carry cosign SLSA attestations",
    );
    expect(validateBlock).toContain(
      "Dockerfile FROM images must be digest-pinned before docker build --pull",
    );
    expect(validateBlock).toContain(
      "dockerfile_base_images_digest_pinned: true",
    );
    expect(validateBlock).toContain(
      "push_job_waits_for_same_sha_quality_gates: true",
    );

    const imageContentProbeBlock = workflow.slice(
      workflow.indexOf("  image_content_probe:"),
      workflow.indexOf("  publish:"),
    );
    expect(imageContentProbeBlock).toContain(
      "github.event_name == 'pull_request'",
    );
    expect(imageContentProbeBlock).toContain("contents: read");
    expect(imageContentProbeBlock).not.toContain("id-token: write");
    expect(imageContentProbeBlock).not.toContain(
      "aws-actions/configure-aws-credentials",
    );
    expect(imageContentProbeBlock).toContain("docker build --pull");
    expect(imageContentProbeBlock).toContain(
      "node scripts/verify-service-image-content.mjs",
    );
    expect(imageContentProbeBlock).toContain(
      'build_and_probe "control-plane" "apps/control-plane/Dockerfile"',
    );
    expect(imageContentProbeBlock).toContain(
      'build_and_probe "dashboard" "apps/dashboard/Dockerfile"',
    );
    expect(imageContentProbeBlock).toContain(
      'build_and_probe "verifier" "apps/verifier/Dockerfile"',
    );
    expect(imageContentProbeBlock).toContain(
      "app-image-content-probes-${{ github.sha }}",
    );

    const publishBlock = workflow.slice(workflow.indexOf("  publish:"));
    expect(publishBlock).toContain("github.event_name != 'pull_request'");
    expect(publishBlock).toContain("github.ref == 'refs/heads/main'");
    expect(publishBlock).toContain(
      "startsWith(github.ref, 'refs/tags/release-')",
    );
    expect(publishBlock).toContain("id-token: write");
    expect(publishBlock).toContain("actions: read");
    expect(publishBlock).toContain("contents: read");
    expect(publishBlock).not.toContain("contents: write");
    expect(publishBlock).not.toContain("packages: write");
    expect(publishBlock).toContain(
      "COSIGN_IMAGE: ${{ env.AIDENID_COSIGN_IMAGE }}",
    );
    expect(publishBlock).toContain("cosign_docker_config");
    expect(publishBlock).toContain(
      'docker --config "${cosign_docker_config}" login --username AWS --password-stdin "${registry}"',
    );
    expect(publishBlock).toContain('chmod 0755 "${cosign_docker_config}"');
    expect(publishBlock).toContain(
      'chmod 0644 "${cosign_docker_config}/config.json"',
    );
    expect(publishBlock).toContain("write_service_image_slsa_predicate()");
    expect(publishBlock).toContain("ensure_service_image_attestation()");
    expect(publishBlock).toContain("verify_service_image_attestation()");
    expect(publishBlock).toContain("builder: {id: $builder_id}");
    expect(publishBlock).toContain(
      'buildType: "https://aidenid.dev/build/service-image/v1"',
    );
    expect(publishBlock).toContain("invocation: {");
    expect(publishBlock).toContain("configSource: {");
    expect(publishBlock).toContain("parameters: {");
    expect(publishBlock).toContain("environment: {");
    expect(publishBlock).toContain("metadata: {");
    expect(publishBlock).toContain("completeness: {");
    expect(publishBlock).toContain("materials: [");
    expect(publishBlock).toContain(".metadata.completeness.materials == true");
    expect(publishBlock).not.toContain("buildDefinition: {");
    expect(publishBlock).not.toContain("runDetails: {");
    expect(publishBlock).toContain('rm -f "${output_path}"');
    expect(publishBlock).toContain('if [ ! -s "${output_path}" ]; then');
    expect(publishBlock).toContain(
      "cosign verify-attestation produced an empty receipt",
    );
    expect(publishBlock).toContain(
      "cosign verify-attestation produced a non-JSON receipt",
    );
    expect(publishBlock).toContain("return 1");
    expect(publishBlock).toContain("COSIGN_YES=true");
    expect(publishBlock).toContain("ACTIONS_ID_TOKEN_REQUEST_TOKEN");
    expect(publishBlock).toContain("ACTIONS_ID_TOKEN_REQUEST_URL");
    expect(publishBlock).toContain("attest");
    expect(publishBlock).toContain("--type slsaprovenance");
    expect(publishBlock).toContain("--predicate");
    expect(publishBlock).toContain("verify-attestation");
    expect(publishBlock).toContain("build-and-push-images.yml@refs/heads/main");
    expect(publishBlock).toContain(
      "build-and-push-images.yml@refs/tags/${release_tag}",
    );
    expect(publishBlock).toContain("refs/(heads/main|tags/release-");
    expect(publishBlock).toContain(
      "Verify required gates and Dockerfile base digests before publish",
    );
    expect(publishBlock).toContain(
      "Same-SHA quality, security, and attestation gates passed before ECR credentials were configured.",
    );
    expect(publishBlock).toContain("require_successful_workflow_for_sha");
    expect(publishBlock).toContain('"CI"');
    expect(publishBlock).toContain('"Omar Gate"');
    expect(publishBlock).toContain('"SBOM"');
    expect(publishBlock).toContain('"OpenSSF Scorecard"');
    expect(publishBlock).toContain('"Artifact Attestation"');
    expect(publishBlock).toContain('"Attestation Contract Check"');
    expect(publishBlock).toContain('"Branch Protection Governance"');
    expect(publishBlock).toContain(
      "aws-actions/configure-aws-credentials@ec61189d14ec14c8efccab744f656cffd0e33f37",
    );
    expect(
      publishBlock.indexOf(
        "Verify required gates and Dockerfile base digests before publish",
      ),
    ).toBeLessThan(
      publishBlock.indexOf("Configure AWS credentials for ECR image push"),
    );
    expect(publishBlock).toContain(
      "role-to-assume: ${{ env.AIDENID_IMAGE_PUSH_ROLE_ARN }}",
    );
    expect(publishBlock).toContain("aws ecr get-login-password");
    expect(publishBlock).toContain("docker login --username AWS");
    expect(publishBlock).toContain('sha_tag="sha-${GITHUB_SHA}"');
    expect(publishBlock).toContain(
      'build_tag="build-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"',
    );
    expect(publishBlock).toContain("refs/tags/release-*");
    expect(publishBlock).toContain("aws ecr describe-images");
    expect(publishBlock).toContain("aws ecr batch-get-image");
    expect(publishBlock).toContain("aws ecr put-image");
    expect(publishBlock).toContain("Release tag ${release_tag}");
    expect(publishBlock).toContain("docker build --pull");
    expect(publishBlock).toContain("verify_service_image_content()");
    expect(publishBlock).toContain(
      "node scripts/verify-service-image-content.mjs",
    );
    expect(publishBlock).toContain('--service "${service}"');
    expect(publishBlock).toContain('--image "${image_ref}"');
    expect(publishBlock).toContain(
      'local output_path="image-push/${service}-image-content.json"',
    );
    expect(
      publishBlock.indexOf(
        'verify_service_image_content "${service}" "${repository_uri}:${build_tag}"',
      ),
    ).toBeLessThan(publishBlock.indexOf("docker push"));
    expect(publishBlock).toContain(
      'docker pull "${repository_uri}:${sha_tag}"',
    );
    expect(publishBlock).toContain("image_content_evidence");
    expect(publishBlock).toContain("cosign_attestation");
    expect(publishBlock).toContain("predicate_sha256");
    expect(publishBlock).toContain("verify_sha256");
    expect(publishBlock).toContain(
      "aidenid_clearance_service_image_cosign_attestation_status",
    );
    expect(publishBlock).toContain("docker push");
    expect(publishBlock).toContain("aidenid-clearance-production/${service}");
    expect(publishBlock).toContain("apps/control-plane/Dockerfile");
    expect(publishBlock).toContain("apps/dashboard/Dockerfile");
    expect(publishBlock).toContain("apps/otel-collector/Dockerfile");
    expect(publishBlock).toContain("apps/verifier/Dockerfile");
    expect(publishBlock).toContain("otel_collector_image");
    expect(publishBlock).toContain("service_images.otel_collector.image");
    expect(publishBlock).toContain("terraform_tfvars.otel_collector_image");
    expect(publishBlock).toContain("aidenid_clearance_service_image_push");
    expect(publishBlock).toContain(
      'local output_path="image-push/${service}.json"',
    );
    expect(publishBlock).toContain('> "${output_path}"');
    expect(publishBlock).not.toMatch(
      /publish_service\s+"[^"]+"\s+"[^"]+"\s*>\s*image-push\//,
    );
    expect(publishBlock).not.toContain("> image-push/control-plane.json");
    expect(publishBlock).not.toContain("> image-push/dashboard.json");
    expect(publishBlock).not.toContain("> image-push/otel-collector.json");
    expect(publishBlock).not.toContain("> image-push/verifier.json");
    expect(publishBlock).toContain("service-images.auto.tfvars");
    expect(publishBlock).toContain("service-images.auto.tfvars.json");
    expect(publishBlock).toContain("service-images.env");
    expect(publishBlock).toContain("service-images.sha256");
    expect(publishBlock).toContain("dashboard-slsa-provenance-predicate.json");
    expect(publishBlock).toContain("dashboard-cosign-attestation.json");
    expect(publishBlock).toContain("dashboard-cosign-attestation-status.json");
    expect(publishBlock).toContain("control-plane-cosign-attestation.json");
    expect(publishBlock).toContain("otel-collector-cosign-attestation.json");
    expect(publishBlock).toContain("verifier-cosign-attestation.json");
    expect(publishBlock).toContain(
      "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
    );
    expect(publishBlock).toContain("retention-days: 30");
    expect(workflow).not.toContain("docker://");
    expect(workflow).not.toContain("docker/login-action");
    expect(workflow).not.toContain("docker/build-push-action");
    expect(workflow).not.toContain("aws-actions/amazon-ecr-login");

    expect(imageContentVerifier).toContain("--network=none");
    expect(imageContentVerifier).toContain("/app/dist/start.js");
    expect(imageContentVerifier).toContain(
      "/app/migrations/0025_operator_reputation_expiry.sql",
    );
    expect(imageContentVerifier).toContain(
      "/app/apps/dashboard/.next/server/app/api/status/route.js",
    );
    expect(imageContentVerifier).toContain(
      "/app/node_modules/@aidenid/verifier-node/dist/index.js",
    );
    expect(imageContentVerifier).toContain(
      "/app/node_modules/@aidenid/verifier-node/templates/github/aidenid-omar-gate.yml",
    );
    expect(imageContentVerifier).toContain("/app/.env");
    expect(imageContentVerifier).toContain("/app/.git");
    expect(imageContentVerifier).toContain("/repo");

    for (const [, ref] of workflow.matchAll(/uses:\s+[^\s@]+@([^\s]+)/g)) {
      expect(ref).toMatch(/^[0-9a-f]{40}$/);
    }

    expect(spec).toContain(
      "The image-push workflow must run on main and `release-*` refs only for AWS publishing",
    );
    expect(spec).toContain("skip immutable `sha-*` rewrites on reruns");
    expect(spec).toContain(
      "network-disabled image-content probe for each built or pulled app image",
    );
    expect(terraformReadme).toContain(
      ".github/workflows/build-and-push-images.yml",
    );
    expect(terraformReadme).toContain("service-images.auto.tfvars");
  });

  it("pins the control-plane runtime image and starts the production server", () => {
    const dockerfile = readRepoFile("apps/control-plane/Dockerfile");
    const packageJson = readRepoFile("apps/control-plane/package.json");
    const start = readRepoFile("apps/control-plane/src/start.ts");
    const migrations = readRepoFile("apps/control-plane/src/migrations.ts");
    const dockerignore = readRepoFile(".dockerignore");
    const rdsBundle = readRepoFile(
      "apps/control-plane/certs/rds-global-bundle.pem",
    );
    const froms = [
      ...dockerfile.matchAll(
        /^FROM node:22-bookworm-slim@sha256:([a-f0-9]{64}) AS (builder|runner)$/gm,
      ),
    ];

    expect(froms).toHaveLength(2);
    expect(new Set(froms.map((match) => match[1])).size).toBe(1);
    expect(dockerfile).not.toContain("FROM node:22-bookworm-slim AS");
    expect(dockerfile).toContain("ARG PNPM_VERSION=10.28.0");
    expect(dockerfile).toContain(
      'corepack prepare "pnpm@${PNPM_VERSION}" --activate',
    );
    expect(dockerfile).toContain('pnpm --version | grep -Fx "${PNPM_VERSION}"');
    expect(dockerfile).toContain(
      "pnpm install --ignore-scripts --frozen-lockfile",
    );
    expect(dockerfile).not.toContain("COPY . .");
    expect(dockerfile).toContain(
      "COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.base.json tsconfig.test.json ./",
    );
    expect(dockerfile).toContain(
      "COPY apps/control-plane/package.json apps/control-plane/tsconfig.json ./apps/control-plane/",
    );
    expect(dockerfile).toContain(
      "COPY apps/control-plane/src ./apps/control-plane/src",
    );
    expect(dockerfile).toContain(
      "COPY packages/common-schemas/src ./packages/common-schemas/src",
    );
    expect(dockerfile).not.toContain("ENV NODE_ENV=production\n\nRUN corepack");
    expect(dockerfile).toContain(
      "pnpm --filter @aidenid/control-plane... build",
    );
    expect(dockerfile).toContain(
      "pnpm --filter @aidenid/control-plane deploy --prod --legacy /app",
    );
    expect(dockerfile).toContain(
      "COPY --chown=node:node --from=builder /app/dist ./dist",
    );
    expect(dockerfile).toContain(
      "COPY --chown=node:node --from=builder /app/node_modules ./node_modules",
    );
    expect(dockerfile).toContain(
      "COPY --chown=node:node --from=builder /app/migrations ./migrations",
    );
    expect(dockerfile).toContain(
      "ENV AIDENID_CONTROL_PLANE_DATABASE_SSLROOTCERT=/app/certs/rds-global-bundle.pem",
    );
    expect(dockerfile).toContain(
      "COPY --chown=node:node --from=builder /repo/apps/control-plane/certs ./certs",
    );
    expect(rdsBundle).toContain("-----BEGIN CERTIFICATE-----");
    expect(rdsBundle.match(/-----BEGIN CERTIFICATE-----/g) ?? []).toHaveLength(
      108,
    );
    expect(createHash("sha256").update(rdsBundle, "utf8").digest("hex")).toBe(
      "e5bb2084ccf45087bda1c9bffdea0eb15ee67f0b91646106e466714f9de3c7e3",
    );
    expect(dockerfile).not.toContain(
      "COPY --chown=node:node --from=builder /repo ./",
    );
    expect(dockerfile).toContain("USER node");
    expect(dockerfile).toContain('CMD ["node", "dist/start.js"]');
    expect(packageJson).toContain('"start": "node dist/start.js"');
    expect(start.indexOf("runControlPlaneMigrations(pool)")).toBeLessThan(
      start.indexOf("createControlPlaneApp({"),
    );
    expect(migrations).toContain(
      "SELECT set_config('lock_timeout', $1, false)",
    );
    expect(migrations).toContain("SELECT pg_advisory_lock($1, $2)");
    expect(migrations).toContain(
      "timed out acquiring control-plane migration advisory lock",
    );
    expect(migrations).toContain(
      "CREATE TABLE IF NOT EXISTS schema_migrations",
    );
    expect(migrations).toContain("filename text NOT NULL UNIQUE");
    expect(migrations).toContain("checksum_sha256");
    expect(migrations).toContain("applied_by text NOT NULL");
    expect(dockerignore).toMatch(/^\.tmp$/m);
    expect(dockerignore).toMatch(/^\.env$/m);
    expect(dockerignore).toMatch(/^\.env\.\*$/m);
    expect(dockerignore).toMatch(/^\*\.tfplan$/m);
    expect(dockerignore).toMatch(/^ci-sbom\.spdx\.json$/m);
    expect(dockerignore).toMatch(/^\*\.key$/m);
  });

  it("mirrors the OTel collector through private ECR from a pinned upstream image", () => {
    const dockerfile = readRepoFile("apps/otel-collector/Dockerfile");

    expect(dockerfile).toContain(
      "FROM ghcr.io/open-telemetry/opentelemetry-collector-releases/opentelemetry-collector-contrib:0.152.0@sha256:f41d7995565df3733b7568702073a9c490792f9c6ac60684fe6a4da21a313f8d",
    );
    expect(dockerfile).toContain("USER 10001:10001");
    expect(dockerfile).toContain('CMD ["--config=env:AOT_CONFIG_CONTENT"]');
    expect(dockerfile).not.toContain(":latest");
    expect(dockerfile).not.toContain(
      "public.ecr.aws/aws-observability/aws-otel-collector",
    );
  });

  it("pins the verifier wrapper runtime image and starts the production proxy", () => {
    const dockerfile = readRepoFile("apps/verifier/Dockerfile");
    const packageJson = readRepoFile("apps/verifier/package.json");
    const froms = [
      ...dockerfile.matchAll(
        /^FROM node:22-bookworm-slim@sha256:([a-f0-9]{64}) AS (builder|runner)$/gm,
      ),
    ];

    expect(froms).toHaveLength(2);
    expect(new Set(froms.map((match) => match[1])).size).toBe(1);
    expect(dockerfile).not.toContain("FROM node:22-bookworm-slim AS");
    expect(dockerfile).toContain("ARG PNPM_VERSION=10.28.0");
    expect(dockerfile).toContain(
      "COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.base.json tsconfig.test.json ./",
    );
    expect(dockerfile).toContain(
      'corepack prepare "pnpm@${PNPM_VERSION}" --activate',
    );
    expect(dockerfile).toContain('pnpm --version | grep -Fx "${PNPM_VERSION}"');
    expect(dockerfile).toContain(
      "pnpm install --ignore-scripts --frozen-lockfile",
    );
    expect(dockerfile).not.toContain("COPY . .");
    expect(dockerfile).toContain(
      "COPY apps/verifier/package.json apps/verifier/tsconfig.json ./apps/verifier/",
    );
    expect(dockerfile).toContain("COPY apps/verifier/src ./apps/verifier/src");
    expect(dockerfile).toContain(
      "COPY packages/verifier-node/templates ./packages/verifier-node/templates",
    );
    expect(dockerfile).toContain(
      "pnpm --filter @aidenid/verifier-app... build",
    );
    expect(dockerfile).toContain(
      "pnpm --filter @aidenid/verifier-app deploy --prod --legacy /app",
    );
    expect(dockerfile).toContain(
      "COPY --chown=node:node --from=builder /app/dist ./dist",
    );
    expect(dockerfile).toContain(
      "COPY --chown=node:node --from=builder /app/node_modules ./node_modules",
    );
    expect(dockerfile).not.toContain(
      "COPY --chown=node:node --from=builder /repo ./",
    );
    expect(dockerfile).toContain("USER node");
    expect(dockerfile).toContain('CMD ["node", "dist/start.js"]');
    expect(packageJson).toContain('"start": "node dist/start.js"');
  });

  it("pins the dashboard runtime image and keeps a scheduled refresh check", () => {
    const dockerfile = readRepoFile("apps/dashboard/Dockerfile");
    const refresh = readWorkflow("dashboard-base-image-refresh.yml");
    const froms = [
      ...dockerfile.matchAll(
        /^FROM node:22-bookworm-slim@sha256:([a-f0-9]{64}) AS (builder|runner)$/gm,
      ),
    ];

    expect(froms).toHaveLength(2);
    expect(new Set(froms.map((match) => match[1])).size).toBe(1);
    expect(dockerfile).not.toContain("FROM node:22-bookworm-slim AS");
    expect(dockerfile).toContain("ARG PNPM_VERSION=10.28.0");
    expect(dockerfile).toContain(
      "COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.base.json tsconfig.test.json ./",
    );
    expect(dockerfile).toContain(
      'corepack prepare "pnpm@${PNPM_VERSION}" --activate',
    );
    expect(dockerfile).toContain('pnpm --version | grep -Fx "${PNPM_VERSION}"');
    expect(dockerfile).not.toContain("COPY . .");
    expect(dockerfile).toContain(
      "COPY apps/dashboard/package.json apps/dashboard/tsconfig.json apps/dashboard/next-env.d.ts apps/dashboard/next.config.mjs ./apps/dashboard/",
    );
    expect(dockerfile).toContain(
      "COPY apps/dashboard/src ./apps/dashboard/src",
    );
    expect(dockerfile).toContain(
      "COPY packages/policy-engine/src ./packages/policy-engine/src",
    );
    expect(dockerfile).toContain("pnpm --filter @aidenid/policy-engine build");
    expect(
      dockerfile.indexOf("pnpm --filter @aidenid/dashboard build"),
    ).toBeGreaterThan(
      dockerfile.indexOf("pnpm --filter @aidenid/policy-engine build"),
    );
    expect(dockerfile).toContain("COPY --chown=node:node --from=builder");
    expect(dockerfile).toContain("USER node");
    expect(dockerfile.indexOf("USER node")).toBeGreaterThan(
      dockerfile.indexOf("COPY --chown=node:node --from=builder"),
    );

    expect(refresh).toContain("schedule:");
    expect(refresh).toContain('cron: "17 9 * * 1"');
    expect(refresh).toContain("workflow_dispatch:");
    expect(refresh).toContain(
      "actions/checkout@0c366fd6a839edf440554fa01a7085ccba70ac98",
    );
    expect(refresh).toContain("apps/dashboard/Dockerfile");
    expect(refresh).toContain("node:22-bookworm-slim@sha256:");
    expect(refresh).toContain("Docker-Content-Digest");
    expect(refresh).not.toContain("COSIGN_IMAGE_PIN");
    expect(refresh).not.toContain('"${COSIGN_IMAGE}" verify');
    expect(refresh).not.toContain(
      "COSIGN_IMAGE: ${{ vars.AIDENID_COSIGN_IMAGE }}",
    );
    expect(refresh).toContain("base-image-refresh-started.json");
    expect(refresh).toContain("digest_pin_only_docker_official_image");
    expect(refresh).toContain("upstream_sigstore_cosign_unavailable: true");
    expect(refresh).toContain("candidate_ref");
    expect(refresh).toContain("candidate_provenance_verified");
    expect(refresh).toContain(
      "AIDENID_DASHBOARD_NODE_BASE_DIGEST_ALLOWLIST_JSON",
    );
    expect(refresh).toContain("curated_signed_digest_allowlist");
    expect(refresh).toContain(
      'candidate_provenance_verified: ($secondary_provenance_verified == "true")',
    );
    expect(refresh).toContain(
      "refusing to open a trust-on-first-header remediation PR",
    );
    expect(refresh).toContain(
      "has no secondary curated/signed allowlist provenance",
    );
    expect(refresh).toContain("protected maintenance approval");
    expect(refresh).toContain("claiming unavailable cosign provenance");
    expect(refresh).toContain("Docker Official Node images do not provide");
    expect(refresh).not.toContain("verified cosign provenance");
    expect(refresh).toContain("[0-9A-Fa-f]{64}");
    expect(refresh).toContain("$ENV{CURRENT_DIGEST}");
    expect(refresh).toContain("node:22-bookworm-slim\\@");
    expect(refresh).toContain(
      'awk -v ref="node:22-bookworm-slim@${CURRENT_DIGEST}"',
    );
    expect(refresh).not.toContain(
      "node:22-bookworm-slim@'\"${CURRENT_DIGEST}\"'",
    );
    expect(refresh).toContain(
      "docker.io/${IMAGE_REPOSITORY}@${current_digest}",
    );
    expect(refresh).toContain(
      "curl_args=(-fsS --connect-timeout 5 --max-time 30 --retry 3 --retry-delay 2 --retry-all-errors)",
    );
    expect(refresh).toContain('curl "${curl_args[@]}" -I');
    expect(refresh).toContain("pull-requests: write");
    expect(refresh).toContain("environment:");
    expect(refresh).toContain("name: aidenid-clearance-maintenance");
    expect(refresh).toContain("Assert maintenance environment review gate");
    expect(refresh).toContain(
      "repos/${GITHUB_REPOSITORY}/environments/${MAINTENANCE_ENVIRONMENT}",
    );
    expect(refresh).toContain(
      '.protection_rules // [] | any(.type == "required_reviewers")',
    );
    expect(refresh).toContain(
      "must require GitHub Environment reviewers before dashboard base-image remediation can write a branch or open a PR",
    );
    expect(refresh).toContain("protected maintenance approval");
    expect(refresh).toContain("base-image-remediation-build-evidence.json");
    expect(refresh).toContain("allowed_remediation_path()");
    expect(refresh).toContain("git status --porcelain --untracked-files=all");
    expect(refresh).not.toContain(
      "git status --porcelain --untracked-files=normal",
    );
    expect(refresh).toContain(
      "Dashboard base-image remediation staged unexpected path before push",
    );
    expect(refresh).toContain("gh pr create");
    expect(refresh).toContain("pnpm --filter @aidenid/dashboard build");
    expect(refresh).toContain("remediation_pr_required_on_drift: true");
    expect(refresh).toContain("idempotent_digest_branch: true");
    expect(refresh).toContain("stable_branch_per_target_digest: true");
    expect(refresh).toContain(
      "force_with_lease_limited_to_digest_branch: true",
    );
    expect(refresh).toContain("branch_collision_locking");
    expect(refresh).toContain(
      'branch="chore/dashboard-node-base-${digest_prefix}"',
    );
    expect(refresh).toContain("git ls-remote --exit-code --heads origin");
    expect(refresh).toContain("git checkout -B");
    expect(refresh).toContain(
      'git push --set-upstream --force-with-lease origin "${BRANCH_NAME}:${BRANCH_NAME}"',
    );
    expect(refresh).not.toContain("fallback_branch=");

    for (const [, ref] of refresh.matchAll(/uses:\s+[^\s@]+@([^\s]+)/g)) {
      expect(ref).toMatch(/^[0-9a-f]{40}$/);
    }
  });

  it("provides bounded ACM certificate DNS validation for Clearance public hostnames", () => {
    const acm = readWorkflow("acm-certificate-dns-validation.yml");
    const deploy = readWorkflow("deploy-dashboard.yml");

    expect(deploy).toContain("Verify public ALB certificate SAN coverage");
    expect(deploy).toContain("phase4-public-alb-deploy-preflight");
    expect(deploy).toContain(
      "AIDENID_ALB_CERTIFICATE_ARN must point to the public SAN certificate before deploy apply",
    );
    expect(acm).toContain("name: ACM Certificate DNS Validation");
    expect(acm).toContain("workflow_dispatch:");
    expect(acm).toContain("certificate_arn:");
    expect(acm).toContain("expected_hostnames:");
    expect(acm).toContain("wait_for_issued:");
    expect(acm).toContain("id-token: write");
    expect(acm).toContain(
      "aws-actions/configure-aws-credentials@ec61189d14ec14c8efccab744f656cffd0e33f37",
    );
    expect(acm).toContain(
      "CLOUDFLARE_API_TOKEN: ${{ secrets.CLOUDFLARE_API_TOKEN }}",
    );
    expect(acm).toContain("CLOUDFLARE_ZONE_ID: ${{ vars.CLOUDFLARE_ZONE_ID }}");
    expect(acm).toContain("AIDENID_DASHBOARD_HOSTNAME");
    expect(acm).toContain("AIDENID_CONTROL_PLANE_HOSTNAME");
    expect(acm).toContain("AIDENID_VERIFIER_HOSTNAME");
    expect(acm).toContain("certificate_arn must be an ACM certificate");
    expect(acm).toContain(
      "ACM validation helper is restricted to aidenid.com hostnames",
    );
    expect(acm).toContain("Refusing reserved hostname");
    expect(acm).toContain(
      "not one of the configured clearance public hostnames",
    );
    expect(acm).toContain(
      "Expected hostnames must include configured Clearance hostname",
    );
    expect(acm).toContain("includes unexpected SAN/name");
    expect(acm).toContain(
      "SAN/name set must exactly match the configured Clearance public hostnames",
    );
    expect(acm).toContain("*.acm-validations.aws");
    expect(acm).toContain("proxied:false");
    expect(acm).toContain("${records_url}/${record_id}");
    expect(acm).toContain(".result.name == $name");
    expect(acm).toContain(".result.content == $content");
    expect(acm).not.toContain("aws acm wait certificate-validated");
    expect(acm).toContain("wait_deadline_seconds=1800");
    expect(acm).toContain("PENDING_VALIDATION_AFTER_WAIT");
    expect(acm).toContain("certificate-after-validation.json");
    expect(acm).toContain("Certificate was not ISSUED after explicit ACM wait");
    expect(acm).toContain("clearance_acm_dns_validation_plan");
    expect(acm).toContain("clearance_acm_dns_validation_verdict");
    expect(acm.indexOf("clearance_acm_dns_validation_verdict")).toBeLessThan(
      acm.indexOf("Certificate was not ISSUED after explicit ACM wait"),
    );
    expect(acm).toContain("bounded_to_clearance_public_hostnames: true");

    for (const [, ref] of acm.matchAll(/uses:\s+[^\s@]+@([^\s]+)/g)) {
      expect(ref).toMatch(/^[0-9a-f]{40}$/);
    }
  });

  it("generates SBOMs on mainline and release refs with local verification", () => {
    const sbom = readWorkflow("sbom.yml");
    const generateScript = readRepoFile("scripts/generate-ci-sbom.mjs");
    const verifyScript = readRepoFile("scripts/verify-ci-sbom.mjs");

    expect(sbom).toContain("branches: [main]");
    expect(sbom).toContain("pull_request:");
    expect(sbom).toContain("tags:");
    expect(sbom).toContain("concurrency:");
    expect(sbom).toContain(
      "group: sbom-${{ github.workflow }}-${{ github.sha || github.ref }}",
    );
    expect(sbom).toContain(
      "cancel-in-progress: ${{ github.event_name == 'pull_request' }}",
    );
    expect(sbom).toContain("timeout-minutes: 20");
    expect(sbom).toContain('node-version: "24"');
    expect(sbom).toContain("PNPM_VERSION: 10.28.0");
    expect(sbom).toContain("Enable pinned pnpm toolchain");
    expect(sbom).toContain(
      "Verify lockfile-bound immutable SBOM input context",
    );
    expect(sbom).toContain("pnpm install --ignore-scripts --frozen-lockfile");
    expect(sbom).toContain("sbom-generation-contract.json");
    expect(sbom).toContain("sha256sum -c sbom.spdx.json.sha256");
    expect(sbom).toContain("Generate source-tree SBOM");
    expect(sbom).toContain("scripts/generate-ci-sbom.mjs");
    expect(sbom).toContain("--artifact-sha256");
    expect(sbom).toContain("Verify source-tree SBOM");
    expect(sbom).toContain("scripts/verify-ci-sbom.mjs sbom.spdx.json");
    expect(sbom).toContain("sbom-spdx-${{ github.sha }}");

    for (const [, ref] of sbom.matchAll(/uses:\s+[^\s@]+@([^\s]+)/g)) {
      expect(ref).toMatch(/^[0-9a-f]{40}$/);
    }
    expect(generateScript).toContain('arg === "--"');
    expect(verifyScript).toContain('arg !== "--"');
  });
});
