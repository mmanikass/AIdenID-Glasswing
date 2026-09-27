import { configDefaults, defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // These source suites require Terraform, deployment scripts, and DD
    // artifacts intentionally omitted from the customer starter subset.
    exclude: [
      ...configDefaults.exclude,
      // Reads a DD route-authorization artifact; PR #5 relocates the contract.
      "apps/control-plane/tests/route-authorization.test.ts",
      // Requires scripts/verify-dashboard-deploy-summary.mjs.
      "packages/transparency/tests/dashboard-deploy-summary.test.ts",
      // Spawns scripts/check-dashboard-live.mjs.
      "packages/transparency/tests/dashboard-live-canary.test.ts",
      // Requires the omitted DD evidence pack and support scripts.
      "packages/transparency/tests/evidence-pack.test.ts",
      // Requires the omitted release workflow tree.
      "packages/transparency/tests/release-manifest.test.ts",
      // Requires scripts/verify-service-image-content.mjs.
      "packages/transparency/tests/service-image-content.test.ts",
      // Requires the omitted Terraform infrastructure/workflow tree.
      "packages/transparency/tests/terraform-infra.test.ts",
      // Reads production workflows, scripts, and Dockerfiles outside this subset.
      "packages/transparency/tests/workflow-hardening.test.ts",
      // Requires the omitted reusable Omar Gate workflow and caller evidence.
      "packages/verifier-node/tests/omar-gate-template.test.ts",
    ],
    coverage: {
      provider: "v8",
      reporter: ["text", "json-summary"]
    },
    include: ["apps/**/*.test.ts", "packages/**/*.test.ts"]
  }
});
