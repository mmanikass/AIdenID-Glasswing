import { configDefaults, defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // These source suites require Terraform, deployment scripts, and DD
    // artifacts intentionally omitted from the customer starter subset.
    exclude: [
      ...configDefaults.exclude,
      "apps/control-plane/tests/route-authorization.test.ts",
      "packages/transparency/tests/dashboard-deploy-summary.test.ts",
      "packages/transparency/tests/dashboard-live-canary.test.ts",
      "packages/transparency/tests/evidence-pack.test.ts",
      "packages/transparency/tests/release-manifest.test.ts",
      "packages/transparency/tests/service-image-content.test.ts",
      "packages/transparency/tests/terraform-infra.test.ts",
      "packages/transparency/tests/workflow-hardening.test.ts",
      "packages/verifier-node/tests/omar-gate-template.test.ts",
    ],
    coverage: {
      provider: "v8",
      reporter: ["text", "json-summary"]
    },
    include: ["apps/**/*.test.ts", "packages/**/*.test.ts"]
  }
});
