import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../..",
);

const requiredDocs = [
  "docs/dd/threat-model.md",
  "docs/dd/control-matrix.md",
  "docs/dd/load-test-report.md",
  "docs/dd/restore-drill.md",
  "docs/dd/sast-sca-secret-scan.md",
  "docs/dd/artifact-attestations.md",
  "docs/dd/sbom.md",
  "docs/dd/ai-governance.md",
  "docs/dd/mcp-auth-hardening.md",
  "docs/dd/mcp-protected-resource-metadata.md",
  "docs/dd/rollback-kill-switch.md",
  "docs/dd/current-main-spec-audit-2026-05-02.md",
  "docs/dd/fingerprint-sidecar-readiness.md",
  "docs/dd/decision-stream-ui-latency.md",
  "docs/dd/cascade-telemetry-dashboard.md",
  "docs/dd/dashboard-public-live-deploy.md",
  "docs/dd/dashboard-public-canary-verdict.md",
  "docs/dd/decision-outbox-chain-receipt-keys.md",
  "docs/dd/billing-export-adapter.md",
  "docs/dd/provider-observability-recipes.md",
  "docs/dd/python-verifier-cascade-provider-parity.md",
  "docs/dd/pitch-readiness-audit-2026-05-03.md",
] as const;

const requiredArtifacts = [
  "docs/dd/artifacts/threat-model-risk-register.json",
  "docs/dd/artifacts/control-evidence-index.json",
  "docs/dd/artifacts/load-smoke-2026-04-24.json",
  "docs/dd/artifacts/restore-drill-2026-04-24.log",
  "docs/dd/artifacts/sast-sca-secret-scan-2026-04-24.json",
  "docs/dd/artifacts/artifact-attestation-2026-04-24.json",
  "docs/dd/artifacts/sbom-spdx-2026-04-24.json",
  "docs/dd/artifacts/ai-governance-review-2026-04-24.json",
  "docs/dd/artifacts/mcp-auth-hardening-2026-04-24.json",
  "docs/dd/artifacts/mcp-protected-resource-metadata-2026-05-02.json",
  "docs/dd/artifacts/rollback-kill-switch-2026-04-24.json",
  "docs/dd/artifacts/current-main-spec-audit-2026-05-02.json",
  "docs/dd/artifacts/fingerprint-sidecar-readiness-2026-05-02.json",
  "docs/dd/artifacts/decision-stream-ui-latency-2026-05-02.json",
  "docs/dd/artifacts/cascade-telemetry-dashboard-2026-05-02.json",
  "docs/dd/artifacts/dashboard-public-live-deploy-2026-05-02.json",
  "docs/dd/artifacts/redis-restore-drill-2026-05-04.json",
  "docs/dd/artifacts/dashboard-public-canary-verdict-2026-05-03.json",
  "docs/dd/artifacts/decision-outbox-chain-receipt-keys-2026-05-03.json",
  "docs/dd/artifacts/billing-export-adapter-2026-05-03.json",
  "docs/dd/artifacts/provider-observability-recipes-2026-05-03.json",
  "docs/dd/artifacts/python-verifier-cascade-provider-parity-2026-05-03.json",
  "docs/dd/artifacts/pitch-readiness-audit-2026-05-03.json",
] as const;

const requiredScripts = [
  "scripts/restore-drill.sh",
  "scripts/load-smoke.sh",
  "scripts/canary-rollback.sh",
] as const;

const readRepoFile = (relativePath: string): string =>
  readFileSync(path.join(repoRoot, relativePath), "utf8");

describe("due diligence evidence pack", () => {
  it("backs every required diligence document with a tracked artifact path", () => {
    for (const doc of requiredDocs) {
      const body = readRepoFile(doc);
      expect(body, doc).toContain("Primary evidence:");
      expect(body, doc).toMatch(
        /docs\/dd\/artifacts\/[a-z0-9-]+-2026-04-24\.(json|log)|docs\/dd\/artifacts\/[a-z0-9-]+\.json/,
      );
    }
  });

  it("keeps referenced evidence artifacts and scripts present", () => {
    for (const artifact of requiredArtifacts) {
      expect(existsSync(path.join(repoRoot, artifact)), artifact).toBe(true);
    }

    for (const script of requiredScripts) {
      expect(existsSync(path.join(repoRoot, script)), script).toBe(true);
    }
  });

  it("keeps JSON artifacts parseable and the SBOM SPDX-shaped", () => {
    for (const artifact of requiredArtifacts.filter((name) =>
      name.endsWith(".json"),
    )) {
      expect(() => JSON.parse(readRepoFile(artifact)), artifact).not.toThrow();
    }

    const sbom = JSON.parse(
      readRepoFile("docs/dd/artifacts/sbom-spdx-2026-04-24.json"),
    ) as {
      spdxVersion?: string;
      packages?: unknown[];
    };
    expect(sbom.spdxVersion).toBe("SPDX-2.3");
    expect(sbom.packages?.length).toBeGreaterThan(0);
  });

  it("requires safety confirmations in operational scripts", () => {
    expect(readRepoFile("scripts/restore-drill.sh")).toContain(
      "RESTORE_DRILL_CONFIRM",
    );
    expect(readRepoFile("scripts/load-smoke.sh")).toContain(
      "ALLOWED_TEST_ORIGINS",
    );
    expect(readRepoFile("scripts/canary-rollback.sh")).toContain(
      "production rollback is not allowed",
    );
  });

  it("keeps the pitch-readiness audit explicit about shipped and missing surfaces", () => {
    const audit = JSON.parse(
      readRepoFile("docs/dd/artifacts/pitch-readiness-audit-2026-05-03.json"),
    ) as {
      artifact_type?: string;
      literal_pitch_safe?: boolean;
      safe_pitch_ready?: boolean;
      remaining_followups?: string[];
      claims?: Array<{
        id?: string;
        implementation_percent?: number;
        subclaims?: Array<{ id?: string; hot_path?: boolean }>;
        gaps?: string[];
      }>;
      recommended_pr_batches?: Array<{ id?: string }>;
    };
    expect(audit.artifact_type).toBe("pitch_readiness_audit");
    expect(audit.literal_pitch_safe).toBe(false);
    expect(audit.safe_pitch_ready).toBe(true);

    const claims = new Map(
      (audit.claims ?? []).map((claim) => [claim.id, claim]),
    );
    expect([...claims.keys()]).toEqual([
      "real_time_decision_layer",
      "four_layer_identification_cascade",
      "allowed_action_authorization",
      "stop_controls",
      "six_outcomes",
      "cryptographic_decision_evidence",
      "per_cleared_action_metering",
    ]);

    for (const claim of claims.values()) {
      expect(claim.implementation_percent).toBeGreaterThanOrEqual(0);
      expect(claim.implementation_percent).toBeLessThanOrEqual(100);
    }

    const cascadeSubclaims = new Map(
      (claims.get("four_layer_identification_cascade")?.subclaims ?? []).map(
        (item) => [item.id, item],
      ),
    );
    expect(cascadeSubclaims.get("cryptographic_signature")?.hot_path).toBe(
      true,
    );
    expect(cascadeSubclaims.get("user_delegation_proof")?.hot_path).toBe(true);
    expect(cascadeSubclaims.get("behavioral_fingerprint")?.hot_path).toBe(true);
    expect(cascadeSubclaims.get("operator_reputation")?.hot_path).toBe(true);
    expect(claims.get("cryptographic_decision_evidence")?.gaps).not.toContain(
      "decision_outbox_not_hash_chained",
    );
    expect(claims.get("cryptographic_decision_evidence")?.gaps).not.toContain(
      "no_receipt_key_rotation_registry",
    );
    expect(
      claims.get("per_cleared_action_metering")?.implementation_percent,
    ).toBeGreaterThanOrEqual(90);
    expect(claims.get("per_cleared_action_metering")?.gaps).not.toContain(
      "no_stripe_or_remittance_adapter",
    );
    expect(audit.remaining_followups).not.toContain(
      "billing_rollup_payment_processor_export_adapter",
    );
    expect(audit.remaining_followups).not.toContain(
      "public_dashboard_live_canary_from_ci",
    );
    expect(audit.remaining_followups).not.toContain(
      "provider_latency_metrics_and_example_provider_recipes",
    );
    expect(audit.remaining_followups).not.toContain(
      "decision_outbox_hash_chain",
    );
    expect(audit.remaining_followups).not.toContain(
      "receipt_key_rotation_registry_runbook",
    );
    expect(audit.remaining_followups).not.toContain(
      "provider_side_finance_delivery_receipt_capture",
    );
    expect(
      (audit.recommended_pr_batches ?? []).map((batch) => batch.id),
    ).toEqual([
      "A",
      "B",
      "C",
      "D",
      "E",
      "F",
      "G",
      "H",
      "I",
      "K",
      "L",
      "M",
      "N",
      "O",
      "P",
    ]);
  });
});
