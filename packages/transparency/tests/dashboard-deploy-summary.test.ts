import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../..",
);
const verifierScript = path.join(
  repoRoot,
  "scripts",
  "verify-dashboard-deploy-summary.mjs",
);

function summary(overrides: Record<string, unknown> = {}) {
  return {
    artifact_type: "dashboard_deploy_summary",
    generated_at: "2026-05-03T14:00:00Z",
    source_sha: "306adede3a54703261a47cc67f17c8df90a8307e",
    environment: "demo",
    apply: false,
    configure_dns: false,
    cloudflare_proxied: true,
    dashboard_image: "",
    dashboard_hostname: "",
    canary_url: "",
    canary_target: "",
    canary_verdict: "skipped",
    control_plane_auth_activation_canary_sha256: "",
    alb_dns_name: "",
    ...overrides,
  };
}

function runVerifier(payload: Record<string, unknown>) {
  const dir = mkdtempSync(path.join(tmpdir(), "aidenid-dashboard-summary-"));
  const summaryPath = path.join(dir, "summary.json");
  const verdictPath = path.join(dir, "verdict.json");
  writeFileSync(summaryPath, `${JSON.stringify(payload, null, 2)}\n`, "utf8");

  const result = spawnSync(
    process.execPath,
    [verifierScript, summaryPath, "--out", verdictPath],
    {
      cwd: repoRoot,
      encoding: "utf8",
    },
  );
  return {
    ...result,
    verdictPath,
  };
}

describe("dashboard deploy summary verifier", () => {
  it("accepts plan-only summaries only when the live canary is skipped", () => {
    const result = runVerifier(summary());

    expect(result.status).toBe(0);
    const verdict = JSON.parse(readFileSync(result.verdictPath, "utf8")) as {
      verified?: boolean;
      live_canary_required?: boolean;
      canary_verdict?: string;
    };
    expect(verdict.verified).toBe(true);
    expect(verdict.live_canary_required).toBe(false);
    expect(verdict.canary_verdict).toBe("skipped");
  });

  it("accepts apply summaries only after the live dashboard canary passes", () => {
    const result = runVerifier(
      summary({
        apply: true,
        dashboard_hostname: "dashboard.aidenid.com",
        canary_target: "https://dashboard.aidenid.com",
        canary_verdict: "success",
        release_manifest_run_id: "123456",
        release_manifest_sha256: "a".repeat(64),
      }),
    );

    expect(result.status).toBe(0);
    const verdict = JSON.parse(readFileSync(result.verdictPath, "utf8")) as {
      live_canary_required?: boolean;
      live_canary_passed?: boolean;
      summary_sha256?: string;
    };
    expect(verdict.live_canary_required).toBe(true);
    expect(verdict.live_canary_passed).toBe(true);
    expect(verdict.summary_sha256).toMatch(/^[0-9a-f]{64}$/);
  });

  it("rejects apply summaries when the live canary did not pass", () => {
    const result = runVerifier(
      summary({
        apply: true,
        dashboard_hostname: "dashboard.aidenid.com",
        canary_target: "https://dashboard.aidenid.com",
        canary_verdict: "failure",
      }),
    );

    expect(result.status).toBe(1);
    expect(result.stderr).toContain(
      "apply=true requires live dashboard canary_verdict=success",
    );
  });

  it("requires promoted release manifest evidence for every apply summary", () => {
    const result = runVerifier(
      summary({
        environment: "demo",
        apply: true,
        dashboard_hostname: "dashboard.aidenid.com",
        canary_target: "https://dashboard.aidenid.com",
        canary_verdict: "success",
      }),
    );

    expect(result.status).toBe(1);
    expect(result.stderr).toContain(
      "apply=true requires numeric release_manifest_run_id",
    );

    const accepted = runVerifier(
      summary({
        environment: "demo",
        apply: true,
        dashboard_hostname: "dashboard.aidenid.com",
        canary_target: "https://dashboard.aidenid.com",
        canary_verdict: "success",
        release_manifest_run_id: "123456",
        release_manifest_sha256: "a".repeat(64),
      }),
    );
    expect(accepted.status).toBe(0);
  });

  it("binds successful production applies to exact auth activation evidence", () => {
    const missing = runVerifier(
      summary({
        environment: "production",
        apply: true,
        dashboard_hostname: "dashboard.aidenid.com",
        canary_target: "https://dashboard.aidenid.com",
        canary_verdict: "success",
        release_manifest_run_id: "123456",
        release_manifest_sha256: "a".repeat(64),
      }),
    );
    expect(missing.status).toBe(1);
    expect(missing.stderr).toContain(
      "production apply requires control_plane_auth_activation_canary_sha256",
    );

    const digest = "b".repeat(64);
    const accepted = runVerifier(
      summary({
        environment: "production",
        apply: true,
        dashboard_hostname: "dashboard.aidenid.com",
        canary_target: "https://dashboard.aidenid.com",
        canary_verdict: "success",
        release_manifest_run_id: "123456",
        release_manifest_sha256: "a".repeat(64),
        control_plane_auth_activation_canary_sha256: digest,
      }),
    );
    expect(accepted.status).toBe(0);
    const verdict = JSON.parse(readFileSync(accepted.verdictPath, "utf8")) as {
      control_plane_auth_activation_canary_sha256?: string;
    };
    expect(verdict.control_plane_auth_activation_canary_sha256).toBe(digest);
  });

  it("rejects reserved dashboard hostnames", () => {
    const result = runVerifier(
      summary({
        apply: true,
        dashboard_hostname: "api.aidenid.com",
        canary_target: "https://api.aidenid.com",
        canary_verdict: "success",
        release_manifest_run_id: "123456",
        release_manifest_sha256: "a".repeat(64),
      }),
    );

    expect(result.status).toBe(1);
    expect(result.stderr).toContain(
      "api.aidenid.com is reserved and cannot host the dashboard",
    );
  });

  it("rejects malformed environment names", () => {
    const result = runVerifier(summary({ environment: "Prod Env" }));

    expect(result.status).toBe(1);
    expect(result.stderr).toContain(
      "environment must be 3-64 lowercase letters, digits, or hyphens",
    );
  });
});
