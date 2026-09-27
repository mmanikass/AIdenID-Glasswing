import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../..",
);

function readWorkflow(name: string) {
  return readFileSync(
    path.join(repoRoot, ".github", "workflows", name),
    "utf8",
  );
}

describe("dashboard release manifest DNS intent", () => {
  it("enables DNS reconciliation for production workflow-run deploys", () => {
    const release = readWorkflow("release.yml");

    expect(release).toContain("release_configure_dns=false");
    expect(release).toContain(
      'if [ "${RELEASE_ENVIRONMENT}" = "production" ]; then',
    );
    expect(release).toContain("release_configure_dns=true");
    expect(release).toContain("release_cloudflare_proxied=true");
    expect(release).toContain(
      '--argjson release_configure_dns "${release_configure_dns}"',
    );
    expect(release).toContain(
      '--argjson release_cloudflare_proxied "${release_cloudflare_proxied}"',
    );
    expect(release).toContain("configure_dns: $release_configure_dns");
    expect(release).toContain(
      "cloudflare_proxied: $release_cloudflare_proxied",
    );
    expect(release).not.toContain("configure_dns: false");
  });
});
