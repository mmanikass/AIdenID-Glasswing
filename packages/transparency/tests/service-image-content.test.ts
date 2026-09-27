import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { describe, expect, it } from "vitest";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../..",
);

interface ImageVerifierModule {
  readonly assertImageContentSnapshot: (input: {
    readonly service: string;
    readonly listing: string;
  }) => {
    readonly service: string;
    readonly required_files: readonly string[];
    readonly required_dirs: readonly string[];
    readonly forbidden_paths: readonly string[];
    readonly path_count: number;
  };
  readonly forbiddenPaths: readonly string[];
  readonly serviceSpecs: Readonly<
    Record<
      string,
      {
        readonly requiredFiles: readonly string[];
        readonly requiredDirs: readonly string[];
      }
    >
  >;
}

async function loadVerifier(): Promise<ImageVerifierModule> {
  const modulePath = pathToFileURL(
    path.join(repoRoot, "scripts", "verify-service-image-content.mjs"),
  ).href;
  return (await import(modulePath)) as ImageVerifierModule;
}

function listingFor(
  service: string,
  serviceSpecs: ImageVerifierModule["serviceSpecs"],
): string {
  const spec = serviceSpecs[service];
  if (spec === undefined) {
    throw new Error(`missing service fixture spec for ${service}`);
  }
  return [
    ...spec.requiredFiles,
    ...spec.requiredDirs.map((dir) => `${dir}/.probe-present`),
    "/app/package-lock-is-not-required.txt",
  ].join("\n");
}

describe("service image content verifier", () => {
  for (const service of ["control-plane", "dashboard", "verifier"]) {
    it(`accepts a captured ${service} image listing with required runtime files`, async () => {
      const { assertImageContentSnapshot, forbiddenPaths, serviceSpecs } =
        await loadVerifier();
      const evidence = assertImageContentSnapshot({
        service,
        listing: listingFor(service, serviceSpecs),
      });

      expect(evidence.service).toBe(service);
      expect(evidence.required_files).toEqual(
        serviceSpecs[service]?.requiredFiles,
      );
      expect(evidence.required_dirs).toEqual(
        serviceSpecs[service]?.requiredDirs,
      );
      expect(evidence.forbidden_paths).toEqual(forbiddenPaths);
      expect(evidence.path_count).toBeGreaterThan(
        serviceSpecs[service]?.requiredFiles.length ?? 0,
      );
    });

    it(`rejects a captured ${service} image listing missing a required runtime file`, async () => {
      const { assertImageContentSnapshot, serviceSpecs } = await loadVerifier();
      const requiredFile = serviceSpecs[service]?.requiredFiles[0];
      expect(requiredFile).toBeDefined();
      const listing = listingFor(service, serviceSpecs)
        .split("\n")
        .filter((pathEntry) => pathEntry !== requiredFile)
        .join("\n");

      expect(() =>
        assertImageContentSnapshot({
          service,
          listing,
        }),
      ).toThrow(`missing required file ${requiredFile} for ${service}`);
    });
  }

  it("rejects captured listings that include forbidden repo or secret paths", async () => {
    const { assertImageContentSnapshot, serviceSpecs } = await loadVerifier();
    const listing = `${listingFor("verifier", serviceSpecs)}\n/app/.env\n/app/.git/config\n/repo/package.json`;

    expect(() =>
      assertImageContentSnapshot({
        service: "verifier",
        listing,
      }),
    ).toThrow("contains forbidden path /app/.env for verifier");
  });
});
