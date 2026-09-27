# Reuse matrix

| Area | Reused source | Starter role | PR-1 additions |
| --- | --- | --- | --- |
| Common schemas and crypto | `packages/common-schemas`, `packages/crypto` | Shared contracts and cryptographic primitives | None |
| Eventing and policy | `packages/eventing`, `packages/policy-engine` | Event delivery and authorization decisions | None |
| Transparency and identity checks | `packages/transparency`, `packages/fingerprint-sidecar`, `packages/verifier-node` | Transparency proofs, fingerprint adapter, verification runtime | None |
| Control plane | `apps/control-plane` | API, grant/session/revocation services, `/healthz` | Safe local development environment in `scripts/dev.mjs`; no route behavior change |
| Dashboard | `apps/dashboard` | Existing operator-facing dashboard | Bounded health probe API/client indicator and focused unit tests |
| Workspace tooling | Root package, pnpm workspace/lock, Turbo, TypeScript, Vitest, ESLint configs | Reproducible nine-workspace install/build/test | Pruned lock/workspace, starter scripts and test-fixture exclusions |
| CI and local config | New `.github/workflows/ci.yml`, `.env.example`, `scripts/security-scan.mjs` | Pinned dependency setup and secret scan | New PR-1 foundation |
| API and test fixtures | `docs/api/openapi.json`, `docs/dd/artifacts/cascade-latency-2026-05-02.json` | Keep existing OpenAPI and dashboard benchmark tests active | Byte-identical source copies added after the initial import |
| Provenance | `docs/aidenid-build/PROVENANCE.md` | Per-file source SHA-256 evidence | Generated from the verified import manifest |

The source import is described in `PROVENANCE.md`. PR-1 adds scaffolding without changing the existing verifier, policy, crypto, or control-plane business behavior.
