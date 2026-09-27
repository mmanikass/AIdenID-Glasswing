# Build state

## Starter scope

This repository starts from the selected nine-workspace tree: `@aidenid/common-schemas`, `@aidenid/crypto`, `@aidenid/eventing`, `@aidenid/policy-engine`, `@aidenid/transparency`, `@aidenid/fingerprint-sidecar`, `@aidenid/verifier-node`, `@aidenid/control-plane`, and `@aidenid/dashboard`. It keeps the root package/workspace/lock/Turbo/TypeScript/Vitest/ESLint configuration needed to build and test those workspaces.

The local development path uses ephemeral in-memory control-plane state and binds both services to loopback. It is intended for local integration and resets on process restart. It does not use cloud credentials or connect to a configured database/Redis service. The dashboard reads the control-plane `/healthz` endpoint through a bounded, no-store server probe.

## Validation

Validated with Node 22.23.1 and pnpm 10.28.0 on the current PR-1 working tree:

- `pnpm install --frozen-lockfile` — passed after pruning the workspace lockfile.
- `pnpm typecheck` — passed for all nine workspaces and root tests.
- `pnpm build` — passed, including the Next.js dashboard production build.
- `pnpm exec vitest run --passWithNoTests` — passed 50 files / 386 tests after excluding the source-only suites listed below.
- `pnpm security:secrets` — passed.
- `pnpm dev` smoke test — passed on alternate loopback ports: control-plane `/healthz` returned `{ok:true,service:"aidenid-control-plane"}` and dashboard `/api/status/health` returned `{"state":"connected"}`. The two local services were stopped after the check.

The full source checkout passed its pre-import baseline (`pnpm typecheck`; 84-file `pnpm test`, 620 tests; `pnpm demo:flow`). The selected subset intentionally omits supporting fixtures and deployment assets, so nine source suites cannot run here yet. Vitest excludes only these files: `apps/control-plane/tests/route-authorization.test.ts`, `packages/transparency/tests/dashboard-deploy-summary.test.ts`, `packages/transparency/tests/dashboard-live-canary.test.ts`, `packages/transparency/tests/evidence-pack.test.ts`, `packages/transparency/tests/release-manifest.test.ts`, `packages/transparency/tests/service-image-content.test.ts`, `packages/transparency/tests/terraform-infra.test.ts`, `packages/transparency/tests/workflow-hardening.test.ts`, and `packages/verifier-node/tests/omar-gate-template.test.ts`. They reference omitted audit artifacts, deployment scripts/workflows, Terraform, or image-verification assets. See the source suite before re-enabling any of them; do not treat this exclusion as a passing result for those checks. The OpenAPI contract and dashboard benchmark artifact tests remain enabled using the two byte-identical files recorded in `PROVENANCE.md`.

## Not yet part of the starter

Cloud deployment infrastructure, production secrets, lab packages, demo portal utilities, and the omitted source-only test fixtures/assets are outside the selected tree. Local dev mode is not a production deployment profile.
