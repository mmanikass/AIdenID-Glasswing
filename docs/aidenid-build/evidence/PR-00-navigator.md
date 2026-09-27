# PR-00 — Navigator independent evidence record

Author: fable-5.1-nav (Navigator). Date: 2026-09-27 (UTC timestamps). Machine: the owner's Windows workstation, Node v22.23.1, pnpm 10.28.0 via corepack, `CI=true`. All runs below were performed by the Navigator independently of the Driver's runs; the Driver reported matching numbers in the coordination room.

## Source under inspection

- Repository: private `mrrCarter/aidenid-clearance`, commit `0e4553e39e68b50aecbd977544f95d40c4e03de7` (default-branch head, committed 2026-08-14). Clean local checkout at that SHA (git status empty).

## Baseline gates at 0e4553e (full monorepo)

| Gate | Command | Result |
|---|---|---|
| Install | `pnpm install --frozen-lockfile --prefer-offline` | exit 0 (5m58s) |
| Typecheck | `pnpm typecheck` | exit 0, turbo 29/29 tasks |
| Tests | `pnpm test` | exit 0, 84 test files passed, 620 tests passed, 0 failed (13.9s) |

Status for the kernel packages (policy-engine, crypto, control-plane, verifier-node, transparency, eventing, common-schemas): implemented and proven on this machine at that SHA.

## Unattended demo flow at 0e4553e

`pnpm demo:flow --out <artifact>` with `AIDENID_ALLOW_EPHEMERAL_CONTROL_PLANE_STORE=true` and `AIDENID_ALLOW_IN_MEMORY_CONTROL_PLANE_OUTBOX=true`:

- `ok: true`
- Green path: signed agent GET → HTTP 200, decision `allow`, actor class `verified_agent`
- Override path: operator override → HTTP 402, decision `price_required`, operator action `price_required`
- Decision stream: 3 SSE events (`recorded`, `recorded`, `updated`)
- Each decision carries a signed receipt with a Merkle inclusion proof and `decision_outbox_chain` (previous hash, entry hash)

## Manual flow against the ephemeral control-plane at 0e4553e

`node apps/control-plane/dist/start.js` with one admin operator token (value not recorded here):

| Step | Call | Result |
|---|---|---|
| 1 | `POST /v1/targets` (admin) | 201, `tgt_…` |
| 2 | `POST /v1/grants` (admin), `catalog:read`, 600 s | 201, `grt_…`, `chn_…`, `issuer_actor_id` bound to the operator |
| 3 | `POST /v1/sessions/exchange` in scope | 201, `DPoP` token, `revocation_epoch: 0` |
| 4 | exchange requesting `catalog:write` | 403 `permission_exceeds_grant` |
| 5 | `POST /v1/grants` without operator token | 401 `operator_auth_required` |
| 6 | `POST /v1/revoke` (admin) | 202, `revocation_epoch: 1` |
| 7 | exchange again on the same grant | **201 with a fresh token at epoch 1** (see F-01) |
| 8 | `GET /v1/decisions?site_id=…` (admin) | 200, empty list (no verifier traffic in this flow) |

## Findings

### F-01 (P1) — chain revocation does not terminate the grant — confirmed

- Location: `apps/control-plane/src/services/revocation.ts` `revokeChain` calls `store.bumpEpoch` only. `apps/control-plane/src/routes/sessions.ts` refuses on `grant.revokedAt`, but `store.revokeGrant` has no caller in `apps/` or `packages/` (type definitions only).
- Invariant: revocation is a terminal transition; a revoked grant cannot mint new sessions.
- Reproducer: manual flow step 7 above.
- Existing test gap: the e2e case "registers a target, grants delegation, issues a downscoped session, and revokes the chain" asserts epoch 1, outbox types and persona audit only; it never exchanges after revoke.
- Fix: PR-2a marks the grant revoked under the same lease, publishes `GRANT_REVOKED_HASH`, and adds the negative test (exchange after revoke → 403 `grant_not_active`).

### F-02 (P1, design gap) — the verifier cannot see a per-chain revocation — confirmed

- `packages/verifier-node/src/cryptoPath.ts` passes `crypto.minRevocationEpoch`, a single global number, to the session-token verifier; `apps/verifier/src/config.ts` reads it from `AIDENID_VERIFIER_MIN_REVOCATION_EPOCH`; `hotpath.ts` raises it from `rollback.globalRevocationEpoch`. No per-chain epoch lookup exists at the verifier.
- Consequence: revoking chain X (epoch 0 → 1) leaves X's existing epoch-0 token valid at the verifier unless the global minimum is raised, which invalidates every chain.
- Fix: PR-2a adds `checkChainAuthority` (store reads only) for the co-located effect boundary; the Glasswing protected route calls it after the verifier says allow and refuses on `unknown_chain`, `grant_revoked`, `grant_expired` or `epoch_stale`.

## Prior-work commit verification

- `main` = `47a68878abbcdcdb53376a26d5f55ea6f080d928`, message exactly `prior work`, author Carther Theogene, 268 files.
- Content: the nine-package subset (`packages/common-schemas`, `crypto`, `eventing`, `policy-engine`, `transparency`, `fingerprint-sidecar`, `verifier-node`, `apps/control-plane`, `apps/dashboard`) plus root build files (`package.json`, `pnpm-workspace.yaml`, `pnpm-lock.yaml`, `turbo.json`, `tsconfig.base.json`, `tsconfig.test.json`, `vitest.config.ts`, `eslint.config.mjs`, `.gitignore`), extracted with `git archive` from `0e4553e`.
- Blob identity: `git ls-files -s` of the commit compared with `git ls-tree -r 0e4553e` at the source for the same paths → 268/268 identical blob hashes, 0 modified, 0 new.
- Secret scan: pattern grep over the staged tree (AWS keys, private-key blocks, Stripe live/test keys, GitHub tokens, Slack tokens, Google API keys) → no matches. `apps/control-plane/certs/rds-global-bundle.pem` is the public Amazon RDS CA bundle (certificates only).
- No git history imported; no `.env` files present in the pinned tree.

## Not run / limitations

- Hosted GitHub Actions are unavailable on this account (billing), so all gates above are local runs; none is a CI-green claim.
- The manual flow did not exercise verifier traffic (no protected route in that harness); the demo flow covers the verifier path.
- Postgres and Redis adapters were not exercised.
