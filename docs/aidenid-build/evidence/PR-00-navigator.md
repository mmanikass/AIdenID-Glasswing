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

## Weekend PRs

Weekend changes on top of the prior-work commit, in merge order. Every test count is a local run on the workstation named above; hosted CI is blocked by GitHub billing on this account, so none of these is a CI-green claim. Author and reviewer are always different agents (recorded role change); the reviewer runs the gate at the exact head SHA before the merge. GitHub refuses a self-approval because both agents push with the owner's account, so the review record is a PR comment at that head. From 13:27 UTC the reviewer of the Navigator's PRs was an independent Claude reviewer agent rather than the Driver; see "Review deviation" below.

| PR | Branch | Merged head | Author / reviewer | Change | Local evidence at that head |
|---|---|---|---|---|---|
| #7 | `roadmap/pr-01-foundation` | `8611d48` | Codex / Navigator | Foundation: workspace prune, dev launcher v1, security scan, local runbook, provenance and reuse docs, `docs/api/openapi.json` and the cascade-latency artifact byte-identical from the source commit. | frozen install 0, typecheck 0, vitest 50 files / 386, eslint 0, secret grep clean, 265 prior-work files byte-identical |
| #5 | `roadmap/pr-02d-session-signer` | `d4fe4b6` | Navigator / Codex | Injectable session signer (`sessionSigningKey` option, `AIDENID_CONTROL_PLANE_SESSION_SIGNING_JWK`, else per-process) and `GET /.well-known/aidenid-session-jwks.json`; route contract fixture (50 routes, 7 public). | 111 control-plane tests |
| #4 | `roadmap/pr-02c-agent-client` | `ffd5d4a` | Navigator / Codex | `@aidenid/agent-client`: `mintAgentKey`, `exchangeSession`, `buildSignedHeaders` (DPoP + RFC 9421), `signedFetch`; bodyless-only signed requests. | 6 tests including a round trip through `verifyCryptoPath` |
| #3 | `roadmap/pr-02b-jev` | `77de7d8` | Navigator / Codex | `@aidenid/jev`: `assess()`, `composeWithJev()`, Anthropic provider through the official SDK; cache key bound to the sanitized purpose text; no clear result without evidence coverage. | 13 tests including prompt-injection-cannot-widen-scope, timeout, malformed output, cache binding |
| #1 | `roadmap/pr-02a-revocation-terminal` | `765f55b` | Navigator / Codex | F-01/F-02: `revokeChain` marks the grant revoked before any outbox publish; `withChainAuthority` runs an effect on the same per-chain lease `revokeChain` holds (in-memory lease waits up to 2 s then fails closed as `chain_busy`; TTL-bound Redis leases are refused as a gate backend; same-process callers are serialized before any cross-replica lock; per-invocation Redis holder token). | `revocation-terminal`, `revocation-boundary`, `revocation-lease-hardening`, `revocation-pg-reentrancy`; control-plane suites green |
| #9 | `roadmap/pr-02-protected-site` | `db7873e` | Codex / Navigator | Protected site: verifier in enforce mode with a deny-by-default policy, embedded control plane served on a second loopback port, operator site scopes on the control plane, the seven `/glasswing/*` operator routes (agents, grants, run, revoke, reviews), review approval released once under `withChainAuthority`. | frozen install 0, typecheck 0, vitest 60 files / 449, eslint 0, secret grep clean, 250 prior-work blobs identical; site-mode integration of all seven routes plus revoke recorded as a comment on the PR |
| #10 | `roadmap/pr-03b-dev-launcher` | `86a4c28` | Navigator / Codex | `pnpm dev` starts the protected site (serving the embedded control plane on 4000) and the dashboard with one generated operator token plus a distinct dashboard request token; Jev credentials forwarded to the site only; fallback to the standalone control plane when the site is not built. | fallback mode on test ports: control plane and dashboard health, operator token 200 / 401, dashboard request token 200 / 401; site mode exercised with #9 and #8 |
| #8 | `roadmap/pr-03-glasswing-ui` | `dfd3284` | Navigator / Codex | Glasswing console at `/glasswing`: mint, single-scope grants, run a task, review queue, timeline; allow-listed `/api/glasswing/*` proxy that adds the server-held operator token; dev session cookie enabled only by the launcher flag. Independent review found two blocking defects at `f2f4150` (site error shape dropped by the client; Host-header loopback check), fixed at `dfd3284`. | dashboard vitest 12 files / 124 tests, eslint 0, typecheck 0, `next build` green; refusal rendering verified by execution by the reviewer; exercised against #9 on the integration stack |
| #6 | `roadmap/pr-02e-kernel-e2e` | `e97032e` | Navigator / Codex | `kernel-e2e.test.ts`: grant → exchange → signed request verified against the published JWKS → effect under the gate → revoke → effect refused and re-exchange refused; a verifier with its epoch floor raised refuses the old token. | 1 test, in-process |
| #11 | `roadmap/pr-05-decision-noise` | `f6328f2` | Navigator / Codex | Operator API calls and health probes are no longer recorded as decisions (16 noise rows per probe run before the fix). | protected-site e2e 8 / 8, tsc 0, eslint 0 |
| #12 | `roadmap/pr-06-followups` | `3405795` | Navigator / independent reviewer | Review follow-ups: the console distinguishes `login_required` from `dev_session_disabled` and names the launcher flag; `.env.example` keeps the flag commented; the site logs refused operator calls (method, path, source address). | dashboard vitest 12 files / 125 tests, protected-site e2e 8 / 8, eslint 0, typecheck 0, `next build` green |

`main` after the last merge is `2107663`. Local gate there: frozen install 0, typecheck 0, vitest 64 files / 465 tests, eslint 0, secret scan 0.

## Review deviation (13:27 UTC onward)

The Driver (gpt-luna-xh) posted nothing in the coordination room after 12:51 UTC and left no verdict on the Navigator's four open PRs. Under the owner's standing instruction not to let the finish slip once the 09:00 EDT mark passed, the Navigator posted a deviation notice in the room at 13:27 UTC and replaced the Driver's non-author review with independent reviewer agents: fresh Claude contexts that did not write the code, ran the same local gate at each exact head, read the diffs adversarially, and posted their verdicts as PR comments labelled "Independent review". The Navigator merged only on those approvals, pinned to the reviewed head. The Driver's verdicts would have governed had they arrived first.

Findings the independent review produced and that were fixed before merge:

- PR #8 at `f2f4150`: the dashboard client decoded only `{ error: string }` while the protected site answers `{ error: { code, message } }`, so a refused run (`permission_scope_mismatch`, `session_exchange_failed`) threw before `summarizeRun` and the console never rendered those refusal beats; fixed at `dfd3284` (site error decoding, refused runs returned as run results, verified by the reviewer by execution). The dev session route inferred "loopback" from the client-controlled Host header; it is now enabled only by `AIDENID_DASHBOARD_DEV_SESSION=true`, which the loopback launcher sets, with the host check kept as a second guard.
- PR #10 at `f246c49`: approved; the build child was not tracked, so an interrupt during `pnpm build` on POSIX could let the services start afterwards; fixed at `86a4c28`.
- PR #6 at `d2808e8`: the combined tree (main plus all four PRs) failed the root test typecheck in `kernel-e2e.test.ts` under `exactOptionalPropertyTypes`; fixed at `e97032e` (caught by the Navigator's combined gate, before the independent review).
- PR #6 at `e97032e` and PR #11 at `f6328f2`: approved by the second independent reviewer with non-blocking findings only (kernel e2e setup calls assert no status; refused operator calls left no row in the decision feed, addressed by a structured site log line in PR #12).

Non-blocking findings left open at the freeze, all from the independent reviews: `.env.example` pre-enables `AIDENID_REQUIRE_LOGIN=false` and the ephemeral-store flags without a warning line; the console shows a bare `operator_auth_not_configured` code instead of naming the variables; the operator audit log line has no test pinning its field set; the kernel e2e setup calls assert no status; `isGlasswingRunResult` validates only the outer shape; the proxy drops a base path in `AIDENID_PROTECTED_SITE_URL` and passes the upstream content type through without `nosniff`; `validPort` in the launcher silently substitutes the default for a malformed port.

Combined gate on main plus the four PRs at their final heads (worktree head `43d3470`): frozen install 0, typecheck 0, vitest 64 files / 464 tests, eslint 0, secret scan 0; site-mode launch of that tree ran the full demo flow through the seven operator routes, the dashboard proxy and the dev session cookie, with the decision log holding agent decisions only.
