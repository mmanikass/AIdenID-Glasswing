# AIdenID Glasswing

A live operations console for websites and APIs that AI agents call. A site owner mints an agent identity, assigns it scoped work as a delegation grant, watches every request the agent makes receive a deterministic decision with a signed receipt, escalates only the ambiguous actions to a bounded semantic check, and can revoke the agent's authority so its next request is refused.

Built for Glasswing Test Flight 2026 (Boston, 27 September 2026) on top of the owner's pre-existing AIdenID clearance kernel. See "Anything built before this weekend" for the exact boundary.

## The problem, and who inside a company has it

AI agents now browse, buy, export and post on behalf of people. A website or API sees a stream of requests and cannot tell which ones are a delegated agent acting inside the scope its owner approved, which ones have exceeded that scope, and which ones should be stopped right now because the owner changed their mind.

The person who owns this problem is the security or platform owner of a website or API that agents call. Today they have three bad options: block all automation, allow all of it, or hand-write rules per integration and hope nobody revokes anything mid-task. None of those produce evidence they can show an auditor afterwards.

## Who pays for this and why they'd buy it

The site owner pays. The hypothesis (not proven revenue) is either per-cleared-action metering, where every non-denied decision is a billable unit, or a fixed SaaS plan per protected site. The kernel already meters every non-deny decision and models pricing plans; what is not yet proven is that a named customer will pay for it.

They would buy it because it turns "an agent did something on our site" into four things they can act on: who the agent was, what it was allowed to do, what was decided per request and why, and a signed receipt they can verify later. Revocation that actually stops the next request is the feature that makes the first three worth paying for.

## How it works, and where the AI does something regular software couldn't

Deterministic path (no model involved):

1. **Mint.** The operator mints an agent identity: an Ed25519 key pair held by the protected site's runner, whose DPoP thumbprint becomes the subject binding. The private key never leaves the server process.
2. **Assign work.** The operator issues a delegation grant against the registered demo site with one permission and an expiry. The grant is bound to one route, carries a chain id, and records the authenticated issuer.
3. **Exchange.** The runner exchanges the grant for a short-lived DPoP session token bound to the site, the resource, the requested permissions (a subset of the grant) and the chain's revocation epoch.
4. **Decide.** Every request through the verifier middleware gets exactly one of six outcomes: `allow`, `throttle`, `queue`, `sandbox`, `deny`, `price_required`. Signatures, audience, resource, expiry, scope and revocation epoch are hard checks.
5. **Record.** Each decision is written to a hash-chained outbox and issued a signed decision receipt with a Merkle inclusion proof, before the protected handler runs. The console reads the decision list and a server-sent-event stream.
6. **Revoke.** The operator revokes the chain. The grant is marked revoked before anything is published to the outbox (a bus failure still leaves the chain revoked), the revocation epoch increments, the agent's next session exchange is refused, and any effect still waiting on that chain (a queued human approval, for example) is refused at the effect gate.

The operator console at `/glasswing` on the dashboard drives this workflow. The protected site (`apps/protected-site`) hosts the demo shop routes, the agent runner and the seven operator endpoints under `/glasswing/*` that the console reaches through an allow-listed dashboard proxy; the operator token stays server-side. The site embeds the control plane and serves it on its own port, so the site, the console and the decision feed share one store, one revocation epoch and one decision log.

Weekend packages on top of the kernel:

- `@aidenid/agent-client` — `mintAgentKey` (Ed25519), `exchangeSession`, `buildSignedHeaders` (DPoP proof plus an RFC 9421 HTTP message signature) and `signedFetch`. This is the agent side of beats 1, 3 and 4.
- `@aidenid/jev` — the bounded semantic assessor: `assess()` returns a verification status of `evaluated`, `unavailable`, `inconclusive` or `not_evaluated` and an obligation of `none` or `review_required`; `composeWithJev()` never changes a deny and turns allow-plus-review into a `queue` that is not dispatch-eligible; `createAnthropicJevProvider()` uses the official Anthropic SDK with structured output (default model `claude-opus-5` at low effort, `JEV_MODEL` override).
- Control-plane session signer — injectable (`sessionSigningKey` option or the `AIDENID_CONTROL_PLANE_SESSION_SIGNING_JWK` env var; otherwise a per-process key for local/demo only) and published at `GET /.well-known/aidenid-session-jwks.json`, so a verifier checks session tokens against the control plane's published key instead of a shared secret.
- `withChainAuthority(services, { chainId, tokenRevocationEpoch }, effect)` — the co-located effect gate. It runs the effect on the same per-chain lease that `revokeChain` holds, so a revoke and an effect on one chain are serialized; the in-memory lease waits up to 2 s and then fails closed as `chain_busy`. `checkChainAuthority` remains available as a read-only snapshot.
- `apps/protected-site` — a Fastify shop behind the verifier in enforce mode with a deny-by-default policy, plus the Glasswing operator API: mint agents, issue single-route grants, run a task server-side (exchange, sign, verify, record, execute), revoke a chain, list and resolve Jev reviews. Review approval releases the queued job exactly once under the chain-authority gate. Operator API calls and health probes are not recorded as decisions, so the feed shows agent traffic only.

Where the AI matters: Jev runs only on ambiguous actions (the bulk report whose stated purpose may or may not fit the grant). It answers one rubric question with a structured result and an explicit status. A restrictive or non-evaluated result adds a review obligation and escalates to a human in the console. A positive result can never override a deterministic deny, and a timeout, malformed answer or missing provider never becomes a pass. Regular software cannot read "purpose: reconcile last month's invoices" against "permissions: reports:bulk" and say whether they fit; the model can, and the system is built so that its answer is advisory, logged, cache-bound to the exact action, purpose and policy, and bounded.

## What's real and what's mocked

Real, running in-process for the demo:

- The clearance kernel: policy engine with the six-outcome ladder, crypto (DPoP, HTTP message signatures, session tokens, replay cache), control-plane API (targets, grants, session exchange, revoke, kill switch, decisions list and SSE stream, signed receipts), verifier middleware, hash-chained outbox and transparency commitments.
- The protected site: real verifier in enforce mode, real signed requests from the runner, real decisions recorded before handlers run, a real chain-authority gate on the reserve effect and on review approval.
- Grant issuance, session exchange, scope enforcement, revocation, and every decision and receipt shown in the console come from the server, not from the UI.
- The weekend packages ship with local tests: `@aidenid/agent-client`, `@aidenid/jev`, the injectable session signer with its JWKS route, the `withChainAuthority` effect gate, the protected site with its end-to-end tests, the console with its proxy and model tests, and an in-process kernel end-to-end test that proves grant → exchange → signed request verified against the published JWKS → effect under the gate → revoke → effect refused and re-exchange refused. Counts per PR are in `docs/aidenid-build/evidence/PR-00-navigator.md`.
- The 84-file test suite of the kernel (620 tests) passes at the prior-work commit.

All of that is local evidence. Hosted GitHub Actions are unavailable on this account (billing), so nothing in this repository is a CI-green claim.

Ephemeral or unavailable in the demo, stated plainly:

- **State does not survive a restart.** The demo runs the control plane with an in-memory store and outbox (`AIDENID_ALLOW_EPHEMERAL_CONTROL_PLANE_STORE`, `AIDENID_ALLOW_IN_MEMORY_CONTROL_PLANE_OUTBOX`). Postgres and Redis adapters exist in the code but are not exercised here. Agents, keys, grants, reviews and released jobs live in the site process.
- **Jev needs a provider key.** Without `ANTHROPIC_API_KEY` the provider is not created, `assess()` reports `unavailable`, the action gets a `review_required` obligation and the console escalates to a human. It never shows a fabricated verdict.
- **Session signing key.** Without `AIDENID_CONTROL_PLANE_SESSION_SIGNING_JWK` the control plane generates a per-process key, which is fine for the demo and wrong for production (a restart rotates it).
- **The demo shop is a stand-in.** Four routes and one item; the point is the enforcement around them, not the shop.
- **The Senti coordination room** the builders used to pair-program is an external service and is not part of the product.

Nothing in the demo is a recorded replay or a stage override.

## How to run it

Requirements: Node 22, pnpm 10 via corepack.

```bash
corepack enable
CI=true pnpm install --frozen-lockfile
pnpm typecheck
pnpm test
pnpm dev
```

`pnpm dev` builds the workspace and starts three loopback listeners with ephemeral state and login disabled: the protected site on http://127.0.0.1:4100, its embedded control plane on http://127.0.0.1:4000, and the dashboard on http://127.0.0.1:3000. The Glasswing console is http://127.0.0.1:3000/glasswing. The launcher generates the operator token and the dashboard request token per run and never prints them; details, the full environment contract and the fallback when the site is not built are in `docs/aidenid-build/LOCAL_DEVELOPMENT.md`. The exact click path for the demo is in `docs/runbook.md`.

Optional environment, all server-side:

| Variable | Effect |
|---|---|
| `ANTHROPIC_API_KEY` | Enables Jev through the Anthropic SDK; forwarded to the protected-site process only. Omit and Jev reports `unavailable`. Never put it in a client bundle. |
| `JEV_MODEL` | Overrides the Jev model (default `claude-opus-5`). |
| `AIDENID_DEV_OPERATOR_TOKEN`, `AIDENID_DEV_DASHBOARD_REQUEST_TOKEN` | Fixed secrets (32+ characters, different from each other) for scripting against the operator API. Omit for random per-run values. |
| `AIDENID_CONTROL_PLANE_SESSION_SIGNING_JWK` | Private Ed25519 JWK JSON (with `kid`) for the standalone control plane; published as public keys at `GET /.well-known/aidenid-session-jwks.json`. |

Keep every key in `.env`, never in this repository, chat, logs or a client bundle.

## Anything built before this weekend

The first commit on `main`, `prior work` (`47a68878abbcdcdb53376a26d5f55ea6f080d928`), is a byte-identical subset of the owner's private `aidenid-clearance` repository at commit `0e4553e39e68b50aecbd977544f95d40c4e03de7` (committed 14 August 2026): nine workspace packages (`common-schemas`, `crypto`, `eventing`, `policy-engine`, `transparency`, `fingerprint-sidecar`, `verifier-node`, `control-plane`, `dashboard`) plus the root build files, 268 files in total. Every file in that commit matches its source blob hash; no git history was imported.

Two more pre-weekend files were added later in the merged foundation (PR #7), byte-identical from the same source commit: `docs/api/openapi.json` and `docs/dd/artifacts/cascade-latency-2026-05-02.json`.

Everything else after the first commit was written during Test Flight weekend (27 September 2026): the foundation itself (workspace prune, local dev runbook, gates), the revocation fixes and effect gate (`withChainAuthority`), `@aidenid/jev`, `@aidenid/agent-client`, the injectable session signer and JWKS route, operator site scopes on the control plane, the protected site with the Glasswing operator API, the kernel end-to-end test, the Glasswing console, the demo launcher, this README and the runbook.

The Senti CLI and API used by the builders to coordinate are pre-existing tools, not shipped code.
