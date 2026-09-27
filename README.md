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

1. **Mint.** The operator mints an agent identity: a key pair whose DPoP thumbprint becomes the subject binding.
2. **Assign work.** The operator issues a delegation grant against a registered target site with explicit permissions and an expiry. The grant carries a chain id and the authenticated issuer.
3. **Exchange.** The agent exchanges the grant for a short-lived DPoP session token bound to the site, the resource, the requested permissions (which must be a subset of the grant) and the chain's revocation epoch.
4. **Decide.** Every request through the verifier middleware gets exactly one of six outcomes: `allow`, `throttle`, `queue`, `sandbox`, `deny`, `price_required`. Signatures, audience, resource, expiry, scope and revocation epoch are hard checks.
5. **Record.** Each decision is written to a hash-chained outbox and issued a signed decision receipt with a Merkle inclusion proof. The console reads the decision list and a server-sent-event stream.
6. **Revoke.** The operator revokes the chain. The grant is marked revoked before anything is published to the outbox (a bus failure still leaves the chain revoked), the revocation epoch increments, and the agent's next exchange returns 403 `grant_not_active`. An effect attempted under the effect gate is refused with `grant_revoked`.

The operator console at `/glasswing` on the dashboard drives this workflow (PR #8, pending review), and the protected site (PR-2, Codex, in progress) hosts the agent runner and the six operator endpoints the console calls through an allow-listed dashboard proxy.

Weekend packages on top of the kernel:

- `@aidenid/agent-client` — `mintAgentKey` (Ed25519), `exchangeSession`, `buildSignedHeaders` (DPoP proof plus an RFC 9421 HTTP message signature) and `signedFetch`. This is the agent side of beats 1, 3 and 4.
- `@aidenid/jev` — the bounded semantic assessor: `assess()` returns a verification status of `evaluated`, `unavailable`, `inconclusive` or `not_evaluated` and an obligation of `none` or `review_required`; `composeWithJev()` never changes a deny and turns allow-plus-review into a `queue` that is not dispatch-eligible; `createAnthropicJevProvider()` uses the official Anthropic SDK with structured output (default model `claude-opus-5` at low effort, `JEV_MODEL` override).
- Control-plane session signer — now injectable (`sessionSigningKey` option or the `AIDENID_CONTROL_PLANE_SESSION_SIGNING_JWK` env var; otherwise a per-process key for local/demo only) and published at `GET /.well-known/aidenid-session-jwks.json`, so a verifier checks session tokens against the control-plane's published key instead of a shared secret.
- `withChainAuthority(services, { chainId, tokenRevocationEpoch }, effect)` — the co-located effect gate. It runs the effect on the same per-chain lease that `revokeChain` holds, so a revoke and an effect on one chain are serialized; the in-memory lease waits up to 2 s and then fails closed as `chain_busy`. `checkChainAuthority` remains available as a read-only snapshot.

Where the AI matters: JEV runs only on ambiguous actions (for example a bulk export whose stated purpose may or may not fit the grant). It answers one rubric question with a structured result and an explicit status. A restrictive or non-evaluated result adds a review obligation and escalates to a human in the console. A positive result can never override a deterministic deny, and a timeout, malformed answer or missing provider never becomes a pass. Regular software cannot read "purpose: reconcile last month's invoices" against "permissions: catalog:read" and say whether they fit; the model can, and the system is built so that its answer is advisory, logged, cache-bound to the exact action and policy, and bounded.

## What's real and what's mocked

Real, running in-process for the demo:

- The clearance kernel: policy engine with the six-outcome ladder, crypto (DPoP, HTTP message signatures, session tokens, replay cache), control-plane API (targets, grants, session exchange, revoke, kill switch, decisions list and SSE stream, signed receipts), verifier middleware, hash-chained outbox and transparency commitments.
- Grant issuance, session exchange, scope enforcement, revocation, and every decision and receipt shown in the console come from the server, not from the UI.
- The weekend packages (`@aidenid/agent-client`, `@aidenid/jev`, the injectable session signer with its JWKS route, and the `withChainAuthority` effect gate) each ship with local tests and are merged into `main` (`65b498f`) with the foundation. An in-process kernel end-to-end test (PR #6, open) proves grant → exchange → signed request verified against the published JWKS → effect under the gate → revoke → effect refused and re-exchange refused. The Glasswing console is PR #8, pending review. Counts per PR are in `docs/aidenid-build/evidence/PR-00-navigator.md`.
- The 84-file test suite of the kernel (620 tests) passes at the prior-work commit.

All of that is local evidence. Hosted GitHub Actions are unavailable on this account (billing), so nothing in this repository is a CI-green claim.

Ephemeral or unavailable in the demo, stated plainly:

- **State does not survive a restart.** The demo runs the control-plane with an in-memory store and outbox (`AIDENID_ALLOW_EPHEMERAL_CONTROL_PLANE_STORE`, `AIDENID_ALLOW_IN_MEMORY_CONTROL_PLANE_OUTBOX`). Postgres and Redis adapters exist in the code but are not exercised here.
- **JEV needs a provider key.** Without `ANTHROPIC_API_KEY` the provider is not created, `assess()` reports `unavailable`, the action gets a `review_required` obligation and the console escalates to a human. It never shows a fabricated verdict.
- **Session signing key.** Without `AIDENID_CONTROL_PLANE_SESSION_SIGNING_JWK` the control-plane generates a per-process key, which is fine for the demo and wrong for production (a restart rotates it).
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

All five work on `main` as of the merged foundation (PR #7, `13e70b3`). Local evidence at that commit: frozen install, typecheck, lint and secret scan clean; vitest 50 test files / 386 tests passed.

`pnpm dev` starts the control plane on http://127.0.0.1:4000 and the dashboard on http://127.0.0.1:3000, loopback only, with ephemeral state and login disabled for local development; details in `docs/aidenid-build/LOCAL_DEVELOPMENT.md`.

To start the control-plane alone in ephemeral demo mode:

```bash
pnpm --filter @aidenid/control-plane build
AIDENID_ALLOW_EPHEMERAL_CONTROL_PLANE_STORE=true \
AIDENID_ALLOW_IN_MEMORY_CONTROL_PLANE_OUTBOX=true \
AIDENID_OPERATOR_TOKENS='{"demo_admin":{"token":"<32+ chars>","roles":["admin"]}}' \
node apps/control-plane/dist/start.js
```

Optional environment, all server-side:

| Variable | Effect |
|---|---|
| `AIDENID_CONTROL_PLANE_SESSION_SIGNING_JWK` | Private Ed25519 JWK JSON (with `kid`) used to sign session tokens; published as public keys at `GET /.well-known/aidenid-session-jwks.json`. Omit for a per-process key (local/demo only). |
| `ANTHROPIC_API_KEY` | Enables JEV through the Anthropic SDK. Omit and JEV reports `unavailable`. Never put it in a client bundle. |
| `JEV_MODEL` | Overrides the JEV model (default `claude-opus-5`). |

The agent side is the `@aidenid/agent-client` package (mint key, exchange session, signed fetch). The Glasswing operations console (PR #8, pending review) is served by the dashboard at http://127.0.0.1:3000/glasswing. It needs the three variables the launcher provides, `AIDENID_PROTECTED_SITE_URL`, `AIDENID_OPERATOR_TOKEN` and `AIDENID_DASHBOARD_OPERATOR_REQUEST_TOKEN`, and cannot act without them; the operator token stays server-side behind the dashboard proxy. With login disabled the page issues its own loopback-only session cookie and refuses to do so off loopback. The exact click path for the demo is in `docs/runbook.md`.

Keep every key in `.env`, never in this repository, chat, logs or a client bundle.

## Anything built before this weekend

The first commit on `main`, `prior work` (`47a68878abbcdcdb53376a26d5f55ea6f080d928`), is a byte-identical subset of the owner's private `aidenid-clearance` repository at commit `0e4553e39e68b50aecbd977544f95d40c4e03de7` (committed 14 August 2026): nine workspace packages (`common-schemas`, `crypto`, `eventing`, `policy-engine`, `transparency`, `fingerprint-sidecar`, `verifier-node`, `control-plane`, `dashboard`) plus the root build files, 268 files in total. Every file in that commit matches its source blob hash; no git history was imported.

Two more pre-weekend files were added later in the merged foundation (PR #7), byte-identical from the same source commit: `docs/api/openapi.json` and `docs/dd/artifacts/cascade-latency-2026-05-02.json`.

Everything else after the first commit was written during Test Flight weekend (27 September 2026): the foundation itself (workspace prune, local dev runbook, gates), the revocation fixes and effect gate (`withChainAuthority`), `@aidenid/jev`, `@aidenid/agent-client`, the injectable session signer and JWKS route, the kernel end-to-end test, the Glasswing console, this README and the runbook.

The Senti CLI and API used by the builders to coordinate are pre-existing tools, not shipped code.
