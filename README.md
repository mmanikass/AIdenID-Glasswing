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
6. **Revoke.** The operator revokes the chain. The revocation epoch increments, the grant is marked revoked, and the agent's next exchange or request is refused.

Where the AI matters: JEV, a bounded semantic assessor, runs only on ambiguous actions (for example a bulk export whose stated purpose may or may not fit the grant). It answers one rubric question with a structured result and an explicit status: `evaluated`, `inconclusive` or `unavailable`. A restrictive or non-evaluated result adds a review obligation and escalates to a human in the console. A positive result can never override a deterministic deny, and a timeout or missing provider never becomes a pass. Regular software cannot read "purpose: reconcile last month's invoices" against "permissions: catalog:read" and say whether they fit; the model can, and the system is built so that its answer is advisory, logged, and bounded.

## What's real and what's mocked

Real, running in-process for the demo:

- The clearance kernel: policy engine with the six-outcome ladder, crypto (DPoP, HTTP message signatures, session tokens, replay cache), control-plane API (targets, grants, session exchange, revoke, kill switch, decisions list and SSE stream, signed receipts), verifier middleware, hash-chained outbox and transparency commitments.
- Grant issuance, session exchange, scope enforcement, revocation, and every decision and receipt shown in the console come from the server, not from the UI.
- The 84-file test suite of the kernel (620 tests) passes at the prior-work commit; see `docs/aidenid-build/evidence/PR-00-navigator.md`.

Ephemeral or unavailable in the demo, stated plainly:

- **State does not survive a restart.** The demo runs the control-plane with an in-memory store and outbox (`AIDENID_ALLOW_EPHEMERAL_CONTROL_PLANE_STORE`, `AIDENID_ALLOW_IN_MEMORY_CONTROL_PLANE_OUTBOX`). Postgres and Redis adapters exist in the code but are not exercised here.
- **JEV needs a provider key.** With no key configured the console shows `unavailable` for the semantic check and escalates to a human. It never shows a fabricated verdict.
- **The Senti coordination room** the builders used to pair-program is an external service and is not part of the product.

Nothing in the demo is a recorded replay or a stage override.

## How to run it

Requirements: Node 22, pnpm 10 via corepack.

```bash
corepack enable
CI=true pnpm install --frozen-lockfile   # works after the workspace-prune commit lands; see PR-1
pnpm typecheck
pnpm test
```

Start the control-plane in ephemeral demo mode:

```bash
pnpm --filter @aidenid/control-plane build
AIDENID_ALLOW_EPHEMERAL_CONTROL_PLANE_STORE=true \
AIDENID_ALLOW_IN_MEMORY_CONTROL_PLANE_OUTBOX=true \
AIDENID_OPERATOR_TOKENS='{"demo_admin":{"token":"<32+ chars>","roles":["admin"]}}' \
node apps/control-plane/dist/start.js
```

The Glasswing console and the agent runner are added in PR-2 and PR-3; their start commands and the exact click path for the demo are in `docs/runbook.md`.

Keep every key in `.env`, never in this repository, chat, logs or a client bundle.

## Anything built before this weekend

The first commit on `main`, `prior work` (`47a68878abbcdcdb53376a26d5f55ea6f080d928`), is a byte-identical subset of the owner's private `aidenid-clearance` repository at commit `0e4553e39e68b50aecbd977544f95d40c4e03de7` (committed 14 August 2026): nine workspace packages (`common-schemas`, `crypto`, `eventing`, `policy-engine`, `transparency`, `fingerprint-sidecar`, `verifier-node`, `control-plane`, `dashboard`) plus the root build files, 268 files in total. Every file in that commit matches its source blob hash; no git history was imported.

Everything after that commit was written during Test Flight weekend (27 September 2026): the workspace prune, the revocation fixes, the Glasswing console, the agent runner, JEV, this README and the runbook.

The Senti CLI and API used by the builders to coordinate are pre-existing tools, not shipped code.
