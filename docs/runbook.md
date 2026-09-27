# AIdenID Glasswing — live demo runbook

One workflow, six beats, all against the real control plane and the real protected site. Every status, decision and reason code below comes from the server; the console only displays them. Judges can inspect the same facts through the site's operator API and the control-plane API.

State this runbook is tied to: `main` with the foundation (PR #7), the kernel PRs (#1 revocation and effect gate, #3 `@aidenid/jev`, #4 `@aidenid/agent-client`, #5 session signer and JWKS), the protected site with the Glasswing operator API (#9, #11), the Glasswing console (#8), the kernel end-to-end test (#6) and the demo launcher (#10). Per-PR evidence: `docs/aidenid-build/evidence/PR-00-navigator.md`.

Conventions:

- `SITE` = the protected site, `http://127.0.0.1:4100` under `pnpm dev`. It serves the demo shop routes and the operator API under `/glasswing/*`.
- `CP` = the control plane, `http://127.0.0.1:4000` under `pnpm dev`. It is served by the protected-site process, so the site and the dashboard share one store, one revocation epoch and one decision log.
- `OP` = the operator token. The launcher generates it per run and hands it to the site and to the dashboard server; the browser never sees it. To use it from a terminal, set `AIDENID_DEV_OPERATOR_TOKEN` (32+ characters) before `pnpm dev` and send `Authorization: Bearer <value>`.
- Console = `http://127.0.0.1:3000/glasswing`. Panels, top to bottom: **Agents** (1 · Mint), **Grants** (2 · Assign scoped work), **Run a task** (3 · Agent acts), **Review queue** (Human escalation), **What happened** (Evidence). The header link **Decision stream and receipts** opens the main dashboard page with the live stream and signed receipts.

## Setup

1. `pnpm dev` (details in `docs/aidenid-build/LOCAL_DEVELOPMENT.md`). It builds the workspace, then starts the protected site on 4100, its embedded control plane on 4000 and the dashboard on 3000: loopback only, in-memory state, login disabled. The first log lines name the three URLs. If the launcher prints `apps/protected-site is not built`, the build failed; fix that before anything else.
2. Health: `GET SITE/healthz` → `{ "status": "ok", "site_id": "sit_glasswing_demo" }`. `GET CP/healthz` → `{ "ok": true }`. `GET http://127.0.0.1:3000/api/status/health` → `{ "state": "connected" }`.
3. Keys: `GET CP/.well-known/aidenid-session-jwks.json` returns the control plane's public Ed25519 key with its `kid`. The site's verifier trusts exactly that key, so a judge can see which key every session token is checked against.
4. At startup the site registered its target on the control plane (`sit_glasswing_demo`, tenant `ten_glasswing_demo`, origin `https://aidenid.local`) and loaded its policy: `GET /catalog` and `POST /items/:id/reserve` allow a verified agent that holds the matching permission; `GET /customers/export` is denied for every actor class; `GET /reports/bulk` allows a verified agent with `reports:bulk` and a stated purpose, then hands the request to Jev; every other path is denied by a catch-all. There is nothing to register by hand.
5. Open the console. Expect the heading **Operations console**, the note `Protected site: http://127.0.0.1:4100`, and the banner **"Live: every outcome below is recorded by the control plane and the protected site."** With login disabled the page issues its own session cookie (`aidenid_operator_token`, 8 h) through `/api/glasswing/session`. That route is enabled only by the launcher flag `AIDENID_DASHBOARD_DEV_SESSION` and refuses without it, off loopback, or when `AIDENID_REQUIRE_LOGIN` is on. If the banner says the operator API is not reachable, see "If something fails".

## Beat 1 — Mint an agent

- Console: **Agents** → **Mint agent**. A row appears and is selected: agent id `agt_…`, `key agk_…`, `jkt <thumbprint prefix>…`. Click a row to select a different agent.
- Timeline (**What happened**): `Minted agt_… (key agk_…, thumbprint …)`.
- Server: `POST SITE/glasswing/agents` with `OP` → **201** `{ agent: { id, keyId, thumbprint, publicJwk, createdAt } }`. The Ed25519 private key is created and held by the site process and is never returned; the DPoP thumbprint is the subject binding for every later session.
- Negative check: the same call without `OP` → **401** `operator_unauthorized`.

## Beat 2 — Assign scoped work (issue a grant)

- Console: **Grants** → **Scope (one permission per grant)**, default `catalog:read` → **Expires in (minutes)**, default 10 → **Issue grant** (enabled once an agent is selected). The row shows `<agent> · catalog:read · chain chn_… · expires in 10 min` and is selected. Click a grant to select a different one.
- Timeline: `Grant grt_… to agt_…: catalog:read on https://aidenid.local/catalog, expires in 10 min`.
- Server: `POST SITE/glasswing/grants` body `{ "agentId", "permissions": ["catalog:read"], "expiresInSeconds": 600 }`. The site calls `POST CP/v1/grants` with `OP` (subject `agent:<id>`, resource `https://aidenid.local/catalog`, issuer bound to the authenticated operator) → **201** `{ grant: { id, chainId, siteId, resource, permissions, expiresAt } }`. Outbox event `GRANT_ISSUED_HASH`.
- A grant is bound to one route. Two permissions in one request → **400** `unsupported_permission_scope`. Later beats need one grant each for `items:reserve`, `customers:export` and `reports:bulk`; the list keeps them all.

## Beat 3 — Agent makes an allowed request

- Console: **Run a task** → **Read catalog — In scope: catalog:read** → **Run signed request** (needs a selected agent and grant).
- Expected row: headline **Allowed and executed**, detail `matched_policy`, decision pill **allow**, actor badge **verified_agent**, and the request id.
- Server, first leg: the site exchanges the grant for a session, `POST CP/v1/sessions/exchange` `{ grant_id, audience: "sit_glasswing_demo", resource, proof_jkt, requested_permissions: ["catalog:read"] }` → **201** with a DPoP-bound access token signed by the published key and `revocation_epoch: 0`. Outbox `SESSION_ISSUED_HASH`. The token stays inside the site process; the run result reports only `session.sessionId` and `session.revocationEpoch`.
- Server, second leg: the site signs `GET https://aidenid.local/catalog` with a DPoP proof and an RFC 9421 HTTP message signature (components `@method`, `@target-uri`, `authorization`, `dpop`; nonce required) and sends it through its own verifier. Policy match → **allow**, actor class `verified_agent`; the decision is recorded in the control plane before the handler runs (fail closed), then the handler returns the catalog.
- Optional: issue an `items:reserve` grant, select it, run **Reserve item** → **Allowed and executed**, effect `{ item_id: "demo-item", status: "reserved" }`. The reserve handler runs inside `withChainAuthority`, the same per-chain lease a revoke takes. A second reserve is refused by the shop and shown as **Refused at the effect boundary (item_already_reserved)**.
- Inspect: **Decision stream and receipts**, or `GET CP/v1/decisions?site_id=sit_glasswing_demo&limit=20` with `OP`: `decision: "allow"`, `reason_codes`, `route_template: "/catalog"`, `actor_class: "verified_agent"`, the signed receipt with its inclusion proof and the `decision_outbox_chain` hashes. Live rows come from `GET CP/v1/decisions/stream?site_id=sit_glasswing_demo` (SSE, `OP`).

## Beat 4 — Agent is denied out of scope

Two walls; show both.

- Wall 1, the grant. With the `catalog:read` grant selected, run **Export customers — Out of scope: expected deny**. Row: **Refused before signing (permission_scope_mismatch)**, detail `The grant does not authorize this task resource and permission.` The site refuses to sign a request outside the grant's resource: no session was minted and nothing reached the verifier. (Site response: **403**, `decision: null`.)
- Wall 2, the policy. Issue a `customers:export` grant, select it, run **Export customers** again. Row: **Denied by policy**, detail `matched_policy`, pill **deny**. The site policy denies `/customers/export` for every actor class, verified or not; the handler never ran and the route returned no data. Server: signed GET → verifier **deny**, recorded with a receipt, response header `X-AIdenID-Decision: deny`.
- Inspect: the deny decision in the list and stream with `route_template: "/customers/export"`.

## Beat 5 — Jev escalation on an ambiguous action

- Console: issue a `reports:bulk` grant and select it. **Run a task** → **Bulk report — Ambiguous: purpose required, Jev review**. The **Stated purpose** textarea appears (untrusted text the agent supplies; Jev reads it as data). Click **Run signed request**.
- Expected row: **Queued for human review**. Detail without `ANTHROPIC_API_KEY`: `Jev unavailable (no_provider); the check did not run and nothing was inferred`. With a key: `Jev <low|elevated|high> risk, confidence N%, evidence <none|partial|full>: <rationale>`. Reason codes `matched_policy, semantic_review_required, jev_unavailable` (or `semantic_review_required` after an evaluated restrictive answer). No effect ran.
- **Review queue (1)** gains `bulk-report by agt_…`, the purpose, the Jev line, status **Awaiting operator**, buttons **Approve** and **Deny**.
  - **Approve** → **Approved, released once**; timeline `Review rev_… approved: queued effect released once`. The site releases the report job exactly once, inside `withChainAuthority` for the grant's chain, and records an allow with `operator_override`. Clicking Approve again returns the same status and releases nothing.
  - **Deny** → **Denied**; timeline `Review rev_… denied: recorded as a deny decision`. The control plane records a deny with `semantic_review_required, operator_override`.
- Server: the policy allowed the route (`allowed_purposes: research, compare`), then `assess()` asked one bounded rubric question with structured output (`riskClass`, `modelConfidence`, `evidenceCoverage`, `verificationStatus` ∈ `evaluated | unavailable | inconclusive | not_evaluated`, obligation `none | review_required`; timeout enforced; cache bound to the exact action digest, grant, policy version and purpose text). `composeWithJev()` turned allow plus `review_required` into **queue**, which is not dispatch-eligible. Response headers `X-AIdenID-JEV-Status` and `X-AIdenID-JEV-Obligation`. Provider: the official Anthropic SDK with structured output, default `claude-opus-5` at low effort, `JEV_MODEL` override; without a key no provider is created.
- What to say: "a safe verdict cannot lift a deterministic deny; a missing provider never becomes a pass; a prompt injected into the purpose text cannot widen the scope, and that case is a test in `packages/jev`."

## Beat 6 — Revoke, then refused

- Run **Bulk report** once more so a second review is **Awaiting operator**. Its authority was captured at revocation epoch 0.
- Console: **Grants** → **Revoke** on the `reports:bulk` grant. The button reads **Revoked** and the row shows `revoked`. Timeline: `Revoked chain chn_…: epoch 1. The next request by agt_… on this grant is refused.`
- Server: `POST SITE/glasswing/revoke` `{ chainId, reason: "owner_revoked_from_glasswing" }` → `POST CP/v1/revoke` with `OP` → **202** `{ revocation: { id, chainId, epoch: 1 } }`. The grant is marked revoked before anything is published (a bus failure still leaves it revoked); outbox `REVOCATION_EPOCH_BUMP` then `GRANT_REVOKED_HASH`.
- Now click **Approve** on the pending review. Status: **Denied**. The approval ran under `withChainAuthority(services, { chainId, tokenRevocationEpoch: 0 }, release)`; the chain is revoked and its epoch is 1, so the gate returned `{ ok: false, reason: "grant_revoked" }`, the job was not released, and the control plane recorded a deny with `operator_override`. This is the effect boundary refusing a human approval issued after the owner changed their mind.
- Then run **Bulk report** (or any task) on the revoked grant. Row: **Session refused**, detail `The grant is no longer active or could not be exchanged.` The control plane refused `POST /v1/sessions/exchange` for the revoked grant, so nothing was signed. A token minted before the revoke carries epoch 0 and the verifier refuses it as `epoch_stale`; that path is proven by the kernel end-to-end test (`packages/agent-client/tests/kernel-e2e.test.ts`), not clicked.
- The revoke and the effect share one per-chain lease; an effect that waits more than 2 s for it fails closed as `chain_busy` instead of running.
- Inspect: the revocation, `GRANT_REVOKED_HASH`, and the deny decisions carrying `operator_override` in the list and stream.

## Reset

Restarting `pnpm dev` is the reset. Targets, grants, sessions, decisions, outbox entries, agents, keys, reviews and released jobs are all in-process. Say this out loud rather than implying persistence.

## If something fails

- Banner **"The Glasswing operator API is not reachable: …"**: the site is down, or the dashboard is missing `AIDENID_PROTECTED_SITE_URL`, `AIDENID_OPERATOR_TOKEN` or `AIDENID_DASHBOARD_OPERATOR_REQUEST_TOKEN` (`pnpm dev` sets them). Check `GET SITE/healthz`, restart `pnpm dev`, reload.
- Banner **"Login is required on this dashboard…"**: `AIDENID_REQUIRE_LOGIN` is on, so the dev session is disabled. Run the local profile (`pnpm dev`).
- Console stuck on **"The Glasswing operator API is not reachable: dev_session_disabled"**: the dashboard was started without `AIDENID_DASHBOARD_DEV_SESSION=true`; `pnpm dev` sets it, a hand-started dashboard must too.
- Banner **"No live control plane configured…"**: the dashboard has no `AIDENID_CONTROL_PLANE_URL`; start `pnpm dev`.
- **Error: unsupported_permission_scope** when issuing a grant: one permission per grant; pick one scope.
- **Error: grant_forbidden** on a run: the selected grant belongs to a different agent; select the agent that owns it.
- **Refused before signing (permission_scope_mismatch)** on the task you meant to allow: the selected grant is for another route; select or issue the matching grant.
- **Session refused** before any revoke: the grant expired (see **Expires in (minutes)**); issue a new one.
- **Refused at the effect boundary (chain_busy)**: a revoke held the per-chain lease for more than 2 s and the gate failed closed by design. Retry; do not bypass the gate.
- **Denied by policy** with `strict_route_degraded`: the verifier could not record the decision and failed closed. Check `GET CP/healthz`, restart `pnpm dev`.
- Jev shows `unavailable`: no provider key, or the provider timed out. That is the honest state; use the Review queue. Never retry with a fake verdict.
- The decision feed shows nothing after a run: `GET CP/v1/decisions?site_id=sit_glasswing_demo` with `OP`. If it is empty, the site's decision emitter is not reaching the control plane; restart `pnpm dev`.
- Anything else: open **Decision stream and receipts** or `GET CP/v1/decisions`, and say what the server recorded. Never narrate a success the server did not record.
