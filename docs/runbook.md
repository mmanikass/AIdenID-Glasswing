# AIdenID Glasswing — live demo runbook

One workflow, six beats, all against the real control-plane and the protected site. Every status, decision and reason code below comes from the server; the console only displays them. Judges can inspect the same facts through the operator API.

State this runbook is tied to: kernel PRs #1 (revocation + `withChainAuthority` effect gate), #3 (`@aidenid/jev`), #4 (`@aidenid/agent-client`), #5 (session signer + JWKS) and #7 (foundation) are merged into `main` (`65b498f`). PR #6 (kernel end-to-end test) and PR #8 (Glasswing console, `roadmap/pr-03-glasswing-ui`, head `bba41f3`) are open. The protected site that hosts the agent runner and the operator endpoints is PR-2 (Codex), in progress. Until PR #8 is merged, treat every console claim below as "PR #8, pending review".

Conventions:

- `ADMIN` = an operator token with role `admin` from `AIDENID_OPERATOR_TOKENS`; the local launcher provides one.
- `CP` = the control-plane base URL, `http://127.0.0.1:4000` under `pnpm dev`.
- Console = the Glasswing operations console at `http://127.0.0.1:3000/glasswing` on the dashboard (PR #8, pending review). Its panels, top to bottom: **Agents** (1 · Mint), **Grants** (2 · Assign scoped work), **Run a task** (3 · Agent acts), **Review queue** (Human escalation), **What happened** (Evidence). The header link **Decision stream and receipts** opens the main dashboard page with the live stream and signed receipts.

## Setup

1. `pnpm dev` builds the workspace and starts the control plane on `http://127.0.0.1:4000` and the dashboard on `http://127.0.0.1:3000`, loopback only, ephemeral state, login disabled (`docs/aidenid-build/LOCAL_DEVELOPMENT.md`). The launcher provides the dashboard with `AIDENID_PROTECTED_SITE_URL`, `AIDENID_OPERATOR_TOKEN` and `AIDENID_DASHBOARD_OPERATOR_REQUEST_TOKEN`; the console cannot act without them. Optional: `AIDENID_CONTROL_PLANE_SESSION_SIGNING_JWK` for a stable signing key; otherwise a per-process key is used.
2. Confirm the published session keys: `GET CP/.well-known/aidenid-session-jwks.json` returns the control-plane's public Ed25519 key(s) with `kid`. The protected site's verifier is configured from this document, so a judge can see exactly which key the tokens are checked against.
3. Start the protected site (PR-2, Codex, in progress). It hosts the agent runner and the six operator endpoints the console reaches through the dashboard's allow-listed proxy: `/glasswing/agents` (GET, POST), `/glasswing/agents/:id/run`, `/glasswing/grants`, `/glasswing/revoke`, `/glasswing/reviews`, `/glasswing/reviews/:id`. The browser never sees the operator token; the proxy adds it server-side. If the site's target is not yet registered on the control plane, register it once per process: `POST CP/v1/targets` with `ADMIN`, body `{ "site_id": "sit_demo", "name": "Demo Shop", "origin": "<protected site origin>" }` → **201** with `id` (`tgt_…`).
4. Open the console. Expect the heading **Operations console**, the note `Protected site: <url>`, and the banner **"Live: every outcome below is recorded by the control plane and the protected site."** With login disabled the page issues its own loopback-only session cookie (`aidenid_operator_token`, 8 h) through `/api/glasswing/session`; it refuses to do so off loopback or when `AIDENID_REQUIRE_LOGIN` is on. If the banner reads **"No live control plane configured: this console cannot act. Start it with pnpm dev."**, stop and fix step 1. `GET CP/healthz` → `{ "ok": true }` is the terminal check.

## Beat 1 — Mint an agent

- Console: **Agents** panel → click **Mint agent**. The button creates an Ed25519 key held by the demo runner and registers its public key with the protected site. The new row (agent id, `key <kid>`, `jkt <thumbprint prefix>…`) appears and is selected; click any row to select a different agent.
- Timeline (**What happened**): `Minted <agent id> (key <kid>, thumbprint <jkt prefix>…)`.
- Server effect: `mintAgentKey()` creates the key pair; the DPoP JWK thumbprint (`proof_jkt`) is the subject binding for every later session.
- What a judge can inspect: the agent row shows the key id and thumbprint prefix and, so far, no grant.

## Beat 2 — Assign scoped work (issue a grant)

- Console: **Grants** panel → **Permissions (comma separated)** (default `catalog:read, items:reserve`) → **Expires in (minutes)** (default 10) → click **Issue grant** (enabled once an agent is selected). The grant appears in the list and is selected; the row shows the agent, permissions, `chain chn_…` and `expires in N min`. Click a grant id to select a different grant.
- Timeline: `Grant grt_… to <agent id>: catalog:read, items:reserve on <resource>, expires in 10 min`.
- Server: `POST CP/v1/grants` with `ADMIN` (through the site's operator endpoint), body `{ "target_id": "tgt_…", "subject": "<agent subject>", "permissions": ["catalog:read", "items:reserve"], "expires_in_seconds": 600 }` → **201** with `id` (`grt_…`), `chain_id` (`chn_…`), `issuer_actor_id` bound to the authenticated operator (a body-supplied issuer is rejected).
- Outbox event: `GRANT_ISSUED_HASH`.
- Negative check to show if asked: the same call without `ADMIN` → **401** `operator_auth_required`.

## Beat 3 — Agent makes an allowed request

- Console: **Run a task** panel → Task **Read catalog — In scope: catalog:read** → click **Run signed request** (enabled once an agent and a grant are selected). Optional second run: **Reserve item — State change, in scope, parameters in the path**.
- Expected timeline row: headline **Allowed and executed**, detail = reason codes, decision pill **allow**, actor badge **verified_agent**, and the request id.
- Server, first leg (`exchangeSession()`): `POST CP/v1/sessions/exchange` body `{ "grant_id": "grt_…", "audience": "sit_demo", "resource": "<origin>", "proof_jkt": "<thumbprint>", "requested_permissions": ["catalog:read"] }` → **201** with a `DPoP` `access_token` signed by the key published at `/.well-known/aidenid-session-jwks.json`, `expires_in` (90 s default), `revocation_epoch: 0`. Outbox event: `SESSION_ISSUED_HASH`.
- Server, second leg (`signedFetch()` / `buildSignedHeaders()`): signed `GET` on the in-scope route of the protected site, carrying a DPoP proof and an RFC 9421 HTTP message signature → **200**, header `X-AIdenID-Decision: allow`, actor class `verified_agent`. The effect runs inside `withChainAuthority(...)`, which returns `{ ok: true, ... }` while the chain is current.
- Judge can inspect: **Decision stream and receipts** (main dashboard page), or `GET CP/v1/decisions?site_id=sit_demo&limit=20` with `ADMIN`, shows the decision with `decision: "allow"`, `reason_codes`, `receipt` (signed, with Merkle inclusion proof) and `decision_outbox_chain` (previous and entry hashes); the live row comes from `GET CP/v1/decisions/stream?site_id=sit_demo` (SSE, `ADMIN`), event `recorded`.

## Beat 4 — Agent is denied out of scope

- Console: Task **Export customers — Out of scope: expected deny** → **Run signed request**.
- Expected timeline row: headline **Denied by policy**, detail = the reason codes, decision pill **deny**. The export route returned no data.
- Server: signed request to the export route with a `catalog:read, items:reserve` session → decision **`deny`** with a scope reason code (`permission_scope_mismatch` when the route requires a permission the session lacks). The response carries `X-AIdenID-Decision: deny` and `X-AIdenID-Reasons`.
- If the runner instead asks the control plane for a permission beyond the grant, the exchange itself fails: `requested_permissions: ["catalog:export"]` → **403** `permission_exceeds_grant`, shown in the timeline as **Session refused**.
- Judge can inspect: the deny decision and its receipt in the decision list; a signed denial is paired with the fact that the export route returned no data.

## Beat 5 — JEV escalation on an ambiguous action

- Console: Task **Bulk report — Ambiguous: purpose required, Jev review**. The **Stated purpose** textarea appears ("untrusted text the agent supplies; Jev reads it as data"; default `Compare prices of the three cheapest laptops for the customer.`). Click **Run signed request**.
- Expected timeline row: headline **Queued for human review**, detail = the Jev line, for example `Jev unavailable (no_provider); the check did not run and nothing was inferred` without `ANTHROPIC_API_KEY`, or `Jev <low|elevated|high> risk, confidence N%, evidence <none|partial|full>: <rationale>` when evaluated.
- **Review queue (1)** gains a row: `bulk-report by <agent id>`, `Purpose: …`, the Jev line, status **Awaiting operator**, with **Approve** and **Deny** buttons.
  - **Approve** → status **Approved, released once**; timeline `Review <id> approved: queued effect released once`. The queued effect runs exactly once.
  - **Deny** → status **Denied**; timeline `Review <id> denied: recorded as a deny decision`.
- Server (`@aidenid/jev` `assess()`): deterministic checks pass first; one bounded rubric question ("does the stated purpose fit the granted scope?"), structured output with `riskClass`, `modelConfidence`, `evidenceCoverage`, `verificationStatus` ∈ `evaluated | unavailable | inconclusive | not_evaluated`, obligation ∈ `none | review_required`, timeout enforced, result cache bound to the exact action, grant and policy version. Provider: `createAnthropicJevProvider()` through the official Anthropic SDK (default `claude-opus-5` at low effort, `JEV_MODEL` override); without `ANTHROPIC_API_KEY` no provider is created and the status is `unavailable`.
- Composition (`composeWithJev()`): a deny never changes; allow plus `review_required` is shown as `queue` and is not dispatch-eligible until the operator decides. `inconclusive`, `unavailable` and `not_evaluated` all escalate.
- What to say: "a safe verdict cannot lift a deterministic deny; a missing provider never becomes a pass; a prompt injected into the purpose text cannot widen the scope (that case is a test)."

## Beat 6 — Revoke, then refused

- Console: **Grants** panel → click **Revoke** on the grant. The button reads **Revoked** and the row shows `revoked`.
- Timeline: `Revoked chain chn_…: epoch 1. The next request by <agent id> on this grant is refused.`
- Server: `POST CP/v1/revoke` with `ADMIN`, body `{ "chain_id": "chn_…", "reason": "owner_revoked_from_glasswing", "actor_id": "<operator actor id>" }` → **202** with `revocation_epoch: 1`. The grant is marked revoked before any outbox publish, so a bus failure still leaves the chain revoked. Outbox events: `REVOCATION_EPOCH_BUMP` and `GRANT_REVOKED_HASH`.
- Then rerun Task **Read catalog** → **Run signed request**. Expected refusals, exactly:
  - Timeline headline **Refused at the effect boundary (grant_revoked)**: the protected route's `withChainAuthority(services, { chainId, tokenRevocationEpoch }, effect)` returned `{ ok: false, reason: "grant_revoked" }` and the effect never ran. The decision pill can still read `allow` from the verifier; the console reports decision and effect separately, and the effect line is what protects the resource.
  - When the runner next needs a session for that grant (its 90 s token expired, or the run re-exchanges), the timeline headline is **Session refused** with detail `The control plane refused to exchange the grant (revoked, expired, or out of scope).`; at the API that is **403** `grant_not_active`.
  - Outbox contains `GRANT_REVOKED_HASH` for the grant, with the chain id and the new epoch.
  - A verifier whose epoch floor has been raised refuses the old token outright. That path is proven in the kernel end-to-end test (PR #6, open), not clicked in the demo.
- The revoke and the effect share one per-chain lease, so they cannot interleave; if an effect waits on the lease for more than 2 s it fails closed as `chain_busy` rather than running.
- Judge can inspect: the revoke record, the `GRANT_REVOKED_HASH` outbox event, and the refused decision in the list and stream.

## Reset

The store is ephemeral: **restarting `pnpm dev` is the reset.** The control plane's targets, grants, sessions, decisions and outbox entries, and the demo runner's agents, grants and review queue, are all in-process and gone on restart; re-run Setup from step 3. Say this out loud during the demo rather than implying persistence.

## If something fails

- **Console banner "The Glasswing operator API is not reachable: …":** `AIDENID_PROTECTED_SITE_URL`, `AIDENID_OPERATOR_TOKEN` or `AIDENID_DASHBOARD_OPERATOR_REQUEST_TOKEN` is missing (`pnpm dev` sets them), or the protected site is down. Fix, reload the page.
- **Console banner "Login is required on this dashboard…":** `AIDENID_REQUIRE_LOGIN` is on, so the loopback session shortcut is disabled. Sign in, or run the local profile.
- **Console banner "No live control plane configured…":** the dashboard has no control-plane URL; start `pnpm dev`.
- **Console cannot reach the control-plane:** show `GET CP/healthz` in a terminal; if it fails, restart `pnpm dev` and re-run Setup. The console's disconnected state is a real state, not a mock.
- **"Session refused" before any revoke:** the grant expired (check **Expires in (minutes)**) or the runner asked for permissions beyond it; issue a new grant.
- **"Denied by policy" on Read catalog:** the selected grant lacks `catalog:read` (check the **Permissions** field); issue a grant with the default permissions.
- **"Error: <code>" in the timeline:** the runner reported an error from the site; read the detail line and say what it says.
- **Exchange returns 403 `audience_or_resource_mismatch`:** the agent used a different `resource`/`audience` than the grant; re-issue the grant for the right target rather than editing the token.
- **JEV shows `unavailable`:** no provider key or the provider timed out. That is the honest state; continue with the Review queue. Do not retry with a fake verdict.
- **Revoke returns 400 `actor_id_mismatch`:** the body `actor_id` must equal the authenticated operator's actor id.
- **Session expired (90 s):** exchange again while the grant is active; after revoke the exchange must fail, which is the point of Beat 6.
- **An effect returns `{ ok: false, reason: "chain_busy" }`:** a revoke held the per-chain lease for longer than 2 s and the gate failed closed by design. Retry the request; do not bypass the gate.
- **Verifier rejects every token with `unknown_issuer` or a key error:** the verifier was not configured from `GET CP/.well-known/aidenid-session-jwks.json`, or the control-plane restarted with a per-process key. Reload the JWKS (or set `AIDENID_CONTROL_PLANE_SESSION_SIGNING_JWK`) and re-exchange.
- **A route returns `queue` or `throttle`:** those are real outcomes from the policy; read the `Retry-After` header and explain the ladder rather than forcing `allow`.
- **Anything else:** stop, open **Decision stream and receipts** or `GET CP/v1/decisions`, and say what the server recorded. Never narrate a success the server did not record.
