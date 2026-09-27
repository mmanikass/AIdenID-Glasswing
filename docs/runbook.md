# AIdenID Glasswing — live demo runbook

One workflow, six beats, all against the real control-plane. Every status, decision and reason code below comes from the server; the console only displays them. Judges can inspect the same facts through the operator API.

Conventions:

- `ADMIN` = an operator token with role `admin` from `AIDENID_OPERATOR_TOKENS`.
- `CP` = the control-plane base URL (default `http://127.0.0.1:3000`).
- Console click paths are marked **TODO (Driver, PR-3)** until the Glasswing UI lands.

## Setup

1. Start the control-plane in ephemeral mode (see README "How to run it").
2. Start the Glasswing console and the agent runner. **TODO (Driver, PR-2/PR-3): commands.**
3. Register the protected demo site once per process:
   `POST CP/v1/targets` with `ADMIN`, body `{ "site_id": "sit_demo", "name": "Demo Shop", "origin": "<protected site origin>" }` → **201** with `id` (`tgt_…`).
4. Open the console; confirm the health indicator reads the control-plane `GET CP/healthz` → `{ "ok": true }`.

## Beat 1 — Mint an agent

- Console: **TODO (Driver, PR-3): "Mint agent" click path.**
- Server effect: a key pair is created; the DPoP JWK thumbprint (`proof_jkt`) is the subject binding. An app event `agent.minted` appears in the timeline.
- What a judge can inspect: the roster shows the agent with its thumbprint prefix and no authority yet.

## Beat 2 — Assign scoped work (issue a grant)

- Console: **TODO (Driver, PR-3): "Assign work" click path** (permissions e.g. `catalog:read`, expiry 10 minutes).
- Server: `POST CP/v1/grants` with `ADMIN`, body `{ "target_id": "tgt_…", "subject": "<agent subject>", "permissions": ["catalog:read"], "expires_in_seconds": 600 }` → **201** with `id` (`grt_…`), `chain_id` (`chn_…`), `issuer_actor_id` bound to the authenticated operator (a body-supplied issuer is rejected).
- Outbox event: `GRANT_ISSUED_HASH`.
- Negative check to show if asked: the same call without `ADMIN` → **401** `operator_auth_required`.

## Beat 3 — Agent makes an allowed request

- Agent runner: exchanges the grant: `POST CP/v1/sessions/exchange` body `{ "grant_id": "grt_…", "audience": "sit_demo", "resource": "<origin>", "proof_jkt": "<thumbprint>", "requested_permissions": ["catalog:read"] }` → **201** with a `DPoP` `access_token`, `expires_in` (90 s default), `revocation_epoch: 0`. Outbox event: `SESSION_ISSUED_HASH`.
- Agent runner: signed `GET` on the in-scope route of the protected site → **200**, header `X-AIdenID-Decision: allow`, actor class `verified_agent`.
- Judge can inspect: `GET CP/v1/decisions?site_id=sit_demo&limit=20` with `ADMIN` shows the decision with `decision: "allow"`, `reason_codes`, `receipt` (signed, with Merkle inclusion proof) and `decision_outbox_chain` (previous and entry hashes). The console's timeline row comes from `GET CP/v1/decisions/stream?site_id=sit_demo` (SSE, `ADMIN`), event `recorded`.

## Beat 4 — Agent is denied out of scope

- Over-scope exchange (if the runner asks for more than the grant): `requested_permissions: ["catalog:export"]` → **403** `permission_exceeds_grant`.
- Signed request to the export route with a `catalog:read` session → decision **`deny`** with a scope reason code (`permission_scope_mismatch` when the route requires a permission the session lacks). The response carries `X-AIdenID-Decision: deny` and `X-AIdenID-Reasons`.
- Judge can inspect: the deny decision and its receipt in `GET CP/v1/decisions`; a signed denial is paired with the fact that the export route returned no data.

## Beat 5 — JEV escalation on an ambiguous action

- Agent runner: requests the ambiguous route (bulk export with a stated purpose). Deterministic checks pass first; the route is marked as needing a semantic check.
- JEV: one bounded rubric question ("does the stated purpose fit the granted scope?"), structured output with `riskClass`, `modelConfidence`, `evidenceCoverage`, `verificationStatus` ∈ `evaluated | inconclusive | unavailable`, timeout enforced.
- Console: **TODO (Driver, PR-3): escalation card** showing the JEV status and an operator approve/deny control. The action stays blocked until the operator decides; `inconclusive` and `unavailable` both escalate.
- What to say: "a safe verdict cannot lift a deterministic deny; a missing provider never becomes a pass."

## Beat 6 — Revoke, then refused

- Console: **TODO (Driver, PR-3): "Revoke" click path.**
- Server: `POST CP/v1/revoke` with `ADMIN`, body `{ "chain_id": "chn_…", "reason": "owner_revoked", "actor_id": "<operator actor id>" }` → **202** with `revocation_epoch: 1`. Outbox events: `REVOCATION_EPOCH_BUMP` and, after PR-2a, `GRANT_REVOKED_HASH`.
- Agent runner: tries to exchange again → **403** `grant_not_active` (PR-2a). Tries a signed request with its old token → refused at the protected route by the per-chain authority check with reason `grant_revoked` (PR-2a `checkChainAuthority`), recorded as a decision.
- Judge can inspect: the revoke record, the `GRANT_REVOKED_HASH` outbox event, and the refused decision in the list and stream.

## Reset

The store is ephemeral: **restarting the control-plane process is the reset.** All targets, grants, sessions, decisions and outbox entries are gone; re-run Setup step 3. Say this out loud during the demo rather than implying persistence.

## If something fails

- **Console cannot reach the control-plane:** show `GET CP/healthz` in a terminal; if it fails, restart the process and re-run Setup. The console's "disconnected" state is a real state, not a mock.
- **Exchange returns 403 `audience_or_resource_mismatch`:** the agent used a different `resource`/`audience` than the grant; re-issue the grant for the right target rather than editing the token.
- **JEV shows `unavailable`:** no provider key or the provider timed out. That is the honest state; continue with the human escalation card. Do not retry with a fake verdict.
- **Revoke returns 400 `actor_id_mismatch`:** the body `actor_id` must equal the authenticated operator's actor id.
- **Session expired (90 s):** exchange again while the grant is active; after revoke the exchange must fail, which is the point of Beat 6.
- **A route returns `queue` or `throttle`:** those are real outcomes from the policy; read the `Retry-After` header and explain the ladder rather than forcing `allow`.
- **Anything else:** stop, show the last recorded decision from `GET CP/v1/decisions`, and say what the server said. Never narrate a success the server did not record.
