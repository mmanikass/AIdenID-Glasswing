# AIdenID — Onboarding friction list

Author: Manika (customer & product lane), drafted with a coding assistant · Date: 27 Sep 2026
Source evidence: exact console strings from `apps/dashboard/src/glasswing/model.ts` and `GlasswingConsole.tsx`, and click steps from `docs/runbook.md`, on `main` at `5c4f3f4`.
**Limitation:** reviewed from the runbook and source text, not from a live run by me, so there are no screenshots yet. Joey: please confirm each on a live `pnpm dev`.

## 1. Clicking "Approve" shows "Denied" after a revoke (partly fixed in PR #13)
- **Exact step:** Runbook Beat 6: revoke the `reports:bulk` grant, then click **Approve** on the pending review.
- **What the build shows now:** the review status pill still reads **Denied**. Since PR #13 the **What happened** timeline explains it: `Review rev_…: approval refused by the chain-authority gate; nothing was released and a deny decision was recorded`.
- **Why it still confuses:** the pill next to the button the customer just clicked says Denied. "Chain-authority gate" is an engineering term, and the timeline sits further down the page.
- **Suggested wording:** status pill "Blocked: access revoked". Timeline: "Approval blocked: access was revoked before the job ran. Nothing was released."
- **Expected understanding:** "Revoking beats a late approval. That's the point."
- **Owner:** Carther/Driver for the copy change; Joey to confirm on a live run.

## 2. "Refused before signing (permission_scope_mismatch)"
- **Exact step:** Beat 4, run **Export customers** with the `catalog:read` grant selected.
- **Why it confuses:** "signing" and "permission_scope_mismatch" are engineering terms. A customer needs to hear that the pass doesn't cover this job and nothing was sent.
- **Suggested wording:** headline "Blocked: this work pass doesn't cover customer export". Detail: "Nothing was sent to the site (permission_scope_mismatch)."
- **Expected understanding:** "The agent can only do the job it was given."

## 3. One permission per grant, and a new grant for every beat
- **Exact step:** Beats 3–6 need four separate grants (`catalog:read`, `customers:export`, `reports:bulk`, optionally `items:reserve`). Two permissions give the error **unsupported_permission_scope**, and running with the wrong grant selected gives **grant_forbidden** or **permission_scope_mismatch**.
- **Why it confuses:** "grant", "mint", "chain" are unfamiliar words, and the demo depends on picking the right grant row before every run.
- **Suggested wording:** rename the panel label "Grants" to "Work passes (one job each)". Under the Run button, show "Using pass: catalog:read · expires in 9 min". Error: "Pick one job per work pass."
- **Expected understanding:** "A pass is for one job, like a visitor badge for one room."

## 4. Reloading the console mid-demo loses the grants
- **Exact step:** reload `/glasswing` at any point during the demo. Agents and reviews come back, but the grant list and the timeline are cleared (runbook "Reset", added in PR #13).
- **Why it confuses:** a customer (or a nervous presenter) sees their work passes disappear and thinks access was revoked or lost.
- **Suggested wording:** if a reload happens, show "Work passes from before this page reload aren't listed. Issue a new one to continue." For the live demo: **do not reload**.
- **Expected understanding:** "The page forgot the list; nothing on the server changed."
- **Owner:** Joey (demo reliability).

## Smaller wording notes
- "Mint agent" → "Create agent identity" (the heading "1 · Mint" could stay as a step label).
- "Jev unavailable (no_provider); the check did not run and nothing was inferred" is honest, but add "Sent to a person instead" so the next step is clear.
- "Session refused" after a revoke → "Refused: this work pass was revoked or expired."

## Technical issues to route to Joey (not wording)
- None observed by me. I haven't run the build live yet.

## Unresolved questions
- Joey: do items 1–4 match what a live `pnpm dev` run shows today?
- Carther: are any of the suggested labels acceptable to change before the 2:00 PM code freeze, or should they go in as post-event notes?
