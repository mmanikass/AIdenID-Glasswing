# AIdenID — Demo narrative

Author: Manika (customer & product lane), drafted with a coding assistant · Date: 27 Sep 2026
Source evidence: `docs/runbook.md` and `README.md` on `main` at `5c4f3f4`. Every beat below matches a runbook beat. If a beat fails live, say what the server recorded, never what we expected.

## 30-second explanation (matches the current build)
"AIdenID lets a business give an AI agent a specific job and enforce the limits. In our demo, an agent can read the catalogue, but it cannot export private customer data, even when it asks. If a request is ambiguous, like a bulk report, it waits for a person; our AI check can flag it but can never unlock something the rules forbid. The owner can revoke the agent's pass, and the next request is refused. Every decision has a signed receipt. We're validating which teams need this enough to install and pay for it."

## Before we start (say this up front)
- We built on AIdenID's pre-existing clearance kernel; the first commit is marked "prior work". This weekend we built the protected demo shop, the agent client, the AI review step (Jev), the revocation gate and the operations console.
- The shop is a stand-in. The state is in memory and resets on restart.
- **Presenter note:** do not reload the console during the demo. It clears the grant list and timeline. If it happens, issue a new grant and continue.

## Walkthrough (about 3 minutes)
| Beat | What we click | What we say | Why it matters to the customer |
|---|---|---|---|
| 1 · Mint | Agents → **Mint agent** | "We create an identity for the agent: a key the site can check on every request." | You know which agent is calling, not just "a bot". |
| 2 · Work pass | Grants → scope `catalog:read`, 10 min → **Issue grant** | "We give it a work pass: one job, one route, ten minutes." | Access is scoped to the job and expires on its own. |
| 3 · Help | Run a task → **Read catalog** → **Run signed request** → *Allowed and executed* | "The useful job works. The site checked the pass and recorded the decision before answering." | Useful agent traffic is not blocked. |
| 4 · Overstep | **Export customers** → *Refused before signing*. Then issue a `customers:export` pass and run it again → *Denied by policy* | "Asking for customer data outside the job fails. Even with a pass for it, the site's own rule says no to everyone. No data left the server." | Private data stays private even if an agent is tricked or over-asks. |
| 5 · Ask a human | `reports:bulk` pass → **Bulk report** with a stated purpose → *Queued for human review* | "This one is ambiguous. Our AI check reads the stated purpose against the job. It can send it to a person, but it can never unlock a forbidden action. Without an AI key it says 'unavailable' and still asks a person." | The costly action waits for a person. The AI helps, but the rules still decide. |
| 6 · Revoke | Run Bulk report again → **Revoke** the grant → **Approve** the pending review → *Denied*, and the timeline says the approval was refused and nothing was released; run again → *Session refused* | "The owner changes their mind. Even an approval clicked after the revoke can't release the job, and the agent can't get a new session." | Revoking really stops the work, which is what makes this worth paying for. |
| Explain | **What happened** timeline → **Decision stream and receipts** | "Here's the record: who, what pass, what was decided and why, with a signed receipt." | You can show an auditor exactly what happened. |

## Why the allowed task is allowed and the blocked one is blocked (for any teammate)
- **Allowed:** the agent holds a pass for `catalog:read` on `/catalog`, and the site policy allows verified agents with that permission.
- **Blocked:** `/customers/export` is outside the catalogue pass, and the site policy denies it for every caller, verified or not. No handler ran and no data was returned.

## Close: who pays and why
"The site owner's security or platform team. The proposed model is per cleared action or a flat price per protected site. That's a hypothesis: we have a working build, not a paying customer yet. The pilot we'd propose is one staging workflow with success measures agreed up front."

## Do not say
- "Customers are paying" / "we have pilots". We have none recorded.
- "Throttle / sandbox / priced" as live features. They exist in the engine but are not in this demo.
- "It persists" or "CI is green". State is in memory, and the test results are local runs.
- "The AI blocks attacks." The rules block; the AI only adds a review.

## Differences from the lane packet (for Carther)
- The packet's beat 4 is "pause an operation, revoke, resume". The build shows it as a **queued review that is refused after revoke**. The narrative above follows the build.
- The packet says "compare catalogue items"; the build's task is **Read catalog** (the console's default purpose text is "Compare prices of the three cheapest laptops…"). Wording kept close to the build.

## Unresolved questions
- Carther: are the 30-second explanation and the walkthrough approved for the public repo? They adapt wording from my lane packet.
- Carther: which customer statements in the brief come from real conversations?
- Joey: confirm every beat on a live run before noon rehearsal.
