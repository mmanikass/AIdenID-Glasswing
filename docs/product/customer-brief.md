# AIdenID — One-page customer brief

Author: Manika (customer & product lane), drafted with a coding assistant · Date: 27 Sep 2026
Build checked against: `mrrCarter/AIdenID-Glasswing` `main` at `5c4f3f4` (README, `docs/runbook.md`)

**Evidence labels:** **[Observed]** = seen in the current build or repo. **[Reported]** = someone told us (source named). **[Hypothesis]** = our assumption, not yet tested.
No customer conversations are recorded in this brief yet. Every customer and payer statement is a hypothesis until Carther confirms which ones come from real conversations.

## In one sentence
AIdenID gives an AI agent a temporary work pass for one job on your website, enforces its limits on every request, lets you revoke the pass, and keeps a signed record of what happened.

## Initial customer
| Field | Answer | Label |
|---|---|---|
| Customer type | Security or platform team that runs a website or API that AI agents already call (e.g. an online store with a public catalogue and private customer data) | [Hypothesis] — matches the README's stated customer |
| Useful agent job | "Compare catalogue items" / "reserve an item" for a shopper's agent | [Observed] — `GET /catalog` and `POST /items/:id/reserve` are allowed with the matching work pass |
| Costly failure | The same agent, or a prompt-injected one, pulls private customer data (`/customers/export`) or runs a costly bulk job, and nobody can prove afterwards what it was allowed to do | [Hypothesis] for cost; [Observed] that the build refuses export and queues the bulk report |
| Current workaround | Block all bots (lose useful agent traffic), allow all of them (accept the risk), or hand-write rules per integration with no evidence trail | [Hypothesis] — from the README; needs a real conversation |
| User (day to day) | Security / platform engineer operating the console | [Hypothesis] |
| Installer | Backend engineer who adds the verifier middleware in front of the site's routes | [Hypothesis]; [Observed] that the demo installs it on a Fastify site |
| Budget owner | Head of security, or head of platform/engineering for the site | [Hypothesis] |

## Pain and consequence (to test)
- How often do agents hit the site today, and what share is wanted? **[Hypothesis — unknown]**
- What did the last unintended agent action cost (data exposure, fraud, support time, compliance)? **[Hypothesis — unknown]**
- Can they show an auditor what an agent was allowed to do? We believe usually not. **[Hypothesis]**

## What the build proves today (observed, local run evidence only)
- **Allow:** an agent with a `catalog:read` pass gets the catalogue; the decision is recorded with a signed receipt before the handler runs. [Observed — runbook Beat 3]
- **Deny:** the agent cannot export customers. Two walls: the pass does not cover it (nothing is sent), and even with a pass the site policy denies it for everyone. [Observed — Beat 4]
- **Queue (human review):** an ambiguous bulk report is held for a person; the AI check (Jev) can only add a review, never unlock a deny. With no AI key it says "unavailable" and still queues. [Observed — Beat 5]
- **Revoke:** after revoking, a pending approval is refused and new requests are refused. [Observed — Beat 6]
- **Not proven:** persistence across restarts (in-memory only), hosted CI, production deployment, any paying customer. [Observed — README "What's real and what's mocked"]
- Throttle, Sandbox and Priced outcomes exist in the policy engine but are **not shown** in the live demo. [Observed — runbook covers allow, deny, queue only]

## Adoption and payer
- Who installs a server check? A backend engineer adds middleware and a policy file. [Hypothesis]
- Who pays? The site owner. [Hypothesis]
- **Proposed pricing (proposal, not an offer):** per cleared (non-denied) action, or a flat plan per protected site. The kernel already meters non-deny decisions. [Observed that metering exists; pricing is a Hypothesis]

## Proposed pilot (to discuss, not promise — Carther approves terms and outreach)
- One staging or synthetic workflow on the customer's site (e.g. catalogue read allowed, customer export denied).
- A named customer owner and a named installer.
- A fixed trial period (proposal: 2–4 weeks).
- Written success measures agreed up front, for example: zero forbidden-route data released; revocation stops the next request in every test; the owner can answer "what did this agent do and why was it allowed" from the records alone.
- Price or the paid-conversion decision agreed **before** the trial starts.

## Evidence and unknowns
- Evidence we have: the working local build and its tests (see `docs/aidenid-build/evidence/PR-00-navigator.md`).
- Unknowns: which industry feels this first (commerce, fintech, SaaS APIs); whether security or platform owns the budget; willingness to pay; how many agents hit a typical site today.
- **Open question for Carther:** can the discovery questions and 30-second explanation (adapted from my lane packet) go in the public repo?
- **Open question for Carther:** which of the customer statements above come from real conversations, and with whom (role only, no names in the public repo)?

## Five discovery questions
1. Tell me about the last time an automated agent used your site or tools in a way you did not intend.
2. Which agent activity do you want to allow, and what must it never access or change?
3. What do you use today, and where does that process fail or consume time?
4. Who would install a control here, and who would approve spending on it?
5. What would we need to prove in a small pilot for you to continue or pay?
