# AIdenID — Customer brief

Author: Manika Sakulsureeyadej (customer & product), drafted with a coding assistant · Date: 27 Sep 2026
Build checked against: `mrrCarter/AIdenID-Glasswing` `main` at `5c4f3f4` (`README.md`, `docs/runbook.md`)

**Labels:** **[Observed]** = seen in the current build or repo. **[Hypothesis]** = our assumption, not yet tested with a customer.
No customer conversations are recorded here, so every customer and payer statement is a hypothesis.

## In one sentence
AIdenID lets a website owner give an AI agent permission for one specific job, checks that permission on every request, lets the owner revoke it, and keeps a signed record of each decision.

## Initial customer
| Question | Answer | Label |
|---|---|---|
| Who has the problem? | The security or platform owner of a website or API that AI agents call | [Hypothesis]; matches the README |
| What should the agent be able to do? | Read the catalogue, reserve an item | [Observed]: `GET /catalog` and `POST /items/:id/reserve` are allowed with the matching permission |
| What must it never do? | Export private customer data | [Observed]: `/customers/export` is denied for every caller |
| What goes wrong today? | Sites can block all automation, allow all of it, or hand-write rules per integration, and none of these leave evidence for an auditor | [Hypothesis]; from the README |
| Who uses it day to day? | A security or platform engineer running the console | [Hypothesis] |
| Who installs it? | A backend engineer who adds the verifier middleware in front of the site's routes | [Hypothesis]; [Observed] that the demo does this on a Fastify site |
| Who pays? | The site owner, likely through the security or platform budget | [Hypothesis] |

## What the build shows today (local runs, not hosted CI)
- **Allowed:** an agent with `catalog:read` gets the catalogue. The decision is recorded with a signed receipt before the page handler runs. [Observed: runbook Beat 3]
- **Denied:** customer export is refused twice over. The agent's permission doesn't cover it, and the site's own rule denies it for everyone. No data is returned. [Observed: Beat 4]
- **Sent to a person:** an ambiguous bulk report waits in a review queue. The AI check (Jev) can add a review but can never unlock something the rules deny. With no AI key it reports "unavailable" and still sends the report to a person. [Observed: Beat 5]
- **Revoked:** after revoking, a pending approval is refused and new requests are refused. [Observed: Beat 6]
- **Not shown or not proven:** throttle, sandbox and priced outcomes (they exist in the policy engine but are not in the demo), persistence across restarts, hosted CI, production deployment, any paying customer. [Observed: README "What's real and what's mocked"]

## How it could make money (proposal, not an offer)
The README's hypothesis: charge per cleared (non-denied) action, or a flat plan per protected site. The kernel already meters non-deny decisions [Observed]; willingness to pay is untested [Hypothesis].

## What we still need to learn
- Which industry feels this first: commerce, fintech or SaaS APIs?
- How much agent traffic does a typical site see today, and how much of it is wanted?
- What has an unintended agent action cost them: data exposure, fraud, support time or compliance?
- Does the security team or the platform team own the budget?
- What result would a first trial need to show before they would pay?
