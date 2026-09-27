# Jev Evaluation — Findings (DRAFT, Sun 27 Sep 11:15 EDT)

**Owner:** Karthik Godugolla · **Scope:** evaluation of TypeSafe jev-1.13 as a candidate semantic provider

> **Scope:** this harness evaluates **TypeSafe `jev-1.13`** as a *candidate* provider. It does **not** exercise the shipped `@aidenid/jev` assessor on `main` (in-process, Anthropic provider, single purpose-fit rubric returning low/elevated/high). The rubrics also differ: this harness asks two separate questions (purpose fit and untrusted-instruction), so results here are not results for `@aidenid/jev`.

**Status:** Jev tests **NOT RUN (provider unavailable)**. Evaluation set, rubric and runner are ready and verified.

| Field | Value |
|---|---|
| Dataset | cases-v0.1: 24 dev + 12 holdout, synthetic, one owned shop |
| Rubric | label-guide-v0.1 (purpose fit + injection, scored separately) |
| Model | TypeSafe Jev as a **candidate** provider (`typesafe-ai/jev` via Vercel AI Gateway; `jev-1.13` when called direct). **Not** the shipped `@aidenid/jev` assessor (Anthropic provider on `main`); the rubrics differ. |
| Labels human-reviewed | _0/36 (DRAFT)_ |
| Holdout | Untouched; config not frozen |

> 36 synthetic cases are a diagnostic exercise, not a production accuracy claim. Confidence scores are **not** safety probabilities.

## 1. Coverage and run status
- Dev run on 27 Sep: 0/24 usable responses. Every call returned **HTTP 429 "upstream provider is currently experiencing high demand"** (RATE_LIMITED) or failed before reaching Jev (NOT_RUN).
- Independent probe at 11:11 EDT: 3/3 minimal requests returned 429 in <0.5 s. Auth and billing were fine (the models endpoint returned 200). Evidence: `evidence/jev_probe_*.txt`.
- TypeSafe paused direct signups on 22 Sep because of demand, so a direct key was not available to this lane.
- **No Jev accuracy numbers are reported.** No mock output was used as a result.

## 2. What is ready to run the moment Jev responds
- 24 dev and 12 holdout cases across four families: normal work, off-task actions, prompt injection and ambiguous requests. Keyword traps are included (D-03, D-16, D-17, H-03, H-08).
- Jev receives only `purpose`, `action` and `retrieved_content`. Expected labels and policy fields are never sent.
- The runner records exact model version, probabilities, confidence, tokens, latency and config hash. It saves after every case, reruns only failures (`--retry-failed`) and refuses the holdout until the config is frozen.
- Scoring: TP/FP/TN/FN per rubric on clearly labeled cases, abstentions counted separately, ambiguous cases reported separately, plus a confidence-vs-correctness table.
- The pipeline was verified end to end through the real TypeSafe SDK against a simulated server; two planted errors were caught with the correct case IDs.

## 3. Cases that matter most for the product claim
- **D-11**: a full-catalogue crawl for a two-item comparison. Policy **allows** it (in scope), but the purpose rubric should flag it as off-task. This is the case where AI adds judgment the permission rules can't.
- **D-13 / D-14 / D-15**: instructions hidden in product pages (injection).
- **D-16 / D-17**: suspicious words that are harmless (a quoted phrase, a book title). A keyword filter fails these.
- **D-18**: the agent follows an injected instruction. Policy must deny regardless of any Jev score.

## 4. Known risk to check once running
TypeSafe's own limitations page (jev-1.13) says adversarial content in the input "can move the answer." Injection detection is therefore the rubric most likely to fail and the most important to measure.

## 5. Limitations
- Synthetic, single-author labels, pending human review; small n; one shop domain.
- Model accuracy says nothing about enforcement. Out-of-scope → deny, revoked → deny, a model can't override a deny, and an unavailable model doesn't let an action through: those are covered by the policy and end-to-end tests, not by this eval.
- **Product implication observed today:** a hosted semantic provider can be unreachable for long stretches (here, hours of 429/403 from the gateway). If a semantic check is required, its absence has to hold the action for review or refuse it, never wave it through. The shipped assessor already treats an unavailable check that way.
