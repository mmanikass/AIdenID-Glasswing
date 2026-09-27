# Karthik lane: Jev evaluation (PR-07)

| File | What |
|---|---|
| `cases.csv` | 36 cases (24 dev / 12 holdout). Policy, purpose and injection labels in separate columns. All rows DRAFT. |
| `label-guide.md` | Label definitions, traps, scoring rules, holdout rule |
| `config.json` | Model/rubric/thresholds. Set `"frozen": true` before the holdout run. |
| `jev_adapter.py` | Calls Jev (TypeSafe AI) with the two rubrics. `python jev_adapter.py` = 1-call smoke test |
| `run_eval.py` | Writes `results.csv`. Unavailable adapter → NOT_RUN. `--mock` rows are never scored. |
| `metrics.py` | Writes `metrics.md`: counts, FP/FN ids, abstentions, coverage, confidence table |
| `findings.md` | One-page report template |

## Jev setup (5 min)

```bash
pip install typesafe-sdk            # Python >= 3.10
# put your key in .env (see .env.example), or export TYPESAFE_API_KEY=...
# or OpenRouter:  export TYPESAFE_API_KEY=$OPENROUTER_API_KEY TYPESAFE_BASE_URL=https://openrouter.ai/api
# or whatever endpoint/key staff or Carther give you (sponsor compute)
python jev_adapter.py               # one real call; should print purpose + injection choices
```

Jev sees only `purpose`, `action` and `retrieved_content`. Policy fields and `notes` are never sent.

## Run

```bash
python run_eval.py              # dev
python metrics.py
# after reviewing labels + tuning on dev only:
#   set "frozen": true in config.json, then
python run_eval.py --split holdout && python metrics.py
```

**Current state:** adapter wired to Jev and tested against a fake server. 24/24 dev cases NOT_RUN until a key is set. Holdout is untouched.

**Senti handoff:**
`KARTHIK | PR-07 eval | build <SHA> | 0/24 dev run, holdout unused | 36 draft cases + runner ready | karthik-eval/ | need: Jev API key/endpoint (or confirm PR-07 uses the same jev-1.13 call)`
