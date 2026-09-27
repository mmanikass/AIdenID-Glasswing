"""Run Jev over cases.csv and write results.csv.

  python run_eval.py                 # dev split, real adapter (NOT_RUN if unavailable)
  python run_eval.py --mock          # plumbing check; rows tagged MOCK, never scored
  python run_eval.py --split holdout # refuses unless config.json has "frozen": true
  python run_eval.py --retry-failed  # keep OK rows, rerun only NOT_RUN/ERROR/RATE_LIMITED/TIMEOUT
"""
import argparse, csv, hashlib, json, os, signal, subprocess, time
from datetime import datetime, timezone

import jev_adapter

HERE = os.path.dirname(os.path.abspath(__file__))
PURPOSE = {"consistent", "deviation", "insufficient_evidence"}
INJECT = {"injection", "none", "insufficient_evidence"}
COLS = ["case_id", "split", "status", "purpose_pred", "purpose_conf", "injection_pred",
        "injection_conf", "purpose_probs", "injection_probs", "latency_ms", "input_tokens", "output_tokens",
        "model_id", "rubric_version", "dataset_version", "build_sha", "config_sha", "run_at", "error"]


class Timeout(Exception):
    pass


def git_sha():
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=HERE,
                                       stderr=subprocess.DEVNULL).decode().strip()
    except Exception:
        return None


def valid(out):
    try:
        return (out["purpose"]["label"] in PURPOSE and out["injection"]["label"] in INJECT)
    except Exception:
        return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", default="dev", choices=["dev", "holdout"])
    ap.add_argument("--mock", action="store_true")
    ap.add_argument("--out", default=os.path.join(HERE, "results.csv"))
    ap.add_argument("--retry-failed", action="store_true")
    ap.add_argument("--ids", default="", help="comma-separated case IDs to run, e.g. D-01,D-11")
    ap.add_argument("--sleep", type=float, default=1.0, help="seconds between calls (be gentle)")
    a = ap.parse_args()

    cfg_path = os.path.join(HERE, "config.json")
    cfg_bytes = open(cfg_path, "rb").read()
    cfg = json.loads(cfg_bytes)
    cfg_sha = hashlib.sha256(cfg_bytes).hexdigest()[:12]
    if a.split == "holdout" and not cfg.get("frozen"):
        raise SystemExit("Refusing holdout run: set \"frozen\": true in config.json first "
                         "(rubric, model settings and thresholds must be final).")

    cases = [r for r in csv.DictReader(open(os.path.join(HERE, "cases.csv")))
             if r["split"] == a.split]
    if a.ids:
        want = {x.strip() for x in a.ids.split(",") if x.strip()}
        cases = [c for c in cases if c["case_id"] in want]
    fn = jev_adapter.mock_assess if a.mock else jev_adapter.assess
    build = git_sha() or cfg.get("build_sha", "UNKNOWN")
    model = "MOCK" if a.mock else jev_adapter.MODEL_ID
    if cfg.get("rubric_version") != jev_adapter.RUBRIC_VERSION:
        raise SystemExit(f"config rubric_version {cfg.get('rubric_version')} != adapter "
                         f"{jev_adapter.RUBRIC_VERSION}; bump both together.")

    def on_alarm(*_):
        raise Timeout()
    signal.signal(signal.SIGALRM, on_alarm)

    # keep rows from the other split (and, with --retry-failed, OK rows of this split)
    keep = []
    if os.path.exists(a.out):
        prev = list(csv.DictReader(open(a.out)))
        keep = [r for r in prev if r["split"] != a.split]
        if a.ids and not a.retry_failed:
            ids_run = {x.strip() for x in a.ids.split(",")}
            keep += [r for r in prev if r["split"] == a.split and r["case_id"] not in ids_run]
        if a.retry_failed:
            done = [r for r in prev if r["split"] == a.split and r["status"] == "OK"
                    and r["config_sha"] == cfg_sha]
            keep += done
            done_ids = {r["case_id"] for r in done}
            cases = [c for c in cases if c["case_id"] not in done_ids]
            print(f"--retry-failed: keeping {len(done)} OK rows, running {len(cases)}")

    rows = []

    def save():  # written after every case, so Ctrl+C never loses finished work
        with open(a.out, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=COLS)
            w.writeheader()
            done_ids = {r["case_id"] for r in rows}
            pending = [dict(dict.fromkeys(COLS, ""), case_id=c["case_id"], split=a.split, status="NOT_RUN",
                            error="not reached yet") for c in cases if c["case_id"] not in done_ids]
            w.writerows(sorted(keep + rows + pending, key=lambda r: (r["split"], r["case_id"])))

    for i, c in enumerate(cases):
        if i and a.sleep:
            time.sleep(a.sleep)
        row = dict.fromkeys(COLS, "")
        row.update(case_id=c["case_id"], split=a.split, model_id=model,
                   rubric_version=cfg["rubric_version"], dataset_version=cfg["dataset_version"],
                   build_sha=build, config_sha=cfg_sha,
                   run_at=datetime.now(timezone.utc).isoformat(timespec="seconds"))
        t0 = time.perf_counter()
        try:
            signal.alarm(int(cfg.get("timeout_s", 30)))
            out = fn(c)
            signal.alarm(0)
            row["latency_ms"] = round((time.perf_counter() - t0) * 1000)
            if not valid(out):
                row.update(status="SCHEMA_FAIL", error=str(out)[:200])
            else:
                row.update(status="MOCK" if a.mock else "OK",
                           purpose_pred=out["purpose"]["label"],
                           purpose_conf=out["purpose"].get("confidence"),
                           injection_pred=out["injection"]["label"],
                           injection_conf=out["injection"].get("confidence"),
                           purpose_probs=json.dumps(out["purpose"].get("probabilities") or {}),
                           injection_probs=json.dumps(out["injection"].get("probabilities") or {}),
                           model_id=out.get("model") or model,
                           input_tokens=out.get("input_tokens") or "",
                           output_tokens=out.get("output_tokens") or "")
        except NotImplementedError as e:
            row.update(status="NOT_RUN", error=str(e))
        except jev_adapter.RateLimited as e:
            row.update(status="RATE_LIMITED", error=str(e))
        except (Timeout, TimeoutError):
            row.update(status="TIMEOUT", error=f">{cfg.get('timeout_s')}s")
        except Exception as e:
            row.update(status="ERROR", error=f"{type(e).__name__}: {e}"[:200])
        finally:
            signal.alarm(0)
        rows.append(row)
        save()
        print(f"  {row['case_id']}: {row['status']} {row['purpose_pred']} {row['injection_pred']}", flush=True)
    save()
    counts = {}
    for r in rows:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    print(f"{a.split}: {len(rows)} cases -> {counts}  (config {cfg_sha}, build {build})")


if __name__ == "__main__":
    main()
