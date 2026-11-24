#!/usr/bin/env python3
"""
run_study.py  --  generation phase of the full study (API calls only, no tests).

For every repetition, case and model it calls run_agent.run_builtin, i.e. the same
code path as `run_agent.py`, with the study settings (prompt v2, reasoning effort
high, 64000 output tokens). Frozen attempts are skipped, so the script can be
resumed after an interruption without repeating any attempt.

It stops the whole run when:
  - a non-retryable API error occurs (bad key or model, HTTP 402 insufficient
    balance, ...): run_agent returns 2 and nothing is frozen for that attempt;
  - a response was received but not frozen (run_agent returns 6);
  - MAX_CONSECUTIVE_EXHAUSTED attempts in a row of the same model end with no
    response after all retries (repeated API errors).

usage: run_study.py --ids-file results/selection/selected_ids.txt --runs runs/full
"""
from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_agent as ra  # noqa: E402

MODELS = [("gpt", "gpt-6-luna"), ("deepseek", "deepseek-flash")]
MAX_CONSECUTIVE_EXHAUSTED = 2


def log(msg: str):
    print(f"{datetime.now(timezone.utc).isoformat(timespec='seconds')} {msg}", flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ids-file", type=Path, required=True)
    ap.add_argument("--runs", type=Path, required=True)
    ap.add_argument("--workspaces", type=Path, default=ra.WORKSPACES)
    ap.add_argument("--repetitions", type=int, default=2)
    args = ap.parse_args()

    for agent, _ in MODELS:
        if not os.environ.get(ra.PROVIDERS[agent]["key_env"]):
            sys.exit(f"{ra.PROVIDERS[agent]['key_env']} is not set; nothing was called")

    ids = [l.strip() for l in args.ids_file.read_text().splitlines() if l.strip()]
    total = len(ids) * len(MODELS) * args.repetitions
    log(f"start: {len(ids)} cases x {len(MODELS)} models x {args.repetitions} reps = {total}")
    exhausted_streak = {agent: 0 for agent, _ in MODELS}
    counts: dict = {}
    k = 0
    for rep in range(1, args.repetitions + 1):
        for vid in ids:
            for agent, model in MODELS:
                k += 1
                out_dir = args.runs / agent / vid / f"rep{rep}"
                if (out_dir / "frozen.json").exists():
                    counts["already_frozen"] = counts.get("already_frozen", 0) + 1
                    continue
                log(f"[{k}/{total}] {agent} {vid} rep{rep}")
                rc = ra.run_builtin(agent, model, vid, rep, args.workspaces / vid, out_dir,
                                    "v2", None, ra.DEFAULT_MAX_OUTPUT_TOKENS,
                                    ra.DEFAULT_REASONING_EFFORT)
                label = {0: "ok", 4: "no_usable_answer", 5: "api_error_exhausted"}.get(rc, f"rc_{rc}")
                counts[f"{agent}:{label}"] = counts.get(f"{agent}:{label}", 0) + 1
                if rc in (2, 6):
                    log(f"STOP: {agent} {vid} rep{rep} returned {rc} "
                        f"({'configuration/balance error' if rc == 2 else 'unfrozen response'}). "
                        f"counts={counts}")
                    sys.exit(rc)
                exhausted_streak[agent] = exhausted_streak[agent] + 1 if rc == 5 else 0
                if exhausted_streak[agent] >= MAX_CONSECUTIVE_EXHAUSTED:
                    log(f"STOP: {MAX_CONSECUTIVE_EXHAUSTED} consecutive attempts of {agent} "
                        f"without an API response. counts={counts}")
                    sys.exit(5)
    log(f"done: counts={counts}")


if __name__ == "__main__":
    main()
