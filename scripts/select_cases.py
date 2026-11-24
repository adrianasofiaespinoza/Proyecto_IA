#!/usr/bin/env python3
"""
select_cases.py  --  eligibility filter and seeded random selection of cases.

--eligibility scan-ok (official run): a case is eligible when its scan status is OK
and meta.json lists at least one new_code_files entry (needed to build the prompt).
The oracle controls are not consulted.

--eligibility controls (preliminary run, default): a case is eligible when:
  1. its scan status is OK, and
  2. the three oracle controls of validate_oracle.py give the expected result:
       reference_fix : complete, A=1 F=1 S=1 (V=1)
       noop          : complete, A=1 F=1 S=0
       corrupt       : complete, A=0
Up to --n eligible cases are drawn with random.Random(--seed).sample over the
sorted eligible list; if there are fewer, all of them are used.

Every excluded OK case is listed with each control it failed and the reason:
the observed values, the test outcome and the first failing test message taken
from that control's eval.json. An optional --notes JSON ({"<id>": "text"}) adds a
manually verified diagnosis.

Outputs (in --out): selected_ids.txt, eligible_ids.txt, exclusions.csv,
exclusions_by_control.csv, selection.json
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import random
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

HERE = Path(__file__).resolve().parent.parent
EXPECTED = {
    "reference_fix": {"A": 1, "F": 1, "S": 1, "V": 1},
    "noop": {"A": 1, "F": 1, "S": 0, "V": 0},
    "corrupt": {"A": 0, "F": 0, "S": 0, "V": 0},
}
NOT_BUILDABLE = "not_buildable (no new_code_files)"


def sha256(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def read_tsv(p: Path) -> List[Dict[str, str]]:
    with open(p, newline="", encoding="utf-8") as f:
        return [r for r in csv.DictReader(f, delimiter="\t") if (r.get("cve_id") or "").strip()]


def first_failure(v: dict) -> Optional[str]:
    for step in ("exploit", "functional"):
        cases = ((v.get(step) or {}).get("junit") or {}).get("failed_cases") or []
        if cases:
            c = cases[0]
            return f"{step} test {c.get('name')}: {c.get('message')}"
    return None


def check_control(control_runs: Path, control: str, cid: str) -> Optional[str]:
    """None if the control gives the expected result, otherwise the reason."""
    ev = control_runs / f"oracle_{control}" / cid / "eval.json"
    if not ev.exists():
        return f"{control}: no evaluation (control not built or not run)"
    v = json.loads(ev.read_text(encoding="utf-8"))
    exp = EXPECTED[control]
    obs = {k: v.get(k) for k in exp}
    if v.get("status") == "complete" and obs == exp:
        return None
    if v.get("status") != "complete":
        return f"{control}: incomplete ({v.get('incomplete_reason')})"
    diff = " ".join(f"{k}={obs[k]}" for k in exp if obs[k] != exp[k])
    parts = [f"{control} {diff} (expected {' '.join(f'{k}={exp[k]}' for k in exp)})"]
    outcomes = [f"{s}={(v.get(s) or {}).get('outcome')}" for s in ("functional", "exploit")
                if v.get(s)]
    if outcomes:
        parts.append(", ".join(outcomes))
    ff = first_failure(v)
    if ff:
        parts.append(ff)
    return "; ".join(parts)


def main():
    ap = argparse.ArgumentParser(description="Eligibility filter + seeded selection of cases.")
    ap.add_argument("--scan-report", type=Path, required=True)
    ap.add_argument("--control-runs", type=Path, default=HERE / "results/oracle_validation/runs")
    ap.add_argument("--notes", type=Path, default=None)
    ap.add_argument("--workspaces", type=Path, default=HERE / "workspaces")
    ap.add_argument("--eligibility", choices=["controls", "scan-ok"], default="controls",
                    help="controls: scan OK + the three oracle controls (preliminary run); "
                         "scan-ok: scan OK only, controls not consulted (official run). "
                         "Cases without new_code_files are excluded in both modes.")
    ap.add_argument("--seed", type=int, required=True)
    ap.add_argument("--n", type=int, default=30)
    ap.add_argument("--out", type=Path, default=HERE / "results/selection")
    args = ap.parse_args()

    rows = read_tsv(args.scan_report)
    status_counts: Dict[str, int] = {}
    for r in rows:
        status_counts[r["status"]] = status_counts.get(r["status"], 0) + 1
    ok_ids = sorted(r["cve_id"] for r in rows if r["status"] == "OK")
    notes = json.loads(args.notes.read_text(encoding="utf-8")) if args.notes else {}

    eligible: List[str] = []
    exclusions: List[Dict] = []
    for cid in ok_ids:
        meta_p = args.workspaces / cid / "meta.json"
        meta = json.loads(meta_p.read_text(encoding="utf-8")) if meta_p.exists() else {}
        if not meta.get("new_code_files"):
            # No code file: the repair prompt (built from new_code_files) would
            # contain no source file at all, and no reference fix can be built.
            exclusions.append({"cve_id": cid, "failed_controls": NOT_BUILDABLE,
                               "reason": "meta.json lists no new_code_files: the repair prompt "
                                         "would contain no source file",
                               "manual_note": notes.get(cid, "")})
            continue
        if args.eligibility == "scan-ok":
            # Official study: eligibility is the scan status alone; the oracle
            # controls are not consulted.
            eligible.append(cid)
            continue
        failed = {c: check_control(args.control_runs, c, cid) for c in EXPECTED}
        failed = {c: r for c, r in failed.items() if r}
        if not failed:
            eligible.append(cid)
            continue
        exclusions.append({"cve_id": cid, "failed_controls": ",".join(failed),
                           "reason": " | ".join(failed.values()),
                           "manual_note": notes.get(cid, "")})

    rng = random.Random(args.seed)
    selected = sorted(eligible if len(eligible) <= args.n else rng.sample(eligible, args.n))

    checked = [NOT_BUILDABLE] if args.eligibility == "scan-ok" else list(EXPECTED) + [NOT_BUILDABLE]
    by_control = [{"control": c,
                   "ok_cases_failing": sum(1 for e in exclusions
                                           if c in e["failed_controls"].split(","))}
                  for c in checked]
    by_control.append({"control": "any (excluded cases)", "ok_cases_failing": len(exclusions)})

    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "selected_ids.txt").write_text("".join(f"{c}\n" for c in selected))
    (args.out / "eligible_ids.txt").write_text("".join(f"{c}\n" for c in eligible))
    with open(args.out / "exclusions.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["cve_id", "failed_controls", "reason", "manual_note"])
        w.writeheader()
        w.writerows(exclusions)
    with open(args.out / "exclusions_by_control.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["control", "ok_cases_failing"])
        w.writeheader()
        w.writerows(by_control)
    summary = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "seed": args.seed, "n_max": args.n, "eligibility": args.eligibility,
        "method": "random.Random(seed).sample(sorted(eligible), n) if len(eligible) > n else all",
        "scan_report": str(args.scan_report), "scan_report_sha256": sha256(args.scan_report),
        "scan_status_counts": status_counts,
        "n_ok": len(ok_ids), "n_eligible": len(eligible), "n_excluded": len(exclusions),
        "n_selected": len(selected),
        "exclusions_by_control": by_control,
        "ok_ids": ok_ids, "eligible": eligible, "selected": selected, "excluded": exclusions,
    }
    (args.out / "selection.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"scan statuses: {status_counts}")
    print(f"OK={len(ok_ids)} eligible={len(eligible)} excluded={len(exclusions)} "
          f"selected={len(selected)} (seed={args.seed})")
    for e in exclusions:
        print(f"  EXCLUDED {e['cve_id']}: {e['reason']}")


if __name__ == "__main__":
    main()
