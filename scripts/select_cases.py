#!/usr/bin/env python3
"""
select_cases.py  --  eligibility filter and seeded random selection of cases.

A case is eligible when its scan status is OK and its meta.json lists at least
one new_code_files entry; without one, the repair prompt (built from
new_code_files) would contain no source file. Up to --n eligible cases are drawn
with random.Random(--seed).sample over the sorted eligible list; if there are
fewer, all of them are used.

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
from typing import Dict, List

HERE = Path(__file__).resolve().parent.parent
ELIGIBILITY = "scan-ok"
NOT_BUILDABLE = "not_buildable (no new_code_files)"


def sha256(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def read_tsv(p: Path) -> List[Dict[str, str]]:
    with open(p, newline="", encoding="utf-8") as f:
        return [r for r in csv.DictReader(f, delimiter="\t") if (r.get("cve_id") or "").strip()]


def main():
    ap = argparse.ArgumentParser(description="Eligibility filter + seeded selection of cases.")
    ap.add_argument("--scan-report", type=Path, required=True)
    ap.add_argument("--workspaces", type=Path, default=HERE / "workspaces")
    ap.add_argument("--seed", type=int, required=True)
    ap.add_argument("--n", type=int, default=30)
    ap.add_argument("--out", type=Path, default=HERE / "results/selection_v2")
    args = ap.parse_args()

    rows = read_tsv(args.scan_report)
    status_counts: Dict[str, int] = {}
    for r in rows:
        status_counts[r["status"]] = status_counts.get(r["status"], 0) + 1
    ok_ids = sorted(r["cve_id"] for r in rows if r["status"] == "OK")

    eligible: List[str] = []
    exclusions: List[Dict] = []
    for cid in ok_ids:
        meta_p = args.workspaces / cid / "meta.json"
        meta = json.loads(meta_p.read_text(encoding="utf-8")) if meta_p.exists() else {}
        if not meta.get("new_code_files"):
            exclusions.append({"cve_id": cid, "failed_controls": NOT_BUILDABLE,
                               "reason": "meta.json lists no new_code_files: the repair prompt "
                                         "would contain no source file",
                               "manual_note": ""})
            continue
        eligible.append(cid)

    rng = random.Random(args.seed)
    selected = sorted(eligible if len(eligible) <= args.n else rng.sample(eligible, args.n))

    by_control = [{"control": NOT_BUILDABLE, "ok_cases_failing": len(exclusions)},
                  {"control": "any (excluded cases)", "ok_cases_failing": len(exclusions)}]

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
        "seed": args.seed, "n_max": args.n, "eligibility": ELIGIBILITY,
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
