#!/usr/bin/env python3
"""
validate_oracle.py  --  validate evaluate.py's interpretation of test results.

No LLM is involved. Two checks:

1. scan-check (fast, no tests are run)
   For every case in the scan report, re-interpret the four scan runs
   (functional/exploit x vulnerable/fixed) with evaluate.classify_step, using
   the rc from the report and the junit XML in <case>/logs/. For status OK the
   answer is known:
       functional vulnerable = 1, functional fixed = 1,
       exploit    vulnerable = 0, exploit    fixed = 1.
   The scan logs are read only if they are not newer than the report.

2. controls (runs the real pipeline: evaluate.evaluate_one)
   Three synthetic patches per case, written as if they were frozen attempts
   under <out>/runs/oracle_<control>/<id>/ and evaluated with the same code as
   the study:
       reference_fix : vulnerable -> fixed diff of meta["new_code_files"]
                       expected A=1 F=1 S=1 (V=1)
       noop          : appends a comment line to the first code file
                       expected A=1 F=1 S=0
       corrupt       : hunk whose removed line does not exist
                       expected A=0 (complete observation)
   A mismatch means either the interpretation is wrong or the oracle cannot
   accept the reference fix (e.g. it depends on files outside new_code_files).
   Existing control evaluations are reused, so the script can be resumed.

Outputs: <out>/scan_check.csv, <out>/controls.csv, <out>/summary.json
"""
from __future__ import annotations

import argparse
import csv
import difflib
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
import evaluate as ev  # noqa: E402

HERE = Path(__file__).resolve().parent.parent
SCAN_REPORT = HERE / "scan_report_final.tsv"
OUT = HERE / "results" / "oracle_validation"

SCAN_RUNS = [  # (report column, junit stem, kind, expected value when status OK)
    ("func_vuln_rc", "functional_vulnerable", "functional", 1),
    ("func_fixed_rc", "functional_fixed", "functional", 1),
    ("exploit_vuln_rc", "exploit_vulnerable", "exploit", 0),
    ("exploit_fixed_rc", "exploit_fixed", "exploit", 1),
]
CONTROLS = {
    "reference_fix": {"A": 1, "F": 1, "S": 1, "V": 1},
    "noop": {"A": 1, "F": 1, "S": 0, "V": 0},
    "corrupt": {"A": 0, "F": 0, "S": 0, "V": 0},
}
NOOP_LINE = "# oracle-validation no-op control\n"


def read_report(path: Path) -> List[Dict[str, str]]:
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f, delimiter="\t"))


# ---------- 1. scan-check ----------

def scan_check(workspaces: Path, report: Path) -> List[Dict]:
    report_mtime = report.stat().st_mtime
    rows = []
    for r in read_report(report):
        cid, status = r["cve_id"], r["status"]
        logs = workspaces / cid / "logs"
        for col, stem, kind, expected in SCAN_RUNS:
            rc_s = (r.get(col) or "").strip()
            rc = int(rc_s) if rc_s.lstrip("-").isdigit() else None
            junit_path = logs / f"{stem}.junit.xml"
            log_path = logs / f"{stem}.log"
            row = {"cve_id": cid, "scan_status": status, "run": stem, "rc": rc}
            if junit_path.exists() and junit_path.stat().st_mtime > report_mtime:
                row.update({"value": None, "outcome": "skipped_log_newer_than_report",
                            "incomplete_reason": None, "expected": None, "match": None})
                rows.append(row)
                continue
            junit = ev.parse_junit(junit_path)
            text = (junit or {}).get("_text", "")
            if log_path.exists():
                text += "\n" + log_path.read_text(encoding="utf-8", errors="replace")
            # No patch exists in a scan run, so rc=2 can never be attributed.
            value, reason, outcome = ev.classify_step(rc, False, junit, text, [])
            exp = expected if status == "OK" else None
            row.update({
                "junit": "missing" if junit is None else
                         f"{junit['tests']}/{junit['failed']}/{junit['errored']}/{junit['skipped']}",
                "value": value, "outcome": outcome, "incomplete_reason": reason,
                "expected": exp, "match": (value == exp) if exp is not None else None,
            })
            rows.append(row)
    return rows


# ---------- 2. controls ----------

def git_show(tree: Path, rel: str) -> Optional[str]:
    cp = subprocess.run(["git", "-C", str(tree), "show", f"HEAD:{rel}"],
                        capture_output=True, text=True)
    return cp.stdout if cp.returncode == 0 else None


def unified(rel: str, old: Optional[str], new: Optional[str]) -> str:
    a = (old or "").splitlines(keepends=True)
    b = (new or "").splitlines(keepends=True)
    out = []
    for line in difflib.unified_diff(a, b,
                                     fromfile="/dev/null" if old is None else f"a/{rel}",
                                     tofile="/dev/null" if new is None else f"b/{rel}"):
        if not line.endswith("\n"):
            line += "\n\\ No newline at end of file\n"
        out.append(line)
    return "".join(out)


def build_control(case_dir: Path, meta: dict, control: str) -> Optional[str]:
    vuln, fixed = case_dir / "vulnerable", case_dir / "fixed"
    files = meta.get("new_code_files", [])
    if not files:
        return None
    if control == "reference_fix":
        parts = [unified(rel, git_show(vuln, rel), git_show(fixed, rel)) for rel in files]
        diff = "".join(parts)
        return diff or None
    first = files[0]
    old = git_show(vuln, first)
    if old is None:
        return None
    if control == "noop":
        new = old + ("" if old.endswith("\n") or not old else "\n") + NOOP_LINE
        return unified(first, old, new)
    if control == "corrupt":
        return (f"--- a/{first}\n+++ b/{first}\n@@ -1,1 +1,1 @@\n"
                f"-oracle-validation: this line does not exist 7f3a9c\n+x = 1\n")
    raise ValueError(control)


def write_fake_attempt(run_dir: Path, control: str, diff: str):
    """Mimic run_agent.py's frozen layout so evaluate_one runs unmodified."""
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "patch.diff").write_text(diff, encoding="utf-8")
    gen = {"agent": f"oracle_{control}", "model": "oracle-control", "status": "ok",
           "claimed_success": None, "confidence": None, "control": control,
           "timestamp_utc": datetime.now(timezone.utc).isoformat()}
    (run_dir / "generation.json").write_text(json.dumps(gen, indent=2), encoding="utf-8")
    hashes = {n: hashlib.sha256((run_dir / n).read_bytes()).hexdigest()
              for n in ("patch.diff", "generation.json")}
    (run_dir / "frozen.json").write_text(json.dumps({"sha256": hashes}, indent=2),
                                         encoding="utf-8")


def run_controls(workspaces: Path, out: Path, ids: List[str], controls: List[str]) -> List[Dict]:
    runs = out / "runs"
    rows = []
    for cid in ids:
        case_dir = workspaces / cid
        meta = json.loads((case_dir / "meta.json").read_text(encoding="utf-8"))
        for control in controls:
            agent = f"oracle_{control}"
            run_dir = runs / agent / cid
            eval_path = run_dir / "eval.json"
            if eval_path.exists():
                v = json.loads(eval_path.read_text(encoding="utf-8"))
            else:
                diff = build_control(case_dir, meta, control)
                if diff is None:
                    rows.append({"cve_id": cid, "control": control, "status": "not_built"})
                    continue
                write_fake_attempt(run_dir, control, diff)
                v = ev.evaluate_one(workspaces, runs, agent, cid)
            exp = CONTROLS[control]
            obs = {k: v.get(k) for k in ("A", "F", "S", "V")}
            rows.append({
                "cve_id": cid, "control": control, "status": v["status"],
                "incomplete_reason": v["incomplete_reason"],
                **{f"obs_{k}": obs[k] for k in obs}, **{f"exp_{k}": exp[k] for k in exp},
                "functional_outcome": (v.get("functional") or {}).get("outcome"),
                "exploit_outcome": (v.get("exploit") or {}).get("outcome"),
                "apply_method": v.get("apply_method"),
                "match": v["status"] == "complete" and obs == exp,
            })
            print(f"  {cid} {control}: status={v['status']} {obs} expected={exp} "
                  f"{v['incomplete_reason'] or ''}")
    return rows


def write_csv(path: Path, rows: List[Dict]):
    if not rows:
        return
    keys: List[str] = []
    for r in rows:
        keys += [k for k in r if k not in keys]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        w.writerows(rows)


def main():
    ap = argparse.ArgumentParser(description="Validate the test-result interpretation of evaluate.py.")
    ap.add_argument("--workspaces", type=Path, default=ev.WORKSPACES)
    ap.add_argument("--scan-report", type=Path, default=SCAN_REPORT)
    ap.add_argument("--out", type=Path, default=OUT)
    ap.add_argument("--ids", help="Comma-separated case IDs for the controls "
                                  "(default: every status OK case in the scan report)")
    ap.add_argument("--controls", default=",".join(CONTROLS))
    ap.add_argument("--skip-controls", action="store_true")
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    sc = scan_check(args.workspaces, args.scan_report)
    write_csv(args.out / "scan_check.csv", sc)
    known = [r for r in sc if r.get("expected") is not None]
    print(f"[scan-check] {len(sc)} runs, {len(known)} with known answer, "
          f"{sum(1 for r in known if r['match'])} match")
    for r in known:
        if not r["match"]:
            print(f"  MISMATCH {r['cve_id']} {r['run']}: rc={r['rc']} junit={r.get('junit')} "
                  f"-> {r['value']} ({r['outcome']}), expected {r['expected']}")

    summary = {"generated_at_utc": datetime.now(timezone.utc).isoformat(),
               "evaluator_version": ev.EVALUATOR_VERSION,
               "scan_check": {"runs": len(sc), "known": len(known),
                              "match": sum(1 for r in known if r["match"]),
                              "outcomes": {}}}
    for r in sc:
        o = summary["scan_check"]["outcomes"]
        o[r["outcome"]] = o.get(r["outcome"], 0) + 1

    if not args.skip_controls:
        ids = args.ids.split(",") if args.ids else \
            [r["cve_id"] for r in read_report(args.scan_report) if r["status"] == "OK"]
        controls = [c for c in args.controls.split(",") if c]
        cr = run_controls(args.workspaces, args.out, ids, controls)
        write_csv(args.out / "controls.csv", cr)
        summary["controls"] = {"n": len(cr), "match": sum(1 for r in cr if r.get("match")),
                               "mismatches": [r for r in cr if not r.get("match")]}
        print(f"[controls] {summary['controls']['match']}/{len(cr)} match expectation")

    (args.out / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"[+] wrote {args.out}")


if __name__ == "__main__":
    main()
