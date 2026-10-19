#!/usr/bin/env python3
"""Aggregate per-attempt eval.json + generation.json into results.csv, VRR and FAR."""
import argparse, csv, json
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=Path, default=HERE / "runs" / "midterm")
    ap.add_argument("--agent", default="gpt")
    ap.add_argument("--out", type=Path, default=HERE / "results")
    args = ap.parse_args()

    rows = []
    for d in sorted((args.runs / args.agent).iterdir()):
        ev, gen = d / "eval.json", d / "generation.json"
        if not ev.exists() or not gen.exists():
            continue
        e = json.loads(ev.read_text())
        g = json.loads(gen.read_text())
        rows.append({
            "vuln_id": e["vuln_id"], "model": g.get("model"),
            "claimed_success": e["C"], "confidence": e["P"],
            "A": e["A"], "F": e["F"], "S": e["S"], "V": e["V"], "FA": e["FA"],
            "latency_ms": g.get("latency_ms"),
            "input_tokens": g.get("input_tokens"), "output_tokens": g.get("output_tokens"),
            "timestamp_utc": g.get("timestamp_utc"),
            "generation_status": g.get("status"),
            "eval_status": e["status"], "incomplete_reason": e["incomplete_reason"],
            "functional_rc": e["functional_rc"], "exploit_rc": e["exploit_rc"],
        })

    args.out.mkdir(parents=True, exist_ok=True)
    csv_path = args.out / "results.csv"
    with open(csv_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    done = [r for r in rows if r["eval_status"] == "complete"]
    inc = [r for r in rows if r["eval_status"] != "complete"]
    N = len(done)
    sumV = sum(r["V"] for r in done)
    sumFA = sum(r["FA"] for r in done)
    sumC = sum(r["claimed_success"] for r in done)

    vrr = (sumV / N) if N > 0 else None
    far = (sumFA / sumC) if sumC > 0 else None

    print(f"Total attempts: {len(rows)} | completed (N): {N} | incomplete: {len(inc)}")
    for r in inc:
        print(f"  INCOMPLETE {r['vuln_id']}: {r['incomplete_reason']}")
    print(f"sum V = {sumV}, sum FA = {sumFA}, sum C = {sumC}")
    print("VRR = " + (f"{sumV}/{N} = {vrr:.1%}" if vrr is not None else "undefined (no completed observations)"))
    print("FAR = " + (f"{sumFA}/{sumC} = {far:.1%}" if far is not None else "undefined (no positive repair claims)"))

    summary = {"attempts": len(rows), "N_completed": N, "incomplete": len(inc),
               "incomplete_ids": [r["vuln_id"] for r in inc],
               "sum_V": sumV, "sum_FA": sumFA, "sum_C": sumC,
               "VRR": vrr, "FAR": far if far is not None else "undefined (no positive repair claims)"}
    (args.out / "summary_midterm.json").write_text(json.dumps(summary, indent=2))
    print(f"[+] wrote {csv_path}")

if __name__ == "__main__":
    main()
