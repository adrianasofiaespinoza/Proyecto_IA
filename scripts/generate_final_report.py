#!/usr/bin/env python3
\"\"\"
generate_final_report.py
Consolidates detailed evaluation reports from Phase 2 into a final academic summary.
\"\"\"
import argparse
import json
import csv
import os
from pathlib import Path
from typing import List, Dict, Any, Optional

ROOT = Path(__file__).resolve().parent.parent

def load_reports(execution_dir: Path) -> List[Dict[str, Any]]:
    \"\"\"Load reports from a specific execution directory's reports subfolder.\"\"\"
    reports_dir = execution_dir / \"reports\"
    if not reports_dir.exists():
        print(f\"[!] Reports directory not found: {reports_dir}\")
        return []
    
    reports = []
    for report_file in sorted(reports_dir.glob(\"report_*.json\")):
        try:
            with open(report_file, 'r', encoding='utf-8') as f:
                reports.append(json.load(f))
        except Exception as e:
            print(f\"[!] Failed to load {report_file}: {e}\")
    return reports

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument(\"--phase2-root\", type=Path, default=ROOT / \"results\" / \"phase2\", 
                    help=\"Root directory containing exec_* folders\")
    ap.add_argument(\"--execution-id\", type=str, help=\"Specific exec_<id> folder to process\")
    ap.add_argument(\"--out-dir\", type=Path, default=ROOT / \"reports\")
    args = ap.parse_args()

    # 1. Identify the execution directory
    execution_dir = None
    if args.execution_id:
        execution_dir = args.phase2_root / args.execution_id
        if not execution_dir.exists() or not execution_dir.is_dir():
            print(f\"[!] Execution directory not found: {execution_dir}\")
            return
    else:
        # Default to the most recent execution directory
        exec_dirs = sorted([d for d in args.phase2_root.glob(\"exec_*\") if d.is_dir()], reverse=True)
        if not exec_dirs:
            print(\"No execution directories found in results/phase2/\")
            return
        execution_dir = exec_dirs[0]
        print(f\"[i] No execution ID provided. Using latest: {execution_dir.name}\")

    reports = load_reports(execution_dir)
    if not reports:
        print(f\"No valid reports found in {execution_dir}\")
        return

    args.out_dir.mkdir(parents=True, exist_ok=True)
    # Save output inside the execution dir to avoid mixing different runs
    final_out_dir = execution_dir / \"final_summary\"
    final_out_dir.mkdir(parents=True, exist_ok=True)

    # 2. Generate Consolidated CSV
    csv_path = final_out_dir / \"phase2_summary.csv\"
    # Extract all possible keys from all reports to avoid missing data
    all_headers = set()
    for r in reports:
        all_headers.update(r.keys())
    headers = sorted(list(all_headers))

    with open(csv_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(reports)

    # 3. Generate Human-Readable Markdown Report
    md_path = final_out_dir / \"final_analysis.md\"
    with open(md_path, 'w', encoding='utf-8') as f:
        f.write(f\"# Final Analysis: LLM Vulnerability Repair\\n\\n\")
        f.write(f\"Execution ID: {execution_dir.name}\\n\\n\")
        f.write(\"## Case-by-Case Summary\\n\\n\")
        for r in reports:
            f.write(f\"### {r.get('vuln_id', 'Unknown CVE')}\\n\")
            f.write(f\"- **Verdict:** {r.get('classification', 'Unknown')}\\n\")
            f.write(f\"- **Metrics:** A={r.get('A')}, F={r.get('F')}, S={r.get('S')} -> V={r.get('V')}\\n\")
            f.write(f\"- **Claimed Success:** {r.get('C')} (Conf: {r.get('P')})\\n\")
            f.write(f\"- **Diagnosis:** {r.get('full_log', 'No log provided')[:500]}...\\n\\n\")

    print(f\"[+] Final report generated in: {final_out_dir}\")
    print(f\"[+] CSV: {csv_path}\")
    print(f\"[+] Markdown: {md_path}\")

if __name__ == \"__main__\":
    main()
