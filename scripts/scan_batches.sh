#!/usr/bin/env bash
# Scan the cases listed in an ids file in batches, deleting the per-case venvs
# after each batch to keep disk usage bounded. vul4py.py merges every batch into
# workspaces/scan_report.tsv; the merged report is copied to the output dir.
#
# usage: scripts/scan_batches.sh <ids_file> <out_dir> [batch_size] [jobs]
set -uo pipefail
cd "$(dirname "$0")/.."
IDS_FILE=$1
OUT=$2
BATCH=${3:-10}
JOBS=${4:-2}
PY=.proyect/bin/python
mkdir -p "$OUT"

mapfile -t IDS < <(grep -v '^\s*$' "$IDS_FILE")
n=${#IDS[@]}
for ((i = 0; i < n; i += BATCH)); do
  chunk=("${IDS[@]:i:BATCH}")
  b=$((i / BATCH + 1))
  only=$(IFS=,; echo "${chunk[*]}")
  echo "[batch $b] $(date -u +%FT%TZ) ${#chunk[@]} cases: $only"
  $PY scripts/vul4py.py --workspace-root workspaces scan --only "$only" --jobs "$JOBS" \
      > "$OUT/scan_batch_${b}.log" 2>&1
  echo "[batch $b] scan exit=$?"
  for id in "${chunk[@]}"; do
    $PY - "$id" <<'EOF'
import sys
from pathlib import Path
sys.path.insert(0, "scripts")
import vul4py
vul4py.wipe_all_venvs(Path("workspaces") / sys.argv[1])
EOF
  done
  cp workspaces/scan_report.tsv "$OUT/scan_report_after_batch_${b}.tsv"
  echo "[batch $b] venvs wiped; disk: $(df -h / | awk 'NR==2{print $4" free"}')"
done
cp workspaces/scan_report.tsv "$OUT/scan_report_full_raw.tsv"
echo "[done] $(date -u +%FT%TZ)"
