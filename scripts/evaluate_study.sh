#!/usr/bin/env bash
# Evaluate every frozen attempt of the study, case by case, then delete the
# case's venvs to keep disk usage bounded. evaluate.py refuses to overwrite an
# existing eval.json, so the script can be re-run after an interruption.
#
# usage: scripts/evaluate_study.sh <ids_file> <runs_dir> [agents...]
set -uo pipefail
cd "$(dirname "$0")/.."
IDS_FILE=$1
RUNS=$2
shift 2
AGENTS=("$@")
[ $# -eq 0 ] && AGENTS=(gpt deepseek)
PY=.proyect/bin/python

mapfile -t IDS < <(grep -v '^\s*$' "$IDS_FILE")
for id in "${IDS[@]}"; do
  for agent in "${AGENTS[@]}"; do
    [ -d "$RUNS/$agent/$id" ] || continue
    echo "[eval] $(date -u +%FT%TZ) $agent $id"
    $PY scripts/evaluate.py --agent "$agent" --runs "$RUNS" --vuln-id "$id" 2>&1 | grep -E "^  |^\[done\]|^\[!\]|Traceback|Error"
  done
  $PY - "$id" <<'EOF'
import sys
from pathlib import Path
sys.path.insert(0, "scripts")
import vul4py
vul4py.wipe_all_venvs(Path("workspaces") / sys.argv[1])
EOF
  echo "[eval] $id venvs wiped; disk: $(df -h / | awk 'NR==2{print $4" free"}')"
done
echo "[done] $(date -u +%FT%TZ)"
