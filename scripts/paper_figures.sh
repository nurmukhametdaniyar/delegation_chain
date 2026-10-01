#!/usr/bin/env bash
# Paper figures (D-78), from a results directory's summary.json, into a
# figures directory. Python is used only for plots (SPEC §3.1); the virtual
# environment is the one scripts/plot.sh builds from scripts/requirements.txt.
set -euo pipefail
cd "$(dirname "$0")/.."
results="${1:-results}"
out="${2:-paper/figures}"
venv=scripts/.venv
if [[ ! -x "$venv/bin/python" ]]; then
  python3 -m venv "$venv"
  "$venv/bin/pip" install -q -r scripts/requirements.txt
fi
"$venv/bin/python" scripts/paper_figures.py "$results" "$out"
