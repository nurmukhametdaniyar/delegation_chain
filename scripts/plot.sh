#!/usr/bin/env bash
# Plots for SPEC §13.8, from a results directory's summary.json. Python is
# used only here (SPEC §3.1). The virtual environment is built from
# scripts/requirements.txt on first use.
set -euo pipefail
cd "$(dirname "$0")/.."
out="${1:-results}"
venv=scripts/.venv
if [[ ! -x "$venv/bin/python" ]]; then
  python3 -m venv "$venv"
  "$venv/bin/pip" install -q -r scripts/requirements.txt
fi
"$venv/bin/python" scripts/plot.py "$out"
