#!/usr/bin/env bash
# The exploratory measurement of Contains after D-97's memoization (D-98)
# and of the prototype work budget (D-99); not pre-registered. Into
# results/exploratory/contains-cost/:
#   search.txt          the search's ranking, one call per candidate
#   criterion.tar.zst   criterion's output for benches/contains_cost.rs and
#                       benches/contains_budget.rs, with its .sha256
#   work.json           the atom-level counts (`dc-bench budget`)
#   oracle-budget.json  the differential oracle under budgets
#   env.json            the machine
# and a BENCH_LOG.md entry. Its run (2026-11-02) was at 7d71b92, where the
# budget was a prototype behind `--features work-budget`; since D-100 the
# budget is always built, and the script no longer passes the feature.
# Everything is built first, with M9's flags. M9's
# machine state (AC power, High Power mode, an idle machine) is checked with
# `dc-bench env`, waiting up to 10 minutes for the machine to become idle.
# It takes about 45 minutes.
#
# Usage: scripts/contains-cost.sh [--dry]
#   --dry   a few small cells with criterion's shortest times, under
#           results/dry-run/; no machine-state requirement. Its numbers are
#           never reported.
set -euo pipefail
cd "$(dirname "$0")/.."

dry=0
if [[ "${1:-}" == "--dry" ]]; then
  dry=1
fi
out=results/exploratory/contains-cost
root_out=results
if [[ $dry == 1 ]]; then
  out=results/dry-run/exploratory/contains-cost
  root_out=results/dry-run
  rm -rf "$out"
else
  if [[ -n "$(git status --porcelain --untracked-files=no)" ]]; then
    echo "contains-cost: commit first; env.json names the measured commit" >&2
    exit 1
  fi
  if [[ -e "$out/criterion.tar.zst" ]]; then
    echo "contains-cost: $out/criterion.tar.zst exists; refusing to overwrite measured data" >&2
    exit 1
  fi
fi
mkdir -p "$out"
abs_out="$PWD/$out"

export RUSTFLAGS="-C target-cpu=native"
echo "== build"
cargo bench -q -p dc-bench --bench contains_cost --no-run
cargo bench -q -p dc-bench --bench contains_budget --no-run
cargo build -q --release -p dc-bench --example contains_search
cargo build -q --release -p dc-bench --bin dc-bench

if [[ $dry == 0 ]]; then
  ok() {
    python3 -I -c 'import json, sys; sys.exit(0 if json.load(open(sys.argv[1]))["m9_requirements"]["ok"] is True else 1)' "$1"
  }
  for i in $(seq 40); do
    ./target/release/dc-bench env --out "$out" >/dev/null
    if ok "$out/env.json"; then
      break
    fi
    if [[ $i == 40 ]]; then
      echo "contains-cost: the machine did not become idle within 10 minutes" >&2
      exit 1
    fi
    echo "contains-cost: waiting for the machine to become idle"
    sleep 15
  done
fi

crit=(--noplot)
if [[ $dry == 1 ]]; then
  crit+=(--warm-up-time 0.01 --measurement-time 0.01 --sample-size 10 "r16_a8")
fi
echo "== 1 of 4: the search"
if [[ $dry == 1 ]]; then
  echo "dry run: the search is skipped" > "$out/search.txt"
else
  ./target/release/examples/contains_search > "$out/search.txt"
fi
echo "== 2 of 4: Contains after the memoization (D-98)"
CRITERION_HOME="$abs_out/criterion" cargo bench -q -p dc-bench --bench contains_cost -- "${crit[@]}"
echo "== 3 of 4: the work budget (D-99)"
budget_filter=()
if [[ $dry == 1 ]]; then
  budget_filter=(--warm-up-time 0.01 --measurement-time 0.01 --sample-size 10 "bounds_r256")
fi
CRITERION_HOME="$abs_out/criterion" cargo bench -q -p dc-bench \
  --bench contains_budget -- --noplot ${budget_filter[@]+"${budget_filter[@]}"}
echo "== 4 of 4: the counts and the oracle under budgets"
cargo run -q --release -p dc-bench -- budget --out "$root_out"
DC_ORACLE_CASES=150000 DC_ORACLE_LOGIC_CASES=150000 DC_ORACLE_SEED=56324 \
  DC_ORACLE_BUDGETS=32,64,128,256,2228,16384,1048576 \
  DC_ORACLE_REPORT="$abs_out/oracle-budget.json" \
  cargo test -q --release -p dc-policy --test oracle >/dev/null

COPYFILE_DISABLE=1 tar -C "$out" -cf - criterion | zstd -q -19 -o "$out/criterion.tar.zst"
(cd "$out" && shasum -a 256 criterion.tar.zst > criterion.tar.zst.sha256)
if [[ $dry == 0 ]]; then
  {
    echo
    echo "## $(date -u +%Y-%m-%d) — Exploratory run (not pre-registered): Contains after the memoization, and a work budget"
    echo "Reason: after D-95 the author asked for the cost of Contains after D-97's memoization at sizes up to the bounds, a search for costlier inputs, and a prototype work budget, to choose the scope-size bounds (D-98, D-99)."
    echo "- **What ran.** \`scripts/contains-cost.sh\` at \`$(git rev-parse --short HEAD)\`, with \`target-cpu=native\` as M9: the search (\`examples/contains_search.rs\`), \`benches/contains_cost.rs\`, \`benches/contains_budget.rs\`, \`dc-bench budget\` and the differential oracle under budgets."
    echo "- **Machine state.** AC power, High Power mode and an idle machine, checked before the run and recorded in \`$out/env.json\`. Nothing monitored the machine during it."
    echo "- **Where the results go.** \`BENCHMARKS.md\` §8 (exploratory) only. Criterion's output is \`$out/criterion.tar.zst\`, pinned by its \`.sha256\`; the counts, the oracle's report and the search's ranking sit beside it."
    echo
    echo "Configurations re-run: none."
  } >> BENCH_LOG.md
fi
echo "contains-cost: done"
