#!/usr/bin/env bash
# The exploratory check of D-94's cost (D-96; not pre-registered): four of
# the frozen grid's cells (B and D warm+prefix, A and C warm; N = 3, medium),
# measured by `dc-bench run` in three builds, three runs each, on M9's
# machine state. Each build writes to its own directory under
# results/exploratory/reorder/:
#   measured     b175599, M9's resume commit (ARTIFACT.md §5)
#   pre-reorder  4239168, the commit before D-94
#   reordered    HEAD, which must be committed and contain D-94
#
# Each build is made first, in its own git worktree under
# target/exploratory/reorder/ and with M9's flags, so that no build runs
# during a measurement and each env.json names its build's commit. Each
# `dc-bench run` checks M9's machine state itself (AC power, High Power
# mode, an idle machine) and aborts if it does not hold. The builds' order
# rotates from run to run. Afterwards every directory's raw data is
# archived under its own manifest, and BENCH_LOG.md gets an entry.
#
# Usage: scripts/reorder-check.sh [--mode dry]
#   --mode dry   10 iterations, under results/dry-run/exploratory/reorder/;
#                no machine-state requirement. Its numbers are never reported.
set -euo pipefail
cd "$(dirname "$0")/.."
root=$(pwd)

mode=full
if [[ "${1:-}" == "--mode" && "${2:-}" == "dry" ]]; then
  mode=dry
fi
out_root="$root/results/exploratory/reorder"
if [[ $mode == dry ]]; then
  out_root="$root/results/dry-run/exploratory/reorder"
fi

if [[ -n "$(git status --porcelain --untracked-files=no)" ]]; then
  echo "reorder-check: commit first; the reordered build is HEAD" >&2
  exit 1
fi
if ! grep -q 'L32ChainSignaturesInvalid' crates/dc-verifier/src/reject.rs; then
  echo "reorder-check: HEAD does not have D-94's order" >&2
  exit 1
fi
if [[ $mode == full && -e "$out_root" ]]; then
  echo "reorder-check: $out_root exists; refusing to overwrite measured data" >&2
  exit 1
fi
if [[ $mode == dry ]]; then
  rm -rf "$out_root"
fi

builds=(measured pre-reorder reordered)
commit_of() {
  case "$1" in
    measured) echo b175599 ;;
    pre-reorder) echo 4239168 ;;
    reordered) git rev-parse HEAD ;;
  esac
}
wt_of() { echo "$root/target/exploratory/reorder/src-$1"; }
cells=(--only "B warm+prefix N=3 medium" --only "D warm+prefix N=3 medium"
  --only "A warm N=3 medium" --only "C warm N=3 medium")

for b in "${builds[@]}"; do
  c=$(commit_of "$b")
  wt=$(wt_of "$b")
  echo "== build: $b at ${c:0:7} (RUSTFLAGS=\"-C target-cpu=native\", as M9)"
  if [[ -d "$wt" ]]; then
    git -C "$wt" checkout -q --detach "$c"
  else
    git worktree add -q --detach "$wt" "$c"
  fi
  (cd "$wt" && RUSTFLAGS="-C target-cpu=native" cargo build -q --release -p dc-bench --bin dc-bench)
  mkdir -p "$out_root/$b"
  (cd "$wt" && ./target/release/dc-bench env --out "$out_root/$b" >/dev/null)
done

for r in 1 2 3; do
  # Rotate: run 1 measured first, run 2 pre-reorder first, run 3 reordered first.
  order=("${builds[@]:$((r - 1))}" "${builds[@]:0:$((r - 1))}")
  for b in "${order[@]}"; do
    echo "== run $r: $b"
    (cd "$(wt_of "$b")" && ./target/release/dc-bench run --run "$r" --mode "$mode" \
      --no-throughput --out "$out_root/$b" "${cells[@]}")
  done
done

head_bin="$(wt_of reordered)/target/release/dc-bench"
for b in "${builds[@]}"; do
  "$head_bin" archive --mode "$mode" --out "$out_root/$b"
done

if [[ $mode == full ]]; then
  {
    echo
    echo "## $(date -u +%Y-%m-%d) — Exploratory run (not pre-registered): the cost of D-94's reorder"
    echo "Reason: D-94 moved the chain signatures ahead of policy after M9, and the author asked whether that changes the measured latencies (D-96)."
    echo "- **What ran.** \`scripts/reorder-check.sh\`: the frozen grid's B and D warm+prefix and A and C warm configurations at N = 3, medium, by \`dc-bench run\` with M9's counts, three runs, in three builds: measured \`$(commit_of measured)\`, pre-reorder \`$(commit_of pre-reorder)\` and reordered \`$(git rev-parse --short HEAD)\`, rotating which ran first."
    echo "- **Machine state.** M9's, checked by each run and recorded in each build's \`env.json\` and run metadata."
    echo "- **Where the results go.** \`BENCHMARKS.md\` §8 (exploratory) only. The raw data are archived under \`results/exploratory/reorder/<build>/archive/\`, each pinned by its \`MANIFEST.sha256\`."
    echo
    echo "Configurations re-run: none."
  } >> BENCH_LOG.md
fi
echo "reorder-check: done; \`dc-bench reorder$([[ $mode == dry ]] && echo ' --mode dry')\` prints the comparison"
