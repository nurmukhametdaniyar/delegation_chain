#!/usr/bin/env bash
# The re-run of D-102's headline check, which stopped on the author's 5%
# rule (D-102, D-103; not pre-registered). D-96's four cells (B and D
# warm+prefix, A and C warm; N = 3, medium), by `dc-bench run` in three
# builds, three runs each, rotating which goes first:
#   measured    b175599, M9's resume commit
#   pre-budget  2df8b53, D-94 and D-97 without the budget
#   budgeted    HEAD, which must be committed
# into results/exploratory/<name>/headline-rerun/<build>/, each with env.json
# and archive/ under its manifest, beside the stopped run's headline/, which
# stays as it is; and a BENCH_LOG.md entry.
#
# Before each of the nine runs the machine must be quieter than M9 asks:
# M9's machine state (AC power, High Power mode, no process above 25% CPU, a
# 1-minute load average below 2.0), and also a load average below 1.0 and
# XprotectService below 1% CPU. Each wait lasts up to --wait minutes, and
# says what keeps the machine busy; every check that passed is logged to
# headline-rerun/quiet.log. Each `dc-bench run` checks M9's machine state
# again itself. Builds go in the worktrees under target/exploratory/<name>/.
# It takes about half an hour once the machine is quiet.
#
# Usage: scripts/headline-rerun.sh [--dry] [--wait MINUTES] [--name NAME]
#   --dry       10-iteration runs under results/dry-run/; no machine-state
#               requirement. Its numbers are never reported.
#   --wait M    how long to wait for a quiet machine before each run
#               (default 30).
#   --name N    the measurement whose headline check is re-run (default
#               `ceiling2`).
set -euo pipefail
cd "$(dirname "$0")/.."
root=$(pwd)

dry=0
mode=full
wait_min=30
name=ceiling2
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry)
      dry=1
      mode=dry
      ;;
    --wait)
      wait_min="${2:?--wait needs a number of minutes}"
      shift
      ;;
    --name)
      name="${2:?--name needs a directory name}"
      shift
      ;;
    *)
      echo "usage: scripts/headline-rerun.sh [--dry] [--wait MINUTES] [--name NAME]" >&2
      exit 2
      ;;
  esac
  shift
done
out="$root/results/exploratory/$name/headline-rerun"
if [[ $dry == 1 ]]; then
  out="$root/results/dry-run/exploratory/$name/headline-rerun"
fi

if [[ -n "$(git status --porcelain --untracked-files=no)" ]]; then
  echo "headline-rerun: commit first; the budgeted build is HEAD" >&2
  exit 1
fi
# Only a run's data blocks a rerun: an attempt that never got a quiet
# machine leaves an empty directory, and running again starts over.
if [[ $dry == 0 ]] && compgen -G "$out/*/raw" >/dev/null; then
  echo "headline-rerun: $out holds measured runs; refusing to overwrite them" >&2
  exit 1
fi
rm -rf "$out"
mkdir -p "$out"

builds=(measured pre-budget budgeted)
commit_of() {
  case "$1" in
    measured) echo b175599 ;;
    pre-budget) echo 2df8b53 ;;
    budgeted) git rev-parse HEAD ;;
  esac
}
wt_of() { echo "$root/target/exploratory/$name/src-$1"; }
cells=(--only "B warm+prefix N=3 medium" --only "D warm+prefix N=3 medium"
  --only "A warm N=3 medium" --only "C warm N=3 medium")

export RUSTFLAGS="-C target-cpu=native"
echo "== build: HEAD's harness"
cargo build -q --release -p dc-bench --bin dc-bench
for b in "${builds[@]}"; do
  c=$(commit_of "$b")
  wt=$(wt_of "$b")
  echo "== build: $b at ${c:0:7}"
  if [[ -d "$wt" ]]; then
    git -C "$wt" checkout -q --detach "$c"
  else
    git worktree add -q --detach "$wt" "$c"
  fi
  (cd "$wt" && cargo build -q --release -p dc-bench --bin dc-bench)
done

# What keeps the machine from being quiet, in one line; empty when quiet.
not_quiet() {
  local env_dir
  env_dir=$(mktemp -d)
  ./target/release/dc-bench env --out "$env_dir" >/dev/null
  python3 -I -c '
import json, subprocess, sys
r = json.load(open(sys.argv[1]))["m9_requirements"]
why = []
if r["ac_power"] is not True:
    why.append("not on AC power")
if r["high_power_mode"] is not True:
    why.append("not in High Power mode")
idle = r["idle"]
if idle["loadavg_1m"] >= 1.0:
    why.append("load average %.2f" % idle["loadavg_1m"])
why += ["%s at %.0f%% CPU" % (p["command"].rsplit("/", 1)[-1], p["pcpu"]) for p in idle["busy_processes"]]
ps = subprocess.run(["ps", "-A", "-o", "pcpu=,comm="], capture_output=True, text=True).stdout
for line in ps.splitlines():
    pcpu, _, comm = line.strip().partition(" ")
    if comm.rsplit("/", 1)[-1] == "XprotectService" and float(pcpu) >= 1.0:
        why.append("XprotectService at %s%% CPU" % pcpu)
print(", ".join(dict.fromkeys(why)))
' "$env_dir/env.json"
  rm -rf "$env_dir"
}

# Waits up to $wait_min minutes for a quiet machine; logs the check. Right
# after the builds, Spotlight indexes the new build trees and XProtect scans
# the new binaries, so the first wait is the longest.
await_quiet() {
  [[ $dry == 1 ]] && return 0
  local why
  for i in $(seq $((wait_min * 4))); do
    why=$(not_quiet)
    if [[ -z "$why" ]]; then
      echo "$(date -u +%FT%TZ) quiet before $1" >> "$out/quiet.log"
      return 0
    fi
    echo "headline-rerun: waiting for a quiet machine before $1 ($why)"
    sleep 15
  done
  echo "headline-rerun: the machine was not quiet within $wait_min minutes before $1 ($why); runs so far are kept under $out" >&2
  exit 1
}

for r in 1 2 3; do
  order=("${builds[@]:$((r - 1))}" "${builds[@]:0:$((r - 1))}")
  for b in "${order[@]}"; do
    await_quiet "run $r, $b"
    echo "== run $r: $b"
    (cd "$(wt_of "$b")" && ./target/release/dc-bench run --run "$r" --mode "$mode" \
      --no-throughput --out "$out/$b" "${cells[@]}")
  done
done
for b in "${builds[@]}"; do
  (cd "$(wt_of "$b")" && ./target/release/dc-bench env --out "$out/$b" >/dev/null)
  ./target/release/dc-bench archive --mode "$mode" --out "$out/$b"
done

if [[ $dry == 0 ]]; then
  {
    echo
    echo "## $(date -u +%Y-%m-%d) — Exploratory run (not pre-registered): the headline cells re-run ($name)"
    echo "Reason: D-102's headline check stopped on the author's 5% rule; the author asked for the four cells to be re-run on a quieter machine, and reported beside the stopped run (D-103)."
    echo "- **What ran.** \`scripts/headline-rerun.sh --name $name\`: the frozen grid's B and D warm+prefix and A and C warm configurations at N = 3, medium, by \`dc-bench run\` with M9's counts, three runs, in three builds: measured \`$(commit_of measured)\`, pre-budget \`$(commit_of pre-budget)\` and budgeted \`$(git rev-parse --short HEAD)\`, rotating which ran first."
    echo "- **Machine state.** Before each of the nine runs: M9's, and a 1-minute load average below 1.0 and XprotectService below 1% CPU, each check logged in \`results/exploratory/$name/headline-rerun/quiet.log\`; each run checked M9's again at its start (its run metadata)."
    echo "- **Where the results go.** \`BENCHMARKS.md\` §8 (exploratory), beside the stopped run. The raw data are archived under \`results/exploratory/$name/headline-rerun/<build>/archive/\`, each pinned by its \`MANIFEST.sha256\`."
    echo
    echo "Configurations re-run: none of the frozen grid."
  } >> BENCH_LOG.md
fi
echo "headline-rerun: done; \`dc-bench ceiling-report --name $name\` prints the block, re-run included"
