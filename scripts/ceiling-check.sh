#!/usr/bin/env bash
# The exploratory measurement of D-101's unit (not pre-registered).
# Into results/exploratory/ceiling/:
#   work.json           `dc-bench ceiling-counts`: each probe's charge, the
#                       admitted shapes and the proposed limits, the bodies
#                       under them, every search input's count, and the
#                       workload profiles' largest counts (deterministic)
#   oracle.json         the differential oracle, 150,000 pairs, seed 56324,
#                       with the budgeted procedure (test statistics)
#   criterion.tar.zst   criterion's output for benches/ceiling.rs: each
#                       charged operation class at the size bounds, the fixed
#                       per-call cost, every search input at the default
#                       budget, and lines 2 and 5 under the proposed limits,
#                       with its .sha256
#   env.json            the machine, after the criterion pass
#   headline/<build>/   D-96's four headline cells (B and D warm+prefix, A
#                       and C warm; N = 3, medium), by `dc-bench run` in three
#                       builds, three runs each, rotating which goes first:
#                         measured    b175599, M9's resume commit
#                         pre-budget  2df8b53, D-94 and D-97 without the budget
#                         budgeted    HEAD, which must be committed with D-101
#                       each with env.json and archive/ under its manifest
# and a BENCH_LOG.md entry.
#
# Everything is built first, with M9's flags, the three headline builds in
# their own git worktrees under target/exploratory/ceiling/. The counts and
# the oracle run next, before the machine has to be idle. Then M9's machine
# state (AC power, High Power mode, an idle machine) is awaited with `dc-bench
# env`, and the timings run: the criterion pass, then, once the machine is
# idle again, the nine headline runs, each of which checks M9's machine state
# itself. It takes about an hour.
#
# An attempt that stops before the criterion pass (the machine never became
# idle, say) leaves only the deterministic files and its machine record, and
# running the script again starts over. Once criterion's output or a
# headline run exists, the script refuses to overwrite it.
#
# Usage: scripts/ceiling-check.sh [--dry] [--wait MINUTES] [--name NAME]
#   --dry       criterion's shortest times and 10-iteration headline runs,
#               under results/dry-run/; no machine-state requirement. Its
#               numbers are never reported.
#   --wait M    how long to wait for an idle machine, each time (default 10).
#   --name N    the directory under results/exploratory/ and
#               target/exploratory/ (default `ceiling`, D-101's first run;
#               `ceiling2` is D-102's).
set -euo pipefail
cd "$(dirname "$0")/.."
root=$(pwd)

dry=0
mode=full
wait_min=10
name=ceiling
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
      echo "usage: scripts/ceiling-check.sh [--dry] [--wait MINUTES] [--name NAME]" >&2
      exit 2
      ;;
  esac
  shift
done
out=results/exploratory/$name
root_out=results
if [[ $dry == 1 ]]; then
  out=results/dry-run/exploratory/$name
  root_out=results/dry-run
fi

if [[ -n "$(git status --porcelain --untracked-files=no)" ]]; then
  echo "ceiling-check: commit first; the budgeted build is HEAD" >&2
  exit 1
fi
if ! grep -q 'pub fn size' crates/dc-policy/src/meter.rs; then
  echo "ceiling-check: HEAD does not have D-101's unit" >&2
  exit 1
fi
if [[ $dry == 0 && (-e "$out/criterion" || -e "$out/criterion.tar.zst" || -e "$out/headline") ]]; then
  echo "ceiling-check: $out holds measured data; refusing to overwrite it" >&2
  exit 1
fi
# Nothing measured: at most an earlier attempt's deterministic files and
# machine record, which this run writes again.
rm -rf "$out"
mkdir -p "$out"
abs_out="$root/$out"

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
echo "== build: HEAD's bench and harness"
cargo bench -q -p dc-bench --bench ceiling --no-run
cargo build -q --release -p dc-bench --bin dc-bench
cargo test -q --release -p dc-policy --test oracle --no-run
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

echo "== 1 of 4: the counts (deterministic)"
./target/release/dc-bench ceiling-counts --out "$root_out" --name "$name"
echo "== 2 of 4: the differential oracle, 150,000 pairs (test statistics)"
DC_ORACLE_CASES=150000 DC_ORACLE_LOGIC_CASES=150000 DC_ORACLE_SEED=56324 \
  DC_ORACLE_REPORT="$abs_out/oracle.json" \
  cargo test -q --release -p dc-policy --test oracle >/dev/null

# What keeps env.json ($1) from M9's machine state, in one line.
not_ready() {
  python3 -I -c '
import json, sys
r = json.load(open(sys.argv[1]))["m9_requirements"]
why = []
if r["ac_power"] is not True:
    why.append("not on AC power")
if r["high_power_mode"] is not True:
    why.append("not in High Power mode")
idle = r["idle"]
if idle["ok"] is not True:
    why.append("load average %.1f" % idle["loadavg_1m"])
    why += ["%s at %.0f%% CPU" % (p["command"].rsplit("/", 1)[-1], p["pcpu"]) for p in idle["busy_processes"]]
print(", ".join(why))
sys.exit(1 if why else 0)
' "$1"
}

# Waits up to $wait_min minutes for M9's machine state, writing env.json
# into $1.
await_idle() {
  [[ $dry == 1 ]] && return 0
  for i in $(seq $((wait_min * 4))); do
    ./target/release/dc-bench env --out "$1" >/dev/null
    if why=$(not_ready "$1/env.json"); then
      return 0
    fi
    echo "ceiling-check: waiting for the machine to become idle ($why)"
    sleep 15
  done
  echo "ceiling-check: the machine did not become idle within $wait_min minutes ($why); nothing was measured, and running the script again starts over" >&2
  exit 1
}
await_idle "$out"

echo "== 3 of 4: the classes, the search, and lines 2 and 5 (criterion)"
crit=(--noplot)
if [[ $dry == 1 ]]; then
  crit+=(--warm-up-time 0.01 --measurement-time 0.01 --sample-size 10)
fi
CRITERION_HOME="$abs_out/criterion" cargo bench -q -p dc-bench --bench ceiling -- "${crit[@]}"
if [[ $dry == 0 ]]; then
  # The machine as the criterion pass left it.
  ./target/release/dc-bench env --out "$out" >/dev/null
fi
COPYFILE_DISABLE=1 tar -C "$out" -cf - criterion | zstd -q -19 -o "$out/criterion.tar.zst"
(cd "$out" && shasum -a 256 criterion.tar.zst > criterion.tar.zst.sha256)

echo "== 4 of 4: the headline cells, three builds, three runs"
# The criterion pass kept a core busy; let the load average settle, so that
# the first run's own check does not refuse. Its record is not kept:
# $out/env.json is the machine right after the criterion pass.
await_idle "$(mktemp -d)"
for r in 1 2 3; do
  order=("${builds[@]:$((r - 1))}" "${builds[@]:0:$((r - 1))}")
  for b in "${order[@]}"; do
    echo "== run $r: $b"
    (cd "$(wt_of "$b")" && ./target/release/dc-bench run --run "$r" --mode "$mode" \
      --no-throughput --out "$abs_out/headline/$b" "${cells[@]}")
  done
done
for b in "${builds[@]}"; do
  (cd "$(wt_of "$b")" && ./target/release/dc-bench env --out "$abs_out/headline/$b" >/dev/null)
  ./target/release/dc-bench archive --mode "$mode" --out "$abs_out/headline/$b"
done

if [[ $dry == 0 ]]; then
  {
    echo
    echo "## $(date -u +%Y-%m-%d) — Exploratory run (not pre-registered): the budget's unit, its derived ceiling, and the proposed size limits ($name)"
    echo "Reason: D-101 made the work budget's unit a sound over-approximation of Contains's work, and the author asked for the ceiling it implies, a search against it, size limits aligned with the budget and their unsigned decoding cost, and the headline cells."
    echo "- **What ran.** \`scripts/ceiling-check.sh\` at \`$(git rev-parse --short HEAD)\`, with \`target-cpu=native\` as M9: \`dc-bench ceiling-counts\`, the differential oracle (150,000 pairs, seed 56324), \`benches/ceiling.rs\`, and the frozen grid's B and D warm+prefix and A and C warm configurations at N = 3, medium, by \`dc-bench run\` with M9's counts, three runs, in three builds: measured \`$(commit_of measured)\`, pre-budget \`$(commit_of pre-budget)\` and budgeted \`$(git rev-parse --short HEAD)\`, rotating which ran first."
    echo "- **Machine state.** M9's, awaited before the criterion pass and recorded in \`$out/env.json\` after it; each headline run checked it at its start (its run metadata). Nothing monitored the machine during the criterion pass."
    echo "- **Where the results go.** \`BENCHMARKS.md\` §8 (exploratory) only. Criterion's output is \`$out/criterion.tar.zst\`, pinned by its \`.sha256\`; the headline runs' raw data are archived under \`$out/headline/<build>/archive/\`, each pinned by its \`MANIFEST.sha256\`."
    echo
    echo "Configurations re-run: none."
  } >> BENCH_LOG.md
fi
echo "ceiling-check: done; \`dc-bench ceiling-report --name $name$([[ $dry == 1 ]] && echo ' --mode dry')\` prints this run's block, headline comparison included"
