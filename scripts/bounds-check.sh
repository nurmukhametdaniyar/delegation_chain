#!/usr/bin/env bash
# The exploratory criterion pass for Contains at the scope-size bounds
# (D-95; not pre-registered): `benches/bounds.rs`, with M9's build flags, on
# M9's machine state, into results/exploratory/bounds/. It records the
# machine in env.json, packs criterion's output as criterion.tar.zst with a
# SHA-256 file, and appends a BENCH_LOG.md entry.
#
# M9's machine state is AC power, High Power mode and an idle machine. The
# script checks them with `dc-bench env`'s record of M9's requirements,
# waiting up to 10 minutes for the machine to become idle after the build,
# as the harness does. The largest cell takes minutes per call, so the pass
# takes about an hour and a quarter.
#
# Usage: scripts/bounds-check.sh
set -euo pipefail
cd "$(dirname "$0")/.."

out=results/exploratory/bounds
if [[ -n "$(git status --porcelain --untracked-files=no)" ]]; then
  echo "bounds-check: commit first; env.json names the measured commit" >&2
  exit 1
fi
if [[ -e "$out/criterion.tar.zst" ]]; then
  echo "bounds-check: $out/criterion.tar.zst exists; refusing to overwrite measured data" >&2
  exit 1
fi
if ! pmset -g batt | grep -q "AC Power" || ! pmset -g | grep -Eq '^ *powermode +2'; then
  echo "bounds-check: needs AC power and High Power mode (pmset powermode 2)" >&2
  exit 1
fi

export RUSTFLAGS="-C target-cpu=native"
echo "== build"
cargo bench -q -p dc-bench --bench bounds --no-run
cargo build -q --release -p dc-bench --bin dc-bench
mkdir -p "$out"
ok() {
  python3 -I -c 'import json, sys; sys.exit(0 if json.load(open(sys.argv[1]))["m9_requirements"]["ok"] is True else 1)' "$1"
}
for i in $(seq 40); do
  ./target/release/dc-bench env --out "$out" >/dev/null
  if ok "$out/env.json"; then
    break
  fi
  if [[ $i == 40 ]]; then
    echo "bounds-check: the machine did not become idle within 10 minutes" >&2
    exit 1
  fi
  echo "bounds-check: waiting for the machine to become idle"
  sleep 15
done
echo "== bench (D-95)"
# Absolute: cargo runs a bench from its package directory, so a relative
# CRITERION_HOME lands under crates/dc-bench/.
CRITERION_HOME="$PWD/$out/criterion" cargo bench -q -p dc-bench --bench bounds -- --noplot
COPYFILE_DISABLE=1 tar -C "$out" -cf - criterion | zstd -q -19 -o "$out/criterion.tar.zst"
(cd "$out" && shasum -a 256 criterion.tar.zst > criterion.tar.zst.sha256)
{
  echo
  echo "## $(date -u +%Y-%m-%d) — Exploratory run (not pre-registered): Contains at the scope-size bounds"
  echo "Reason: after D-94 the author asked what the scope-size bounds still let a compromised signer force (D-95)."
  echo "- **What ran.** \`scripts/bounds-check.sh\`: \`cargo bench -p dc-bench --bench bounds\` at \`$(git rev-parse --short HEAD)\`, with \`target-cpu=native\` as M9, ten samples of one call each per cell."
  echo "- **Machine state.** AC power and High Power mode, checked with pmset and recorded in \`results/exploratory/bounds/env.json\`."
  echo "- **Where the results go.** \`BENCHMARKS.md\` §8 (exploratory) only. Criterion's output is \`results/exploratory/bounds/criterion.tar.zst\`, pinned by its \`.sha256\`."
  echo
  echo "Configurations re-run: none."
} >> BENCH_LOG.md
echo "bounds-check: done"
