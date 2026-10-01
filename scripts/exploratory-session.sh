#!/usr/bin/env bash
# The exploratory session (not pre-registered; BENCHMARKS.md §8), from one
# terminal:
#   1. the phase breakdown of warm verification (D-77);
#   2. AIP's own chained-mode benchmark at its arXiv commit, unmodified, on
#      this machine (D-79).
#
# Everything is built first: fetching AIP's code and crates needs the
# network, and no build runs during a measurement. Each measurement then
# checks M9's machine state itself (AC power, High Power mode, an idle
# machine), records it in its env.json, and aborts if it does not hold.
#
# Usage: scripts/exploratory-session.sh [--mode dry]
#   --mode dry   10 iterations, one run each, written under results/dry-run/;
#                no machine-state requirement. Its numbers are never reported.
set -euo pipefail
cd "$(dirname "$0")/.."

mode=(--mode full)
if [[ "${1:-}" == "--mode" && "${2:-}" == "dry" ]]; then
  mode=(--mode dry)
fi

AIP_URL=https://github.com/sunilp/aip.git
AIP_COMMIT=ad2faa62420af75ca26b235fb698a671281d1ade
AIP_DIR=target/exploratory/aip
BIN=target/phase-timing/release/dc-bench

echo "== build: dc-bench with phase-timing (RUSTFLAGS=\"-C target-cpu=native\", as M9)"
RUSTFLAGS="-C target-cpu=native" cargo build --release -p dc-bench \
  --features phase-timing --target-dir target/phase-timing

echo "== build: AIP at ${AIP_COMMIT:0:7}, unmodified and with the timings patch"
mkdir -p "$AIP_DIR"
if [[ ! -d "$AIP_DIR/repo/.git" ]]; then
  git clone -q "$AIP_URL" "$AIP_DIR/repo"
fi
if ! git -C "$AIP_DIR/repo" cat-file -e "$AIP_COMMIT^{commit}" 2>/dev/null; then
  git -C "$AIP_DIR/repo" fetch -q origin
fi
rm -rf "$AIP_DIR/unmodified" "$AIP_DIR/timings"
for v in unmodified timings; do
  mkdir -p "$AIP_DIR/$v"
  git -C "$AIP_DIR/repo" archive "$AIP_COMMIT" rust | tar -x -C "$AIP_DIR/$v"
done
patch -s -p1 -d "$AIP_DIR/timings" < scripts/aip-timings.patch
# AIP commits no Cargo.lock: Cargo resolves the versions here, once, and the
# timings copy reuses that lock file. AIP records no build flags, so both
# copies are built with `cargo build --release` and no RUSTFLAGS. The
# toolchain is this repository's pinned one (rust-toolchain.toml).
(cd "$AIP_DIR/unmodified/rust" &&
  env -u RUSTFLAGS -u CARGO_TARGET_DIR cargo build -q --release --bin bench_chained)
cp "$AIP_DIR/unmodified/rust/Cargo.lock" "$AIP_DIR/timings/rust/Cargo.lock"
(cd "$AIP_DIR/timings/rust" &&
  env -u RUSTFLAGS -u CARGO_TARGET_DIR cargo build -q --release --locked --bin bench_chained)

echo "== 1 of 2: the phase breakdown (dc-bench phases)"
"$BIN" phases "${mode[@]}"

echo "== 2 of 2: AIP's benchmark (dc-bench aip)"
"$BIN" aip "${mode[@]}" --aip-dir "$AIP_DIR"

echo "== done. Both runs appended their BENCH_LOG.md entries; the new files are under results/exploratory/."
