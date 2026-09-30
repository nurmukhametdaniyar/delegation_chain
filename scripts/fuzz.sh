#!/usr/bin/env bash
# The dc-cbor decoder fuzz target on the pinned stable toolchain, with the
# coverage instrumentation cargo-fuzz uses (D-74). Usage: scripts/fuzz.sh [seconds]
set -euo pipefail
cd "$(dirname "$0")/../fuzz"
secs="${1:-600}"
host=$(rustc -vV | sed -n 's/^host: //p')
export RUSTFLAGS="--cfg fuzzing -Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-level=4 \
-Cllvm-args=-sanitizer-coverage-inline-8bit-counters -Cllvm-args=-sanitizer-coverage-pc-table \
-Cllvm-args=-sanitizer-coverage-trace-compares"
if [[ "$(uname)" == "Darwin" ]]; then
  # Build libFuzzer's C++ against the SDK only (D-74).
  export CXXFLAGS="-isysroot $(xcrun --show-sdk-path)"
fi
cargo build --release --target "$host" --bin cbor_decode
mkdir -p corpus-work artifacts
"./target/$host/release/cbor_decode" corpus-work corpus/cbor_decode \
  -artifact_prefix=artifacts/ -max_total_time="$secs" -print_final_stats=1
