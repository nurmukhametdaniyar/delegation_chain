#!/usr/bin/env bash
# Local equivalent of .github/workflows/ci.yml. The repository has no remote,
# so this is how "CI green" is checked (MILESTONES.md, M0).
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== cargo fmt --check"
cargo fmt --all --check
echo "== cargo clippy --workspace --all-targets -- -D warnings"
cargo clippy --workspace --all-targets -- -D warnings
echo "== cargo test --workspace"
cargo test --workspace
echo "== scripts/check-unsafe.sh"
scripts/check-unsafe.sh
echo "CI: all checks passed"
