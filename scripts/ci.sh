#!/usr/bin/env bash
# Local equivalent of .github/workflows/ci.yml. The repository has no remote,
# so this is how "CI green" is checked (MILESTONES.md, M0).
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== cargo fmt --check"
cargo fmt --all --check
echo "== cargo clippy --workspace --all-targets -- -D warnings"
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy -p delegationchain --features aggregate-variant --all-targets -- -D warnings
echo "== cargo test --workspace (the default instantiation, Ed25519 per hop)"
cargo test --workspace --no-fail-fast
echo "== the workspace suites over the aggregate variant (D-84)"
cargo test -p delegationchain --features aggregate-variant --no-fail-fast
echo "== phase timing (D-77): clippy and the partition test"
cargo clippy -p dc-bench --features phase-timing --all-targets -- -D warnings
cargo test -q -p dc-crypto --features phase-timing --lib phases
echo "== extended: differential oracle, 150,000 cases (SPEC §9.7)"
DC_ORACLE_CASES=150000 DC_ORACLE_LOGIC_CASES=150000 cargo test --release -q -p dc-policy --test oracle
echo "== scripts/check-unsafe.sh"
scripts/check-unsafe.sh
echo "== scripts/check-deps.sh"
scripts/check-deps.sh
echo "CI: all checks passed"
