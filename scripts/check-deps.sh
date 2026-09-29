#!/usr/bin/env bash
# Dependency policy.
# 1. Only dc-crypto depends on blst, so that its threading mode is controlled
#    in one place (D-29).
# 2. VARIANT code never reaches the default protocol path (SPEC §0 rule 3):
#    the protocol crates' normal dependency graphs must not enable any
#    `variant-*` feature of dc-crypto.
set -euo pipefail
cd "$(dirname "$0")/.."
status=0

for manifest in Cargo.toml crates/*/Cargo.toml; do
  [[ "$manifest" == "crates/dc-crypto/Cargo.toml" || "$manifest" == "Cargo.toml" ]] && continue
  if grep -Eq '^blst' "$manifest"; then
    echo "check-deps: $manifest depends on blst directly (D-29)" >&2
    status=1
  fi
done

protocol=(dc-cbor dc-types dc-crypto dc-policy dc-registry dc-chain dc-verifier)
for crate in "${protocol[@]}"; do
  if cargo tree -q -p "$crate" -e normal -f '{p} {f}' 2>/dev/null | grep -E '^.*dc-crypto .*variant-' >/dev/null; then
    echo "check-deps: $crate's default graph enables a dc-crypto variant feature" >&2
    status=1
  fi
done

exit $status
