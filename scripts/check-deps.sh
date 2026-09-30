#!/usr/bin/env bash
# Dependency policy.
# 1. Only dc-crypto depends on blst, so that its threading mode is controlled
#    in one place (D-29).
# 2. VARIANT code never reaches the default protocol path (SPEC §0 rule 3):
#    the protocol crates' normal dependency graphs must not enable any
#    `variant-*` feature of dc-crypto.
# 3. The registry's `test-hooks` feature (a compromised root, for the T5b
#    and T5d tests) is never enabled on a normal dependency graph.
set -euo pipefail
cd "$(dirname "$0")/.."
status=0

for manifest in Cargo.toml crates/*/Cargo.toml; do
  [[ "$manifest" == "crates/dc-crypto/Cargo.toml" || "$manifest" == "Cargo.toml" ]] && continue
  # A dependency key `blst = …` or `blst.workspace = …`; not a feature such
  # as `blst-no-threads`.
  if grep -Eq '^blst *(=|\.)' "$manifest"; then
    echo "check-deps: $manifest depends on blst directly (D-29)" >&2
    status=1
  fi
done

protocol=(dc-cbor dc-types dc-crypto dc-policy dc-registry dc-chain dc-verifier)
for crate in "${protocol[@]}"; do
  graph=$(cargo tree -q -p "$crate" -e normal -f '{p} {f}' 2>/dev/null)
  if grep -E 'dc-crypto .*variant-' <<<"$graph" >/dev/null; then
    echo "check-deps: $crate's default graph enables a dc-crypto variant feature" >&2
    status=1
  fi
  # 3. Test hooks stay out of normal graphs, and so does operation counting
  #    (SPEC §10.3), so that no protocol crate's default build is
  #    instrumented.
  if grep -E 'test-hooks|count-ops' <<<"$graph" >/dev/null; then
    echo "check-deps: $crate's default graph enables test-hooks or count-ops" >&2
    status=1
  fi
done

exit $status
