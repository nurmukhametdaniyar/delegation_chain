#!/usr/bin/env bash
# Dependency policy.
# 1. Only dc-crypto depends on blst, so that its threading mode is controlled
#    in one place (D-29).
# 2. VARIANT code never reaches the default protocol path (SPEC §0 rule 3):
#    the protocol crates' normal dependency graphs enable no `variant-*`
#    feature of dc-crypto. Since the default instantiation is Ed25519 per hop
#    and BLS is the aggregate variant (paper §4.2, §4.8; D-80), blst is not in
#    those graphs at all, and ed25519-dalek is.
# 3. Instrumentation and test hooks stay out of normal graphs: the registry's
#    `test-hooks` (a compromised root, for the T5b and T5d tests), operation
#    counting and phase timing (SPEC §10.3; D-77).
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
  # 2. The BLS variant's library is not on the protocol path (D-80).
  if grep -E '(^|[^a-z_-])blst v' <<<"$graph" >/dev/null; then
    echo "check-deps: $crate's default graph contains blst, the aggregate variant's library (D-80)" >&2
    status=1
  fi
  # 3. Instrumentation and test hooks stay out of normal graphs, so that no
  #    protocol crate's default build is instrumented.
  if grep -E 'test-hooks|count-ops|phase-timing' <<<"$graph" >/dev/null; then
    echo "check-deps: $crate's default graph enables test-hooks, count-ops or phase-timing" >&2
    status=1
  fi
done

# 2. The default instantiation's library is on the protocol path.
if ! cargo tree -q -p dc-crypto -e normal 2>/dev/null | grep -q 'ed25519-dalek v'; then
  echo "check-deps: dc-crypto's default graph lacks ed25519-dalek, the default instantiation (D-80)" >&2
  status=1
fi

exit $status
