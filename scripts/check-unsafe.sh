#!/usr/bin/env bash
# SPEC §0 rule 9 / D-48: `unsafe` is denied workspace-wide. Only the places
# listed below may opt out, and each must be logged in DECISIONS.md.
set -euo pipefail
cd "$(dirname "$0")/.."

allowed=(
  "crates/dc-crypto/src/pairing_cache.rs"   # SPEC §5.7; none expected with blst 0.3.17
  "crates/dc-bench/src/qos.rs"               # SPEC §13.5, D-42
)

status=0

# Every package must inherit the workspace lint table.
for manifest in Cargo.toml crates/*/Cargo.toml; do
  if ! grep -q '^\[lints\]' "$manifest" || ! grep -A1 '^\[lints\]' "$manifest" | grep -q 'workspace = true'; then
    echo "check-unsafe: $manifest does not inherit [workspace.lints]" >&2
    status=1
  fi
done

# No lint table may relax unsafe_code.
if grep -rn --include=Cargo.toml 'unsafe_code *= *"\(allow\|warn\)"' . --exclude-dir=target >/dev/null; then
  echo "check-unsafe: a Cargo.toml relaxes unsafe_code" >&2
  status=1
fi

# Every allow(unsafe_code) must be in an allowed file.
while IFS=: read -r file _; do
  ok=0
  for a in "${allowed[@]}"; do
    [[ "$file" == "./$a" || "$file" == "$a" ]] && ok=1
  done
  if [[ $ok -eq 0 ]]; then
    echo "check-unsafe: allow(unsafe_code) outside the permitted modules: $file" >&2
    status=1
  fi
done < <(grep -rn --include='*.rs' 'allow *( *unsafe_code' . --exclude-dir=target || true)

exit $status
