#!/usr/bin/env bash
# The MCP expressiveness study (D-105; exploratory): which live-probed MCP
# tools of a pinned MCP-Eco release can a DelegationChain policy authorize?
# Downloads the release's tool table at its frozen revision, verifies its
# SHA-256, classifies every tool (scripts/mcp_expressiveness.py), cross-checks
# the classes against the implementation (dc-mcp-calls), and writes
# results/exploratory/mcp-expressiveness/ and paper/tables/mcp_expressiveness.tex.
#
#   scripts/mcp-expressiveness.sh
#
# MCP_ECO_DIR overrides where the download is kept (default target/mcp-eco).
set -euo pipefail
cd "$(dirname "$0")/.."

DATASET=mcp-research-alliance/mcp-ecosystem
REVISION=c8edfd4bdf51b15ea95d6b0ede5dec97945f398a
FILE=parquet/mcp_tools.parquet
SHA256=ad9adf2a2cd986c6c35aa50b5840392ba3ea005f570f0f98e05c65938c392b16
DATA=${MCP_ECO_DIR:-target/mcp-eco}
OUT=results/exploratory/mcp-expressiveness
WORK=target/mcp-expressiveness
VENV=target/mcp-venv

mkdir -p "$DATA" "$OUT" "$WORK"
if [ ! -f "$DATA/mcp_tools.parquet" ]; then
  curl -fsSL -o "$DATA/mcp_tools.parquet.part" \
    "https://huggingface.co/datasets/$DATASET/resolve/$REVISION/$FILE"
  mv "$DATA/mcp_tools.parquet.part" "$DATA/mcp_tools.parquet"
fi
echo "$SHA256  $DATA/mcp_tools.parquet" | shasum -a 256 -c -

if [ ! -x "$VENV/bin/python" ]; then
  python3 -m venv "$VENV"
  "$VENV/bin/pip" install -q -r scripts/mcp-expressiveness-requirements.txt
fi
PY="$VENV/bin/python -I"

$PY scripts/test_mcp_expressiveness.py
$PY scripts/mcp_expressiveness.py classify --tools "$DATA/mcp_tools.parquet" \
  --dataset "$DATASET" --revision "$REVISION" --file "$FILE" \
  --out "$OUT" --calls "$WORK/calls.jsonl"
cargo build --release -p dc-bench --bin dc-mcp-calls
target/release/dc-mcp-calls < "$WORK/calls.jsonl" > "$WORK/got.jsonl"
$PY scripts/mcp_expressiveness.py crosscheck --calls "$WORK/calls.jsonl" \
  --got "$WORK/got.jsonl" --out "$OUT"
$PY scripts/mcp_expressiveness.py report --out "$OUT" --paper-dir paper

{
  echo "{"
  echo "  \"commit\": \"$(git rev-parse HEAD)\","
  echo "  \"dirty\": $([ -z "$(git status --porcelain -- crates scripts)" ] && echo false || echo true),"
  echo "  \"date_utc\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
  echo "  \"python\": \"$($VENV/bin/python -c 'import sys; print(sys.version.split()[0])')\","
  echo "  \"pyarrow\": \"$($VENV/bin/python -c 'import pyarrow; print(pyarrow.__version__)')\","
  echo "  \"rustc\": \"$(rustc --version)\""
  echo "}"
} > "$OUT/env.json"
cat "$OUT/summary.md"
