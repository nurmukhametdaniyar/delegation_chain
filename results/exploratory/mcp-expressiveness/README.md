# Which MCP tools the policy language can authorize (D-105; exploratory)

Rerun with `scripts/mcp-expressiveness.sh`. `summary.md` holds the numbers;
DECISIONS.md D-105 gives the classes, the schema reading and the cross-check.

`tools.csv.gz` is derived from MCP-Eco: Khalid Tounoussi, Mohammed Sayagh,
Ali Ouni and Yutaro Kashiwa, "MCP-Eco: A Linked Dataset of MCP Servers,
Consumers, and Development Activity", arXiv:2611.06897, 2026; dataset
`mcp-research-alliance/mcp-ecosystem` on Hugging Face, revision
`c8edfd4bdf51b15ea95d6b0ede5dec97945f398a`, licensed CC BY 4.0
(https://creativecommons.org/licenses/by/4.0/). It keeps each probed tool's
server identifier and name from the dataset, adds the SHA-256 of its input
schema and this study's classification, and drops everything else.
