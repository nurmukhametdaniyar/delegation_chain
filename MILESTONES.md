# Milestones

Progress log (SPEC §15). Read this first to see where the last session stopped.

**Current state:** see the last entry below.

---

## Pre-M0 — spec review (2026-09-28)

- **Done:**
  - Read SPEC.md and paper §3–§8, Algorithms 1–2 and Table 1 (revision 2026-09-28, sha256 `bd94cef2…2e81e`).
  - Probed the dependency build on this machine.
  - Reported the review. The author answered, and the agreed changes were applied to SPEC.md in one commit, with a changelog at its top.
- **Decisions added:** D-28 to D-47.
- **Paper issues found:** P-15 to P-25.
  - P-15, a containment soundness bug, was confirmed with a throwaway model.
  - The author is fixing P-15, P-16 and P-17 in the next paper revision.
- **Constraint for later sessions:** M0 to M3 do not depend on the paper revision. **M4 must not start until `docs/paper.pdf` is the revision that fixes P-15. If it is not there yet, stop and ask** (SPEC §15).
- **Commits:** `e223f05` (import), `7aaa327` (SPEC changes).

## M0 — scaffold (2026-09-28)

- **Done:**
  - Initialised the git repository on `main`.
  - Created the workspace: a root package `delegationchain` (D-46) plus nine empty crates under `crates/`, pinned to rustc 1.97.1, edition 2024 (D-47). `unsafe_code` is denied workspace-wide (D-48).
  - Added CI: `.github/workflows/ci.yml` runs fmt, clippy, tests and the unsafe check on Linux and macOS. `scripts/ci.sh` runs the same checks locally, and `scripts/check-unsafe.sh` enforces SPEC §0 rule 9.
  - Created the docs:
    - `DECISIONS.md`: D-01 to D-48;
    - `PAPER_ISSUES.md`: the open Appendix C issues plus P-15 to P-25;
    - `QUESTIONS.md`, `BENCH_LOG.md`, and placeholders for `BENCH_PLAN_FROZEN.md` and `BENCHMARKS.md`.
- **Verified:** `scripts/ci.sh` passes on the empty workspace. `scripts/check-unsafe.sh` was also shown to fail on a stray `allow(unsafe_code)`.
- **Not verified:** the GitHub workflow itself. The repository has no remote, so "CI green" at M0 means the same commands pass locally.
- **Decisions added:** D-48 (the mechanical `unsafe` policy). The rest were logged from SPEC.
- **Paper issues found:** none beyond the pre-M0 review.

## M1 — `dc-cbor` (2026-09-28)

- **Done:**
  - Strict deterministic CBOR subset (SPEC §4): a `Value` model, a canonical encoder, a single-pass decoder, NFC helpers for parameter maps, and a reader for uint-keyed protocol structures (D-01).
  - The decoder fails on malformed input and records the first canonical-form violation (D-31). `decode_strict` rejects both. The encoder refuses anything the decoder would reject: out-of-range integers, duplicate keys, too-deep nesting.
- **Tests:** 25 hand-written vectors and 5 property tests (4,096 cases each).
  - Vectors: every §4.4 rejection rule with its exact error; every canonical-form violation, checked as recorded, strictly rejected, and re-encoding differently; and accepted boundary values at every argument width.
  - Properties:
    - `decode(encode(x)) == x`;
    - key order equals encoded-byte order;
    - for deliberately non-canonical encodings, a violation is recorded exactly when the bytes differ from the canonical encoding;
    - for mutated inputs, `decode_strict` acceptance implies `encode(decode(b)) == b`;
    - arbitrary bytes never panic.
  - A one-off count (not committed) confirmed that the properties are not vacuous: 3,285 of 4,096 variant encodings were non-canonical, and 748 of 4,096 mutations decoded.
- **Test fixes:** two of my own vectors were wrong and were corrected. `8201…` had been truncated to a valid array, and a truncation offset was off by one. No assertion was weakened.
- **Not done:** the optional `cargo-fuzz` target (§4.5, §11.4). It is deferred to §11.4's "if time allows".
- **Decisions added:** D-49 (map key types). D-02 was made precise: containers are counted, and the top-level container is depth 1.
- **Paper issues found:** none.

## M2 — `dc-crypto` and `dc-types` (2026-09-29)

- **Done:**
  - `dc-crypto`:
    - `SigScheme`/`ChainScheme` (D-52), and BLS via `blst::min_pk`, with validated parsing (length first, compressed only, subgroup and identity checks via library calls).
    - Arm A's `BlsAggregate`: `aggregate_verify(false, …, pks_validate = false)` (D-05, D-30).
    - Ed25519 behind the `variant-ed25519` feature, with weak-key rejection.
    - The `blst-no-threads` default feature, and the `BLST_THREADED` constant (D-29). `blst` is re-exported, so that no other crate depends on it.
  - `dc-types`:
    - principals and identifiers (D-08, D-51);
    - every digest of §5.4, with position-determined chain tags;
    - the three bodies, decoded by their own kind field (D-32), with canonical-form violations recorded (D-31);
    - parameters with NFC (`Canon` normalizes);
    - receipts (D-14, D-15, D-34, D-50);
    - certificates, which also reject a kind that does not match the identifier (SPEC §6.3);
    - revocation assertions, PoP challenges, the envelope (D-16), and the clock.
  - Scopes are carried as raw CBOR until `dc-policy` exists (M4).
- **Tests:**
  - `dc-crypto`, 17 tests:
    - round trips and DST separation (5×5);
    - rejection of the identity, off-subgroup points (found by searching small x-coordinates), off-curve points, uncompressed forms and wrong lengths;
    - aggregate negatives: wrong message, key, missing or extra pair, and permuted messages;
    - a test pinning that `blst` accepts duplicate messages, so line 48 is the only distinctness check;
    - Ed25519 weak keys and non-canonical `s`.
  - `dc-types`, 27 tests:
    - 23 structure tests, including every malformed-field class, non-NFC parameters recorded as a violation, receipt-list rules, and the invocation digest excluding receipts;
    - 2 property tests (1,024 cases): round trip with random parameters, and consistent classification of mutated bodies;
    - 2 regression-vector tests.
- **Regression vectors:** `tests/vectors/bls.json` and `tests/vectors/ed25519.json`, labelled "regression, not normative". They were generated once and are compared on every run. The BLS test also decodes the committed envelope and verifies its aggregate.
- **CI:** added `scripts/check-deps.sh`:
  - only `dc-crypto` depends on `blst` (D-29);
  - no protocol crate's normal dependency graph enables a `variant-*` feature (SPEC §0 rule 3).
- **Decisions added:** D-50 (non-canonical nested structures are malformed), D-51 (principal checks at decode), D-52 (trait split).
- **Paper issues found:** none new.
