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

## M3 — `dc-registry` (2026-09-29)

- **Done:**
  - `Registry<S, C>`, generic over the arm's scheme and clock:
    - PoP challenges, with 16-byte single-use nonces from a seeded ChaCha20 generator and a 60 s TTL (D-11);
    - registration with every §6.4 check, in a fixed order, consuming the nonce on the first attempt (D-53);
    - issuance with the D-10 lifetimes, or an explicit validity window for scheduled rotation;
    - serials unique per registry;
    - revocation assertions under the REVOKE DST.
  - `Resolver`, whose in-process implementation returns the latest certificate for (id, pk) whether or not it is valid (D-26). `Directory` routes a lookup to the identifier's organization.
  - `PolicyStore`, with a content-addressed in-memory store. `WithLatency` wraps a resolver or store with a per-call sleep and a call counter (§13.4).
  - `verify_revocation` and `RevocationSet`, which the verifier's `ingest_revocation` will use at M6.
  - `test-hooks` feature: a root that signs anything, for T5b and T5d (D-54).
- **Tests:** 15 tests, with the registry tests run for both BLS and Ed25519.
  - PoP success;
  - every failure path: unknown nonce, used nonce, nonce consumed by a failed attempt, the 60/61 s expiry boundary, altered challenge, T5a misattribution, wrong organization, kind mismatch, service kind, identity or weak key;
  - PoP under the CHAIN DST rejected (BLS). For Ed25519, which has no DSTs, the analogue is a PoP over a chain-tagged digest;
  - reproducible nonces;
  - scheduled rotation with two overlapping certificates, each resolved by its key;
  - D-26 resolution: an expired or revoked certificate is still returned, a newer certificate for the same binding wins, and an unknown binding gives `None`;
  - directory routing;
  - revocation ingestion (correct root, wrong root, unknown organization, tampered assertion);
  - the policy store, injected latency, and the compromised-root hook.
- **CI:** `scripts/check-deps.sh` now also keeps `test-hooks` out of the protocol crates' normal dependency graphs.
- **Decisions added:** D-53 (registration procedure), D-54 (test hooks).
- **Paper issues found:** none new.
- **Next:** M4 (`dc-policy`) needs the paper revision that fixes P-15. As of this entry, `docs/paper.pdf` is still revision 2026-09-28 (sha256 `bd94cef2…2e81e`), so work stops here, and the question is in `QUESTIONS.md`.

## Reconciliation with paper revision 2026-09-29 (2026-09-29)

- **Paper:** revision 2026-09-29, 44 pages, sha256 `51eff0ec620940c3062de303f671f5ddeee9907ddb3c06c46e19fc1b6da84e14`. It replaces revision 2026-09-28 (sha256 `bd94cef2…2e81e`), which remains in git history at commit `e223f05`.
- **Algorithms 1–2:** compared line by line from the rendered pages 14–15. Numbering is unchanged (1–52). Only four lines changed:
  - lines 18 and 20: identifier and key pairs, matching D-36;
  - line 27: "not yet valid, expired, or revoked", matching D-35;
  - line 41: gains "reject if unresolvable", which changes D-27.
  SPEC Appendix A now reproduces revision 2026-09-29.
- **Decisions that ran ahead of the paper:** D-28 (§6.1 well-formedness, condition 1), D-35 (line 27) and D-36 (lines 18 and 20) all match the paper now. The SPEC §2 exception is closed.
- **§6.1 against D-17 and D-20:** same meaning.
  - The lexical details equal D-17 plus D-08. They add that string literals are NFC-normalized, which is now in D-17, with the AST side logged as D-55.
  - The well-formedness table equals D-20. The paper writes "any" as the path type of `==` and `in`, and says the declared type decides `==`; both agree with D-20.
- **Other sections diffed** (the Proposition 2 proof, §3.3, §4.3, §4.5, §4.6, §5.2, §5.4, §6.1, §6.4, §7.3, Theorems 5 and 6):
  - 16 issues resolved: P-03, P-07, P-09, P-10, P-14, P-15 to P-25;
  - 4 still open: P-05, P-06, P-08, P-12;
  - 1 new: P-26 (line 27 does not state its boundary).
- **Decisions changed:** D-27, because the paper wins: an unresolvable approver is now `L41`, and two §11.2 rows moved from L42 to L41.
- **Decisions added:** D-55 (NFC scope text). Sixteen decisions gained a "Paper status" line.
- **Benchmark impact:** §4.6 no longer claims that the variation with N is small for N ≤ 10. SPEC §13.1 Q3 and §13.11 now check the revised claim, which leaves the dominant term to measurement.
- **No decision needed the author.** Nothing in the revision weakens soundness relative to the decisions.

## M4 — `dc-policy` (2026-09-29)

- **Paper:** revision 2026-09-29 (reconciled above).
- **Done:**
  - The AST, and its canonical CBOR form (D-18, D-33, D-56).
  - Well-formedness exactly as paper §6.1 states it: every where-path declared (D-28), no path declared twice or as a strict prefix of another (D-19), the operator/type table (D-20), `at` and `approval` kinds. Also the size limits (D-21).
  - The text parser and printer (D-17, with NFC string literals, and contextual keywords per D-56).
  - `Evaluate`, closed world, per paper §6.3 (D-22, D-23).
  - `implies`/`unsat`: exact for int, bool, and strings with a finite set; sound but incomplete otherwise (D-57, P-08).
  - `Contains`, with the paper's defensive malformed ⇒ false check (§6.4).
  - Policy-document decoding for line 31 (D-12, D-55, D-56).
  - `dc-types` gained D-55: non-NFC scope text in a body is a canonical-form violation (L05).
- **Tests:** 18 fixed tests and 2 property tests (the oracle, and text/CBOR round trips).
  - The fixed tests cover: the §6.2 example verbatim and its five SPEC decisions; Remark 1; reflexivity, including the recommended order; the D-24 special forms; step-3(b) approval retention; every well-formedness rule and size limit; AST-level rules; strict policy decoding; lexical details; contextual keywords; closed-world evaluation and `under`.
  - **P-15 regression.** The child scope, the parent-side variant and a bool-tautology variant are all rejected as malformed, from text and from CBOR. With the check off (`test-hooks`), the pre-review procedure returns true on both P-15 pairs, and a concrete invocation shows each is not contained. With the check on, `contains` refuses both.
- **Differential oracle, first M4 record run** (release build; seed 56324; superseded by the 64-shard re-run under "M4 follow-up" below, because shard seeds then depended on the core count; statistics generated into `docs/test-reports/policy-oracle-m4.json`, figures below copied from it):
  - cases: 150000; well-formed pairs: 108133.
  - Malformed scopes rejected: 49802, all as independently predicted. The generator produced 54030 undeclared-path atoms and 8385 non-canonical `under` literals.
  - soundness violations: 0; reflexivity failures: 0 of 250198 checks.
  - `Contains` completeness overall: 0.921 (47802/51911).
  - `implies`/`unsat` completeness by type, with zero soundness violations for every type:
    - int: 1.000 (77688/77688) / 1.000 (60889/60889);
    - bool: 1.000 (93525/93525) / 1.000 (54941/54941);
    - string with a finite set: 1.000 (53606/53606) / 1.000 (51565/51565);
    - string without a finite set: 0.841 (13687/16269) / 0.743 (8739/11763). Against the richer string domain: 0.919 (13687/14891) / 0.855 (8739/10220).
  - Mutation check: three planted bugs, all caught (D-58).
- **CI:** the extended profile (150,000 pairs, plus 150,000 cases per type) now runs in `scripts/ci.sh` and in the workflow.
- **Decisions added:** D-55 (at the reconciliation), D-56, D-57, D-58.
- **Paper issues found:** none new. P-08's entry now records the measured string completeness.

## M4 follow-up (2026-09-29)

- **Reproducibility:** the oracle now uses 64 fixed shards on a thread pool (D-58). The record run was repeated with 14 threads and with 3 threads, and the reports matched apart from elapsed time. `docs/test-reports/policy-oracle-m4.json` was replaced with this run.
- **Record run** (seed 56324; figures generated from the JSON):
  - cases 150000; well-formed pairs 108370;
  - soundness violations 0; reflexivity failures 0 of 250533.
  - `Contains` completeness: 0.920 (47822/51998) overall, and 0.999 (36156/36188) when S2 has no unsatisfiable rule.
  - `implies`/`unsat` by type:
    - int: 1.000 (78059/78059) / 1.000 (61273/61273);
    - bool: 1.000 (93335/93335) / 1.000 (54708/54708);
    - string with a finite set: 1.000 (53123/53123) / 1.000 (51099/51099);
    - string without: 0.838 (13718/16367) / 0.740 (8762/11843), and against the richer string set 0.914 (13718/15014) / 0.848 (8762/10328).
- **Miss causes** (4176 misses):
  - unsatisfiable child rule: 4138;
  - child rule fully shadowed: 23;
  - step 3(b): 11, all with the joint region decided by earlier child rules;
  - string implication: 3 (1 holding on the richer string set, 2 artifacts);
  - union of rules (Remark 1): 1;
  - int/bool anomalies: 0.
  Step 3(b) is a measurable share (11 of the 38 misses that remain once unsatisfiable child rules are excluded), so it is logged as P-27, together with dead child rules.
- **String rules:** each sound rule in `logic.rs` (`StrC::unsat`, `StrC::implies`) now carries its one-line soundness argument.
- **Paper issues found:** P-27.

## M5 — `dc-chain` (2026-09-29)

- **Done:** the §8 roles, generic over the arm's scheme:
  - `IssuanceService`;
  - `SigningService`, which checks identifier and key, runs the enforcement hook (P-12) and computes m_k itself;
  - `ApprovalService`, which signs over InvocationDigest with a 300 s window.
  - `ChainBuilder<C: ChainScheme>` follows SPEC §8.3, including evaluating the holder's own scope to find the required approvals, and sorting receipts (D-15). Receipts are the aggregate for arm A, a list for the others.
  - `assemble`/`combine`: attacker-style signing for the security suite (D-59).
  - `World`: a deterministic fixture of organizations, registries (one `Directory`), keys and a policy store.
- **Smoke test ("chains verify end-to-end"):** the verifier arrives at M6, so the test performs its core by hand, for a three-hop chain built from the paper's §6.2 policy with each hop tightening rule 1. It checks:
  - canonical decode and round trip of every body, and the recomputed digests;
  - every signer's certificate, resolved through the registries and verified under its root;
  - the BLS aggregate, every containment link (policy ⊇ session ⊇ delegations), and `Evaluate`: allow for 500, allow-with-approval for 5,000, with the finance receipt verifying over InvocationDigest.
  - Also: tampering breaks the aggregate, the builder refuses a denied invocation, the signing service refuses foreign or session bodies, an enforcement policy can refuse, and one seed gives byte-identical chains.
  - 6 tests.
- **Decisions added:** D-59.
- **Paper issues found:** none.
