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

## M6 — `dc-verifier` and the security suite (2026-09-29)

- **Done:**
  - `Verifier<C: ChainScheme, R, P, K>` implements Algorithms 1–2 line by line.
    - One `Reject` variant per rejecting line.
    - Bodies are decoded by kind, and scopes and signature points are validated at line 2 (D-28, D-30, D-32). Canonical-form violations are recorded and rejected at line 5, with a re-encoding comparison too (D-31).
    - Identifier-and-key links at lines 18 and 20 (D-36). A closed validity window at line 27 (D-35).
    - The approver's own reject clause at line 41 (D-27). Distinct digests at line 48. The aggregate at line 49.
    - An atomic insert at line 50, with TTL = (exp − t) + 60 s (D-25).
  - Certificate and policy caches, filled during verification (D-37, D-60), plus `VerifierConfig::uncached()`.
  - Revocation ingestion with eviction; pins; the `count-ops` instrumentation (D-63); test hooks for D-31 and line 48.
  - `check_phase8` is public, for Theorem 3.
- **Tests:**
  - `tests/security.rs`: 51 tests covering every SPEC §11.2 row.
  - `tests/concurrency.rs`: Theorem 5.
  - `tests/cache_equivalence.rs`: SPEC §11.3 for the warm state, plus the P-29 probe.
  - `crates/dc-verifier/tests/caches.rs`: nonce-cache semantics.
- **Concurrent replay** (`docs/test-reports/concurrent-replay-m6.json`):
  - 64 threads × 1000 rounds, 64000 verifications;
  - rounds by number of accepts: {'1': 1000};
  - rejected at line 17: 49638; at line 50: 13362; other rejections: 0.
- **Cache equivalence, warm state** (`docs/test-reports/cache-equivalence-m6.json`):
  - 10000 chains, with no disagreement between the uncached and the warm verifier;
  - outcomes: L02 764, L08 267, L09 84, L11 864, L13 780, L15 8, L17 82, L18 319, L20 132, L23 67, L27 1134, L30 723, L32 93, L34 402, L37 1201, L41 7, L43 7, L49 453, accept 2613;
  - events: clock advance 217, new pin 1, revocation 34, rotation 49.
- **Rows not constructible as specified:** one. For the phase-ordering row, SPEC expects 0 pairings for a line-34 rejection. That holds warm; cold, line 24's N+1 certificate verifications are pairings. The test asserts the actual counts (D-61), and the paper's claim is logged as P-28.
- **Findings:**
  - P-28 (above).
  - P-29: renewing a certificate for the same key, then revoking the renewal, makes the warm verifier accept what the uncached one rejects at L27. §11.3's events never renew a key, so the equivalence run passes. A dedicated test records the divergence.
- **CI:** `check-deps.sh` now also keeps `count-ops` off every protocol crate's normal dependency graph.
- **Decisions added:** D-60 to D-64.
- **Paper issues found:** P-28, P-29.

## M6 follow-up — P-29 resolved ahead of the paper (2026-09-29)

- **Done:** binding revocation, as agreed at the M6 checkpoint (D-65):
  - the revocation body gains `identifier` and `pk`, and keeps the serial for audit;
  - `ingest_revocation` checks the namespace and marks (registry, identifier, key) revoked;
  - lines 27 and 42 reject any certificate of a revoked binding, and eviction is by binding;
  - the registry refuses to certify a revoked binding and caps lifetimes at 7 days;
  - verifiers keep revoked bindings for the maximum lifetime;
  - the regression vectors were regenerated (only the revocation-assertion vector changed).
- **Tests:**
  - `renewal_of_the_same_key_then_revocation_diverges` became `renewal_then_revocation_of_the_newer_certificate_rejects_in_both`. Its mirror, `..._of_the_older_certificate_rejects_in_both`, is new; under serial revocation that case accepted even uncached. Both assert L27 from the uncached and the warm verifier, and that the registry refuses to re-certify.
  - New registry tests: refusal of a revoked binding (and acceptance of a new key), the lifetime cap, the retention boundary, and the namespace check.
  - `resolution_returns_the_latest_certificate_valid_or_not` now renews before revoking. Re-certifying after revocation is refused, which is the point of D-65.
- **Cache equivalence, warm state, extended events** (`docs/test-reports/cache-equivalence-d65.json`; the M6 report is kept):
  - 10000 chains, with no disagreement between the uncached and the warm verifier;
  - outcomes: L02 769, L08 292, L09 80, L11 851, L13 839, L15 9, L17 77, L18 319, L20 139, L23 58, L27 1061, L30 728, L32 86, L34 423, L37 1210, L40 2, L41 6, L43 9, L44 2, L49 418, accept 2622;
  - events: clock advance 223, new pin 1, renewal 52, renewal refused (revoked binding) 5, renewal then revocation of the newer certificate 6, renewal then revocation of the older certificate 10, revocation 29, rotation 59.
- **Finding:** P-30. With revocation out of the picture, a same-key renewal can still make the caches change outcomes, because resolution returns the newest certificate even when it is not yet valid or has already expired.
  - A future-dated renewal makes the uncached verifier reject at L27 while the warm one accepts under the older, valid certificate.
  - So does a renewal that expires before the older certificate.
  - Two probe tests record this. The §11.3 run renews from now with the default lifetime, which cannot shorten or defer validity.
- **P-28:** two points added: line-24 verifications are cached per binding, and failures are not cached. The §13.11 verdict is split between warm and cold verifiers.
- **Decisions added:** D-65.
- **Paper issues:** P-29 resolved ahead of the paper; P-30 found.

## M7 — `dc-baselines` (2026-09-29)

- **Done:**
  - Chain schemes A-ind (`BlsIndividual`), C (`Ed25519List`) and C-batch (`Ed25519Batch`), run by the same generic verifier as arm A (D-69). C-batch uses `verify_batch`, whose semantics differ from `verify_strict` (D-66).
  - Arm B's pairing cache, `dc_crypto::pairing_cache` (SPEC §5.7), using only safe `blst` APIs; no `unsafe` anywhere.
  - `PrefixVerifier` (arms B and D, SPEC §12.1), behind dc-verifier's `variant-prefix-cache` (D-67).
    - The default verifier's full path now takes an accept hook (`()` for arms A, A-ind, C and C-batch). Its per-line checks are functions that the hit path shares.
    - Entries are filled only on acceptance, live no longer than the certificate cache's TTL, are evicted when a listed binding is revoked, and are cleared on any pin change.
  - Arm E: biscuit-auth 6.0.0, with the mapping in D-68.
  - The shared test suite is generic over the chain scheme (`ArmSuite<C>`, `Suite` = arm A). `ChainBuilder` is `Clone`, so that one prefix can carry many invocations.
- **§5.7 pairing-cache equivalence** (`docs/test-reports/pairing-cache-equivalence-m7.json`):
  - 10000 randomized chains, 10000 agreeing with `aggregate_verify`, 0 disagreeing;
  - 3345 distinct prefixes, with 4899 checks reusing a cached prefix product;
  - by mutation (accepted/rejected): bit flip in a prefix body 0/934; bit flip in the last body 0/994; extra signature in the aggregate 0/1008; last key replaced 0/1018; last signature by another key 0/1012; last signature over another message 0/1060; prefix key replaced 0/1000; prefix signature by another key 0/1009; signature missing from the aggregate 0/989; valid 976/0;
  - 64 fixed shards; identical counts on 3 and 14 threads.
- **§11.3 equivalence, every configuration** (`docs/test-reports/cache-equivalence-m7-*.json`; D-70): 10,000 chains per family, with no disagreement in any family.
  - **BLS aggregate** (A uncached, A warm, B warm+prefix):
    - outcomes: L02 611, L08 275, L09 46, L11 656, L13 660, L15 653, L17 72, L18 369, L20 550, L23 41, L27 1895, L30 775, L32 70, L34 265, L37 797, L40 17, L41 3, L43 3, L49 259, accept 1983;
    - B warm+prefix: 2346 hits, by outcome: L02 35, L08 59, L09 16, L13 169, L15 196, L17 72, L18 78, L20 104, L27 16, L37 434, L40 8, L41 2, L43 2, L49 128, accept 1027;
    - events: clock advance 187, invocation on a stored prefix 7329, new prefix 2379, pin P2 1, pin P2 again 1, renewal 45, renewal refused (revoked binding) 6, renewal then revocation of the newer certificate 13, renewal then revocation of the older certificate 14, replay 292, revocation 27, rotation 52, unpin P2 1.
  - **Ed25519 list** (C uncached, C warm, C-batch uncached, C-batch warm, D warm+prefix):
    - outcomes: L02 949, L08 269, L09 54, L11 301, L13 633, L15 625, L17 65, L18 208, L20 518, L23 29, L27 1161, L30 904, L32 78, L34 357, L37 1044, L40 22, L43 11, L49 406, accept 2366;
    - D warm+prefix: 2699 hits, by outcome: L02 19, L08 77, L09 19, L13 222, L15 208, L17 63, L18 67, L20 151, L27 17, L37 515, L40 16, L43 4, L49 75, accept 1246;
    - events: clock advance 209, invocation on a stored prefix 7319, new prefix 2389, pin P2 1, pin P2 again 1, renewal 52, renewal refused (revoked binding) 4, renewal then revocation of the newer certificate 12, renewal then revocation of the older certificate 19, replay 292, revocation 28, rotation 66, unpin P2 1.
  - **BLS list** (A-ind uncached, A-ind warm):
    - outcomes: L02 1138, L08 296, L09 40, L11 324, L13 619, L15 583, L17 84, L18 240, L20 494, L23 37, L27 1146, L30 838, L32 44, L34 284, L37 1090, L40 28, L41 5, L43 6, L49 285, accept 2419;
    - events: clock advance 181, invocation on a stored prefix 7316, new prefix 2368, pin P2 1, pin P2 again 1, renewal 48, renewal refused (revoked binding) 1, renewal then revocation of the newer certificate 13, renewal then revocation of the older certificate 12, replay 316, revocation 32, rotation 51, unpin P2 1.
- **Other tests:**
  - `tests/arms.rs` covers warm operation counts per arm at N = 3, arm B's hit (one hash to G2, two Miller loops, one final exponentiation, no resolution, no containment) and arm D's (one Ed25519 verification).
  - It also covers arm D's byte-identical prefix rule, eviction on revocation, clearing on a pin change, the TTL cap, and nothing being cached on a rejection.
  - `crates/dc-baselines/tests/ed25519_batch.rs` covers the C vs C-batch edge cases (D-66).
  - `crates/dc-baselines/tests/biscuit.rs`: arm E runs at depths 0–5, attenuates, fails on expiry, a wrong root, tampering, a wrong type and an undeclared parameter, and agrees with `Evaluate`'s plain Allow on 204 invocations.
- **Departure from SPEC text, for the checkpoint:** a prefix-cache entry's window is also capped at the certificate cache's TTL (D-67). SPEC §12.1 lists only the certificates' and bodies' windows.
- **Decisions added:** D-66 to D-70.
- **Paper issues found:** none new in M7. (P-30 was found while resolving P-29.)

## M8 — `dc-bench` (2026-09-30)

- **Done:**
  - Workloads: small, medium, medium-approval and large; the seeded world; per-set random streams; cross-organizational identity pools (D-71).
  - Arms and states behind one `Subject::verify`: cold, warm, warm+prefix, prefix-miss, Q5's injected latency, and E stateless.
  - The latency harness: sets generated per run, a seeded random order, and rejections, hits and misses asserted. Also Q6 throughput (shared verifier, HdrHistogram p99), Q2 bytes, and Q10 memory in a `stats_alloc` binary (D-72).
  - Criterion benches: primitives, Q7 signing and Q8 policy (D-73).
  - `env.json` capture, including the compile-time `RUSTFLAGS` from a build script.
  - The statistics: type-7 quantiles, a seeded bootstrap with draws kept in order, paired ratios, and the Q3 OLS with bootstrap CIs.
  - The report generator (`summary.md`, `summary.json`) and `scripts/plot.py`, in a venv with pinned requirements. The plots use a validated categorical palette, with a marker and a direct label per series.
  - The one-command `all`, which builds and runs A-mt separately (D-29).
  - The QoS FFI call in `qos.rs`, the one permitted `unsafe`.
- **Dry run** (`--mode dry`, 10 iterations per configuration; results in `results/dry-run/`, not committed, numbers not reported). It completed end to end:
  - all 231 latency configurations (215 in the main build, 16 in the A-mt build), with every verification accepted and every B/D hit or miss as expected;
  - Q5's call counts of 4 resolver calls and 1 policy-store call per cold N = 3 verification, as SPEC §13.4 expects;
  - Q6 (24 rows), Q2, Q10, criterion (92 benchmarks), the summary and five plots.
- **Fuzzing (before M9, as asked):** the `fuzz/` crate with target `cbor_decode`, and `scripts/fuzz.sh` (D-74).
  - The first run found a wrong property, not a decoder bug: decoded `Value`s differ in map order after re-encoding non-canonical input. The property now compares bytes (a fixed point), and the input is kept as a corpus seed.
  - A 10-minute run then found no crash: 111,517,984 executions, 8,875 new corpus units.
- **Draft `BENCH_PLAN_FROZEN.md`,** for the author's approval. Not frozen, not tagged.
- **CI:** `check-deps.sh`'s blst check matched dc-bench's feature `blst-no-threads`, a false positive. It now matches only a `blst` dependency key; a real `blst` dependency is still caught.
- **Environment note:** the machine was on battery for the dry run. The frozen plan requires AC power for full runs.
- **Decisions added:** D-71 to D-74.
- **Paper issues found:** none.

## Pre-freeze changes from the M8 checkpoint (2026-09-30)

- **P-30 resolved ahead of the paper** (D-26, revised).
  - Resolution returns the newest certificate for the binding that is valid at t, and otherwise the newest.
  - `publish_arbitrary` makes its certificate the binding's only one, so the security suite still receives its forged and malformed certificates.
  - `future_dated_renewal_diverges` and `shortening_renewal_diverges` became `future_dated_renewal_agrees` and `shortening_renewal_agrees`, and a registry test covers both renewal kinds.
- **§11.3 equivalence with future-dated and shortening renewals** (`docs/test-reports/cache-equivalence-p30*.json`): 10,000 chains per run, no disagreement in any.
  - **arm A, uncached against warm**:
    - outcomes: L02 810, L08 272, L09 62, L11 863, L13 819, L15 11, L17 71, L18 339, L20 131, L23 67, L27 1263, L30 721, L32 103, L34 337, L37 1167, L40 1, L41 6, L43 14, L49 374, accept 2569;
    - events: clock advance 207, future-dated renewal 28, new pin 1, renewal 42, renewal refused (revoked binding) 8, renewal then revocation of the newer certificate 16, renewal then revocation of the older certificate 18, revocation 26, rotation 64, shortening renewal 29.
  - **bls-aggregate** (A uncached, A warm, B warm+prefix):
    - outcomes: L02 612, L08 298, L09 44, L11 649, L13 583, L15 597, L17 95, L18 401, L20 534, L23 64, L27 846, L30 810, L32 62, L34 371, L37 1084, L40 34, L41 5, L43 9, L49 320, accept 2582;
    - prefix-cache hits: B warm+prefix 3079;
    - events: clock advance 180, future-dated renewal 33, invocation on a stored prefix 7281, new prefix 2393, pin P2 1, pin P2 again 1, renewal 47, renewal refused (revoked binding) 4, renewal then revocation of the newer certificate 17, renewal then revocation of the older certificate 13, replay 326, revocation 27, rotation 55, shortening renewal 27, unpin P2 1.
  - **bls-list** (A-ind uncached, A-ind warm):
    - outcomes: L02 1106, L08 269, L09 39, L11 318, L13 615, L15 594, L17 63, L18 214, L20 557, L23 34, L27 960, L30 810, L32 57, L34 283, L37 1186, L40 23, L41 2, L43 4, L49 320, accept 2546;
    - events: clock advance 193, future-dated renewal 24, invocation on a stored prefix 7311, new prefix 2417, pin P2 1, pin P2 again 1, renewal 48, renewal refused (revoked binding) 7, renewal then revocation of the newer certificate 17, renewal then revocation of the older certificate 20, replay 272, revocation 23, rotation 54, shortening renewal 22, unpin P2 1.
  - **ed25519-list** (C uncached, C warm, C-batch uncached, C-batch warm, D warm+prefix):
    - outcomes: L02 986, L08 286, L09 48, L11 336, L13 588, L15 562, L17 73, L18 196, L20 525, L23 25, L27 1304, L30 795, L32 80, L34 353, L37 1058, L40 33, L41 2, L43 15, L49 390, accept 2345;
    - prefix-cache hits: D warm+prefix 2574;
    - events: clock advance 212, future-dated renewal 29, invocation on a stored prefix 7293, new prefix 2405, pin P2 1, pin P2 again 1, renewal 63, renewal refused (revoked binding) 8, renewal then revocation of the newer certificate 9, renewal then revocation of the older certificate 12, replay 302, revocation 21, rotation 54, shortening renewal 31, unpin P2 1.
- **D-67 approved;** SPEC §12.1 now includes the TTL cap.
- **Plan changes (D-75, `BENCH_PLAN_FROZEN.md`):**
  - a ±10% margin on every ratio verdict, and agreement of all three runs;
  - Q2: A against C with the break-even N, at every N from 1 to 10, medium-approval included;
  - `pmset -g therm` before and after every configuration, with throttled configurations re-run and logged;
  - claims judged against revision 2026-09-29;
  - arm E's 3× sanity rule;
  - AC power, High Power mode and an idle machine, required and recorded in `env.json`;
  - raw CSVs archived with zstd outside git, under a committed SHA-256 manifest that the report verifies.
- **Checked on a dry run:**
  - thermal CSVs for all 239 configurations;
  - archives that verify with `shasum -a 256 -c`;
  - a forced thermal re-run, which replaced its configuration's samples and was marked;
  - a tampered archive, which stopped the report.

## M9 — aborted before running (2026-09-30)

- `bench-freeze` is tagged on `9e57e5c`.
- The first `all` attempt aborted, as the frozen plan requires, before building or measuring anything. `dc-bench`'s check reported:
  - power source Battery, not AC;
  - `powermode 0` (automatic), not 2 (High Power);
  - not idle: a 1-minute load average of 4.09, and XprotectService at 38% CPU.
- No measured number exists. M9 resumes with `RUSTFLAGS="-C target-cpu=native" cargo run --release -p dc-bench -- all` once the machine is on AC power, in High Power mode, and idle. M10 waits for M9's results.

## Pre-measurement amendments, `bench-freeze-2` (2026-09-30)

- **Amendment 1: the calibration probe** (D-76, frozen plan §5).
  - The workload: 100 BLS verifications and 1,000 Ed25519 `verify_strict` calls on fixed inputs.
  - A baseline of 5 probes after the settle; probes before and after every configuration, Q6 included.
  - A configuration is flagged if a probe is more than 5% slower than the baseline, or if pmset records a warning.
  - Flagged configurations are re-run and logged, naming the signal and whether the re-run was flagged again.
  - The safety valve: more than 10% flagged aborts the run.
  - Every probe time is in `run*-thermal.csv`, and the summary counts flagged configurations by signal.
- **Amendment 2:** the stale §8 line on D-67 is corrected.
- **Both are logged in `BENCH_LOG.md`** as made before any measurement. The plan's status line names `bench-freeze-2`, and `bench-freeze` is unchanged.
- **Dry run on battery** (numbers not reported). The probe path, the re-runs, the BENCH_LOG entries (written to `results/dry-run/BENCH_LOG.dry.md`) and the summary all worked. One systematic effect, for the author:
  - The "after" probe that follows a Q5 injected-latency configuration (1, 20 or 80 ms per call; the measuring thread mostly sleeps) ran 9–39% slower than the baseline. That flagged 5 of the 239 main-run configurations, and their re-runs were flagged again, by the probe only.
  - Every other probe in the main run was within 4% of the baseline (462 probes, median 0.993).
  - This looks like the CPU ramping back up from idle, not throttling. Under the rule as frozen, Q5's sleep-dominated configurations will be re-run in every run, and flagged again. That stays well under the 10% valve, but it is wasted time and it muddies the flag counts.
  - The rule was left as the author specified it.

## M9 — interrupted; deviations before resuming (2026-10-01)

- **Measured so far** (backed up read-only, with checksums, in `backups/m9-raw-20261001T010020Z/`):
  - run 1 complete: 215 configurations plus Q6, and 16 A-mt;
  - run 2's main process complete.
- **The interruption.** Run 2's A-mt process aborted on the per-process safety valve, at 2 of 16.
- **Changes, approved by the author and logged as post-measurement deviations** (`BENCH_LOG.md`, `BENCHMARKS.md`; D-76 revised):
  - the valve counts per run, across the main and A-mt processes;
  - a 200 ms busy spin before every probe;
  - `all --resume`, a guard against overwriting completed processes, and setting aside aborted ones.
- **The measured path is unchanged since `bench-freeze-2`:** the harness's measurement code, the arms, the workloads, the protocol crates and `Cargo.lock`. Only the orchestration (`main.rs`), the probe and the report changed.
- **No latency result has been opened.**

## M9 — complete (2026-10-01)

- **The resume.** `all --resume` completed, at `b175599`:
  - run 2's A-mt process, redone;
  - run 3;
  - 26 throttling re-runs, of which two A-mt configurations were flagged again;
  - memory, criterion, the zstd archives with `MANIFEST.sha256`, the report and the plots.
- **Requirements.** Every run process passed the machine-state check (`env.json`, `env-resume.json`). pmset recorded no warning anywhere, and no run came near the per-run safety valve.
- **Refused attempts.** Three earlier `--resume` attempts were refused at the machine-state check; nothing ran.
- **Logs.** The harness's re-run entries were committed to `BENCH_LOG.md` unchanged.

## M10 — report (2026-10-01)

- **The generator.** `BENCHMARKS.md` is generated by `dc-bench benchmarks` from `crates/dc-bench/BENCHMARKS.template.md`.
  - It loads the raw data only from the archives verified against `results/archive/MANIFEST.sha256`, and computes with the report generator's own statistics.
  - Every number is a placeholder resolved from those data, or a section spliced from the generated `summary.md`. An unresolved placeholder stops generation.
  - `summary.md` regenerated from the archives is byte-identical to the one `all` produced.
- **Contents** (SPEC §14):
  - the three-paragraph summary;
  - environment, method, generated results tables, and answers to Q1–Q10;
  - the claims against revision 2026-09-29, threats to validity, deviations from the frozen plan, and a separate exploratory section.
- **Outcome.** By the frozen rule, BLS aggregation is not a net benefit: B/D, A/C and A/C-batch are "not a net benefit" in every cell, with all runs agreeing. One paper claim is not supported: cheap checks before pairing, for cold verifiers (P-28). Arm E triggered the 3× sanity rule (faster than AIP's published figures); the harness was checked against D-68, and the gap is unexplained.
- **Committed results:** `results/archive/MANIFEST.sha256`, `summary.md`, `summary.json`, `plots/`, `bytes.json`, `memory.json`, `env.json`, `env-resume.json`. The raw CSVs and archives stay out of git; the author keeps them.
- `PAPER_ISSUES.md` is final.


## M10 follow-ups (2026-10-01)

The author asked for three follow-ups.

**1. Arm E against AIP (Q9).**
- **AIP's figures, checked.** SPEC §13.10's figures match arXiv:2603.24775v1, Table 5. The paper's evaluation text names only the iterations (100 per depth), the hardware (M3 Max, macOS 15.3) and biscuit-auth 6.0.
- **AIP's code.** It shows what the timed Rust "verify" contains (github.com/sunilp/aip at `ad2faa6`, the arXiv submission commit). Against D-68's timed scope, it:
  - decodes base64;
  - verifies every block's signature twice;
  - prints block 0's Datalog and parses it back;
  - parses the authorizer from Datalog text;
  - reports the mean of 100 single timings, with no warm-up.
- **No harness bug, and nothing changed.**
- **One report error, corrected.** M10 compared arm E's raw token sizes with AIP's base64 lengths (BENCH_LOG.md).
- **Verdict on the gap.** It is partly explained. AIP's per-block cost is still about twice E's once a second signature check per block is added. The rest is unattributed, and BENCHMARKS.md Q9 says so.

**2. Phase breakdown (exploratory).**
- **A gap closed.** SPEC §10.3's `phase-timing` feature had never been built; it now is (D-77).
- **The command.** `dc-bench phases` runs arms A and C, warm, N = 3, in the small, medium and large profiles: three runs on M9's machine state, archived under a committed manifest. It appends its own BENCH_LOG.md entry.
- **Generated.** BENCHMARKS.md §8 is generated from the archive once it exists.
- **Not run yet.** The machine was on battery during this session, so the full run is waiting. Only a dry run, whose numbers are never reported, was made.

**3. Paper artifacts (D-78).**
- **The command.** `dc-bench paper` writes `paper/tables/*.tex` and `paper/figures/*.pdf`, all generated:
  - the §1 verdicts, Q2's break-even, the claims, the primitives, the security suite and the M4 oracle;
  - three vector figures.
- **Reproduction.** ARTIFACT.md says how to reproduce them from the deposit.
- **Checks.** The tables compile with pdflatex, and the figures regenerate byte-identically.

**Other changes.**
- **The security suite.** `t5c_expiry_and_not_yet_valid`'s loop became three explicit assertions; its last case now asserts L27 exactly.
- **CI** lints the `phase-timing` build and runs its partition test.
- **`report`** refuses to run without criterion's output, rather than rewrite `summary.json` without it.

## M10 follow-ups, second round (2026-10-01)

- **Commits.** The first round was committed as three commits: the Q9 correction and AIP's scope; phase timing (D-77); the paper artifacts (D-78).
- **Q9's table.** Its flag now reads "outside 3×: investigated, see text", and its headers carry units (µs here, ms for AIP).
- **AIP's own benchmark** (D-79, exploratory).
  - `dc-bench aip` runs `bench_chained` from AIP's arXiv commit on this machine.
  - It runs two builds: the unmodified one, for AIP's mean, and a copy that only prints the timings, for the median.
  - It records the versions Cargo resolves, and archives under a committed manifest.
  - It appends its own BENCH_LOG.md entry.
- **One script for the session.** `scripts/exploratory-session.sh` builds everything and then runs the phase breakdown and AIP's benchmark, each on M9's machine state. A dry run exercised it end to end; its numbers are never reported.
- **BENCHMARKS.md §8, exploratory.**
  - a positioning table: C (warm) and D (warm+prefix) against arm E, medium, at matching depth, with E's functional gaps in the caption;
  - a ratio figure: A/C and B/D against N in every profile, with the ±10% band;
  - the AIP run's block.
- **Paper.** Caption macros for every figure (`paper/figures/captions.tex`), each saying what its error bars are. Also the positioning table and its caption, and the ratio figure.
- **Waiting.** The session needs AC power. Until it runs, §8's phase and AIP blocks say "Not run yet".

## Exploratory session (2026-10-04)

- **What ran.** `scripts/exploratory-session.sh` ran on M9's machine state: the phase breakdown (three runs) and AIP's own benchmark (three runs of each build). Both runs logged their own BENCH_LOG.md entries.
- **The phase breakdown.** BENCHMARKS.md §8 bases its conclusions on the category shares, which agree across runs to within 0.7 percentage points. The probe flagged 5 of 18 configurations, none of which was re-run. At that rate, M9's safety valve would have aborted.
- **AIP.** Its own code runs at about 0.45 of its published times on this machine. Arm E takes 0.60–0.82 of AIP's time here, within the sanity rule's 3×.
- **An earlier run.** A complete phase run from an earlier session that day is logged, but its data were removed before the rerun, for an unknown reason, and it is not reported. It was not the dry run (BENCH_LOG.md, note of 2026-10-04).

## After the exploratory session (2026-10-04)

- **Logs.** `results/logs/m9.log` (M9's console log) is committed: it is §7's evidence for the valve abort and the three refused resumes.
- **BENCH_LOG.md** has a follow-up to the note on the deleted first phase run: the author deleted it to re-run the script after the first session's AIP step failed, without having opened the results. §8's sentence says the same.
- **The positioning table** gains an exploratory column: AIP's code as measured on this machine (D-78, D-79).
- **Waiting.** Step 3, flipping the defaults and reconciling, waits for the rewritten paper.

## Step 2 finished; step 3 blocked (2026-10-04)

- **(b) Captions.** Both caption files exist and are generated: `paper/figures/captions.tex` by `scripts/paper_figures.py`, and `paper/tables/captions.tex` by `paper.rs`. The references to them now name the full path.
- **(c) The ratio figure** plots the pre-registered verdict ratios. It is a vector PDF in `paper/figures/`, and it now sits in BENCHMARKS.md §3, no longer labelled exploratory (D-78). The positioning table stays exploratory.
- **BENCH_LOG.md** has a closing note on the deleted first phase run (the author's account). §8's sentence matches it.
- **The first session's AIP error** cannot be recovered. The whole `results/exploratory/` was recreated at 05:30:58Z, so its output went with the deleted data. It is not established that the machine-state re-check caused it, so that path is unchanged.
- **Step 3 is blocked** (QUESTIONS.md, Q-02). The `docs/paper.pdf` now in the tree (2026-10-04, sha256 `d4fd47d6…`) is a light revision whose protocol is still BLS aggregate, not the rewrite the flip assumes. It is not committed. (a) waits for step 3.

## The rewritten paper (2026-10-04)

- **`docs/paper.pdf`** is the rewritten paper: revision 2026-10-04, 56 pages, sha256 `0ed3f58978ef0c8b670034ba717fa394c2970a57dd9ebdeb329a53ecbfae8bbd`, built from the LaTeX agent's latest commit.
  - It specifies DelegationChain over per-hop Ed25519 signatures, with BLS aggregation as a measured variant (§4.2, §4.8).
  - Its §8 still has `[PENDING]` placeholders; the author asked for them to be ignored in step 3.
- **Its predecessor.** Revision 2026-09-29 (sha256 `51eff0ec…6e14`) stays in git history. The benchmark's claims were judged against it.
- **Q-02 is answered** (QUESTIONS.md). Step 3, the reconciliation, starts from this commit.
