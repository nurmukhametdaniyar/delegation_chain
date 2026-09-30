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
