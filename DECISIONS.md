# Decisions

Every choice the paper leaves open, in the format of SPEC Appendix B.

- D-01 to D-27 were pre-assigned by SPEC.md.
- D-28 to D-47 were agreed with the author in the pre-M0 review (2026-09-28; SPEC changelog).
- Later entries were added during implementation. The milestone that added each one is in `MILESTONES.md`.

"Paper" means revision 2026-09-28, `docs/paper.pdf`.

---

## D-01 — Protocol structures use unsigned-integer map keys; unknown keys are rejected
Spec section: §4.3     Paper section: §4.7
Decision: Every map inside a protocol structure (bodies, certificates, receipts, approval bodies, PoP challenges, revocation assertions, scope-AST nodes, envelope) has unsigned-integer keys. A key the structure does not define is rejected. The exceptions are parameter maps (text keys) and declaration maps (D-33).
Why: The paper asks for integer keys. Unsigned integers are the narrowest choice, and rejecting unknown keys fails closed (SPEC §0 rule 8).
Affects benchmarks: no

## D-02 — Maximum CBOR nesting depth 16
Spec section: §4.4     Paper section: not specified
Decision: Containers (arrays and maps) are counted, and the top-level container is depth 1. Sixteen nested containers decode; seventeen are rejected. The encoder refuses to write deeper values, so it never produces what the decoder rejects.
Why: Bounds the decoder's recursion. The deepest legitimate structure needs about 10 levels: a body whose parameters are nested to D-21's path depth of 8 (body, parameter map, seven nested maps, leaf). A scope AST inside a body needs 7. Each body is decoded separately from the envelope, so the envelope adds nothing.
Affects benchmarks: no

## D-03 — Maximum encoded body size 64 KiB
Spec section: §4.4     Paper section: not specified
Decision: A single body whose encoding exceeds 65,536 bytes is rejected.
Why: Bounds the work per body. The largest benchmark body, a large-profile session scope, is far below this.
Affects benchmarks: no

## D-04 — Domain-separation tags for BLS signatures
Spec section: §5.2     Paper section: §4.2, §4.5, §5.3 (distinct DSTs required, strings unspecified)
Decision:
- chain signatures: `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_`
- proof-of-possession: `DC-V1-POP_BLS12381G2_XMD:SHA-256_SSWU_RO_`
- approval receipts: `DC-V1-RCPT_BLS12381G2_XMD:SHA-256_SSWU_RO_`
- registry certificates: `DC-V1-CERT_BLS12381G2_XMD:SHA-256_SSWU_RO_`
- revocation assertions: `DC-V1-REVOKE_BLS12381G2_XMD:SHA-256_SSWU_RO_`
Why: The chain DST is the paper's basic-scheme ciphersuite. The others follow the same suite format with a protocol prefix, so a signature made for one purpose never verifies for another.
Affects benchmarks: no

## D-05 — Public keys are validated once
Spec section: §5.3     Paper section: §4.7, §5.3
Decision:
- A public key gets its subgroup and identity checks at registration, and again when its certificate enters the verifier's cache.
- Hot-path verification then passes `pks_validate = false`.
- The Ed25519 arms decompress and check a key once, at the same points.
Why: A cached key cannot change. Revalidating it on every verification would be repeated work.
Affects benchmarks: yes. Per-verification key validation is removed from every arm alike.

## D-06 — InvocationDigest
Spec section: §5.4     Paper section: §4.5 ("a digest over this preliminary body"); P-03
Decision: `InvocationDigest(B_N) = SHA256("TAG_IVD\0" ‖ canon(B_N with key 9 removed))`.
Why: Receipts are omitted when empty (D-14), so the body with key 9 removed is exactly the preliminary body of §4.5. The tag separates this digest from `m_N`.
Affects benchmarks: no

## D-07 — Tags for the auxiliary signed messages
Spec section: §5.4     Paper section: not specified (P-06)
Decision:
- approval message: `SHA256("TAG_APR\0" ‖ canon(ApprovalBody))`
- certificate message: `SHA256("TAG_CRT\0" ‖ canon(CertBody))`
- revocation message: `SHA256("TAG_REV\0" ‖ canon(RevocationBody))`
- PoP message: `SHA256("TAG_POP\0" ‖ canon(PopChallenge))`
- Every tag is seven ASCII characters followed by `\0`.
Why: Every signed structure gets its own tag. This is also the only domain separation the Ed25519 arms have, since Ed25519 has no DSTs.
Affects benchmarks: no

## D-08 — Identifier letters are ASCII
Spec section: §6.1     Paper section: §5.2, §6.1 (`letter` undefined; P-23)
Decision: `letter` is `[A-Za-z]` and `digit` is `[0-9]`.
Why: This rules out Unicode confusables, and makes NFC irrelevant for identifiers.
Affects benchmarks: no

## D-09 — Certificate kind enum
Spec section: §6.1     Paper section: §5.2
Decision: `0 agent`, `1 signer`, `2 approver`, `3 issuer`. Service identifiers name verifiers and get no certificate; the registry refuses to register them.
Why: The paper lists five kinds but says services need no certificate.
Affects benchmarks: no

## D-10 — Default certificate lifetimes
Spec section: §6.3     Paper section: §5.2 (24 h to 7 d, for agents and signing services only)
Decision: 24 hours for agents, signers and issuers; 7 days for approvers.
Why: This stays inside the paper's range. Approvers get the upper end because their keys are named by identifier and rotate less often (§5.5).
Affects benchmarks: no. Benchmark certificates are valid throughout a run.

## D-11 — PoP challenge nonce
Spec section: §6.4     Paper section: §5.3 ("single-use, short expiry")
Decision: 16 random bytes, single use, 60-second lifetime.
Why: This makes the paper's "short expiry" concrete.
Affects benchmarks: no

## D-12 — Policy content addressing; a malformed policy is unavailable
Spec section: §6.6     Paper section: §5.4
Decision: The verifier accepts policy bytes only if `SHA256(bytes) == policy_hash` and the bytes decode as a well-formed policy (§9.3, including D-28). Anything else is treated as unavailable, and rejected at line 31.
Why: Content addressing is the paper's. Folding "malformed" into "unavailable" keeps line 31 the single rejection point for policy loading.
Affects benchmarks: cold path only. The policy is validated when it is loaded.

## D-13 — Body kind enum at key 1
Spec section: §7     Paper section: §4.3 ("Role distinguishability by position")
Decision: `0 session`, `1 delegation`, `2 invocation`.
Why: The paper requires an explicit kind field but does not number it.
Affects benchmarks: no

## D-14 — Receipts field omitted when empty
Spec section: §7.3     Paper section: §4.3, §4.5
Decision: `InvocationBody` key 9 is absent when there are no receipts. Present-but-empty is malformed (D-34).
Why: This gives every receipt-free body exactly one encoding, and makes D-06's "key 9 removed" equal to the preliminary body.
Affects benchmarks: bytes only. Bodies without approval are one byte smaller than they would be with an empty array.

## D-15 — Receipt order and multiplicity
Spec section: §7.3     Paper section: §4.3, §4.5 (P-10)
Decision: Receipts are sorted by `approver_id`, bytewise ascending, with at most one per approver. How violations are handled is in D-34.
Why: A canonical order makes the receipt list deterministic, and one receipt per approver matches the paper's "one approval receipt for each approval service the policy requires".
Affects benchmarks: no

## D-16 — Chain length cap
Spec section: §7.5     Paper section: not specified
Decision: N ≤ 16. A chain with N > 16 fails decoding (`L02`).
Why: This bounds verifier work; ZCAP recommends a cap of 10. The benchmark's largest N is 10.
Affects benchmarks: no

## D-17 — Policy lexical syntax
Spec section: §9.1     Paper section: §6.1 (lexical level unspecified; P-23)
Decision:
- Whitespace is insignificant.
- Strings are double-quoted, with JSON escapes.
- Integers are decimal, with an optional leading `-`, and must lie in the CBOR integer range [−2⁶⁴, 2⁶⁴ − 1].
- Booleans are `true` and `false`.
Why: This is the smallest lexical layer that accepts the paper's §6.2 example verbatim.
Affects benchmarks: no

## D-18 — Canonical scope AST
Spec section: §9.2     Paper section: not specified
Decision: The CBOR AST of SPEC §9.2, with integer keys. Rule order is semantic, atoms stay in written order, and approval sets are sorted and deduplicated. The policy document named by `policy_hash` is a Scope, canonically encoded.
Why: Scopes are signed inside bodies and hashed as policies, so they need one canonical byte form.
Affects benchmarks: bytes. Scope encoding size counts toward chain bytes identically in every arm.

## D-19 — No declared path is a strict prefix of another
Spec section: §9.3     Paper section: not specified
Decision: A `params` declaration containing both `a` and `a.b` is malformed.
Why: After flattening, a leaf cannot also be an interior node, so such a rule could never match. Rejecting it keeps declarations meaningful.
Affects benchmarks: no

## D-20 — Operator/operand type compatibility
Spec section: §9.3     Paper section: not specified (P-23)
Decision:
- `lt le ge gt`: an int path and an int operand.
- `eq`: the operand's type equals the declared type of the path.
- `starts_with ends_with contains`: a string path and a string operand.
- `in`: a non-empty list, every element of the path's declared type.
- `under`: a string path, and an operand that is a canonical absolute path.
- Anything else is malformed.
- Because of D-28, every path has a declared type, so this is always defined.
Why: The grammar lets `path numop value` take a string or boolean value (`amount < "x"`). The paper never says what that means.
Affects benchmarks: no

## D-21 — Policy size limits
Spec section: §9.3     Paper section: not specified
Decision: At most 256 rules per scope, 32 params per rule, 32 atoms per rule, 64 list elements. Text at most 1,024 bytes; path depth at most 8.
Why: This bounds `Evaluate` and `Contains` on input the sender chooses. The Q8 sizes (up to 64 rules, 8 atoms) are within the limits.
Affects benchmarks: no

## D-22 — `under` includes equality
Spec section: §9.3     Paper section: §6.1 ("q is a prefix of it segment by segment")
Decision: `p under q` holds when `p` is a canonical absolute path and `segments(q)` is a prefix of `segments(p)`, including `p = q`.
Why: "Prefix" in the paper is non-strict.
Affects benchmarks: no

## D-23 — Invalid parameter keys match no rule
Spec section: §9.4     Paper section: §6.3 (flattening unspecified)
Decision: If any parameter-map key, at any depth, fails the identifier grammar (which excludes `.`), the invocation matches no rule.
Why: Such a key cannot be named by any declaration, so under the closed-world rule nothing can authorize it.
Affects benchmarks: no

## D-24 — Tests for the containment special forms
Spec section: §9.6     Paper section: §6.4 steps 1–3
Decision: Two dedicated tests.
- `Contains(S1, allow all)` with S1 not `allow all` returns false (step 2).
- `Contains(deny all, S2)` with S2 a rule list returns false (step 3(a) finds no r1).
Why: Step 2 is soundness-critical: getting it wrong lets a delegation widen to everything. An earlier paper revision was ambiguous there.
Affects benchmarks: no

## D-25 — Nonce cache key and TTL
Spec section: §10.4     Paper section: §4.6, Theorem 5 (P-07)
Decision:
- The key is `(invoker_pk bytes, nonce bytes)`.
- TTL = `(B_N.exp − t) + 60 s`.
- Insertion is atomic, via `DashMap::entry`.
- Eviction is lazy on lookup, plus a periodic sweep; neither removes an unexpired entry.
Why: The paper asks for the remaining validity window plus a clock-skew tolerance. 60 s makes that tolerance concrete.
Affects benchmarks: Q10 memory, and the constant cost of the insert in every arm.

## D-26 — Resolution returns the latest certificate for (id, pk), valid or not
Spec section: §6.6     Paper section: §5.4, Algorithm 1 lines 23 and 27 (P-18)
Decision: `resolve(id, pk, t)` returns the most recently issued certificate binding `id` to `pk`, whether or not it is currently valid. Validity and revocation are rejected at line 27.
Why: If resolution filtered out invalid certificates, line 27 could never fire, and tests could not tell "unknown" from "expired". This departs from §5.4's wording, "returns the valid certificate". The author agreed to keep D-26 and log the conflict.
Affects benchmarks: no

## D-27 — An unresolvable approver fails line 42
Spec section: §10.2     Paper section: Algorithm 2 lines 41–42 (P-14)
Decision: Line 41 has no reject clause. If `Resolve(s, R.approver_pk)` fails, the chain is rejected at line 42.
Why: Line 42's "passes the phase-5 checks" includes resolution. Adding a new reject line is not ours to do.
Affects benchmarks: no

## D-28 — An atom on an undeclared path makes the scope malformed
Spec section: §9.3, §9.4, §9.5, §9.7     Paper section: §6.1, §6.3 step 1(c), §6.4 Proposition 2 (P-15)
Decision:
- Every path named in a rule's `where` clause must be declared in that rule's `params`.
- Otherwise the scope is malformed:
  - at policy load, the policy is unavailable (`L31`, D-12);
  - inside a session or delegation body, decoding fails (`L02`).
- The evaluator keeps §6.3 step 1(c) as a defensive check; it never fires for a well-formed scope.
Why: Without this, `Contains` is unsound (P-15). A tautology on an undeclared path lets a dead child rule drop a required approval (step 3(b)), or lets a dead parent rule subsume a live child rule (step 3(a)). The author chose to forbid such scopes rather than special-case them in `implies`/`unsat`, and is revising the paper to match. This is ahead of paper revision 2026-09-28 (SPEC §2 exception).
Affects benchmarks: no. Every benchmark policy declares its where-paths.

## D-29 — `blst` is single-threaded in every arm; A-mt is supplementary
Spec section: §3.2, §5.6, §12, §13.1, §13.3, §13.5     Paper section: §4.6 (the cost model assumes one multi-pairing)
Decision:
- What `blst` 0.3.17 actually does:
  - With its default `std` build, `aggregate_verify` hands the N+1 (key, message) pairs to a thread pool sized to the core count. Each worker runs `Pairing::aggregate` on its share; the partial Miller-loop products are merged, and one final exponentiation follows.
  - With the `no-threads` feature, the whole multi-Miller loop runs on the calling thread.
  - `blst_fp12::miller_loop_n` and `verify_multiple_aggregate_signatures` are threaded in the same way.
- Every arm is built with `no-threads`, so one verification runs on one thread.
- The threaded build is measured only as arm A-mt: warm state, Q1 only, never Q6, always labelled "supplementary: multi-threaded blst".
- Mechanism (implemented at M2 and M8):
  - `dc-crypto` has a default feature `blst-no-threads` that enables `blst/no-threads`.
  - Every workspace crate that depends on `dc-crypto` uses `default-features = false`.
  - The leaf packages that matter (`dc-bench`, the root test package) turn the feature on.
  - A-mt is a separate `dc-bench` build without it. Cargo unifies features, so one binary cannot hold both modes.
  - `dc-crypto` exports a constant reporting the mode it was built with. The harness records it and refuses to run a row whose build does not match its label.
Why: Threaded `blst` gives arm A hidden multi-core help against the single-threaded Ed25519 arms (four threads at N = 3), and oversubscribes the cores in the Q6 throughput runs.
Affects benchmarks: yes. It defines the headline arms as one thread per verification. A-mt shows what the default costs or saves.

## D-30 — Every point is validated once, at decode
Spec section: §5.3, §5.6     Paper section: §4.7
Decision:
- Every received signature goes through `Signature::sig_validate(bytes, true)` when it is decoded: σ_agg, individual chain signatures, receipt signatures, certificate signatures.
  - The length is checked first, to exactly 96 bytes. `blst`'s `from_bytes` would also accept the uncompressed 192-byte form.
  - The call checks both the subgroup and the identity.
  - A failure in a chain or receipt is `L02`. A failure in a certificate signature is a certificate rejection (line 24).
- Line 49 calls `aggregate_verify(false, …)`.
- Public-key fields in bodies are only length-checked at decode; they are compared as bytes and resolved (line 23). Certified keys are validated at registration and at cache fill (D-05).
- The Ed25519 arms parse each signature once; `verify_strict` does its own small-order checks.
- Recorded `blst` behaviour:
  - `aggregate_verify` does not check that messages are distinct (the source has a `TODO`), so line 48 is the only distinctness check.
  - Its `sig_groupcheck` calls `validate(false)`: a subgroup check without the identity check.
Why: Passing `sig_groupcheck = true` at line 49 would repeat the decode-time subgroup check, so arm A would pay twice, and it still would not reject the identity. Validating once at decode gives every arm exactly one validation per point.
Affects benchmarks: yes. It removes a duplicate G2 subgroup check from arm A's line 49.

## D-31 — Decode errors are split between L02 and L05
Spec section: §4.4, §10.2     Paper section: Algorithm 1 lines 2 and 5; §4.7
Decision:
- **Canonical-form violations** are a non-shortest argument, an indefinite length, unsorted map keys, or non-NFC text in a parameter map. When the verifier decodes a body, it records these instead of failing. Line 5 then rejects them (`L05`).
- Line 5 also compares the re-encoding with the received bytes (`L05`). `Canon` NFC-normalizes parameter text, so the comparison alone catches every canonical-form violation; a test-only hook shows this.
- **Everything else** is malformed and rejected at line 2 (`L02`). That includes duplicate map keys: such a map has no well-defined value, so it is not merely non-canonical.
- A non-canonical envelope is `L02`, because line 5 covers bodies only.
- Outside the verifier's body decoding, `decode_strict` rejects both classes.
Why: A strict decoder that rejects everything at line 2 would make line 5 unreachable. Recording in a single pass keeps one decode per body.
Affects benchmarks: no. Valid chains take the same path.

## D-32 — Bodies are decoded by their own kind field
Spec section: §10.2     Paper section: Algorithm 1 lines 2 and 7; §4.3
Decision: Line 2 reads each body's key 1 (`kind`) and decodes the body under that kind's schema, whatever its position. An unknown kind value is malformed (`L02`).
Why: Decoding by position would make a misplaced body fail at `L02`, so line 7 would be unreachable. The T1b and T3c rows need it.
Affects benchmarks: no

## D-33 — Declaration maps are a third map class
Spec section: §4.3, §9.2     Paper section: §4.7
Decision: Key 4 of a scope-AST `Rule` is a map from text keys to type uints. The keys must follow the `path` grammar (ASCII, so NFC is automatic) and are sorted by encoded bytes. Every other map in a protocol structure has uint keys.
Why: SPEC §9.2 fixes this AST shape, which conflicted with §4.3's "policy AST nodes: unsigned-int keys".
Affects benchmarks: no

## D-34 — Receipt-list rules
Spec section: §7.3, §10.2     Paper section: §4.3, §4.5, Algorithm 2 line 40 (P-10)
Decision:
- These make the invocation body malformed (`L02`):
  - receipts out of `approver_id` order;
  - two receipts for one approver;
  - key 9 present with an empty array;
  - a malformed receipt.
- A receipt from an approver that the evaluated decision (line 36) does not require is ignored.
Why: No line of Algorithm 2 rejects an extra receipt, and line 40 only looks up required approvers, so ignoring extras implements the paper as written. The ordering rules make the list canonical.
Affects benchmarks: no

## D-35 — Certificate validity is `t ∈ [nbf, exp]`
Spec section: §6.6, §10.2, §12.1, Appendix A     Paper section: Algorithm 1 line 27, §5.2, §5.5 (P-17)
Decision:
- Line 27 rejects unless `t ∈ [cert.nbf, cert.exp]`, and rejects a revoked serial.
- Line 42's "phase-5 checks" include the same window.
- A prefix-cache entry is valid only from the latest prefix-certificate `nbf` to its earliest expiry.
Why: The paper's line 27 says only "expired or revoked", so a certificate that is not yet valid would be accepted. The author is fixing line 27. This is ahead of paper revision 2026-09-28 (SPEC §2 exception).
Affects benchmarks: no

## D-36 — Lines 18 and 20 compare identifiers as well as keys
Spec section: §6.4, §10.2, §12.1, Appendix A     Paper section: Algorithm 1 lines 18 and 20 (P-16)
Decision:
- Line 18 rejects unless `B0.subject_id = sid(B1)` and `B0.subject_pk = spk(B1)`.
- Line 20 rejects unless `Bk.delegatee_id = sid(Bk+1)` and `Bk.delegatee_pk = spk(Bk+1)`.
- The prefix cache stores the handed-on identifier as well as the key.
Why: PoP does not stop one key from being registered under two identifiers. With keys alone, a chain could name one party and be signed by another, which violates provenance, asset (ii) of paper §3.1. The author is fixing the paper. This is ahead of paper revision 2026-09-28 (SPEC §2 exception).
Affects benchmarks: negligibly. It adds one identifier comparison per hop in every arm.

## D-37 — Caches are filled during verification
Spec section: §10.2     Paper section: §4.6, §5.4 (P-20)
Decision:
- A certificate enters the cache after line 24 verifies its signature; lines 25–27 are then checked on every use.
- A policy enters the cache after its hash and well-formedness check (D-12).
- A chain rejected later may leave cache entries behind.
- Line 50 is the only mutation that can change a later decision. §11.3's equivalence test checks that the caches never change one.
Why: §5.4 describes resolution caches that fill on use, which contradicts §4.6's "leaves the verifier exactly as it found it".
Affects benchmarks: yes. It defines what the warm state has cached.

## D-38 — Large profile: rule dropping never goes below 4 rules
Spec section: §13.2     Paper section: not applicable (workload)
Decision:
- Each hop drops 2 rules and tightens 1 bound, but the rule count never drops below 4; from then on hops only tighten. At N = 10 (9 hops), hops 1–6 drop rules and hops 7–9 only tighten. N ≤ 5 is unaffected.
- A hop never drops an approval rule while keeping a permissive rule that the approval rule overlaps.
Why: With 16 rules and 2 dropped per hop, none are left by N = 9. Dropping an approval rule but keeping a permissive rule it shadows is a real escalation, and line 34 correctly rejects it.
Affects benchmarks: yes. It defines the large workload at N = 10.

## D-39 — warm+prefix schedule
Spec section: §13.5     Paper section: not applicable (method)
Decision: 10 prefixes × 1,100 invocations, presented round-robin across the prefixes. The first 100 invocations per prefix are warm-up, including the miss that populates the entry; the remaining 1,000 per prefix are measured. That is 1,000 warm-up and 10,000 measured, as elsewhere.
Why: SPEC's "first invocation per prefix is warm-up" did not match its own 1,000 + 10,000 counts.
Affects benchmarks: yes (arms B and D, warm+prefix)

## D-40 — Identity pools
Spec section: §13.2, §13.5     Paper section: not applicable (workload)
Decision:
- Within a chain, every hop uses a distinct agent identity, except in the §11.2 tests.
- Identities come from a fixed per-organization pool.
- The warm-up chains cover every identity and certificate the measured chains use.
Why: If identities never repeated across chains, the warm state would still resolve every agent certificate, and would not be warm.
Affects benchmarks: yes. It is what makes the warm state warm.

## D-41 — Q10 memory with `stats_alloc`
Spec section: §3.2, §13.5     Paper section: not applicable
Decision: Measure memory per entry with the `stats_alloc` crate as the global allocator of a dedicated binary.
Why: A hand-written counting allocator needs `unsafe impl GlobalAlloc`, which SPEC §0 rule 9 forbids.
Affects benchmarks: Q10 method only

## D-42 — QoS user-interactive for measuring threads; no core pinning
Spec section: §0 rule 9, §13.5     Paper section: not applicable
Decision:
- macOS on Apple Silicon has no working thread-affinity API, so runs are not pinned.
- Every measuring thread, in every arm, calls `pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0)`, so that the scheduler places it on performance cores.
- The call lives in `crates/dc-bench/src/qos.rs`, and is the one permitted `unsafe` FFI call in `dc-bench`.
- The harness records whether the call succeeded.
Why: It is the closest macOS gets to pinning. The author allowed this one `unsafe` call.
Affects benchmarks: yes. It applies to every arm equally.

## D-43 — Q6 thread counts
Spec section: §13.5     Paper section: not applicable
Decision: 1, 2, 4, 8, 10 (all performance cores), and 14, labelled "includes efficiency cores".
Why: The machine has 10 performance and 4 efficiency cores, and "all cores" alone would mix the two kinds unlabelled.
Affects benchmarks: yes (Q6)

## D-44 — Q5 iteration counts
Spec section: §13.4     Paper section: not applicable
Decision: The injected-latency configurations use reduced counts, which the frozen plan fixes. Each configuration gets at least 200 measured verifications, and every result carries a CI.
Why: These configurations are dominated by sleeps. At full counts, 80 ms alone takes about 73 minutes per arm per run.
Affects benchmarks: yes (Q5 precision)

## D-45 — Recording the macOS / Apple Silicon environment
Spec section: §3.3, §13.5     Paper section: not applicable
Decision: `env.json`, and the threats-to-validity section, record:
- no frequency governor or turbo control;
- no ADX path (`blst` uses its armv8 assembly);
- the `curve25519-dalek` backend (serial u64; its SIMD backends are x86-only);
- that `-C target-cpu=native` does not reach `blst`'s C and assembly (built by `cc`, which ignores `RUSTFLAGS`);
- the performance and efficiency core counts;
- the power source and macOS power mode;
- the `blst` threading mode of each binary (D-29).
Full runs require AC power and an idle machine. No C flags are tuned for `blst`.
Why: SPEC asks for a governor, pinning and an ADX report, none of which exist here. Recording the substitutes is the honest alternative. Tuning `blst`'s C flags would be optimizing one arm.
Affects benchmarks: yes (threats to validity)

## D-46 — A root package hosts the workspace-level tests
Spec section: §3.1     Paper section: not applicable
Decision: The workspace root `Cargo.toml` is also the package `delegationchain` (no code of its own), so that `tests/security.rs` can live at the root.
Why: A virtual workspace manifest cannot own integration tests.
Affects benchmarks: no

## D-47 — Toolchain, edition and dependency pinning
Spec section: §3.1, §3.2     Paper section: not applicable
Decision:
- rustc 1.97.1 stable (2026-07-14), pinned in `rust-toolchain.toml`; edition 2024.
- Dependencies are added at the milestone that needs them, at the latest release within the major version SPEC names, and pinned exactly by `Cargo.lock`.
- Versions resolved during the pre-M0 build probe: `blst` 0.3.17, `ed25519-dalek` 2.2.0 (`curve25519-dalek` 4.1.3), `biscuit-auth` 6.0.0, `criterion` 0.5.1, `sha2` 0.10.9.
Why: SPEC §3.2 asks for the latest release within each major version at project start, pinned.
Affects benchmarks: yes. The versions are recorded in `BENCHMARKS.md`.

## D-48 — `unsafe_code` is denied workspace-wide
Spec section: §0 rule 9     Paper section: not applicable
Decision:
- The workspace lint table sets `unsafe_code = "deny"`, and every package inherits it.
- Only `crates/dc-crypto/src/pairing_cache.rs` (none expected) and `crates/dc-bench/src/qos.rs` (D-42) may carry `#[allow(unsafe_code)]`.
- `scripts/check-unsafe.sh` runs in CI and fails on any other opt-out, on a package that does not inherit the lints, or on a manifest that relaxes the lint.
Why: This makes rule 9 mechanically enforced rather than a convention.
Affects benchmarks: no

## D-49 — Map keys are unsigned integers or text
Spec section: §4.1, §4.3     Paper section: §4.4, §4.7
Decision: The CBOR layer rejects any map key that is not an unsigned integer or a text string, as malformed (`L02`). Which of the two a given map needs is checked by the structure that owns it: uint keys in protocol structures (D-01), text keys in parameter and declaration maps (D-33).
Why: The paper uses no other key type. Rejecting the rest at the lowest layer fails closed (SPEC §0 rule 8), and gives keys a simple canonical order: uints numerically, then texts by length and then bytes. A property test checks that order against the encoded bytes.
Affects benchmarks: no

## D-50 — Non-canonical nested structures are malformed
Spec section: §4.4, §7.4     Paper section: §4.7 ("Verifiers reject any structure whose received encoding differs from the canonical re-encoding")
Decision:
- Structures carried as byte strings inside another structure are decoded strictly. That covers a receipt's approval body inside `InvocationBody` key 9, and the body inside a certificate or revocation assertion. A canonical-form violation in them is malformed input, not an `L05`:
  - inside a chain body: `L02`;
  - in a certificate: a certificate rejection;
  - in a revocation assertion: the assertion is refused.
- Their digests are taken over the received bytes, which strict decoding guarantees are canonical.
Why: Paper §4.7 requires canonical encoding of every structure, but Algorithm 1 line 5 covers only the chain bodies. The nearest reject line for a nested structure is decoding.
Affects benchmarks: no

## D-51 — Principals in bodies are checked for grammar, not position
Spec section: §6.1, §7     Paper section: §5.2; Algorithm 1 lines 8, 26; Algorithm 2 line 42
Decision: Decoding a body checks every principal against the grammar, and requires the kind component to be one of the five kinds of §5.2; any other kind is malformed. Decoding does **not** check that the kind suits the field. For example, a `delegator_id` of kind `issuer`, or an `aud` that is not a service, decodes. Kind is enforced by the certificate checks of lines 26 and 42, and by line 8 for `aud`.
Why: If decoding checked kind by position, the role-confusion tests of §11.2 (T4a, T5e: "issuer-kind cert as a delegator → L26") would be rejected at `L02` instead, and would prove nothing about line 26.
Affects benchmarks: no

## D-52 — SPEC §5.1's scheme trait is split in two
Spec section: §5.1     Paper section: not applicable
Decision:
- `SigScheme` is the single-signature scheme: key generation, sign and verify under a `Dst`, and validated key and signature parsing.
- `ChainScheme` is how the N+1 chain signatures are carried (`start`, `accumulate`, `to_wire`, `from_wire`) and checked at line 49 (`verify_chain`).
- Arm A is `BlsAggregate` over `Bls`. The other chain schemes are built on the same `SigScheme` implementations in `dc-baselines`.
- Scheme types are zero-sized markers with the usual derives.
Why: Certificates, receipts, PoP and revocations need the arm's single-signature scheme without the chain machinery, and SPEC says they use "the same scheme within an arm". The generic verifier stays identical across arms, as §12 requires.
Affects benchmarks: no. The split does not change what is computed.

## D-53 — Registration procedure details
Spec section: §6.4, §6.6     Paper section: §5.3, §5.4
Decision:
- The registry checks a registration in this order, and reports the first failure:
  1. the nonce was issued here;
  2. it is unused;
  3. it is at most 60 s old;
  4. the presented challenge equals the one issued, byte for byte;
  5. the kind is not `service`;
  6. the identifier's kind component equals the requested kind;
  7. `org(identifier)` equals the registry id;
  8. the public key passes validation;
  9. the PoP signature verifies under the PoP DST.
- The nonce is consumed by the first registration attempt, whatever its outcome, so a registrant cannot retry against one challenge.
- A `service` identifier is refused when the challenge is requested, since a challenge cannot encode that kind.
- The in-process resolver ignores `t`; D-26 leaves validity to line 27.
- Nonces come from a seeded ChaCha20 generator, so runs are reproducible.
Why: The paper lists what a PoP challenge contains and says the registry verifies it (§5.3), but not the order of checks or what happens to a nonce after a failure. Consuming it always is the fail-closed choice.
Affects benchmarks: no. Registration happens outside every timed region.

## D-54 — Test hooks for a compromised or misbehaving registry
Spec section: §11.2 (T5b, T5d)     Paper section: §3.3.1, §7.1
Decision:
- `dc-registry`'s `test-hooks` feature adds two functions:
  - `root_sign_arbitrary`, which signs any certificate body with the root key, bypassing every registration check;
  - `publish_arbitrary`, which makes the resolver serve such a certificate.
- Only dev-dependencies enable the feature. `scripts/check-deps.sh` fails if any protocol crate's normal dependency graph enables it.
Why: The T5b bounded tests and the T5d `registry_id` test need a root that signs what an honest registry would refuse. That capability must not exist in the default build.
Affects benchmarks: no
