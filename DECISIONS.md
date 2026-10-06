# Decisions

Every choice the paper leaves open, in the format of SPEC Appendix B.

- D-01 to D-27 were pre-assigned by SPEC.md.
- D-28 to D-47 were agreed with the author in the pre-M0 review (2026-09-28; SPEC changelog).
- Later entries were added during implementation. The milestone that added each one is in `MILESTONES.md`.

"Paper" means `docs/paper.pdf`. It was revision 2026-09-28 until 2026-09-29, and is now revision 2026-09-29 (sha256 `51eff0ec…6da84e14`). Entries the revision affected carry a "Paper status" line.

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
Paper status (revision 2026-09-29): adopted verbatim. §4.5 now defines InvocationDigest(B_N) = H(TAG_IVD ‖ Canon(B_N without its receipts field)), and notes that the tag separates it from m_N (P-03 resolved).

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
Paper status (revision 2026-09-29): adopted. §6.1 "Lexical details" says `letter` is `[A-Za-z]` and `digit` is `[0-9]`.

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
Paper status (revision 2026-09-29): adopted. §4.5: "The receipts field is omitted when there are no receipts", and a body carrying an empty receipts field is malformed.

## D-15 — Receipt order and multiplicity
Spec section: §7.3     Paper section: §4.3, §4.5 (P-10)
Decision: Receipts are sorted by `approver_id`, bytewise ascending, with at most one per approver. How violations are handled is in D-34.
Why: A canonical order makes the receipt list deterministic, and one receipt per approver matches the paper's "one approval receipt for each approval service the policy requires".
Affects benchmarks: no
Paper status (revision 2026-09-29): adopted. §4.5: receipts are ordered by approver identifier, bytewise ascending, with at most one per approval service (P-10 resolved).

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
- String literals are NFC-normalized; the string operators compare bytewise (added from the paper, revision 2026-09-29; the AST side is D-55).
Why: This is the smallest lexical layer that accepts the paper's §6.2 example verbatim.
Affects benchmarks: no
Paper status (revision 2026-09-29): adopted into §6.1 "Lexical details", with the same meaning; the wording differs only in layout. The paper adds one rule, that string literals are NFC-normalized like the parameter values they are compared with. The decision above now includes it (P-23 resolved).

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
Paper status (revision 2026-09-29): adopted. §6.1 well-formedness, condition 1: "No path is declared twice, and no declared path is a strict prefix of another."

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
Paper status (revision 2026-09-29): adopted as the table in §6.1 well-formedness, condition 2, with the same meaning. Wording differences, none of which changes the rule: (1) the paper lists the path type of `==` and `in` as "any", constrained through the operand ("a literal of the path's type"; "every element of the path's type"), which is what the bullets above say; (2) the paper says "the declared type of the path decides" whether `==` is the numeric or the string operator, where SPEC §9.2 says the operand's type disambiguates, and since the two types must be equal these agree (P-23 resolved).

## D-21 — Policy size limits
Spec section: §9.3     Paper section: not specified
Decision: At most 256 rules per scope, 32 params per rule, 32 atoms per rule, 64 list elements. Text at most 1,024 bytes; path depth at most 8.
Why: This bounds `Evaluate` and `Contains` on input the sender chooses. The Q8 sizes (up to 64 rules, 8 atoms) are within the limits.
Affects benchmarks: no
Paper status (revision 2026-09-29): consistent. §6.1 says implementations bound scope size and that "those bounds belong in a normative specification", so the values stay ours.

## D-22 — `under` includes equality
Spec section: §9.3     Paper section: §6.1 ("q is a prefix of it segment by segment")
Decision: `p under q` holds when `p` is a canonical absolute path and `segments(q)` is a prefix of `segments(p)`, including `p = q`.
Why: "Prefix" in the paper is non-strict.
Affects benchmarks: no
Paper status (revision 2026-09-29): adopted. §6.1 now defines a canonical absolute path in these terms, and says "the segments of q are a prefix of its segments, equality included".

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
_Revised 2026-10-04: the skew term is `VerifierConfig::clock_skew` (formerly `nonce_skew`), which also extends revocation retention (D-82)._
Spec section: §10.4     Paper section: §4.6, Theorem 5 (P-07)
Decision:
- The key is `(invoker_pk bytes, nonce bytes)`.
- TTL = `(B_N.exp − t) + 60 s`.
- Insertion is atomic, via `DashMap::entry`.
- Eviction is lazy on lookup, plus a periodic sweep; neither removes an unexpired entry.
Why: The paper asks for the remaining validity window plus a clock-skew tolerance. 60 s makes that tolerance concrete.
Affects benchmarks: Q10 memory, and the constant cost of the insert in every arm.
Paper status (revision 2026-09-29): consistent. §4.6 ("Replay protection") and Theorem 5 now say that line 13 applies no tolerance, and that the TTL's added term must be at least the clock disagreement among the instances sharing the cache. Here one instance holds the cache, so 60 s satisfies that (P-07 resolved).

## D-26 — Resolution returns the newest certificate for (id, pk) valid at t, or else the newest
Spec section: §6.6     Paper section: §5.4, Algorithm 1 lines 23 and 27 (P-18, P-30)
Decision:
- `resolve(id, pk, t)` returns the newest certificate binding `id` to `pk` that is valid at t (`nbf ≤ t ≤ exp`, D-35) if there is one. Otherwise it returns the newest certificate, valid or not.
- Validity and revocation are still rejected at line 27.
- The test hook `publish_arbitrary` makes its certificate the binding's only one, so that the security suite's forged and malformed certificates are served whatever their content.
Why:
- Returning an expired or not-yet-valid binding lets line 27 fire. If resolution filtered such bindings out, tests could not tell "unknown" from "expired".
- Preferring a valid certificate is P-30's fix. Under "newest, valid or not", a future-dated same-key renewal shadowed the older, valid certificate for an uncached verifier. After a shortening renewal expired, it ended the binding for an uncached verifier while a caching one still accepted. So caches changed outcomes, contrary to paper §4.6.
- With the fix, `future_dated_renewal_agrees` and `shortening_renewal_agrees` pass, and both renewal kinds are in the §11.3 event list.
Affects benchmarks: no. The workloads renew no certificates, and each binding has one certificate.
Paper status (revision 2026-09-29): ahead of the paper since 2026-09-30, agreed with the author under the SPEC §2 exception.
- Revision 2026-09-29's §5.4 reads: "Resolution returns the most recently issued certificate binding that identifier to that key, whether or not it is currently valid". This decision's first version adopted that verbatim (P-18 resolved).
- The revision for P-30 prefers a valid certificate.
History: until 2026-09-30, "the latest certificate for (id, pk), valid or not", with `t` ignored.

## D-27 — An unresolvable approver is rejected at line 41
Spec section: §10.2, §11.2     Paper section: Algorithm 2 lines 41–42 (P-14)
Decision: If `Resolve(s, R.approver_pk)` fails, the chain is rejected at line 41 (`L41`). Every other approver-certificate failure (root, namespace, kind, validity, revocation) is line 42.
Why: Revision 2026-09-29 gives line 41 its own clause: "reject if unresolvable".
Affects benchmarks: no
Change log: until 2026-09-29 this decision read "Line 41 has no reject clause; an unresolvable approver fails line 42", as revision 2026-09-28 required. The paper now has the clause, and the paper wins (SPEC §2). This changes two §11.2 rows from L42 to L41: a receipt whose `approver_pk` is not certified for its `approver_id`, and an agent key signing a receipt.

## D-28 — An atom on an undeclared path makes the scope malformed
Spec section: §9.3, §9.4, §9.5, §9.7     Paper section: §6.1, §6.3 step 1(c), §6.4 Proposition 2 (P-15)
Decision:
- Every path named in a rule's `where` clause must be declared in that rule's `params`.
- Otherwise the scope is malformed:
  - at policy load, the policy is unavailable (`L31`, D-12);
  - inside a session or delegation body, decoding fails (`L02`).
- The evaluator keeps §6.3 step 1(c) as a defensive check; it never fires for a well-formed scope.
- `Contains` returns false if either scope is malformed, as a defensive check that a decoded chain never reaches (paper §6.4, revision 2026-09-29).
Why: Without this, `Contains` is unsound (P-15). A tautology on an undeclared path lets a dead child rule drop a required approval (step 3(b)), or lets a dead parent rule subsume a live child rule (step 3(a)). The author chose to forbid such scopes rather than special-case them in `implies`/`unsat`.
Affects benchmarks: no. Every benchmark policy declares its where-paths.
Paper status (revision 2026-09-29): adopted. §6.1 well-formedness, condition 1: "Every path its where clause mentions is declared in its params." A malformed scope is rejected by LoadPolicy, and at line 2 inside a body. The Proposition 2 proof now relies on well-formedness in both step 3(a) and the step-3(b) skip argument (P-15 resolved). The paper adds the defensive rule that Contains returns false on a malformed scope, which is now in the decision above. This decision was ahead of the paper under the SPEC §2 exception, and no longer is.

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
_Revised 2026-10-04: for Ed25519, now the default instantiation, decode also rejects non-canonical key and signature encodings (paper §4.7; D-81)._
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
Paper status (revision 2026-09-29): adopted. §4.5: violations of the receipt order or multiplicity, or an empty receipts field, make the body malformed, and "a receipt from an approval service that the policy does not require for the invocation is ignored" (P-10 resolved).

## D-35 — Certificate validity is `t ∈ [nbf, exp]`
Spec section: §6.6, §10.2, §12.1, Appendix A     Paper section: Algorithm 1 line 27, §5.2, §5.5 (P-17)
Decision:
- Line 27 rejects unless `t ∈ [cert.nbf, cert.exp]`, and rejects a revoked certificate: since D-65, one whose binding is revoked.
- Line 42's "phase-5 checks" include the same window.
- A prefix-cache entry is valid only from the latest prefix-certificate `nbf` to its earliest expiry.
Why: Revision 2026-09-28's line 27 said only "expired or revoked", so a certificate that is not yet valid would have been accepted (P-17). The interval is closed at both ends, as in lines 13 and 44.
Affects benchmarks: no
Paper status (revision 2026-09-29): adopted. Line 27 now reads "reject if cert_k is not yet valid, expired, or revoked at t", and §5.4 repeats "not yet valid, expired, or revoked" (P-17 resolved). The paper does not say whether t = exp counts as expired; this decision keeps the closed interval, which is consistent with lines 13 and 44 (logged as P-26). This decision was ahead of the paper under the SPEC §2 exception, and no longer is.

## D-36 — Lines 18 and 20 compare identifiers as well as keys
Spec section: §6.4, §10.2, §12.1, Appendix A     Paper section: Algorithm 1 lines 18 and 20 (P-16)
Decision:
- Line 18 rejects unless `B0.subject_id = sid(B1)` and `B0.subject_pk = spk(B1)`.
- Line 20 rejects unless `Bk.delegatee_id = sid(Bk+1)` and `Bk.delegatee_pk = spk(Bk+1)`.
- The prefix cache stores the handed-on identifier as well as the key.
Why: PoP does not stop one key from being registered under two identifiers. With keys alone, a chain could name one party and be signed by another, which violates provenance, asset (ii) of paper §3.1. Affects benchmarks: negligibly. It adds one identifier comparison per hop in every arm.
Paper status (revision 2026-09-29): adopted. Lines 18 and 20 now compare `(B0.subject_id, B0.subject_pk)` with `(sid(B1), spk(B1))`, and `(Bk.delegatee_id, Bk.delegatee_pk)` with `(sid(Bk+1), spk(Bk+1))`. §4.6 explains that this makes the party that acts the one that was named, "even where one key is certified under more than one identifier" (P-16 resolved). This decision was ahead of the paper under the SPEC §2 exception, and no longer is.

## D-37 — Caches are filled during verification
Spec section: §10.2     Paper section: §4.6, §5.4 (P-20)
Decision:
- A certificate enters the cache after line 24 verifies its signature; lines 25–27 are then checked on every use.
- A policy enters the cache after its hash and well-formedness check (D-12).
- A chain rejected later may leave cache entries behind.
- Line 50 is the only mutation that can change a later decision. §11.3's equivalence test checks that the caches never change one. The exception found since, P-30 (a same-key renewal that does not cover the older certificate's window), is fixed by D-26 as revised, and both renewal kinds are in the §11.3 run.
Why: §5.4 describes resolution caches that fill on use, which contradicts §4.6's "leaves the verifier exactly as it found it".
Affects benchmarks: yes. It defines what the warm state has cached.
Paper status (revision 2026-09-29): adopted. §4.6: "The only decision-relevant state the procedure changes is the nonce cache … Resolution and policy loading may fill caches"; the Figure 2 caption says the same (P-20 resolved).

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

## D-55 — Text in a scope AST is NFC, like parameters
Spec section: §4.4, §9.2, §10.2     Paper section: §6.1 "Lexical details" (revision 2026-09-29: "String literals are NFC-normalized, like the text values they are compared with")
Decision:
- The policy parser NFC-normalizes string literals.
- The canonical scope AST (D-18) holds NFC text. `Canon` of a session or delegation body NFC-normalizes the text inside its scope, as it does parameters.
- A received body whose scope contains non-NFC text is therefore a canonical-form violation, rejected at line 5 (`L05`), the same class as non-NFC parameters (extends D-31).
- A policy document is decoded strictly (D-12), so non-NFC text there makes it malformed, and it is rejected at line 31.
Why: The paper puts literals and parameter values under the same normalization rule, so the two are treated alike. Identifiers, principals and paths are ASCII (D-08), so in practice only string operands are affected.
Affects benchmarks: no. It adds one NFC check per scope text, identical in every arm.

## D-56 — Canonical form of the scope AST, and policy-document decoding
Spec section: §9.2, §9.3, §6.6     Paper section: §6.1, §5.4
Decision:
- A `Scope` value can only be built by validating it (`Scope::new`, `Scope::parse`, `Scope::from_value`, `Scope::decode_policy`). `contains` therefore performs the paper's defensive "malformed ⇒ false" check through a flag set at construction, in O(1) per call (D-28). Only the `test-hooks` constructor can produce a malformed `Scope`.
- The AST's own canonical-form rules, beyond CBOR's:
  - an approval list is sorted bytewise and deduplicated;
  - keys 4, 5 and 6 of a rule are either absent or non-empty;
  - a special form carries no key but key 1;
  - a rule list is non-empty.
  - Violations are malformed.
- `Scope::decode_policy`, for line 31, requires all of: strict canonical CBOR, NFC text (D-55), well-formedness, and that re-encoding reproduces the bytes exactly. Anything else is a malformed policy, which is unavailable (D-12).
- In the text form, a path declared twice is a syntax error, since the AST map cannot represent it.
- Keywords are contextual: a parameter may be called `in`, `and` or `approval`.
- JSON escapes include `\uXXXX` with surrogate pairs; a lone surrogate or an unescaped control character is a syntax error.
Why: The paper leaves the AST open, and SPEC fixes its shape (D-18). These rules give every scope exactly one encoding, and make "well-formed" a property of the type rather than something each caller has to remember to check.
Affects benchmarks: no. Scopes in bodies are validated once, at line 2, in every arm.

## D-57 — String implication: two tautologies are handled exactly
Spec section: §9.5     Paper section: §6.4 (P-08)
Decision: Besides the sound rules SPEC §9.5 lists for strings without a finite set, `implies` returns true for `starts_with ""`, `ends_with ""` and `contains ""`, which every string satisfies. Every other rule is as SPEC gives it. A string path constrained by `==`/`in` is decided exactly by filtering the finite set.
Why: SPEC asks for exactness where it is easy to get and easy to test. These three are both, and they remove a trivially avoidable source of incompleteness. The differential oracle checks them for soundness.
Affects benchmarks: no

## D-58 — Differential oracle method
Spec section: §9.7     Paper section: §6.4, Definition 1
Decision:
- **Universe:** SPEC §9.7's, with boundary constants and undeclared-path atoms added.
- **Generated pairs:** half are independent pairs; in the other half, S2 is derived from S1 by mutation (dropping, adding, replacing and duplicating atoms and rules, toggling approvals, swapping adjacent rules), so that containment is often true or nearly so.
- **Validator check:** for every generated scope, the test computes independently whether it is malformed (an atom on an undeclared path, or `under` with a non-canonical literal), and asserts that the validator agrees.
- **Oracle:** Definition 1, over the invocations that can match one of S2's rule heads, which is complete for a rule-list S2. For S2 = `allow all`, every invocation is checked, including two shapes no rule can declare.
- **Per-type check:** `implies`/`unsat` are tested against each type's enumerated domain. Strings are also tested against a richer domain (concatenations of up to three constants). Soundness must hold against both; completeness is reported against both, because the SPEC domain is small enough to make some implications look true that are false.
- **Determinism:** the work is split into 64 shards, each seeded from `DC_ORACLE_SEED` and its index, and scheduled on a pool of `DC_ORACLE_THREADS` threads (default: all cores). The statistics are sums, so a run reproduces for a given seed on any machine and with any thread count. The record run was repeated with 14 threads and with 3, and matched apart from elapsed time. Reports are written to JSON (`DC_ORACLE_REPORT`).
- **Scale:** the extended CI profile runs 150,000 pairs and 150,000 `implies`/`unsat` cases per type. Plain `cargo test` runs 4,096 pairs.
- **Miss causes:** every miss (the oracle says contained, `Contains` says no) is replayed step by step to find where the procedure returns false; the test asserts the replay agrees with `contains`. The miss is then attributed:
  - an unsatisfiable, or fully or partly shadowed, child rule that step 3(a) still requires to be subsumed;
  - a child rule covered only by a union of parent rules (Remark 1);
  - step-3(b) conservatism, split by whether the jointly matched invocations are decided by earlier child rules or earlier parent rules;
  - string implication, split by whether the implication still holds on the richer string set.
  Attribution uses semantic `implies`/`unsat` over the enumerated domain, per path.
- **Teeth:** before the M4 record run, three bugs were planted one at a time and each was caught: dropping the step-3(b) approval check, an off-by-one in integer implication, and a reversed `under` prefix test.
Why: SPEC §9.7 fixes the universe and the assertions but not how pairs are generated. Random independent pairs are almost never contained, which would leave soundness under-tested and make completeness meaningless.
Affects benchmarks: no

## D-59 — Chain construction details
Spec section: §8     Paper section: §3.1, §4.1, §4.5 (P-12)
Decision:
- **Signing service.** It signs delegation and invocation bodies only, and only when the body names its own agent identifier and key as signer. Both are checked, consistent with D-36. It then runs the pluggable `EnforcementPolicy` (default: accept all; P-12) and computes m_k itself from the body and m_{k−1}.
- **`ChainBuilder`.** It sets what an honest participant sets: hop index, session id, and the chaining of identifier and key to the next signer. It does **not** check containment or expiry: those are the verifier's job, and the security suite needs chains that fail them. Invocation follows SPEC §8.3's five steps, and a scope that denies the invocation is an error (`Denied`).
- **`assemble`.** It signs arbitrary bodies with arbitrary keys, using position-determined tags. It stands for an attacker who holds keys, and is how the security suite builds altered but correctly signed chains. `Chain::parts` keeps σ_0 … σ_N, which an observer can recover from the running sums (paper §4.3). The Theorem 3 tests use them.
- **Approval service.** It signs over InvocationDigest (D-06), with iat = now and exp = now + 300 s (SPEC §8.4), and fixed attestation bytes.
- **`World`.** Keys, registry roots and registry nonce streams are derived from the world seed and a label, so a seed reproduces the whole world, including the envelope bytes (tested).
Why: SPEC §8 fixes the roles, not these mechanics.
Affects benchmarks: no. Chains are built outside every timed region. Q7's signing-side costs time the services' `sign`, `approve` and `issue`.

## D-60 — Certificate resolution failures, and the certificate cache
Spec section: §6.6, §10.1, §10.2     Paper section: Algorithm 1 lines 23–27; Algorithm 2 lines 41–42; §5.4
Decision:
- **Which line rejects what.** For position k:
  - `L23` if the resolver returns nothing, or returns a certificate that does not bind `(sid(B_k), spk(B_k))` (wrong identifier or key). A certificate for another binding does not resolve this one.
  - `L24` if the certificate is malformed (D-50), no root is configured for `org(sid)`, its signature does not verify under that root, or its key fails validation (D-05).
  - For approvers, the same failures map to `L41` and `L42`. Lines 25–27 map to `L42` as well.
- **Certificate cache.** Keyed by identifier, then key. An entry is stored after line 24 passes (D-37), and lives until `min(cert.exp, t + 3600 s)`. Lines 25–27 are re-checked on every use. Ingesting a revocation evicts every entry with that registry and serial. A verifier built with `VerifierConfig::uncached()` never caches, and serves as the reference for SPEC §11.3.
- **Receipts.** Line 40 finds a required approver's receipt by binary search, since receipts are sorted (D-15). The invocation digest is computed only when an approval is required.
Why: The paper names the checks, not the reject line for each way resolution can fail, nor the cache's key.
Affects benchmarks: yes. The warm state depends on these cache rules.

## D-61 — The phase-ordering row: cold line-34 rejections involve pairings
_Revised 2026-10-04: the test runs for both instantiations; the pairing counts are asserted under the aggregate variant, and the signature-check counts under both (D-84). Paper revision 2026-10-04 states the cold-path exception (§4.6), resolving P-28._
Spec section: §11.2 "Phase ordering (Figure 2, count-ops)"     Paper section: §4.6, Figure 2 (P-28)
Decision: For the line-34 case, SPEC expects 0 pairings. The test instead asserts the counts that actually occur:
- 0 pairings for a warm verifier;
- for a cold verifier, exactly N+1 certificate verifications and no aggregate or receipt check: for N = 2, 3 signature verifications, 3 hash-to-G2, 6 Miller loops, 3 final exponentiations.
The expired-chain and wrong-audience cases assert 0 pairings and 0 resolver calls, as SPEC says, and pass on a cold verifier.
Why: Line 24 verifies each certificate under its registry root, and in arms A and B that is a BLS verification. Phase 5 precedes phase 6, so a cold verifier has paired before it reaches line 34. Asserting 0 would make the test fail against a correct implementation of the paper. The discrepancy is the paper's claim, logged as P-28, and not a defect to hide. (SPEC §0 rule 10: this test's expectation changed, and this entry records why.)
Affects benchmarks: yes, for the §13.11 claim "cheap checks reject hostile chains before any pairing". Its verdict must separate warm from cold.

## D-62 — Nonce-cache eviction
Spec section: §10.4     Paper section: §4.6, Theorem 5
Decision:
- Lookups evict an expired entry lazily, and only if it is still expired under the shard lock.
- `insert_if_absent` treats an expired entry as absent.
- The periodic sweep is a public method (`NonceCache::sweep`) that the host calls. It is never called inside `verify`, so a sweep does not land inside a timed verification and inflate p99. The benchmark harness sweeps between configurations.
- Neither path evicts an unexpired entry; this is tested.
- The key is the invoker key followed by the nonce, in one byte vector.
Why: SPEC asks for a periodic sweep but does not say who runs it. Running it inside `verify` would put an occasional O(cache) cost into some measured calls, and would not be the same across arms with different call rates.
Affects benchmarks: yes (Q6, Q10). It keeps sweep cost out of the latency samples.

## D-63 — How `count-ops` counts
Spec section: §10.3     Paper section: §4.6
Decision:
- Counters are thread-local; one verification runs on one thread (D-29). They are reset at the start of `verify_counted`.
- Crypto operations are counted in `dc-crypto`, where it asks `blst` for the work, with the multiplicities `blst` performs:
  - a single BLS verification: one hash-to-G2, two Miller loops and one final exponentiation;
  - an aggregate over n messages: n hash-to-G2, n + 1 Miller loops and one final exponentiation.
  - An Ed25519 verification counts one signature verification and nothing else.
- Resolver calls, policy-store calls, `Contains` and `Evaluate` are counted by the verifier.
- "Pairings" in the §11.2 rows means Miller loops plus final exponentiations.
- The feature is off by default. `dc_crypto::ops::ENABLED` reports whether it is on, so that a benchmark harness can refuse an instrumented build.
Why: `blst` exposes no counters, so counting at the call sites is the closest honest measure.
Affects benchmarks: no. It is never enabled in timed runs (SPEC §10.3).

## D-64 — Dependencies optimized in dev and test builds
Spec section: §3.3     Paper section: not applicable
Decision: `[profile.dev.package."*"] opt-level = 3`, so that `blst`, `dalek` and the other dependencies are optimized in `cargo test`. Workspace crates stay at the dev profile. Release and bench profiles are unchanged.
Why: The security suite's 64-thread, 1,000-round replay test and the 10,000-chain equivalence test would otherwise take minutes.
Affects benchmarks: no

## D-65 — Revocation names a binding, not a certificate (ahead of the paper)
_Adopted by paper revision 2026-10-04 (§5.6). Retention now adds the clock-skew bound (D-82)._
Spec section: §2, §6.5, §10.1, §10.2, §11.3, §12.1     Paper section: §5.4, §5.5, §5.6, Algorithm 1 lines 27 and 42 (P-29)
Decision:
- **The assertion.** Its body is `{1: registry_id, 2: serial, 3: revoked_at, 4: identifier, 5: pk}`. It revokes the binding of `identifier` to `pk`, whichever certificate `serial` names; the serial is kept for audit and does not affect any decision.
- **Ingestion.** `ingest_revocation`:
  - verifies the assertion under `Root[registry_id]`;
  - requires `identifier` to be in that registry's namespace (`RevocationError::Namespace` otherwise);
  - marks (registry, identifier, key) revoked;
  - evicts every cached certificate for the binding, whatever its serial, and, from M7, every prefix-cache entry that lists the binding.
- **Lines 27 and 42.** A certificate is revoked if its binding is revoked. This is checked on every use, cached or not, so the eviction is hygiene, not what makes the decision correct.
- **Registry.** It refuses to certify a revoked binding (`RegistryError::RevokedBinding`). A new key for the same identifier is a new binding and is certified: that is emergency rotation.
- **Lifetime cap.** `MAX_CERT_LIFETIME` = 7 days: the registry refuses `exp > now + MAX_CERT_LIFETIME` (`RegistryError::LifetimeTooLong`). The workloads use 24 hours or less, so the cap binds nothing in the benchmark.
- **Retention.** A verifier keeps a revoked binding through `revoked_at + MAX_CERT_LIFETIME`; `forget_revocations(t)` drops a record only when `t` is later than that.
  - Every certificate for the binding was issued no later than the revocation, so it has expired by then. The registry never certifies the binding again.
  - Forgetting is the host's call, never made inside `verify`.
  - The single injected clock means registry–verifier clock skew is not modelled. A deployment would add the skew bound to the retention.
- **Regression vectors.** `tests/vectors/*.json` were regenerated for the new body. Only the revocation-assertion vector changed.
- **One registry test reordered.** `resolution_returns_the_latest_certificate_valid_or_not` used to re-certify a revoked binding, which is now refused. It now renews first and revokes second, and checks the same D-26 properties: an expired or revoked certificate is still returned, and the newer certificate wins.
Why: P-29, under serial revocation:
- a warm verifier kept accepting a renewed key whose newer certificate was revoked, while an uncached verifier rejected it; the caches changed outcomes;
- revoking the older certificate of a renewed binding left the key accepted even by an uncached verifier.
The author chose binding revocation (option (c) at the M6 checkpoint), to be implemented ahead of the paper under the SPEC §2 exception, as D-35 and D-36 were.
Affects benchmarks: marginally, and identically for every arm, since all arms share the verifier core. Line 27's revocation lookup is now keyed by identifier rather than by (org, serial). Revocation ingestion is not timed.
Paper status (revision 2026-09-29): ahead of the paper. §5.6 revokes a certificate by serial. P-29 records the problem and this fix.

## D-66 — C-batch uses `verify_batch`, whose semantics differ from `verify_strict`
Spec section: §5.8, §12     Paper section: not applicable (VARIANT)
Decision:
- **What each arm calls.** Arm C checks each chain signature with `verify_strict`; arm C-batch makes one `ed25519_dalek::verify_batch` call over the N + 1 triples (`Ed25519::verify_batch` in dc-crypto). The keys are copied into a vector, because the library takes them by value.
- **Where they differ** (ed25519-dalek 2.2.0, read from its source):
  - `verify_batch` checks the cofactorless equation over a random linear combination. Its 128-bit coefficients come from a Merlin transcript of the inputs, finalized with a zero RNG, so a batch decides deterministically.
  - It does not reject a small-order R. It compares points, where `verify_strict` compares R's encoding with the recomputed one.
- **Consequences, shown by `crates/dc-baselines/tests/ed25519_batch.rs`:**
  - A signer can make σ with R the identity, which C rejects and C-batch accepts.
  - A signer can make σ with a mixed-order R, which C always rejects. C-batch accepted it in 37 of 64 chains that differed only in their other signatures.
  - These signatures need the signer's own secret key, so they are not third-party forgeries.
  - Weak (small-order) public keys are rejected at decode in both arms (D-30). Mixed-order keys are not.
- **Scope.** C-batch appears only as its own arm (SPEC §5.8). On the §11.3 run it agrees with C on all 10,000 chains (D-70), none of which carries such a signature.
- **Short-circuiting.** C and A-ind stop at the first failing signature. Valid chains, the ones timed, verify every signature.
- **Counting.** `count-ops` counts C-batch as N + 1 signature verifications.
Why: SPEC §5.8 asks for the difference to be logged. The tests show it is not only theoretical.
Affects benchmarks: C-batch's latency is for different semantics, and every report that shows it says so.

## D-67 — Prefix caches (arms B and D): what is cached, when, and for how long
Spec section: §5.7, §12.1, §11.3     Paper section: §5.4 (certificate cache TTL), §8.3
Decision:
- **Structure.**
  - `dc_verifier::PrefixVerifier<C: PrefixScheme, …>` wraps the default verifier. It lives behind dc-verifier's `variant-prefix-cache` feature, which only dc-baselines enables.
  - Arm B is `PrefixVerifier<BlsAggregate>`: arm A's wire format and full path, with the pairing cache of §5.7 on a hit.
  - Arm D is `PrefixVerifier<Ed25519List>`: arm C's, with σ_N alone checked on a hit.
- **The full path.** It is the default verifier's `verify_envelope`, which takes a hook it calls once after line 50. Arms A, A-ind, C and C-batch pass `()`, whose hook is an empty inline function, so their path does no extra work.
  - The per-line checks the hit path needs (5, 8–9, 13, 17, 23–27, 36–37, phase 7, 50) are functions that both paths call. The two paths therefore share code line by line, rather than keeping two copies.
  - The refactor left all 51 §11.2 rows and Theorem 5's test unchanged.
- **Key.** The key is `m_{N−1}`, computed with the session tag and then the delegation tag. `chain_digests` over the prefix alone would give its last body the invocation tag, which is not the digest the chain signs.
- **Filling.** An entry is filled only when the full path accepts. The SPEC's "run the full algorithm, then populate the cache" is read as populating on acceptance.
  - A chain rejected for its invocation (for example denied at line 37) fills nothing, though its prefix may be sound.
  - Everything an entry holds was then checked by an accepting run. For arm D, that includes every prefix signature.
- **Validity window.** From the latest prefix certificate's `nbf` to the earliest of:
  - every prefix body's `exp`;
  - every prefix certificate's `exp`;
  - each prefix certificate's certificate-cache lifetime, which is the time it was resolved plus the TTL (one hour by default).

  The last bound was not in SPEC §12.1; the author approved it at the M8 checkpoint, and SPEC §12.1 now includes it. It keeps a prefix entry from holding a resolution result longer than the certificate cache itself may (paper §5.4). Without it, warm+prefix could keep using a certificate that warm would have re-resolved. It binds nothing in the benchmark, whose runs are much shorter than an hour of verifier-clock time.
- **Invalidation.**
  - Revocation evicts every entry that lists the binding (D-65). Any pin or unpin clears the cache.
  - Ordering: revocation and pin changes update their own state, then take the entries' lock. An insert checks the revocation set and the pins while holding that lock. So a verification that began before a revocation or unpin cannot leave a stale entry behind.
  - Expired entries are dropped when a lookup finds them.
- **Hit path.** It is the path of SPEC §12.1, in Algorithm order.
  - Line 2 decodes B_N and the signature container in the full path's order, so a decode failure yields the same L02 message.
  - The last key link is line 18 when N = 1, and line 20 at k = N − 1 otherwise.
  - Line 48 compares m_N with the cached digests.
- **Arm D matching.** A hit requires the received prefix signatures to be byte-identical to the cached ones; any difference is a miss. Arm B accepts any aggregate on a hit, since the full equation covers every signature.
- **Pairing cache (§5.7).** `dc_crypto::pairing_cache` uses only safe `blst` APIs; there is no `unsafe`. `P` is `Pairing::aggregate` with no signature, then `as_fp12`.
  - The hit check is `blst_fp12::finalverify(ML(σ, g1), P · ML(H(m_N), pk_N))`. `finalverify` conjugates its first argument, and after the final exponentiation that is inversion, so this is SPEC §5.7's equation, exactly as `aggregate_verify` evaluates it.
  - The §5.7 test compares the two on 10,000 randomized chains (`docs/test-reports/pairing-cache-equivalence-m7.json`).
Why: SPEC §12.1 leaves open when to fill, how the hit path shares code, how to handle the certificate cache TTL, and how invalidation races with verification.
Affects benchmarks: yes. This defines arms B and D. The warm+prefix schedule (D-39) fills each entry during warm-up.

## D-68 — Arm E: the Biscuit mapping
Spec section: §12.3     Paper section: Table 1 (positioning only)
Decision:
- **Library.** biscuit-auth 6.0.0, pinned exactly. Its default features minus `pem` (so `datalog-macro` and `regex-full`).
  - Its ed25519-dalek features (`rand_core`, `zeroize`) are already enabled by dc-crypto, so adding arm E changes nothing in arm C's build.
  - It uses sha2 0.9, a different crate from our sha2 0.10.9.
  - It pulls in `proc-macro-error2`, which draws a future-incompatibility warning from rustc 1.97.1. The warning concerns that crate, not ours.
- **Mapping** (`crates/dc-baselines/src/biscuit.rs`, module documentation):
  - the authority block holds a `right(aud, tool, action)` fact per session rule, an expiry check, and the session scope as one check (`check if body_1 or … or body_k`);
  - each delegation is an appended block with an expiry check and its scope as a check;
  - DC's N is Biscuit depth N − 1;
  - the authorizer holds `aud`, `tool`, `action`, `now`, `param_count` and one `param(path, value)` fact per flattened leaf. Its policies allow if the authority block grants the right, or `allow_all`.
- **Faithful parts.** Rule heads, closed-world parameter sets with their types (`param_count`, `.type()`), and integer, equality, `starts_with`, `ends_with`, `contains` and `in` atoms all map exactly.
- **Differences from Evaluate:**
  - `under` does not check that the value is a canonical absolute path;
  - a check passes if any body matches, while DC's first matching rule decides;
  - a rule that requires approval also requires an `approved` fact that the authorizer never holds, because Biscuit carries no receipts.
  - On the §6.2 policy family, arm E allows exactly what DC allows without approval: 204 invocations at depths 0–3 (`crates/dc-baselines/tests/biscuit.rs`).
- **Keys.** Deterministic: the root and per-block keys are derived from a seed. Tokens are therefore byte-reproducible.
- **Limits.** The authorizer's time budget is one second instead of the default one millisecond, so that load (Q6) cannot turn into spurious rejections. Fact and iteration limits keep the library's defaults.
- **The timed operation.** `Biscuit::from` (deserialize, verify every block), authorizer construction and `authorize`, as SPEC §12.3 specifies. Facts are built programmatically, and the policies are parsed once, outside the timed region.
- **Checked against AIP (2026-10-01, after M10; BENCHMARKS.md Q9).** SPEC §13.10's figures match arXiv:2603.24775v1, Table 5. AIP's timed Rust "verify" is not this operation:
  - it is `ChainedToken::from_base64` plus `authorize` (github.com/sunilp/aip at `ad2faa6`);
  - it decodes base64, prints block 0's Datalog and parses it back, verifies every block's signature twice (once more in `authorize`, after re-serializing), and parses its authorizer from Datalog text;
  - it reports the mean of 100 single timings with no warm-up;
  - its published sizes are base64 lengths, so arm E's raw sizes are compared through their base64 length.
  
  The mapping and the timed scope were not changed.
Why: SPEC §12.3 asks for the mapping to be recorded.
Affects benchmarks: yes, for Q9 and every table that shows arm E, together with its functional gaps (SPEC §12.3).

## D-69 — A-ind, C and C-batch wire formats
Spec section: §5.1, §7.5, §12     Paper section: not applicable (VARIANT)
Decision:
- **Wire format.** A-ind carries N + 1 BLS signatures (96 bytes each) as a list; C, C-batch and D carry N + 1 Ed25519 signatures (64 bytes each).
- **Decoding.** Anything but a list of exactly N + 1 well-formed signatures is line 2: `WireShape` or `SignatureCount`. Each signature is validated once, at decode (D-30).
- **Registries.** A-ind's use BLS roots. C's, C-batch's and D's use Ed25519 roots (SPEC §12).
- **Code.** The schemes are in `dc-baselines`, and run the same generic verifier as arm A.
Why: SPEC §12 names the arms but not their envelope forms.
Affects benchmarks: yes, for Q2's bytes.

## D-70 — The §11.3 run for every arm, and how it exercises the prefix caches
Spec section: §11.3, §12.1     Paper section: §4.6
Decision:
- **Families.** `tests/prefix_equivalence.rs` runs one family per wire format, 10,000 chains each, and requires identical decisions and reject variants across all configurations:
  - BLS aggregate: A uncached, A warm, B warm+prefix;
  - Ed25519 list: C uncached and warm, C-batch uncached and warm, D warm+prefix;
  - BLS list: A-ind uncached and warm.
- **Prefix reuse.** A prefix cache only matters when prefixes repeat. So three chains in four are new invocations on one of 12 stored prefixes (one delegation, many invocations), and the rest start a new prefix.
  - Invocation-level mutations reach the hit path's rejections: another holder, an expiry beyond the prefix's, a future `nbf`, a missing approval.
  - Whole-chain mutations reach its misses.
- **Events.** As `cache_equivalence.rs` (D-65), plus pin changes: P2 is pinned at 1/2 of the run, unpinned at 3/4, and pinned again at 7/8.
- **Coverage floor.** Each prefix configuration must hit on more than one chain in five.
  - A first draft reused a prefix only about 1.5 times on average and fell short: 289 hits in 1,500 chains. The generator was then changed to reuse more, with the same threshold.
  - This changes only the test workload, not any arm.
- **The arm-A-only test stays.** `cache_equivalence.rs` remains, as the M6 record extended by D-65.
Why: SPEC §11.3 names the configurations, not how to make a prefix cache hit often enough for the test to mean something.
Affects benchmarks: no

## D-71 — Workload definitions
Spec section: §13.2, §13.5     Paper section: §6.2 (the medium policy)
Decision: everything is generated from seed `0xDC_2026_0929` (`crates/dc-bench/src/workload.rs`).
- **Parties.**
  - `orga` holds the issuer, the finance approver, and agents `p0`–`p11`; `orgc` holds agents `p0`–`p11`; `orgb` holds the services.
  - Hop k of chain i is agent `(i + k) mod 12` of `orga` for even k and of `orgc` for odd k. Chains are cross-organizational, and no identity repeats within a chain for N ≤ 10 (D-40).
  - The first 12 warm-up chains cover every agent at every hop position.
- **small.** One rule: `amount <= 1000` over `amount: int` and `to: string`. Delegations are identity. The invocation is 500 to `acct_vendor_a`.
- **medium.** The §6.2 policy, verbatim. Odd hops tighten rule 1's bound by 10, even hops rule 2's by 1,000: one bound per hop, cumulative. The invocation is 500 to `acct_vendor_a` (rule 1, no approval).
- **medium-approval.** The same chain; the invocation is 5,000, which falls to rule 2 and carries one finance receipt.
- **large.** 16 rules: tools payments/transfer and refunds/issue at the payments service, and files/read and archive/restore at the files service, 4 rules each.
  - Each rule declares 4 parameters and has 3 atoms.
  - Rule 0 of each payment tool requires approval and precedes the permissive rule 1 it overlaps.
  - The target, archive rule 3, is last. Its size bound is 4,000,000 − k at hop k.
  - Hops 1–6 drop 2 rules each, from the 13 that are neither approval rules nor the target, in a seeded Fisher–Yates order; 4 rules remain from hop 6 on (D-38).
  - The invocation (archive/restore, path under `/data/archive/3/`) matches only the target, which is Evaluate's worst case.
- **Times.** Every chain is issued and verified at T0 = 1,790,000,000. Bodies expire at T0 + 3,600, the invocation window is [T0, T0 + 600], and certificates last 24 hours.
- **Sets.** Each chain set has its own random stream, from SHA-256(seed, set tag). The tag names the family, profile, N, layout and count. Sets verified by one verifier therefore never share a nonce stream.
- **Verification.** `crates/dc-bench/tests/workload.rs` checks that every profile verifies at every N for arms A, A-ind and C, in both layouts, and the large profile's shape.
Why: SPEC §13.2 fixes the profiles' shape, not their exact rules, tightening steps, identities or times.
Affects benchmarks: yes. This defines the workloads.

## D-72 — Harness method details
Spec section: §13.3–§13.6, §13.8     Paper section: not applicable (method)
Decision:
- **Sets.** Each run process generates all its chain sets first, on every core, into `target/dc-bench-sets/`. It then waits 30 s for the machine to settle, and runs its configurations in an order seeded per run (`order_seed(run)`), so each run has a different order. The sets are deleted at the end of the run.
- **The timed operation.**
  - One `Subject::verify(&bytes)` call through a trait object, the same for every arm.
  - Arms B and D call `verify_traced(bytes, clock.now())`, which is the body of their `verify`, so that the harness can assert the path.
  - Arm E calls `BiscuitArm::verify`.
  - A cold verifier is a normal verifier (caching on) with empty caches, built before every call, outside the timer.
- **Rejections are fatal.** Every verification must accept. Arms B and D must hit on every measured warm+prefix call and miss on every measured prefix-miss call. Any exception aborts the run rather than producing numbers.
- **Q5.** Latency is injected by `WithLatency`, which sleeps at least the delay per call. The call counts per verification are recorded in `run*-calls.csv`.
- **Q6.**
  - One shared verifier per (arm, threads). Its certificate caches are warmed with 1,000 separate chains; arms B and D fill their prefix entries during the timed run, one miss per prefix.
  - Chains are handed out by an atomic counter.
  - Wall time runs from the start barrier to the join.
  - The p99 comes from per-thread HdrHistograms (3 significant digits), merged.
  - The (arm, threads) order is shuffled per run.
- **Statistics.** Headline statistics pool the samples of all runs for a configuration. Each run's median is reported for run-to-run variation. Bootstrap seeds derive from the configuration's key.
- **A-mt.** A separate build (`--no-default-features`, into `target/a-mt`). A binary refuses every row whose build does not match its label, and records its blst threading mode.
- **Arm E's label.** Its state is `stateless`: Biscuit keeps nothing between calls, so it has no cold/warm distinction.
- **Q2.** 20 sampled chains per cell. Arm E's token bytes are reported as a total only.
- **Q10.** A dedicated binary with `stats_alloc`. Caches are measured by difference between two verifiers that differ only in the cache under test; see the binary's documentation.
- **One command.** `cargo run --release -p dc-bench -- all` (`default-run`). It builds A-mt, runs the three runs, bytes, memory, criterion (with `CRITERION_HOME` in the results directory), the report and the plots. `--mode dry` is M8's dry run, into `results/dry-run/`, which is not committed.
Why: SPEC §13.5 leaves these open.
Affects benchmarks: yes (method)

## D-73 — Micro-benchmark definitions (Q7, Q8, primitives)
Spec section: §13.5     Paper section: §4.6 (cost attribution)
Decision:
- **Hash-to-G2.** `blst` has no safe hash-to-G2 on points, and `unsafe` is not permitted in dc-bench. `bls/hash_to_g2_proxy` therefore times a pairing context plus one `Pairing::aggregate` with no signature (hash, then queue the pair). `bls/pairing_context` times the context alone, and the difference estimates hash-to-G2. The Miller loop and the final exponentiation are timed directly (`blst_fp12::miller_loop`, `final_exp`).
- **Q8 scopes.** Every rule has one head and 8 declared integer parameters. Rule i's atoms bound x0 … x(a−2) by 1,000 and require x(a−1) == i, so a rule fails only at its last atom.
  - Evaluate, typical: the first rule matches. Worst: only the last rule matches.
  - Contains, typical: the child equals the parent. Worst: every child rule's bounds are tightened.
- **Q7.**
  - Per-hop signing is `SigningService::sign` on a delegation: canonical encoding, digest and signature.
  - "Aggregate add" is `ChainScheme::accumulate`: a point addition for BLS, a push for Ed25519.
  - Receipt signing is `ApprovalService::approve`.
  - Issuance is `IssuanceService::issue`.
Why: SPEC §13.5 lists what to measure, not how to construct the inputs.
Affects benchmarks: yes (Q7, Q8, the α/β attribution)

## D-74 — Fuzzing the CBOR decoder on the stable toolchain
Spec section: §11.4     Paper section: not applicable
Decision:
- **Target.** `fuzz/` is a cargo-fuzz crate with one target, `cbor_decode`: the dc-cbor decoder on arbitrary bytes.
- **Properties.**
  - Nothing panics.
  - Input decoded with no canonical-form violation re-encodes to itself.
  - Re-encoding is a fixed point.
- **Toolchain.** cargo-fuzz is not installed, and the installed nightly (1.67, 2022) predates edition 2024. The target is therefore built on the pinned stable toolchain with cargo-fuzz's own coverage flags, which are all stable `-C` options, for the host triple (`scripts/fuzz.sh`).
  - AddressSanitizer (`-Zsanitizer`) is nightly-only and is left out; the decoder has no `unsafe`.
  - On this machine, `/usr/local/include` holds C headers that shadow the SDK's, so libFuzzer's C++ is built with `-isysroot` of the Xcode SDK. That is a local quirk, not a project setting.
  - `cargo fuzz run cbor_decode` works unchanged wherever cargo-fuzz is installed.
- **A failing property, corrected.** The third property first compared decoded `Value`s. It failed at once, because for input whose map keys are out of order (a recorded violation) the decoder keeps the input order, while the encoder writes canonical order. So the values differ in map order only. The property was wrong, not the decoder, and it now compares bytes (the fixed point). The failing input is kept as the corpus seed `regress-unsorted-map-keys`.
Why: the author asked for a decoder fuzz target before M9. SPEC §11.4 requires no panics and no accepted mutation.
Affects benchmarks: no

## D-75 — Benchmark method changes from the M8 checkpoint
Spec section: §13.5, §13.6, §13.8, §13.9     Paper section: not applicable (method)
Decision: the author's changes to the frozen plan, and the details this implementation chose for them.
- **Verdicts.** Every ratio verdict uses a ±10% margin on the pooled 95% CI, and needs all three runs' own ratios of medians on the same side (`report::verdict`, with unit tests). Otherwise the verdict is "inconclusive (runs disagree)".
- **Bytes.** Q2's primary comparison is A against C. `dc-bench bytes` measures every N from 1 to 10, so that the break-even N is exact. A against A-ind is the aggregation ablation, and medium-approval rows are included.
- **Thermal state.**
  - `pmset -g therm` is read before and after every configuration and every Q6 row, into `run*-thermal.csv`.
  - A reading counts as throttled if `CPU_Speed_Limit` < 100, or if it records a thermal or performance warning level. This Mac reports no `CPU_Speed_Limit`, only "no warning level recorded" notes, so the warning levels are the signal that can actually fire here. That was decided before any measurement.
  - Throttled configurations are re-run after the main runs (`dc-bench run --rerun --only …`), their samples replace that run's, and an entry is appended to `BENCH_LOG.md` whatever the result.
- **Machine state.**
  - AC power (`pmset -g batt`) and High Power mode (`powermode 2`) are required before anything is built.
  - An idle machine means a 1-minute load average below 2.0 and no other process above 25% of a core (`ps`). It is required after the harness's own builds, with up to 10 minutes for it to hold, because XProtect scans newly built binaries. It is checked again at the start of every run process.
  - `env.json` records the three checks (`m9_requirements`), and `all` aborts unless they all pass.
- **Raw data.**
  - `dc-bench archive` compresses each file in `results/raw/` with zstd (level 10) into `results/archive/`, and writes `MANIFEST.sha256` over the archives.
  - The report generator reads raw data only from archives whose SHA-256 matches the manifest; a missing manifest or a mismatch stops it.
  - The raw CSVs and archives are out of git; the manifest, `summary.md` and `summary.json` are committed.
- **Claims** are evaluated against paper revision 2026-09-29.
- **Arm E's 3× sanity rule** is flagged in the summary: an arm E ratio to AIP outside 3× must be investigated before arm E is reported.
Why: the author's conditions for approving the plan (M8 checkpoint); the details fill what those conditions leave open.
Affects benchmarks: yes (verdicts, re-runs, the preconditions of a run).

## D-76 — The calibration probe and the safety valve
Spec section: §13.5     Paper section: not applicable (method)
Decision: the author's amendment before any measurement (frozen plan §5), with these details.
- **Probe** (`crates/dc-bench/src/probe.rs`).
  - 100 BLS verifications and 1,000 Ed25519 `verify_strict` calls, cycling over 8 fixed, valid (key, message, signature) triples of each scheme.
  - The triples are built once from fixed seeds, outside any timing.
  - Each call goes through `std::hint::black_box`, and a probe panics if any verification fails.
  - It uses the same crates and build as the arms.
- **Placement.** On the measuring thread, which has QoS user-interactive.
  - Before a configuration: pmset, then the probe. After it: the probe, then pmset.
  - For Q6 the probe runs single-threaded on the measuring thread, between thread counts.
- **Baseline.** The median of 5 probes after the 30 s settle, recorded as rows `baseline-1` … `baseline-5` of `run*-thermal.csv`.
- **Columns.** Every row carries the probe time, the baseline, `probe_slow` (probe > 1.05 × baseline), `pmset_warning`, and `throttled` (either).
- **Valve** (revised 2026-10-01, a post-measurement deviation; `BENCH_LOG.md`). It counts flagged configurations **per run**, over the run's main and A-mt processes together: 255 configurations (231 latency plus 24 Q6).
  - The A-mt process starts its count from the main process's flags, read from that run's meta file.
  - Once more than 10% are flagged, the process stops. It writes its partial CSVs and a meta file giving the reason, and exits with an error, which stops `all`.
  - A re-run process records its flags but has no valve.
  - The dry run uses the same code.
  - History: until 2026-10-01 the count was per process. That tripped run 2's A-mt process (2 of 16), on flags caused by A-mt's own all-core load.
- **Warm-up spin** (added 2026-10-01, a post-measurement deviation). A fixed busy spin of about 200 ms runs on the probing thread before every probe, baseline probes included, outside the probe's timing, and is recorded as `warmup_ns`. Probes after Q5's sleep-dominated configurations had measured the idle core's ramp-up. It applies from run 2's A-mt redo on.
- **Measured data are never overwritten.**
  - A run process refuses to overwrite a completed process.
  - An aborted or partial process's files are moved to `results/aborted/<stem>-attempt-<k>/` before its redo, and are never read.
  - A fresh `all` refuses to start over measured data.
  - `all --resume` skips completed processes and re-runs, and records the machine at the restart in `env-resume.json`.
- **Reporting.** `BENCH_LOG.md`'s re-run entries name the signal that flagged each configuration, and whether its re-run was flagged again. The summary counts flagged configurations per run process, by signal.
Why: `pmset -g therm` on this Mac cannot report a CPU speed limit. A fixed probe measures what matters directly: how fast this machine runs the arms' own primitives, compared with the start of the run.
Affects benchmarks: yes (which configurations are re-run, and whether a run is usable at all).

## D-77 — Phase timing (`phase-timing`) and the exploratory phase breakdown
Spec section: §10.3, §13.5     Paper section: §4.6 (where verification time goes)
Decision:
- **A gap first.** SPEC §10.3 asks for a `phase-timing` feature beside `count-ops`. It was not built in M3–M9: nothing in the code, this file or MILESTONES.md mentions it, and no headline run needed it. It was added after M10, when the author asked for a phase breakdown.
- **Mechanism.** `dc_crypto::phases`, modelled on `ops`.
  - The state is thread-local. Without the feature, every function is a no-op, and `within(p, f)` is just `f()`.
  - The verifier calls `phases::begin` and `end` around `verify_at`, and `phases::enter` where each phase starts, in Algorithm order.
  - dc-crypto wraps its own primitives in `within`: `pk_from_bytes` and `sig_from_bytes` (point validation), and `verify`, `BlsAggregate::verify_chain` and `Ed25519::verify_batch` (signatures). Their time is charged to cryptography whichever phase calls them, so a signature's subgroup check during decoding counts as cryptography, not decoding.
  - Between `begin` and `end`, every nanosecond is charged to exactly one phase, so the phases partition the call.
  - The prefix-cache verifiers (arms B and D) do not call `begin`, so nothing is recorded for them.
- **The phases** (`Phase`, with their Algorithm lines): envelope, bodies, scopes (all line 2), canonical (4–6), structure (3, 7–12), temporal (13–16), replay (17, 50), key chain (18–21), identity (23–28), policy load (30–31), Contains (32–35), Evaluate (36–37), approvals (38–46), digests (47–48), point validation, signatures (24, 43, 49), and commit (after 50).
- **The categories** of the author's question (`dc_bench::phases::GROUPS`):
  - decoding: envelope, bodies, scopes, canonical;
  - policy: Contains and Evaluate;
  - identity: identity;
  - cryptography: point validation, digests, signatures. SHA-256 is counted as cryptography, and the per-phase table lets a reader regroup it.
  - Everything else is "other". Policy load is not "policy", because the author's definition names Contains and Evaluate.
- **The run** (`dc-bench phases`, a build with `--features phase-timing`).
  - The frozen grid's own configurations: arms A and C, warm, N = 3, small, medium and large. They use M9's chain sets and counts, run in each run's seeded order, three runs in separate processes.
  - It requires M9's machine state and records `env.json`.
  - pmset and the calibration probe are recorded around each configuration, with no valve and no re-runs.
  - Raw data are archived with zstd under a committed `MANIFEST.sha256` in `results/exploratory/phases/`, and the run appends its own `BENCH_LOG.md` entry.
- **Guards.** A `phase-timing` build refuses `run` and `all`, so it can never produce headline data (SPEC §10.3). CI runs clippy on the feature build and the partition test.
- **Statistics.** Per configuration, pooled over runs:
  - the median of each phase, and of each category's per-call sum;
  - each category's share, as its median over the sum of the five category medians;
  - the median instrumented call, the median outer-timed call, and this build's median over M9's (the instrumentation's cost, read across two different sessions);
  - per run, the median call and the largest difference in any category's share.
Why: SPEC §10.3 specifies the feature, and §13.5 the breakdown. Charging primitives wherever they run answers "what share is cryptography" without moving point validation into decoding. The run reuses M9's configurations so that the breakdown describes the measured operations.
Affects benchmarks: no headline result. BENCHMARKS.md §8 only (exploratory).

## D-78 — Paper artifacts (`dc-bench paper`)
Spec section: §0 rule 7, §13.8     Paper section: not applicable (artifacts for the revision)
Decision:
- **Tables** (`paper/tables/*.tex`) are generated by `crates/dc-bench/src/paper.rs`.
  - They load through `benchmarks::Doc`, so their numbers are the same data and statistics as BENCHMARKS.md. `Doc::load` first regenerates the summary from the verified archives.
  - Each is a bare booktabs `tabular` for the author to wrap in a float with a caption. The security suite's is a `longtable`.
  - **The §1 verdict table** gives B/D (warm+prefix), A/C and A/C-batch (warm) at every cell, each a ratio with its CI and a verdict symbol. The symbols are defined in the file's header comment, and a verdict of runs disagreeing has its own symbol.
  - **Q2's break-even** comes from `Doc::break_even`, the rule BENCHMARKS.md uses.
  - **The claims table** is BENCHMARKS.md §5, rendered from the same template and converted. Markdown bold and code become `\textbf` and `\texttt`. A character with no LaTeX mapping stops generation.
  - **Primitive costs** are criterion medians and CIs. Hash-to-G2 is shown as D-73's proxy, the context alone, and their difference.
  - **The security suite** is parsed from `tests/security.rs` and `tests/concurrency.rs`: every `assert!` and `assert_eq!` in each test, classified as a `Reject` line, accept, a registry rejection, or an operation count, in order. An assertion that cannot be classified stops generation. The suites are then run in release, and each row records whether its test passed. One test's loop of `is_ok() == ok` cases was rewritten as three explicit assertions so that it could be read, which also made its third case assert exactly L27, a stronger check than "not ok".
  - **The M4 oracle** comes from `docs/test-reports/policy-oracle-m4.json`.
- **Figures** (`paper/figures/*.pdf`) are drawn by `scripts/paper_figures.py` from `results/summary.json`, in the medium profile.
  - Points are pooled medians. The bars span the three run medians, because the pooled CIs are degenerate (BENCHMARKS.md §6).
  - Both latency figures use a log scale. The author asked for one for warm latency, and the prefix-hit figure needs one too, because B's hit is about 20× D's. Both are labelled at 1, 2 and 5 times each power of ten.
  - The bytes figure marks the break-even, recomputed with the report's rule and checked against `summary.json`'s statement of it.
  - The PDFs embed TrueType fonts and carry no creation date, so the same `summary.json` gives byte-identical files.
- **ARTIFACT.md** says how to reproduce every figure and table from the archives.
- **Added after the author's review (2026-10-01).**
  - **Captions.** `paper/figures/captions.tex` holds a caption macro per figure, generated with the figures. Each says what its error bars are: the range of the three runs' medians, or of their ratios for the ratio figure. The bytes figure has none, because sizes do not vary between runs. `paper/tables/captions.tex` holds the positioning table's caption.
  - **The ratio figure** (`ratios.pdf`, plus `ratios.png` for BENCHMARKS.md §3) plots the pre-registered verdict ratios: A/C (warm) and B/D (warm+prefix) against N in the small, medium and large profiles, in one panel, on a log scale, with a line at 1 and the frozen plan's ±10% band.
    - It is not exploratory. It was first placed in §8 and labelled exploratory, and was corrected on 2026-10-04 at the author's request.
    - Colour is the comparison, and marker and line style are the profile.
    - The bar is the range of the three runs' ratios of medians, drawn as it is: the ratio of pooled medians need not lie inside it.
    - The caption says that every run ratio lies above the band only when that is true of the data.
  - **The positioning table** (`positioning.tex`) is exploratory. It sets C (warm) and D (warm+prefix) against arm E at matching depth (medium), using M9's pooled medians, and its caption lists E's functional gaps (paper Table 1).
    - **An AIP column, added 2026-10-04 at the author's request,** is also labelled exploratory. It is AIP's own code measured on this machine (D-79): the median of all the timings build's timings at Biscuit depth N − 1, on AIP's own workload rather than the medium profile.
    - AIP's benchmark stops at depth 5, so N = 10 shows a dash, as does every row while the AIP archive is absent.
Why: SPEC §0 rule 7 forbids typing measured numbers by hand, and the paper is being rewritten around these results.
Affects benchmarks: no.

## D-79 — AIP's own benchmark, run here (exploratory)
Spec section: §12.3, §13.10     Paper section: not applicable (positioning)
Decision:
- **Why.** Q9's gap between arm E and AIP's published figures is only partly explained by the timed scope. The author asked for AIP's benchmark to be run unmodified on this machine, so that the hardware can be separated from the scope.
- **The source.** `bench_chained` from github.com/sunilp/aip at `ad2faa6` (`aip::COMMIT`), the commit that prepared arXiv:2603.24775v1.
  - `scripts/exploratory-session.sh` clones the repository and extracts its `rust/` tree twice under `target/exploratory/aip/`.
  - `dc-bench aip` checks that the unmodified copy's `bench_chained.rs` and `chained.rs` are byte-identical to the commit's before it runs anything.
- **The build.**
  - `cargo build --release --bin bench_chained`, with no RUSTFLAGS, because AIP records no build flags.
  - The toolchain is this repository's pinned one.
  - AIP commits no `Cargo.lock`, so Cargo resolves one for the unmodified copy, and the timings copy reuses it (`--locked`). The resolved versions of biscuit-auth, ed25519-dalek and curve25519-dalek are recorded, and the lock file is archived.
- **Two builds.**
  - **Unmodified.** Its printed means are AIP's own statistic: the mean of 100 single timings per depth, after no warm-up.
  - **Timings.** It adds `scripts/aip-timings.patch`: one `eprintln!` after the timed loop that prints the depth's 100 timings, for the median. Nothing timed changes; the median cannot be had without it, because the unmodified binary prints only means.
- **The run.**
  - Three runs of each build, alternating which goes first. Each binary runs as AIP runs it: no arguments, default scheduling, from its own directory.
  - pmset and the calibration probe are read around each invocation and recorded, with no valve and no re-runs.
  - It requires M9's machine state and records `env.json`.
  - It runs in the same session as the phase breakdown, from one script.
  - Raw outputs are archived with zstd under a committed manifest in `results/exploratory/aip/`, and the run appends its own BENCH_LOG.md entry.
- **Reporting** (BENCHMARKS.md §8, exploratory), per depth:
  - token size in base64 characters, here and as published;
  - AIP's published mean;
  - each unmodified run's mean, and each timings run's median;
  - the median and mean of all timings;
  - here ÷ published (the median of the runs' means);
  - arm E's M9 median and E ÷ AIP here (medians), small and medium.
Why: running the same code on this machine separates the hardware and build from the timed scope, which Q9 could only argue.
Affects benchmarks: no headline result. BENCHMARKS.md §8 only.

## D-80 — The flip: Ed25519 per hop is the protocol path, BLS aggregate a variant
Spec section: §3.2, §5.1, §5.8; §0 rule 3     Paper section: §4.2, §4.6, §4.8 (revision 2026-10-04)
Decision:
- **The paper.** Revision 2026-10-04 specifies DelegationChain over a scheme Σ. The default instantiation signs each hop with Ed25519 and verifies strictly, and the chain carries σ0 … σN. BLS aggregation is "the aggregate variant", which differs only in line 49's `VerifyChain`. Within one deployment, certificates and receipts use the same scheme.
- **dc-crypto.**
  - `Ed25519` and `Ed25519List` (the per-hop chain scheme, moved from dc-baselines) are compiled unconditionally. ed25519-dalek is a normal dependency.
  - `Bls`, `BlsAggregate`, the `blst` re-export and `BLST_THREADED` are behind a new `variant-bls` feature. blst is an optional dependency that only it enables.
  - `blst-no-threads` implies `variant-bls`, and the A-mt build is `variant-bls` without it (D-29 unchanged). The old `variant-ed25519` feature is gone.
  - The list helpers (`from_wire`, `to_wire`, `verify_each`) are a public `list` module, shared with dc-baselines.
  - Arm D's prefix state (`impl PrefixScheme for Ed25519List`) moved to dc-crypto's `prefix` module, because the orphan rule requires it once the type lives there. Arm B's pairing cache is behind `variant-prefix` and `variant-bls`.
- **dc-baselines** keeps A-ind (`BlsIndividual`), C-batch (`Ed25519Batch`), arm E and the arm table. It enables `variant-bls`.
- **dc-bench** enables `variant-bls` and `variant-prefix`. The measured arms are unchanged in what they verify, but the default instantiation's decoder now has D-81's checks. Re-measuring under the frozen plan therefore uses the measured commit (ARTIFACT.md).
- **The protocol crates are already generic over the scheme** (dc-types, dc-registry, dc-chain, dc-verifier), so none of them changed for the flip. Their tests that use BLS enable `blst-no-threads` as a dev-dependency.
- **`scripts/check-deps.sh`** keeps blst out of, and ed25519-dalek in, every protocol crate's normal graph, and keeps phase timing out of them as well.
- **Line 49's rejection variant** is renamed from `L49AggregateInvalid` to `L49ChainSignaturesInvalid`, after the paper's "Phase 8 — chain signatures".
Why: the paper wins (CLAUDE.md), and it now names Ed25519 per hop as the protocol and BLS aggregation as a variant. SPEC §0 rule 3 requires VARIANT code to stay off the default protocol path.
Affects benchmarks: not the measured results; the frozen benchmark is described as measured (SPEC §12 note).

## D-81 — Ed25519 encodings are checked at decode (paper §4.7)
Spec section: §5.3, §5.8     Paper section: §4.7, §5.3 (revision 2026-10-04)
Decision:
- **Public keys.** `Ed25519::pk_from_bytes` rejects:
  - a key whose y (the low 255 bits) is not below p, i.e. a non-canonical encoding;
  - one that does not decompress;
  - one of small order (`is_weak`).

  The other non-canonical form, x = 0 with the sign bit set, encodes a small-order point and falls under the last rule. Registries call it at registration (paper §5.3), and certificate decoding calls it when a certificate is verified (line 24).
- **Signatures.** `Ed25519::sig_from_bytes` rejects:
  - an R whose y is not below p;
  - an s not below ℓ.

  Both are byte comparisons, so each point is still decompressed once (D-30). A failure in a chain or receipt is L02.
- **R's order** is left to `verify_strict`, which rejects a small-order R at line 49, as paper §4.7 says ("strict verification also rejects a signature whose R is of small order").
- **The check is not redundant.** ed25519-dalek 2.2.0 decompresses a key's y + p alias to the same point (`dc-crypto` unit test `non_canonical_keys_are_ours_to_reject`), so without this check a non-canonical key would be accepted.
- **One test changed expectation.** `crates/dc-crypto/tests/ed25519.rs::strict_verification_rejects_non_canonical_s` decoded s + ℓ and expected verification to reject it. Decode now rejects it, so the test, renamed `non_canonical_s_is_rejected_at_decode_and_by_strict_verification`, asserts both. The second assertion goes through dalek's unchecked constructor (SPEC §0 rule 10).
- **Body key fields** are still only length-checked at decode. They are compared as bytes with resolved certificates, whose keys passed these checks (D-05).
Why: paper §4.7 requires decoders to reject non-canonical encodings and small-order keys. Which line a non-canonical signature fails at is otherwise open (P-32), and rejecting at decode matches the aggregate variant's treatment of points (D-30).
Affects benchmarks: the default instantiation's decode does a few more byte comparisons than in the measured build.

_2026-10-04: what these checks add to the measured latencies is measured on its own by an exploratory micro-benchmark (D-87)._

## D-82 — A revoked binding is kept for the maximum lifetime plus the clock-skew bound (paper §5.6)
Spec section: §6.5, §10.4     Paper section: §5.6 (revision 2026-10-04)
Decision:
- `RevocationSet::forget_before(t, skew)` keeps a record through `revoked_at + MAX_CERT_LIFETIME + skew`.
- The verifier passes `VerifierConfig::clock_skew`, which was called `nonce_skew` (D-25) and keeps its default of 60 seconds. One bound on clock skew serves both the nonce TTL and revocation retention.
- The registry test covers both boundaries.
Why: paper §5.6: "for the registry's maximum certificate lifetime after the revocation, plus a bound on clock skew". The paper gives no value (P-33). Using the verifier's one skew bound avoids two knobs for one quantity.
Affects benchmarks: no.

## D-83 — Reconciliation notes: paper changes that needed no code
Spec section: §8.2, §10     Paper section: revision 2026-10-04, §3, §4.5, §4.6, §5.4, §6.4
Decision:
- **§3 (signing service).** "At minimum, a signing service refuses to sign a body that does not name its own agent's identifier and key as the signer." `dc_chain::SigningService::sign` already refuses such a body.
- **§4.5 (receipts).** Receipts' "own domain separation tag" is D-04's BLS DST under the aggregate variant and D-07's `TAG_APR` digest tag under Ed25519, which has no DSTs.
- **§4.6 (cold path).** The cold-path exception and Figure 2's phase-5 label describe what D-61 tests.
- **§5.4 (resolution, P-30) and §5.6 (revocation by binding, P-29)** are what D-26 (revised) and D-65 implement.
- **§6.4.** It now states the string checks' incompleteness and their polynomial cost, which is what SPEC §9.5 implements (P-08).
Why: recorded so that the reconciliation is complete.
Affects benchmarks: no.

## D-84 — The workspace suites run for both instantiations
Spec section: §11.2, §11.3     Paper section: §4.2, §4.8, §8.2 (revision 2026-10-04)
Decision:
- **Selecting the instantiation.** `tests/common` picks the instantiation under test (`A`, `S`): `Ed25519List` and `Ed25519` by default, or `BlsAggregate` and `Bls` with the root package's `aggregate-variant` feature. CI runs both.
- **Instantiation-specific tests** are separate functions under `#[cfg(feature = "aggregate-variant")]` or its negation, so that each instantiation's table rows are its own:
  - `point_validation_bls` and `point_validation_ed25519` (D-30, D-81);
  - `t5a_pop_under_the_chain_dst` (BLS) and `t5a_chain_signature_as_pop` (Ed25519, where the challenge digest's tag separates a PoP from a chain signature, paper §5.3).
  Each instantiation runs 52 tests: 50 shared and 2 of its own.
- **Tests rewritten to run under both:**
  - `t1a_foreign_aggregate` became `t1a_foreign_signatures`: N+1 signatures by an unrelated key, whose sum is an unrelated G2 point under the variant.
  - Theorem 3's reorder case permutes the signatures with the bodies.
  - `phase_ordering_count_ops` asserts no signature check and no pairing warm, and N+1 certificate checks cold, with the pairing counts asserted under the variant only (`#[cfg]` on those assertions; D-61).
- **Dropped hops.** `t1b_truncation`, `t1b_drop_session_or_invocation` and `structure` drop the removed body's signature with it under per-hop signatures (`drop_body`), as an attacker who drops a hop can. Without that, the signature count fails at line 2 before the line under test. Under the aggregate variant `drop_body` leaves the aggregate as before. The expected lines are unchanged in both.
Why: the paper specifies two instantiations, and the security suite must show each one's rejecting lines (paper §8.2).
Affects benchmarks: no.

## D-85 — No containment cache on the default verifier (paper §6.5)
Spec section: §10.5     Paper section: §6.5 (revision 2026-10-04)
Decision: Paper §6.5 says "a verifier should cache containment results by scope digest, as the prefix cache of Section 8.4 does". The default `Verifier` keeps no containment cache (SPEC §10.5: warm uses certificate and policy caches only). The prefix-cache VARIANT (arms B and D) caches a prefix's verified containment.
Why: it is a recommendation, not a check. A cache of a deterministic function changes cost, not outcome, but on the default verifier it would change the measured warm state and SPEC §10.5's cache table. It can be added when an evaluation wants it.
Affects benchmarks: no.

## D-86 — Paper section numbers and rule names come from a mapping file
Spec section: §13.11; D-78     Paper section: §8.5, Table 5 (revision 2026-10-04)
Decision:
- `docs/paper-sections.json` maps each claim's section references and each rule name to two texts:
  - `checked`, for revision 2026-09-29, against which the claims were judged, used by BENCHMARKS.md;
  - `current`, for the paper in `docs/paper.pdf`, used by `paper/tables/claims.tex`.
- The template's claims table cites `{{psec:KEY}}` and `{{prule:KEY}}` instead of typed numbers.
- `dc-bench paper` refuses to run if the file's `current.sha256` is not `docs/paper.pdf`'s, so the map must be updated whenever the paper changes.
- For revision 2026-10-04 the map follows each claim's content, not its old number:
  - old §2.2, §4.6 and Figure 2 are §2.2, §4.6 and Figure 2;
  - old §4.3's 96-byte aggregate is in §4.8;
  - old §8.2 is §9.2;
  - the non-aggregating baseline claim (old §4.6, §8.3) is §8.3, where the question is posed;
  - "the §6 rule" is "the verdict rule of Section 8.3".
Why: the claims table printed revision 2026-09-29's numbers and the frozen plan's rule name, which the rewritten paper had to explain in its caption. The author asked for them to come from a file updated with the paper.
Affects benchmarks: no.
_Revised 2026-10-06: the map also holds the sections the paper cites where BENCHMARKS.md keeps an internal reference, and `inline-arithmetic`'s current text changed (D-88)._

## D-87 — The cost of D-81's encoding checks, measured on their own (exploratory)
Spec section: §10.3, §13.5; D-81     Paper section: §4.7 (revision 2026-10-04)
Decision:
- **Why.** D-81 added canonical-encoding checks to the Ed25519 decoders at step 3, after M9.
  - The measured binaries (`4e134dc`, `b175599`) did not have them. They already decompressed keys and rejected small-order ones.
  - The paper reads the default instantiation's latencies as the protocol's cost, so the author asked what the checks add.
- **What is timed.**
  - The checks as the decoders call them, made public for this: `Ed25519::canonical_signature` (R's y < p, s < ℓ) and `Ed25519::canonical_key` (y < p).
  - Inputs:
    - a cycled pool of 1,024 honest keys and signatures from seeded keys;
    - the worst passing inputs, y = p − 1 and s = ℓ − 1, which agree with their bounds in every byte but the lowest, so that every byte is compared.
  - For context, the whole decoders on honest inputs: `sig_from_bytes`, and `pk_from_bytes` with its decompression and small-order test.
  - Inputs go through `black_box`, and every call must accept (asserted after each batch), so nothing is optimized away.
- **How.**
  - Each batch is 100,000 calls (2,000 for the key decoder), timed with `Instant`, and gives one figure in ns per call.
  - Each operation has 10 warm-up batches, then 200 timed, per run.
  - Three runs, each in its own process, at QoS user-interactive after a 30 s settle.
  - It requires M9's machine state and records it in `env.json`. pmset and the calibration probe are read around each operation, with no valve and no re-runs.
  - The raw data are archived with zstd under a committed manifest in `results/exploratory/encoding/`.
  - The run appends its own BENCH_LOG.md entry, which names the measured commit. That commit must have D-81's checks, so it is not M9's.
- **Why on their own.** A before-and-after comparison of whole verifications cannot resolve the difference:
  - it would need M9's configurations re-measured at two commits;
  - the difference is tens of nanoseconds against tens of microseconds;
  - the timer ticks every 41.7 ns, and runs differ by a few percent.
- **The model.** One verification's added cost is the signatures it checks times the signature checks' median, plus the keys it checks times the key check's median. The worst-input medians give the bound.
  - **The counts** are per signer, for M9's states of arms C and D on the medium profile, which has no receipts (`encoding::LOADS`):
    - C warm, D hit and D miss: 1 signature and no key, since certificates are cached;
    - C cold: 2 signatures and 1 key, which are the chain signature, the certificate's signature and its key (line 24).
  - **The counts are tested.**
    - `count-ops` counts the keys and signatures the decoders check (`key_encoding_checks`, `sig_encoding_checks`).
    - `tests/encoding_checks.rs` checks `LOADS` on M9's own chains and subjects (`harness::generate`, `arms::subject`) at N = 1, 3 and 10, warmed as the harness warms them.
    - For that test the root package dev-depends on `dc-bench`.
  - **The shares** are of M9's pooled medians for each state (medium profile), read from the verified archives.
- **Caveat.** The checks are timed in a tight loop, with warm caches and a trained branch predictor. Their cost inside a verification may differ, which the model does not capture.
- **Reporting.** BENCHMARKS.md §8, exploratory.
Why: the checks are a few byte comparisons, far below a verification's cost. Measured on their own, with tested counts, they give a number, where a whole-verification comparison would give noise.
Affects benchmarks: no measured result changes. BENCHMARKS.md §8 only. The two counters exist only in `count-ops` builds, which never make headline runs (SPEC §10.3).

## D-88 — The paper's generated text carries no internal identifiers
Spec section: §13.8; D-78, D-86     Paper section: §4.6, §8.4, §8.5, §9.1 (revision 2026-10-04)
Decision:
- **The rule.** Nothing under `paper/` carries an identifier internal to this repository: no D-, P- or Q-numbers, no pre-registered question numbers (Q2, Q4, Q5), no milestone numbers (M4, M9) and no dates.
  - LaTeX comments are included, since a LaTeX source is published with its comments.
  - Arm letters stay: the paper defines them (§8.3).
  - BENCHMARKS.md keeps its internal references, and regenerates unchanged.
- **The claims table.**
  - `{{iref:REF:KEY}}` prints REF in BENCHMARKS.md, and section KEY's `current` text from `docs/paper-sections.json` in the paper.
  - Q4 (A against A-ind) and Q5 (the cold path's calls) cite §8.4, where the paper reports both.
  - P-28 and D-61 cite §4.6, which now states the cold-path exception (§8.5 says so).
  - "The 2026-09-29 text's arithmetic (its §8.2)" became "The arithmetic as specified before measurement", Table 5's own phrase.
- **The positioning caption** (`Doc::positioning_caption`). The paper's says "medians pooled over the three runs" for "M9's pooled medians" and drops "(D-79)". For "paper Table 1" it cites §9.1, where the comparison with related systems (revision 2026-09-29's Table 1, now Table 6) is.
- **The map.** An entry with only `current` is a section the paper cites where BENCHMARKS.md keeps an internal reference.
- **The test.** `crates/dc-bench/tests/paper_text.rs` scans every text file under `paper/`, and fails on any identifier. It also checks its matcher on positive and negative cases; "Apple M4 Max" is the chip, not a milestone.
- **Not covered.**
  - The figures' text (axis labels and legends) is in compressed PDF streams and PNG pixels, which the test cannot read without a new dependency. `scripts/paper_figures.py` draws it, and `pdftotext` found no identifier in the PDFs on 2026-10-06. A binary file under `paper/` that is not a PDF or PNG fails the test.
  - Comments still cite SPEC and BENCHMARKS.md sections, which are files of the artifact.
Why: the author asked that the text the paper reads carry no internal identifiers.
Affects benchmarks: no. Only wording and comments under `paper/tables/` changed; every number, BENCHMARKS.md and the figures regenerate unchanged.
