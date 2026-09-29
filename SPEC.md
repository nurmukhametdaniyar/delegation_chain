# DelegationChain — Reference Implementation and Benchmark Specification

**Audience:** Claude Code, working in a fresh Rust repository.
**Protocol source of truth:** the paper _DelegationChain: Aggregatable Capability Chains for Cross-Organizational Agent Authorization_, revision dated 2026-09-29 (44 pages; sha256 `51eff0ec620940c3062de303f671f5ddeee9907ddb3c06c46e19fc1b6da84e14`). Place it at `docs/paper.pdf`. Section and line numbers below (e.g. "§4.3", "Algorithm 1 line 26") refer to that revision; its line numbering is the same as revision 2026-09-28's.
**What this document adds:** every bit-level and engineering decision the paper deliberately leaves open (§4 says field numbering and byte layout "are not fixed by this paper"), a test plan, and a benchmark plan.

Put this file in the repository root as `SPEC.md`.

## Changelog

**2026-09-29 — reconciled with paper revision 2026-09-29.** The paper now carries every change that ran ahead of it, so the §2 exception is closed. Algorithm line numbering is unchanged; only lines 18, 20, 27 and 41 differ from revision 2026-09-28.
- **Resolved:** P-03, P-07, P-09, P-10, P-14 and P-15 to P-25. **Open:** P-05, P-06, P-08, P-12, and the new P-26 (Appendix C).
- **Adopted by the paper:** D-06, D-08, D-14, D-15, D-17, D-19, D-20, D-22, D-26, D-28, D-34, D-35, D-36 and D-37 now match the paper. The "ahead of the paper" notes are removed from §6.6, §10.2 and Appendix A.
- **Changed because the paper wins:** D-27. Line 41 now rejects an unresolvable approver itself, so two §11.2 rows move from L42 to L41 (§10.2, §11.2).
- **Added from the paper:**
  - string literals are NFC-normalized (D-17, §9.1), with non-NFC scope text in a body rejected at L05 as a canonical-form violation (new D-55, §4.4);
  - `Contains` returns false on a malformed scope, as a defensive check (§9.6, D-28).
- **Benchmark claims:** §4.6 no longer claims that the variation with N is small relative to α for N ≤ 10. It now says β (one hash to G2 plus one Miller loop per hop) "cannot be assumed small relative to α", and leaves which term dominates to measurement. §13.1 Q3 and §13.11 are updated.
- **Tests:** added a boundary row for certificate validity at `nbf` and `exp` (P-26, D-35).

**2026-09-28 — pre-M0 review, agreed with the author.** Read this before anything else; later sessions must not work from the pre-review text. New paper issues are P-15 to P-25 (Appendix C). New decisions are D-28 to D-47 (`DECISIONS.md`). Three changes run ahead of paper revision 2026-09-28 and are being carried into the next revision (P-15, P-16, P-17); §2 gives this spec precedence on those points until the revised PDF is in `docs/`.

- **Policy (§9.3, §9.5, §9.7).** An atom on a path its rule does not declare makes the scope malformed (D-28, P-15): L31 at policy load, L02 inside a body. The oracle generator gains boundary constants and undeclared-path atoms. M4 waits for the revised paper (§15).
- **Verifier (§10.2, Appendix A).** Lines 18 and 20 compare identifiers as well as keys (D-36, P-16). Line 27 checks `t ∈ [nbf, exp]` (D-35, P-17). Decode errors are split between L02 and L05 (D-31). Bodies are decoded by their own `kind` (D-32). Receipt-list rules (D-34). Caches are filled mid-verification; line 50 is the only decision-relevant mutation (D-37).
- **Crypto (§3.2, §5.3, §5.6).** blst is built with `no-threads` for every arm (D-29). Points are validated once, at decode; line 49 passes `sig_groupcheck = false` (D-30). blst's real behaviour is recorded; line 48 is the only distinctness check.
- **Encoding (§4.3, §4.4).** Declaration maps are a third map class (D-33).
- **Tests (§11.2).** Rows added for T5b (bounded), P-15, P-16, P-17, receipt lists and point validation.
- **Benchmark (§12, §13).** Supplementary threaded arm A-mt, in Q1 only (D-29). Large-profile rule dropping (D-38). warm+prefix schedule (D-39). Per-org identity pools (D-40). `stats_alloc` for Q10 (D-41). QoS user-interactive, with one logged `unsafe` FFI call (D-42). Q6 thread counts (D-43). Q5 iteration counts (D-44). macOS environment recording (D-45).
- **Fixes.** §6.4 cross-reference; §12 fairness wording; root package for workspace tests (D-46); toolchain pin (D-47).

---

## 0. Rules of engagement

Read these before writing any code. They override anything that seems locally convenient.

1. **Implement the paper as written.** Do not improve the protocol. If you believe the paper is wrong, ambiguous or incomplete, implement what it says, then log the problem in `PAPER_ISSUES.md` (format in Appendix B), with a failing test or a concrete example where possible. Appendix C lists issues already known; log them at M0.
2. **Every choice the paper leaves open goes in `DECISIONS.md`** with an ID (`D-01`, `D-02`, …) and the spec section it implements. This spec pre-assigns many decisions; record those too, so the file is complete.
3. **Benchmark variants are not protocol changes.** Anything marked **VARIANT** below exists only to answer a benchmark question. It must live behind a feature flag or in `dc-baselines`, and must never be reachable from the default protocol path.
4. **Never tune the benchmark to favor any arm.** All arms get the same inputs, machine, build flags, iteration counts and warm-up. If you optimize one arm, apply the equivalent optimization to every arm or to none.
5. **Report every result, including results that contradict the paper.** The benchmark exists to find out whether BLS aggregation is a net benefit. A result showing it is not is a successful outcome, not a failure to be engineered away. If a result contradicts the paper, the paper changes, not the benchmark.
6. **Freeze before measuring.** Before the first full benchmark run, write `BENCH_PLAN_FROZEN.md` (§13.9) and tag the commit `bench-freeze`. After that, harness changes are allowed only to fix bugs. Log each one in `BENCH_LOG.md` with the reason, then re-run every affected configuration.
7. **No fabricated numbers.** Every number in `BENCHMARKS.md` must be generated from `results/` by the report generator. Never type a measured value by hand.
8. **Fail closed.** Unknown fields, unknown enum values, oversized inputs, and anything the decoder cannot classify are rejected.
9. **`unsafe` is allowed in exactly two places**, each logged in `DECISIONS.md`:
   - `dc-crypto::pairing_cache` (§5.7), and only if the pinned `blst` version lacks a safe API for what is needed there. `blst` 0.3.17 has safe APIs for all of it, so none is expected.
   - One FFI call in `dc-bench` that sets the measuring thread's QoS class (§13.5, D-42).
10. **Do not weaken tests to make them pass.** Never mark a failing test `#[ignore]`, loosen an assertion or delete a test without logging why in `DECISIONS.md`.
11. **When genuinely blocked**, write the question in `QUESTIONS.md` and stop that milestone. Otherwise decide, log, and continue.
12. **No network code.** The registry and policy store are in-process behind traits, with optional injected latency (§6.6).

---

## 1. Goals and non-goals

### Goals

- **G1. Reference implementation** of the protocol in paper §4–§6: token bodies, chain digest, BLS aggregation, registry with proof-of-possession, revocation, policy language (parser, evaluator, containment procedure), and the verifier of Algorithms 1–2.
- **G2. Executable security suite:** one or more tests for every threat T1a–T6b (§3.3) and every theorem (§7.2), each asserting the exact Algorithm line that rejects.
- **G3. Benchmark** answering the questions in §13.1, above all: is BLS aggregation a net benefit for per-invocation verification cost, and how many bytes does it actually save, once caching is taken into account?

### Non-goals

Production hardening, network transport, MCP integration, a transparency log, persistence, HSM integration, post-quantum migration, and a normative wire specification. The encodings here are one reasonable instantiation, not a standard.

---

## 2. Precedence

1. The paper's normative content: Algorithms 1–2, §4–§6, and the theorems' stated preconditions.
2. This spec's decisions, which fill what the paper leaves open.
3. Your own decisions, logged in `DECISIONS.md`.

If this spec contradicts the paper, the paper wins. Log the contradiction as a `PAPER_ISSUES.md` or `DECISIONS.md` entry, whichever is appropriate. Appendix A reproduces Algorithms 1–2 for convenience; if it differs from the PDF, the PDF wins.

**Exception (agreed 2026-09-28, closed 2026-09-29).** For P-15 (D-28), P-16 (D-36) and P-17 (D-35), this spec ran ahead of paper revision 2026-09-28 and took precedence on those points. Revision 2026-09-29 adopts all three, so no exception remains, and the paper wins everywhere again.

---

## 3. Repository and toolchain

### 3.1 Layout

```
delegationchain/
  Cargo.toml                 # workspace, plus root package `delegationchain` that hosts tests/ (D-46)
  rust-toolchain.toml        # pin the current stable at project start; record it (1.97.1, D-47)
  SPEC.md  DECISIONS.md  PAPER_ISSUES.md  BENCH_LOG.md
  BENCH_PLAN_FROZEN.md  BENCHMARKS.md  QUESTIONS.md  MILESTONES.md
  docs/paper.pdf
  crates/
    dc-cbor/        strict deterministic CBOR subset (§4)
    dc-types/       identifiers, bodies, certificates, receipts, wire format, digests (§6–§7)
    dc-crypto/      signature-scheme trait; BLS (blst) and Ed25519 impls; pairing_cache (§5)
    dc-policy/      policy AST, text parser/printer, validation, evaluate, contains (§9)
    dc-registry/    in-memory registry, PoP, certificates, revocation, policy store (§6)
    dc-chain/       issuer, signing service, agent, approval service, chain builder (§8)
    dc-verifier/    Algorithms 1–2, caches, nonce cache, clock (§10)
    dc-baselines/   VARIANT arms: BLS-individual, Ed25519, prefix caches, Biscuit (§12)
    dc-bench/       harness binary, workload generators, criterion benches, report generator (§13)
  tests/            workspace-level security suite (§11)
  results/          raw CSV + env.json + generated summary
  scripts/          plotting (Python allowed here only)
```

### 3.2 Dependencies

Pin exact versions in `Cargo.lock`, and record every version that affects a measurement in `BENCHMARKS.md`. Use the latest release within each major version at project start.

| Purpose            | Crate                        | Notes                                                                             |
| ------------------ | ---------------------------- | --------------------------------------------------------------------------------- |
| BLS12-381          | `blst` 0.3.x                 | min-pk API (`blst::min_pk`). Feature `no-threads` in every arm (D-29). Record whether the build uses the ADX assembly path (N/A on aarch64: armv8 assembly, D-45). |
| Ed25519            | `ed25519-dalek` 2.x          | features `batch`, `rand_core`. Record which `curve25519-dalek` backend is active. |
| Hashing            | `sha2` 0.10.x                |                                                                                   |
| Unicode            | `unicode-normalization`      | NFC checks (§4.3)                                                                 |
| Biscuit arm        | `biscuit-auth` 6.x           | AIP's chained mode is built on biscuit-auth 6.0                                   |
| Nonce cache        | `dashmap`                    | atomic per-key entry API (§10.4)                                                  |
| Errors             | `thiserror`                  |                                                                                   |
| Secrets            | `zeroize`                    |                                                                                   |
| Tests              | `proptest`                   | differential and property tests                                                   |
| Micro-bench        | `criterion` 0.5.x            |                                                                                   |
| Latency histograms | `hdrhistogram`               |                                                                                   |
| Memory (Q10)       | `stats_alloc`                | counting global allocator without `unsafe` in our code (D-41)                     |
| QoS (bench only)   | `libc`                       | the one `pthread_set_qos_class_self_np` call (D-42)                               |
| Determinism        | `rand_chacha`                | all key and workload generation is seeded                                         |
| Output             | `serde`, `serde_json`, `csv` |                                                                                   |

Do **not** use `ciborium`, `serde_cbor` or `minicbor` for protocol structures. Their decoders do not enforce canonical form, and canonicity is a security property here (Algorithm 1 line 5). Write the small codec in §4.

### 3.3 Build profile

```toml
[profile.release]
opt-level = 3
lto = "fat"
codegen-units = 1
panic = "abort"
debug = false

[profile.bench]
inherits = "release"
```

Benchmarks run with `RUSTFLAGS="-C target-cpu=native"` for **all** arms, and the flag is recorded. CI builds and tests without it.

The flag reaches Rust code only. `blst`'s C and assembly are compiled by the `cc` crate, which ignores `RUSTFLAGS`. So the flags are equal, but the effect is not: the pure-Rust Ed25519 arms can benefit and `blst` mostly cannot. Record this under threats to validity. Do not hand-tune C flags for `blst`; that would be optimizing one arm (D-45).

---

## 4. Canonical encoding (`dc-cbor`)

### 4.1 Allowed data model

| CBOR major type  | Allowed                                     | Notes                             |
| ---------------- | ------------------------------------------- | --------------------------------- |
| 0 unsigned int   | yes                                         | 0 … 2⁶⁴−1                         |
| 1 negative int   | yes                                         | −2⁶⁴ … −1                         |
| 2 byte string    | yes                                         | definite length only              |
| 3 text string    | yes                                         | valid UTF-8, definite length only |
| 4 array          | yes                                         | definite length only              |
| 5 map            | yes                                         | definite length only              |
| 6 tag            | **no**                                      | paper §4.4 and §4.7 disallow tags |
| 7 simple / float | only `false` (20), `true` (21), `null` (22) | no floats, no `undefined`         |

Represent integers internally as `i128`, restricted to the CBOR range above.

### 4.2 Encoding rules

Follow RFC 8949 §4.2.1, core deterministic encoding:

- Every argument uses the shortest form.
- Map keys are sorted by the bytewise lexicographic order of their encodings.
- No duplicate keys.
- Definite lengths only.

### 4.3 Key rules (paper §4.4, §4.7)

- **Protocol structures** (bodies, certificates, receipts, approval bodies, PoP challenges, revocation assertions, policy AST nodes, chain envelope): map keys are **unsigned integers**. Unknown keys are rejected (**D-01**).
- **Parameter maps** (`InvocationBody.params`): map keys are **text** and NFC-normalized; text values are NFC-normalized. Keys are sorted by encoded bytes like any other map.
- **Declaration maps** (key 4 of a scope-AST `Rule`, §9.2): map keys are **text** that must follow the `path` grammar (ASCII, so NFC is automatic); values are type uints. This is a third map class; every other map inside a protocol structure has uint keys (**D-33**).

### 4.4 Decoder

The decoder is strict. It rejects:

- non-shortest arguments
- indefinite lengths
- unsorted or duplicate map keys
- tags, floats, or disallowed simple values
- invalid UTF-8
- non-NFC text inside a parameter map
- trailing bytes after the top-level item
- nesting depth > 16 (**D-02**)
- total encoded size of any single body > 64 KiB (**D-03**)

In addition, the verifier re-encodes each decoded body and compares the result to the received bytes (Algorithm 1 line 5). Implement both the strict decoder and the re-encode check. They are redundant on purpose.

**Error classes and reject lines (D-31).** A strict decoder that rejected everything at line 2 would make line 5 unreachable. So the decoder splits its failures into two classes:

- **Canonical-form violations**: a non-shortest argument, an indefinite length, unsorted map keys, or non-NFC text in a parameter map or in a body's scope (D-55). These are valid values encoded the wrong way.
  - When the verifier decodes a body, these are **recorded, not rejected**.
  - Line 5 rejects a recorded violation, and then separately rejects any mismatch between the re-encoded body and the received bytes. Both give `L05`.
- **Malformed input**: everything else. That covers
  - malformed CBOR, tags, floats, disallowed simple values;
  - invalid UTF-8, duplicate map keys, unknown keys, wrong field types;
  - trailing bytes, the depth and size limits;
  - malformed scopes (D-28) and invalid points (D-30).
  - These are rejected at line 2 (`L02`).
- Outside the verifier's body decoding, `decode_strict` rejects both classes.
- A non-canonical **envelope** (as opposed to a body) is rejected at `L02`, since line 5 covers bodies only.
- The re-encode comparison gets its own test, through a test-only hook that ignores the recorded violations. The hook shows that the comparison alone catches every canonical-form violation.

### 4.5 Tests

- Hand-written vectors for every rejection rule above.
- Property: for any value `x`, `decode(encode(x)) == x`.
- Property: for any bytes `b` that `decode` accepts, `encode(decode(b)) == b`.
- Optional: a `cargo-fuzz` target on `decode` that must never panic.

---

## 5. Cryptography (`dc-crypto`)

### 5.1 Scheme trait

All four chain-signature arms (§12) share one verifier implementation that is generic over this trait, so that the arms differ only where the signature scheme forces them to:

```rust
pub trait ChainScheme {
    type PublicKey;      // serializes to fixed bytes
    type SecretKey;
    type Signature;
    type WireSigs;       // what the chain envelope carries: one aggregate, or N+1 signatures
    const PK_LEN: usize;
    const SIG_LEN: usize;
    fn sign(sk: &Self::SecretKey, msg32: &[u8; 32], dst: &[u8]) -> Self::Signature;
    fn accumulate(acc: &mut Self::WireSigs, sig: Self::Signature);
    fn verify_chain(pks: &[&Self::PublicKey], msgs: &[[u8; 32]], sigs: &Self::WireSigs) -> bool;
    // registry/certificate signatures use the same scheme within an arm
}
```

The paper's protocol is the BLS aggregate implementation of this trait. The other implementations are **VARIANT** arms (§12).

### 5.2 BLS parameters (paper §4.2)

- **Curve and variant:** BLS12-381, minimal-pubkey-size. Public keys are G1 points, 48 bytes compressed; signatures are G2 points, 96 bytes compressed. Use `blst::min_pk`.
- **Messages:** every signed message is a 32-byte SHA-256 digest (§5.4).
- **Chain ciphersuite (paper §4.2):** the basic scheme, `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_`. Distinct messages are the rogue-key defense (paper §2.2, §5.3), and Algorithm 2 line 48 checks them explicitly.
- **Other domain-separation tags.** The paper requires PoP (§5.3) and receipts (§4.5) to use DSTs distinct from the chain's. The strings are **D-04**:

| Use                   | DST                                            |
| --------------------- | ---------------------------------------------- |
| Chain signatures      | `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_`  |
| Proof-of-possession   | `DC-V1-POP_BLS12381G2_XMD:SHA-256_SSWU_RO_`    |
| Approval receipts     | `DC-V1-RCPT_BLS12381G2_XMD:SHA-256_SSWU_RO_`   |
| Registry certificates | `DC-V1-CERT_BLS12381G2_XMD:SHA-256_SSWU_RO_`   |
| Revocation assertions | `DC-V1-REVOKE_BLS12381G2_XMD:SHA-256_SSWU_RO_` |

### 5.3 Point validation (paper §4.7, §5.3)

- Accept the compressed form only.
- Every deserialized G1 or G2 point gets a subgroup check.
- The identity element is rejected, both as a public key and as a signature.
- Use library functions (`PublicKey::key_validate`, `Signature::sig_validate(bytes, true)`); never reimplement subgroup checks. Check the length first (48 or 96 bytes): `blst`'s `from_bytes` also accepts the uncompressed 96- and 192-byte forms, which must be rejected.
- A public key is validated **once**: at registration, and again when its certificate is resolved into the verifier's cache. Hot-path aggregate verification then passes `pks_validate = false` (**D-05**). The Ed25519 arms get the equivalent treatment.
- **Signatures are validated once, at decode (D-30).**
  - Every signature the verifier receives (σ_agg, individual chain signatures, receipt signatures, certificate signatures) goes through `Signature::sig_validate(bytes, true)` when it is decoded. That call checks both the subgroup and the identity; a failure is `L02`, or a certificate rejection for certificate signatures.
  - Line 49 then passes `sig_groupcheck = false`. `blst`'s group check would only repeat the subgroup check, and it does not reject the identity (it calls `validate(false)`).
  - Public-key fields inside bodies are only length-checked at decode. They are compared as bytes and resolved (line 23), and the certified key was validated when its certificate was cached.
  - The Ed25519 arms likewise decode each point once.

### 5.4 Digests (paper §4.3, plus decisions)

All tags are 8 bytes: seven ASCII characters followed by `\0`.

```
m_0 = SHA256("TAG_SES\0" ‖ canon(B_0))
m_k = SHA256("TAG_DEL\0" ‖ m_{k-1} ‖ canon(B_k))      for 1 ≤ k < N
m_N = SHA256("TAG_INV\0" ‖ m_{N-1} ‖ canon(B_N))
```

These three are from the paper. The rest are decisions or follow paper wording:

| Digest                  | Definition                                            | Source                                                 |
| ----------------------- | ----------------------------------------------------- | ------------------------------------------------------ |
| `params_hash`           | `SHA256(canon(params))`                               | §4.4 (no tag in paper)                                 |
| `policy_hash`           | `SHA256(canon(policy_document))`                      | §5.4 (no tag in paper)                                 |
| `InvocationDigest(B_N)` | `SHA256("TAG_IVD\0" ‖ canon(B_N with key 9 removed))` | **D-06**; paper: "a digest over this preliminary body" |
| Approval message        | `SHA256("TAG_APR\0" ‖ canon(ApprovalBody))`           | **D-07**                                               |
| Certificate message     | `SHA256("TAG_CRT\0" ‖ canon(CertBody))`               | **D-07**                                               |
| Revocation message      | `SHA256("TAG_REV\0" ‖ canon(RevocationBody))`         | **D-07**                                               |
| PoP message             | `SHA256("TAG_POP\0" ‖ canon(PopChallenge))`           | **D-07**                                               |

### 5.5 Aggregation (paper §4.3)

The aggregate accumulates along the chain: each participant receives the running aggregate from its predecessor, adds its own signature, and forwards the sum. Use `AggregateSignature::from_signature` and `add_signature(&sig, true)`, and serialize with `to_signature().compress()`.

### 5.6 Verification (Algorithm 2 line 49)

Use `Signature::aggregate_verify(false, &msgs, CHAIN_DST, &pks, false)` over the N+1 pairs `(pk_k, m_k)`. σ_agg was validated at decode (D-30).

What `blst` 0.3.17 actually does (recorded in D-29 and D-30):

- **Threading.** With its default `std` build, `aggregate_verify` splits the pairs across a thread pool sized to the core count. Each worker computes its own Miller-loop product, and the products are merged before one final exponentiation. With the `no-threads` feature, it runs a single multi-Miller loop in the calling thread, which is what the paper's §4.6 cost model describes.
  - Every arm is built with `no-threads` (D-29), so one verification runs on one thread.
  - The threaded build appears only as the supplementary arm A-mt (§12).
- **Distinct messages.** It does **not** check that messages are distinct (the source has a `TODO` saying so). Line 48 is the only distinctness check.
- **Group check.** Its `sig_groupcheck` does not reject the identity element.

### 5.7 Pairing cache (**VARIANT**, arm B only)

Line 49's check is equivalent to

```
Π_{k=0}^{N} e(pk_k, H(m_k)) · e(−g1, σ_agg) == 1
```

For a known prefix, precompute and cache

```
P = Π_{k=0}^{N−1} ML(H(m_k), pk_k)        // Miller-loop product in Fp12, before final exponentiation
```

Then per invocation compute `FE( P · ML(H(m_N), pk_N) · ML(σ_agg, −g1) ) == 1`, where FE is the final exponentiation. This is the full equation, not a weaker check, so security is unchanged.

Implementation:

- Prefer safe `blst` APIs if the pinned version exposes Miller loop, `Fp12` multiplication and final exponentiation. `blst` 0.3.17 does: `Pairing::aggregate` and `Pairing::as_fp12` (hash-to-G2 plus Miller loop), `Pairing::aggregated` (Miller loop of σ against g1), `blst_fp12::miller_loop_n`, `Mul`, `final_exp`, `finalverify`, and `From<PublicKey> for blst_p1_affine`. No `unsafe` is expected.
- Otherwise use the raw FFI (`blst_hash_to_g2`, `blst_p2_to_affine`, `blst_miller_loop`, `blst_fp12_mul`, `blst_final_exp`, `blst_fp12_is_one`, the G1 generator and negation), confined to this module.
- Confirm exact function names and signatures against the pinned crate before writing code.

Required test: on at least 10,000 randomized chains, valid and invalid (flipped bit in a body, wrong signature, wrong key), the cached check returns exactly the same decision as `aggregate_verify`.

### 5.8 Ed25519 (**VARIANT** arms C and D)

- Keys are 32 bytes and signatures 64 bytes, signing the same 32-byte digests.
- Individual verification uses `VerifyingKey::verify_strict`.
- Batch verification uses `ed25519_dalek::verify_batch`. Log in `DECISIONS.md` that batch and strict verification differ in edge-case semantics; batch appears only as the C-batch arm.
- Ed25519 has no DSTs. Domain separation comes from the digest tags in §5.4, which already differ per structure.

---

## 6. Identity infrastructure (`dc-registry`)

### 6.1 Identifiers (paper §5.2, §6.1)

```
principal  ::= identifier ":" identifier ":" identifier     # organization-id : kind : local-id
identifier ::= letter (letter | digit | "_" | "-")*
```

Letters are ASCII only (**D-08**). Kinds are `agent`, `signer`, `approver`, `issuer` and `service`. Write `org(x)` for the first component of a principal.

In certificates, the kind is a uint enum (**D-09**): `0 agent`, `1 signer`, `2 approver`, `3 issuer`. `service` identifiers name verifiers and have no certificates (paper §5.2), so the registry refuses to register them.

### 6.2 Registry model (paper §5.1)

- One registry per organization, with `registry_id = org`.
- Each registry holds a root BLS key pair (an Ed25519 pair in the Ed25519 arms).
- The verifier's trust configuration is `Root: org → root public key` (paper §7.1, "Verifier configuration integrity").
- Model direct peering only; transparency logs and hierarchical attestation are out of scope.

### 6.3 Certificates (paper §5.2)

A certificate is a CBOR array `[cert_body_bytes: bstr, registry_sig: bstr]`. The body:

| Key | Field       | Type                                                         |
| --- | ----------- | ------------------------------------------------------------ |
| 1   | version     | uint, = 1                                                    |
| 2   | identifier  | text principal                                               |
| 3   | pk          | bstr (48 BLS / 32 Ed25519)                                   |
| 4   | kind        | uint enum (§6.1); must equal the identifier's kind component |
| 5   | registry_id | text                                                         |
| 6   | registry_pk | bstr                                                         |
| 7   | iat         | uint (Unix seconds)                                          |
| 8   | nbf         | uint                                                         |
| 9   | exp         | uint                                                         |
| 10  | serial      | uint, unique per registry                                    |

The registry signs `SHA256("TAG_CRT\0" ‖ canon(body))` under the CERT DST.

Default lifetimes (**D-10**): 24 hours for agents, signers and issuers, 7 days for approvers. The paper specifies 24 h–7 d only for agents and signing services.

### 6.4 Registration with proof-of-possession (paper §5.3)

1. The registrant requests a challenge. The registry returns a `PopChallenge`:

   | Key | Field              |
   | --- | ------------------ |
   | 1   | claimed identifier |
   | 2   | pk                 |
   | 3   | kind               |
   | 4   | registry_id        |
   | 5   | nonce (bstr 16)    |
   | 6   | timestamp          |

   The nonce is single-use with a 60 s TTL (**D-11**).

2. The registrant signs `SHA256("TAG_POP\0" ‖ canon(challenge))` under the POP DST.
3. The registry verifies, and checks all of the following:
   - the PoP signature is valid;
   - the nonce is unused and unexpired;
   - `org(identifier) == registry_id`;
   - the identifier's kind component equals the requested kind;
   - the kind is not `service`;
   - the public key passes subgroup and identity checks.
4. The registry issues the certificate.

The purpose is attribution, not aggregate security (paper §5.3). The tests in §11.1 and §11.2 (T5a) check that registration without a valid PoP fails.

PoP proves possession, not uniqueness. A registrant may register its own key under two identifiers, and registries cannot coordinate across organizations to prevent it. This is why lines 18 and 20 also compare identifiers (D-36, P-16).

### 6.5 Revocation (paper §5.6)

- **Revocation assertion:** a CBOR array `[body_bytes, sig]`, with body `{1: registry_id, 2: serial, 3: revoked_at}`, signed by the registry root under the REVOKE DST.
- **Delivery:** the verifier exposes `ingest_revocation(assertion)`, modelling push delivery. It verifies the assertion under `Root[registry_id]`, marks the serial revoked, and evicts every cache entry that depends on it (certificate cache and prefix caches).
- **Semantics:** revocation applies relative to _verification_ time (paper §5.6).

### 6.6 Resolution and policy store (paper §5.4)

```rust
trait Resolver   { fn resolve(&self, id: &str, pk: &[u8], t: u64) -> Option<Certificate>; }
trait PolicyStore{ fn load(&self, policy_hash: &[u8; 32]) -> Option<Vec<u8>>; }
```

- **In-process implementations.** Both accept an optional injected latency (a sleep per call) for cold-path experiments (§13.4).
- **Resolution is by identifier and key** (paper §5.4, Algorithm 1 line 23). Every body names its signer's key, so during a scheduled rotation, when two certificates for one identifier are valid at once, the key selects between them. This applies to issuers, agents and approvers alike. Implement scheduled rotation with overlapping certificates (§11.2 has a test for it).
- **`resolve` returns the most recently issued certificate binding `id` to `pk`, whether or not it is currently valid** (**D-26**). Expiry and revocation are then rejected at line 27, where the paper checks them. If `resolve` filtered them out instead, line 27 would never fire and a test could not tell the two failures apart.
  - Paper §5.4 (revision 2026-09-29) says the same. Revision 2026-09-28 said "resolution returns the valid certificate" (P-18, resolved).
  - Line 27 checks `t ∈ [nbf, exp]` and revocation (D-35, P-17).
- **Content addressing.** `load` returns bytes; the verifier accepts them only if `SHA256(bytes) == policy_hash` and the bytes decode as a well-formed policy (§9.3). A malformed policy is treated as _unavailable_ (line 31) (**D-12**).

---

## 7. Token bodies and wire format (`dc-types`)

Body kind is a uint enum (**D-13**): `0 session`, `1 delegation`, `2 invocation`. Every body carries it at key 1 (paper §4.3, "Role distinguishability by position").

### 7.1 SessionBody (paper §4.3)

| Key | Field       | Type                                      |
| --- | ----------- | ----------------------------------------- |
| 1   | kind        | uint = 0                                  |
| 2   | issuer_id   | principal (kind issuer)                   |
| 3   | issuer_pk   | bstr                                      |
| 4   | subject_id  | principal (kind agent) — the orchestrator |
| 5   | subject_pk  | bstr                                      |
| 6   | session_id  | bstr 16                                   |
| 7   | policy_hash | bstr 32                                   |
| 8   | scope       | Scope AST (§9.2)                          |
| 9   | iat         | uint                                      |
| 10  | exp         | uint                                      |
| 11  | nonce       | bstr 16                                   |

`sid(B_0) = issuer_id` and `spk(B_0) = issuer_pk` (paper §4.3, §4.6).

### 7.2 DelegationBody (paper §4.3)

| Key | Field        | Type                                 |
| --- | ------------ | ------------------------------------ |
| 1   | kind         | uint = 1                             |
| 2   | delegator_id | principal (agent)                    |
| 3   | delegator_pk | bstr                                 |
| 4   | delegatee_id | principal (agent)                    |
| 5   | delegatee_pk | bstr                                 |
| 6   | scope        | Scope AST (the attenuated sub-scope) |
| 7   | hop_index    | uint                                 |
| 8   | session_id   | bstr 16                              |
| 9   | exp          | uint                                 |
| 10  | nonce        | bstr 16                              |

`sid = delegator_id`, `spk = delegator_pk`.

### 7.3 InvocationBody (paper §4.3, §4.4, §4.5)

| Key | Field       | Type                                                |
| --- | ----------- | --------------------------------------------------- |
| 1   | kind        | uint = 2                                            |
| 2   | invoker_id  | principal (agent)                                   |
| 3   | invoker_pk  | bstr                                                |
| 4   | aud         | principal (kind service)                            |
| 5   | tool        | identifier text                                     |
| 6   | action      | identifier text                                     |
| 7   | params      | map, text keys (§4.3)                               |
| 8   | params_hash | bstr 32                                             |
| 9   | receipts    | array of Receipt, **omitted when empty** (**D-14**) |
| 10  | nbf         | uint                                                |
| 11  | exp         | uint                                                |
| 12  | nonce       | bstr 16                                             |

`sid = invoker_id`, `spk = invoker_pk`. Receipts are ordered by `approver_id`, bytewise ascending, with at most one per approver (**D-15**; paper §4.3 and §4.5 allow one receipt per required service).

Receipt lists (**D-34**):
- These make the body malformed (`L02`):
  - receipts out of order;
  - two receipts for one approver;
  - key 9 present with an empty array;
  - a receipt whose parts are not well formed.
- A receipt from an approver that the evaluated decision (line 36) does not require is **ignored**. No line of Algorithm 2 rejects it, and line 40 only looks up the approvers that are required.

### 7.4 Receipts (paper §4.5)

- **Receipt:** a CBOR array `[approval_body_bytes: bstr, sig: bstr]`.
- **ApprovalBody:**

  | Key | Field                             |
  | --- | --------------------------------- |
  | 1   | approver_id                       |
  | 2   | approver_pk                       |
  | 3   | invocation_digest (bstr 32)       |
  | 4   | attestation (opaque bstr ≤ 256 B) |
  | 5   | iat                               |
  | 6   | exp                               |

- **Signature:** over the approval message (§5.4), under the RCPT DST.

### 7.5 Chain envelope

The envelope is a CBOR array `[bodies: [bstr; N+1], sigs]`.

- Each body is carried as the byte string of its canonical encoding, so that line 5's canonical re-encode check has something to check.
- `sigs` depends on the arm:
  - **A, B:** a single `bstr` of 96 bytes (the aggregate).
  - **A-ind:** an array of N+1 BLS signatures (96 B each).
  - **C, C-batch, D:** an array of N+1 Ed25519 signatures (64 B each).
- N ≥ 1, so the smallest chain is session plus invocation. Cap N at 16 (**D-16**; ZCAP recommends a cap of 10). A chain with N > 16 fails decoding (`L02`).

---

## 8. Chain construction (`dc-chain`)

### 8.1 Issuance

The issuance service holds a key certified with kind `issuer`. The registry root never signs sessions (paper §4.1).

`issue(subject_id, subject_pk, scope, policy_hash, ttl)` builds `B_0`, naming the issuance service's own `issuer_id` and `issuer_pk`, computes `m_0`, signs it, and returns `(B_0 bytes, m_0, running_aggregate = σ_0)`.

### 8.2 Signing service (paper §3.1)

An agent never holds its own key; a signing service does. It receives `{body, m_prev}`, **not** a digest. It then:

1. Checks that the body is well formed and that its `delegator_pk` or `invoker_pk` is the key it holds.
2. Runs a pluggable `EnforcementPolicy` hook (default: accept). The paper does not specify what a signing service enforces; log this as P-12.
3. Computes `m_k` itself.
4. Signs and returns `σ_k`.

### 8.3 Delegation and invocation

- **Delegation:** each agent appends a `DelegationBody` with an attenuated scope and gets it signed. The chain holder adds `σ_k` to the running aggregate (arms A and B) or appends it to the signature list (the other arms).
- **Invocation:**
  1. Build the invocation body without receipts, and compute `params_hash`.
  2. Evaluate the agent's own scope on the invocation to learn which approvals are required.
  3. Request a receipt from each required approval service, over `InvocationDigest`.
  4. Embed the receipts, sorted per D-15.
  5. Sign `m_N` and finalize the envelope.

### 8.4 Approval service

For tests and benchmarks, human approval is simulated as automatic. The service holds a key of kind `approver` and signs the ApprovalBody with a configurable validity window (default 300 s).

---

## 9. Policy language (`dc-policy`)

This is the part of the implementation most likely to hide a soundness bug. Read §9.5 twice.

### 9.1 Text syntax (paper §6.1, verbatim)

```
scope      ::= rule+ | "allow" "all" | "deny" "all"
rule       ::= "allow" at tool action params? where? approval?
at         ::= "at" "=" principal
tool       ::= "tool" "=" identifier
action     ::= "action" "=" identifier
params     ::= "params" "{" binding ("," binding)* "}"
binding    ::= path ":" type
where      ::= "where" expr
expr       ::= expr "and" expr | "(" expr ")" | atom
atom       ::= path numop value
             | path strop string-value
             | path "in" list-value
             | path "under" string-value
approval   ::= "approval" "requires" principal ("," principal)*
type       ::= "int" | "string" | "bool"
numop      ::= "<" | "<=" | "==" | ">=" | ">"
strop      ::= "==" | "starts_with" | "ends_with" | "contains"
path       ::= identifier ("." identifier)*
principal  ::= identifier ":" identifier ":" identifier
identifier ::= letter (letter | digit | "_" | "-")*
value      ::= integer | string | boolean
list-value ::= "[" value ("," value)* "]"
```

Lexical details (**D-17**):

- Whitespace is insignificant.
- Strings are double-quoted, with JSON escapes.
- Integers are decimal with an optional leading `-`, within the CBOR integer range.
- Booleans are `true` and `false`.
- String literals are NFC-normalized, and the string operators compare bytewise (paper §6.1, revision 2026-09-29). In the canonical AST, scope text is NFC (D-55).

Paper §6.1 "Lexical details" (revision 2026-09-29) states these rules and D-08.

The parser must accept the paper's §6.2 example verbatim, `at` clauses included.

### 9.2 Canonical AST (CBOR, integer keys; **D-18**)

```
Scope := {1: 0}                    ; allow all
       | {1: 1}                    ; deny all
       | {1: 2, 2: [Rule, ...]}    ; rules, in declaration order (order is semantic)

Rule  := {1: at, 2: tool, 3: action,
          4: {path_text: type_uint, ...}   ; omitted when no params are declared
          5: [Atom, ...]                   ; omitted when there is no where clause; order as written
          6: [principal, ...]}             ; approval set, sorted bytewise and deduplicated; omitted if none

type_uint := 0 int | 1 string | 2 bool

Atom := [op_uint, path_text, operand]
op_uint: 0 lt, 1 le, 2 eq, 3 ge, 4 gt, 5 starts_with, 6 ends_with, 7 contains, 8 in, 9 under
operand: int | text | bool | array (for `in`, elements as written)
```

- The text form `x == "a"` (strop) and `x == 5` (numop) both map to `eq`; the operand's type disambiguates. Paper §6.1 says "the declared type of the path decides which is meant"; the two agree, because D-20 requires the operand's type to equal the path's.
- A rule without `params` declares the empty parameter set. Under the closed-world rule it matches only invocations with no parameters.
- The policy document that `policy_hash` names is a Scope, canonically encoded.

### 9.3 Validation (policy load and body decode)

Anything that fails validation is **malformed** and rejected.

- **Principals and identifiers** follow the grammar. `at` names a principal of kind `service`, and every `approval` entry names one of kind `approver` (paper §6.1).
- **Parameter paths** follow the grammar, and no declared path is a strict prefix of another (e.g. `a` and `a.b` together) (**D-19**).
- **Operator/type compatibility** (**D-20**):
  - `lt le ge gt`: int path, int operand.
  - `eq`: operand type equals the declared path type.
  - `starts_with ends_with contains`: string path, string operand.
  - `in`: non-empty array, every element of the path's type.
  - `under`: string path, operand a canonical absolute path (paper §6.1: a non-canonical literal is malformed).
- **Every where-path must be declared in its rule's `params` (D-28, P-15).**
  - An atom on a path its rule does not declare makes the scope **malformed**.
  - This validator runs:
    - at policy load: a malformed policy is unavailable, `L31` (D-12);
    - on every scope inside a session or delegation body: a malformed scope is a decoding failure, `L02`.
  - The evaluator keeps paper §6.3 step 1(c) as a defensive check. For a well-formed scope it never fires.
  - _History:_ the pre-review text allowed undeclared where-paths, with a lint. Combined with §9.5, where an atom on a path is judged against that path's unconstrained domain, that made `Contains` unsound. A tautology on an undeclared path (`z >= -18446744073709551616`, `f in [true, false]`) counts as implied by any clause, although the rule carrying it can never match.
    - In step 3(b), such a dead child rule wrongly triggers the skip, and a required approval is dropped.
    - In step 3(a), a dead parent rule wrongly subsumes a live child rule.
    - The counterexample is in P-15.
  - Because every where-path is now declared, D-20 below is always well defined.
  - Paper §6.1 "Well-formedness" (revision 2026-09-29) states this rule (condition 1), together with D-19 (condition 1), D-20 (condition 2, as a table) and the `at`/`approval` kinds (condition 3).
- **Size limits** (**D-21**): ≤ 256 rules per scope, ≤ 32 params per rule, ≤ 32 atoms per rule, ≤ 64 list elements, text ≤ 1024 bytes, path depth ≤ 8.

**Canonical absolute path (paper §6.1):**

- Starts with `/`.
- Either exactly `/`, or `/` followed by non-empty segments joined by `/`.
- No segment is `.` or `..`, and there is no trailing `/`.
- `p under q` holds iff `p` is canonical absolute and `segments(q)` is a prefix of `segments(p)`. Equality counts (**D-22**).

### 9.4 Evaluation (paper §6.3, exactly)

`Evaluate(scope, I)` where `I = (aud, tool, action, params)`:

- **Special forms.** `allow all` returns `allow`. `deny all` returns `deny`.
- **Flattening parameters.** Nested maps flatten to leaf paths joined by `.`:
  - A key that fails the identifier grammar or contains `.` makes the invocation match no rule (**D-23**).
  - Leaves typed int, text or bool have that type.
  - A byte string, null, array or empty map is a leaf of **no** type and matches no declaration (paper §6.1).
- **Rules, in declaration order:**
  - (a) Skip the rule unless `at == I.aud`, `tool == I.tool` and `action == I.action`.
  - (b) Closed-world check: skip unless the set of leaf paths equals the declared set **exactly** and every value has its declared type.
  - (c) Skip if any where-path resolves absent. This is a defensive check: because of D-28, it never fires for a well-formed scope.
  - (d) Skip unless every atom holds.
  - (e) Return `allow` if the rule has no approval clause, else `allow_with_approval(set)`.
- If no rule matched, return `deny`.

Atom semantics:

- `under` requires the _value_ to be canonical absolute; a non-canonical value makes the atom false.
- `starts_with`, `ends_with` and `contains` are bytewise on NFC-normalized UTF-8.

### 9.5 Implication and satisfiability — soundness contract

The containment procedure (§9.6) relies on two per-path decision functions over conjunctions of atoms. For soundness they must err in **one direction only**:

| Function                                          | May return a false...                                     | Must never return a false... | Why                                                                                         |
| ------------------------------------------------- | --------------------------------------------------------- | ---------------------------- | ------------------------------------------------------------------------------------------- |
| `implies(C, b)`: does conjunction C force atom b? | `false` (incomplete: rejects some legitimate delegations) | `true`                       | A false `true` makes step 3(a) accept an escalation, or step 3(b) skip a rule it must check |
| `unsat(C)`: is conjunction C unsatisfiable?       | `false` (reports "satisfiable" when unsure)               | `true`                       | A false `true` makes step 3(b) ignore a parent rule that can actually decide the invocation |

If `unsat(C)` holds, `implies(C, b)` is vacuously true.

The paper claims these are closed-form and exact (§6.4). For combinations of string constraints, implement the sound procedures below. Where you can make a case exact, do so with tests; where you cannot, stay conservative, and log the gap as P-08.

Atoms are grouped by path; paths are independent (paper §6.4).

**Int paths.** The domain is the CBOR range [−2⁶⁴, 2⁶⁴−1].

- Build an interval `[lo, hi]` from `lt le ge gt` and from `eq` with an int operand.
- Build an optional finite set F as the intersection of all `in` lists and `eq` values.
- The admissible set is `A = {v ∈ F : lo ≤ v ≤ hi}` if F exists, else the interval.
- This case is **exact**:
  - `unsat` iff A is empty.
  - `implies(b)`: if A is finite, test every element. If A is the interval, then for a comparison `b` test interval containment; for `b = in L`, require `hi − lo + 1 ≤ |L|` and every integer in `[lo, hi]` to be in L.

**Bool paths.** The domain is {true, false}. Compute the admissible subset. Exact.

**String paths.** Collect:

- E: a finite set, from the intersection of `eq`/`in` operands
- P: `starts_with` operands
- S: `ends_with` operands
- K: `contains` operands
- U: `under` operands

If E exists, the case is **exact**: `A = {s ∈ E : s satisfies all of P, S, K, U}`; `unsat` iff A is empty; `implies(b)` iff every `s ∈ A` satisfies b.

If E does not exist, use these sound rules.

- `unsat` returns true only when one of these holds; otherwise it returns false:
  - two P entries, neither a prefix of the other;
  - two S entries, neither a suffix of the other;
  - two U entries, neither a segment-prefix of the other;
  - some p ∈ P and q ∈ U that are incompatible as string prefixes.
- `implies(b)` returns true only when one of these holds; otherwise it returns false:
  - `b = starts_with p`: ∃ p′ ∈ P with p′ starting with p, or ∃ q ∈ U with q starting with p. (A value under q is q itself or starts with `q/`, so it starts with q.)
  - `b = ends_with s`: ∃ s′ ∈ S with s′ ending with s.
  - `b = contains s`: ∃ x ∈ P ∪ S ∪ K ∪ U containing s.
  - `b = under q`: ∃ q′ ∈ U with `segments(q)` a prefix of `segments(q′)`.
  - `b = eq/in`: never.

**Conjunction implication:** `implies(C2, C1)` holds iff, for every atom b in C1, `implies(atoms of C2 on b's path, b)`. An atom of C1 on a path C2 does not constrain is judged against the unconstrained domain of that path's **declared** type.

- This is sound only because every where-path is declared (D-28), and because the rules compared by subsumption and by the step-3(b) skip have identical declarations.
- An undeclared path's true domain is "absent", on which every atom is false.
- `implies` and `unsat` are never called on a malformed scope. The oracle checks that the validator rejects every scope the generator gives an undeclared-path atom.

**Joint satisfiability** of two clauses is `¬unsat(C1 ∧ C2)`.

### 9.6 Containment `Contains(S1, S2)` (paper §6.4, exactly)

0. If either scope is malformed (§9.3), return false. This is a defensive check that a decoded chain never reaches (paper §6.4, revision 2026-09-29; D-28).
1. If S1 is `allow all`, return true.
2. If S2 is `deny all`, return true. If S2 is `allow all` (and, by step 1, S1 is not), return false.
3. For each rule r2 of S2, in order:
   - **(a)** Find the first rule r1 of S1 with `r2 ⊆ r1`. If there is none, return false.
   - **(b)** For every r′ preceding r1 in S1 that agrees with r2 on `at`, tool, action and parameter declaration, and whose clause is jointly satisfiable with r2's:
     - **Skip** r′ if some r2′ preceding r2 in S2 agrees with r′ on `at`, tool, action and declaration, and `implies(r′.where, r2′.where)`.
     - Otherwise, return false if `approval(r′) ⊄ approval(r2)`.
4. Return true.

Rule subsumption `r2 ⊆ r1` holds iff all of the following hold:

- `at`, tool and action are equal;
- the declarations are identical (the same path-to-type map);
- `approval(r1) ⊆ approval(r2)`, as sets ("no stronger");
- `implies(r2.where, r1.where)`.

Special forms need a test each (**D-24**):

- **`Contains(S1, allow all)` with S1 not `allow all` returns false** (step 2). This is soundness-critical: getting it wrong lets a delegation widen to everything. An earlier paper revision worded step 2 so that it could be read the other way.
- If S1 is `deny all` and S2 has rules, step 3(a) finds no r1 and returns false. This is conservative, and correct.

### 9.7 Required policy tests (in addition to §11)

- **Paper examples:**
  - The §6.2 policy parses.
  - A 500-unit transfer to `acct_vendor_a` returns `allow`, via rule 1 (paper §6.3, "Match order").
  - Adding an undeclared `override_limits` parameter returns `deny` (paper §6.3).
  - A file path containing `/../` returns `deny`.
  - A mismatched `aud` returns `deny`.
- **Remark 1:** the counterexample returns false from `Contains` while the oracle (below) says contained.
- **P-15 regression.** The P-15 counterexample is a fixed test.
  - The child scope (a dead rule carrying `z >= -18446744073709551616`) is rejected as malformed.
  - So is the parent-side variant (a dead parent rule).
  - Separately, running the pre-review procedure on the P-15 pair is shown to return `true` although the oracle finds a counterexample. This keeps the bug demonstrable.
- **Reflexivity:** `Contains(P, P)` is true for every generated P. Include the recommended-order policy (an approval rule before an overlapping permissive rule), the regression this property was added for.
- **Differential oracle (the most important test in the repository):**
  - **Generator.** Use proptest over a tiny universe:
    - 2 audiences, 2 tools, 1 action;
    - parameter declarations drawn from subsets of `{x: int, s: string, f: bool}`;
    - int constants in [−2, 6], plus the boundary constants −2⁶⁴ and 2⁶⁴ − 1 (the ends of the CBOR integer range; +2⁶⁴ itself is outside it);
    - string constants drawn from a set that includes canonical paths, non-canonical paths (`/a/../b`, `//a`, `/a/`), near-miss prefixes (`/home/agent/workspace-evil`), short words, and the empty string;
    - 2 approvers;
    - where-atoms that may name a path the rule does not declare. The validator must reject every such scope as malformed (D-28), and the test asserts it does. Only well-formed scopes go on to the soundness assertions.
  - **Enumeration.** Enumerate every invocation in the universe: ints in [−4, 8] plus −2⁶⁴, −2⁶⁴ + 1, 2⁶⁴ − 2 and 2⁶⁴ − 1; the string set plus concatenations of pairs; both booleans; and every parameter-set shape.
  - **Oracle.** Definition 1 evaluated exhaustively over the enumeration.
  - **Assertions.**
    - (i) Soundness: `Contains(S1, S2) == true` implies the oracle finds no counterexample. Any counterexample is a real bug, because it is a concrete invocation.
    - (ii) Reflexivity.
    - (iii) The same soundness property separately for `implies` and `unsat`, per type.
  - **Reporting.** Track the completeness rate (the fraction of oracle-contained pairs that `Contains` accepts) and report it; do not assert on it. The oracle is bounded to the enumerated universe, so a pair it calls contained may have a counterexample outside that universe. Report the rate as relative to the bounded oracle.
  - **Scale.** At least 100,000 generated cases in CI's extended profile.

---

## 10. Verifier (`dc-verifier`)

### 10.1 Structure

```rust
pub struct Verifier<S: ChainScheme, R: Resolver, P: PolicyStore, C: Clock> {
    self_id: Principal,                        // "self" in Algorithm 1 line 8; kind service
    roots: HashMap<Org, S::PublicKey>,         // Root[o]
    pinned: HashMap<Org, HashSet<[u8; 32]>>,   // Pinned[o]
    resolver: R, policy_store: P, clock: C,
    cert_cache: CertCache,                     // TTL = min(cert.exp, 3600 s) (paper §5.4); evicted on revocation
    policy_cache: PolicyCache,                 // keyed by hash; immutable
    nonce_cache: NonceCache,                   // §10.4
    revoked: HashSet<(Org, Serial)>,
    config: VerifierConfig,
}

pub fn verify(&self, chain: &[u8]) -> Result<Accepted, Reject>;
```

### 10.2 Algorithms 1–2, line by line

Implement Appendix A exactly, in order. The `Reject` enum has one variant per rejecting line, named for the line number, e.g. `L05NonCanonical`, `L26WrongKind { k }`, `L49AggregateInvalid`. Tests assert on these variants, so a check moved to the wrong phase shows up as a failing test.

Definitions, from paper §4.6:

- `sid(B_k)`: `issuer_id`, `delegator_id` or `invoker_id`, by position.
- `spk(B_k)`: `issuer_pk`, `delegator_pk` or `invoker_pk`, by position.
- `scope(B_k)`: the session scope, or the delegation sub-scope.
- `role(k)`: `issuer` for k = 0, `agent` for k ≥ 1.

Line-level notes:

- **Line 2:** decode the envelope. Decode each body **by its own `kind` field** (key 1), not by its position (**D-32**), so that a misplaced body reaches line 7 rather than failing here.
  - Also decode and validate every scope (D-28) and every signature point (D-30).
  - Malformed input is rejected here (`L02`). Canonical-form violations are only recorded (D-31).
  - An unknown `kind` value is malformed.
- **Line 5:** reject a recorded canonical-form violation, then compare the re-encoding with the received bytes (§4.4, D-31).
- **Line 9:** recompute `params_hash` from the canonical parameter map.
- **Line 11:** every delegation body's `hop_index` equals its position, and its `session_id` equals `B_0`'s. These are redundant with the digest recursion (paper §4.3), which is why §11.2 tests Theorem 3 on the phase-8 check directly as well as end to end.
- **Line 13:** no clock-skew tolerance, as written (P-07).
- **Lines 18 and 20 compare identifiers as well as keys (D-36, P-16).** Reject at line 18 unless both `B0.subject_id = sid(B1)` and `B0.subject_pk = spk(B1)`. Reject at line 20 unless both `Bk.delegatee_id = sid(Bk+1)` and `Bk.delegatee_pk = spk(Bk+1)`.
  - Comparing keys alone lets a chain name one party and be signed by another. PoP does not stop one key from being registered under two identifiers (§6.4). That breaks provenance, asset (ii) of paper §3.1.
  - Paper revision 2026-09-29 states lines 18 and 20 this way.
- **Line 23:** `Resolve(sid(B_k), spk(B_k))`, per D-26.
- **Line 24:** verify the certificate signature under `Root[org(sid)]`. Once verified, it is cached with its certificate. If no root is configured for `org(sid)`, reject at line 24.
- **Line 27:** reject unless `t ∈ [cert.nbf, cert.exp]`, closed at both ends, and reject if the serial is revoked (**D-35**). The paper's line 27 says "not yet valid, expired, or revoked at t", without stating the boundary (P-26). Line 42's "phase-5 checks" include the same window.
- **Line 41:** `Resolve(s, R.approver_pk)`; reject if unresolvable (`L41`, **D-27**).
- **Line 42:** the phase-5 checks (lines 24–27) with kind `approver`: root, namespace, kind, validity window, revocation.
- **Line 40:** receipts from approvers outside `svcs` are ignored (D-34).
- **Line 48:** compare all N+1 digests pairwise; use a hash set. This is the only distinctness check; `blst` does not do one (§5.6).
- **Line 49:** §5.6.
- **Line 50:** atomic `InsertIfAbsent` (§10.4). This is the only mutation that can change a later **decision** (**D-37**, P-20).
  - The certificate and policy caches are filled during phases 5 and 6 (paper §5.4): a certificate after line 24 passes, a policy after its hash and well-formedness check.
  - They are semantically transparent, and §11.3 enforces that.
  - A chain rejected later may still leave cache entries behind.

### 10.3 Instrumentation

Add a cargo feature `count-ops` that counts, per `verify` call: hash-to-curve calls, Miller loops or pairings, final exponentiations, signature verifications, resolver calls, policy-store calls, `Contains` calls and `Evaluate` calls.

Tests use it to prove phase ordering: for example, an expired chain is rejected with zero pairings and zero resolver calls (paper Figure 2).

Add a separate feature `phase-timing` that records per-phase nanoseconds, for the breakdown in §13.5. Never enable either feature in headline latency runs.

### 10.4 Nonce cache (paper §4.6, Theorem 5)

- **Key and value:** the key is `(invoker_pk bytes, nonce bytes)` and the value an expiry time.
- **Line 17:** a lookup only; it is an early filter.
- **Line 50:** `InsertIfAbsent`, atomic and linearizable per key. Use `DashMap::entry`, which locks the key's shard. TTL = `(B_N.exp − t) + skew`, with `skew = 60 s` (**D-25**).
- **Eviction:** lazy on lookup, plus a periodic sweep. Neither may evict an unexpired entry.
- **Replicas:** one logical cache. Replicated deployments are out of scope (paper Theorem 5 hypothesis).

### 10.5 Caches used in each benchmark state

| State       | Certificate cache | Policy cache | Containment results | Prefix cache (§12)         |
| ----------- | ----------------- | ------------ | ------------------- | -------------------------- |
| cold        | empty             | empty        | none                | none                       |
| warm        | populated         | populated    | none                | none                       |
| warm+prefix | populated         | populated    | prefix links cached | populated (arms B, D only) |

"Warm" uses only the caches the paper describes (§5.4). "warm+prefix" is a **VARIANT**.

---

## 11. Test plan

### 11.1 Unit and property tests

- **`dc-cbor`:** §4.5.
- **`dc-crypto`:**
  - sign/verify round trips;
  - rejection of identity and non-subgroup points;
  - DST separation (a signature under one DST fails under every other);
  - aggregate negative tests;
  - pairing-cache equivalence (§5.7).
- **`dc-types`:** regression vectors. Fixed inputs with committed expected bytes and digests go in `tests/vectors/*.json`. Generate them once and label them _regression_, not normative.
- **`dc-policy`:** §9.7.
- **`dc-registry`:** PoP success and failure paths; revocation ingestion.

### 11.2 Security suite (`tests/security.rs`)

Each row is at least one test. "Expected" is the `Reject` variant, or _accept_ where the paper says the threat is bounded rather than prevented. Build chains with the builders from §8, then mutate them.

Unless a row says otherwise, give every body the same `exp`, set every `hop_index` and `session_id` correctly, keep every other field valid, and use a fresh nonce per verification. Otherwise an earlier line (line 11, 15 or 17, typically) fires first and the test proves nothing about the named line.

| Threat / property                      | Test construction                                                                                                                                                                                                                                                                                                                                                 | Expected                                               |
| -------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------ |
| T1a token forgery                      | Replace σ_agg with an unrelated valid G2 signature                                                                                                                                                                                                                                                                                                                | L49                                                    |
| T1a                                    | Delegation claims victim's `delegator_id` and `delegator_pk`, signed with the attacker's key                                                                                                                                                                                                                                                                      | L49                                                    |
| T1a                                    | Delegation claims victim's `delegator_id` with the attacker's own `delegator_pk` (the preceding body names `(victim_id, attacker_pk)` as delegatee, so line 20 passes)                                                                                                                                                                                              | L23 (no certificate binds that identifier to that key) |
| T1b reorder                            | Swap two delegation bodies                                                                                                                                                                                                                                                                                                                                        | L11                                                    |
| T1b truncation                         | Drop an interior delegation hop                                                                                                                                                                                                                                                                                                                                   | L11                                                    |
| T1b                                    | Drop the session body; drop the invocation body                                                                                                                                                                                                                                                                                                                   | L07, L07                                               |
| T1b extension                          | Append a delegation after the invocation                                                                                                                                                                                                                                                                                                                          | L07                                                    |
| T1b insertion                          | Insert an extra correctly signed hop mid-chain                                                                                                                                                                                                                                                                                                                    | L11                                                    |
| T1b splice                             | A delegation body from another session, keys made consistent                                                                                                                                                                                                                                                                                                      | L11                                                    |
| Theorem 3, digest recursion            | Line 11 now catches the reorder, truncation and insertion rows before phase 8, but the paper says those checks are redundant with the digest recursion. Prove it: call the phase-8 check (lines 47–49) directly on the mutated body lists, with the running aggregate adjusted as an attacker could (subtracting σ_k, recoverable from partial sums, paper §4.3). | aggregate check fails for each mutation                |
| T2a parameter substitution             | Change a param, keep `params_hash`                                                                                                                                                                                                                                                                                                                                | L09                                                    |
| T2a                                    | Change a param and recompute `params_hash`                                                                                                                                                                                                                                                                                                                        | L49                                                    |
| T2b scope escalation                   | Delegation sub-scope wider than its parent                                                                                                                                                                                                                                                                                                                        | L34                                                    |
| T2b                                    | Session scope exceeds the pinned policy                                                                                                                                                                                                                                                                                                                           | L32                                                    |
| T2b                                    | `policy_hash` not pinned for the issuing org                                                                                                                                                                                                                                                                                                                      | L30                                                    |
| T2b                                    | Pinned but absent from the store; or malformed policy bytes                                                                                                                                                                                                                                                                                                       | L31                                                    |
| T2b (step 2 regression)                | Delegate `allow all` under a rule-list parent                                                                                                                                                                                                                                                                                                                     | L34                                                    |
| T3a replay across sessions             | `t > B_N.exp`; `t < B_N.nbf`; delegation exp > parent exp                                                                                                                                                                                                                                                                                                         | L13, L13, L15                                          |
| T3b replay                             | Verify the same chain twice sequentially                                                                                                                                                                                                                                                                                                                          | 2nd: L17                                               |
| T3b (Theorem 5, concurrent)            | 64 threads present the same chain simultaneously; 1,000 rounds, a fresh chain each round                                                                                                                                                                                                                                                                          | exactly 1 accept per round; others L17 or L50          |
| T3c cross-context                      | Invocation body at a delegation position and vice versa; `kind` field ≠ position                                                                                                                                                                                                                                                                                  | L07                                                    |
| T3d cross-verifier                     | `aud` names a different verifier                                                                                                                                                                                                                                                                                                                                  | L08                                                    |
| T3d / audience clause                  | `aud` = self, but the matching rule's `at` names another service                                                                                                                                                                                                                                                                                                  | L37                                                    |
| T4a compromised approver (bounded)     | Approver key signs a receipt for a within-policy invocation                                                                                                                                                                                                                                                                                                       | **accept** (document the bound)                        |
| T4a                                    | Approver key used as a delegator                                                                                                                                                                                                                                                                                                                                  | L26                                                    |
| T4b routing                            | Receipt only from a non-required approver                                                                                                                                                                                                                                                                                                                         | L40                                                    |
| T4c receipt reuse                      | Receipt for I attached to I′ ≠ I                                                                                                                                                                                                                                                                                                                                  | L43                                                    |
| T4d stale approval                     | Invoker changes params after approval, recomputes `params_hash`, re-signs                                                                                                                                                                                                                                                                                         | L43                                                    |
| Receipt window                         | Expired receipt; revoked approver; receipt's `approver_pk` not certified for its `approver_id` (unresolvable, D-27); approver certificate not yet valid (`t < nbf`, D-35)                                                                                                                                                                                            | L44; L42; L41; L42                                     |
| Receipt list (D-34)                    | Two receipts for one approver; receipts out of order; key 9 present but empty; the required receipt plus one from a non-required approver                                                                                                                                                                                                                          | L02; L02; L02; **accept**                              |
| T5a misattribution                     | Register another principal's pk without their secret key                                                                                                                                                                                                                                                                                                          | registry rejects                                       |
| T5a                                    | Replay a used PoP nonce; PoP signed under the CHAIN DST                                                                                                                                                                                                                                                                                                           | registry rejects                                       |
| T5b compromised root (bounded)         | With `orga`'s stolen root key: issue an issuer certificate and a session within `orga`'s pinned policy; the same with a session scope exceeding that policy; a certificate for an `orgb:` identifier signed with `orga`'s root. Paper §7.1 assumes an honest root; §7.3 bounds the damage by pinning and the namespace binding (P-19)                                 | **accept** (document the bound); L32; L24              |
| T5c revocation                         | Revoke a delegator. Verify one chain through it before ingesting the assertion, and a second chain (new nonce) after                                                                                                                                                                                                                                              | **accept** (the propagation window), then L27          |
| T5c expiry                             | Signer's certificate expired at `t`; signer's certificate not yet valid at `t` (`t < nbf`, D-35, P-17); boundaries `t = nbf` and `t = exp` (P-26)                                                                                                                                                                                                                  | L27; L27; **accept**, **accept**                       |
| T5d substitution                       | Cert for an `orga:` identifier signed by `orgb`'s root                                                                                                                                                                                                                                                                                                            | L24                                                    |
| T5d                                    | `registry_id` ≠ org of the identifier                                                                                                                                                                                                                                                                                                                             | L25                                                    |
| T5e role confusion                     | Agent-kind cert at position 0                                                                                                                                                                                                                                                                                                                                     | L26                                                    |
| T5e                                    | Issuer-kind cert as a delegator; approver-kind cert as the invoker                                                                                                                                                                                                                                                                                                | L26, L26                                               |
| T5e                                    | Agent key signs a receipt, naming the required approver (no certificate binds that approver to the agent's key, D-27)                                                                                                                                                                                                                                             | L41                                                    |
| Scheduled rotation (P-04, resolved)    | Issuer, a delegator and an approver each hold two overlapping certificates; chains signed under either key verify; a chain naming the old key after its certificate expires fails; a chain naming the new key before its certificate's `nbf` fails (D-35)                                                                                                          | **accept**, **accept**; L27; L27                       |
| T6a prompt injection (bounded)         | Within-policy invocation by a "compromised" agent; out-of-policy invocation                                                                                                                                                                                                                                                                                       | **accept**; L37                                        |
| T6b confused deputy (bounded)          | Delegation to an adversary within scope; wider than scope                                                                                                                                                                                                                                                                                                         | **accept**; L34                                        |
| Closed world                           | Undeclared parameter; array-valued parameter; `/../` path under `under`                                                                                                                                                                                                                                                                                           | L37 each                                               |
| Structure                              | Garbage bytes; single body (N = 0); non-canonical body encoding                                                                                                                                                                                                                                                                                                   | L02, L03, L05                                          |
| Structure (D-16, D-31, D-32)           | N = 17; non-canonical envelope encoding; float or tag inside a body; unknown `kind` value; the same body with a non-shortest integer (canonical-form violation only)                                                                                                                                                                                                 | L02; L02; L02; L02; L05                                |
| Point validation (D-30)                | σ_agg is the identity; σ_agg is not in the G2 subgroup; σ_agg in uncompressed form; a receipt signature that is the identity                                                                                                                                                                                                                                      | L02 each                                               |
| Malformed scope (P-15, D-28)           | The P-15 child scope (an atom on an undeclared path) as a delegation scope; the same defect in a session scope; the same defect in the pinned policy document                                                                                                                                                                                                       | L02; L02; L31                                          |
| Key chain                              | `subject_pk` ≠ `spk(B_1)`; `delegatee_pk` ≠ next `spk`                                                                                                                                                                                                                                                                                                            | L18, L20                                               |
| Key chain, identifiers (P-16, D-36)    | One key registered under two identifiers (PoP passes for both). `subject_id` ≠ `sid(B_1)` with `subject_pk` = `spk(B_1)`; `delegatee_id` ≠ next `sid` with `delegatee_pk` = next `spk`                                                                                                                                                                            | L18, L20                                               |
| Resolution                             | Unknown signer identifier                                                                                                                                                                                                                                                                                                                                         | L23                                                    |
| Distinct messages                      | Unit test through a test-only hook that injects duplicate digests (a real duplicate needs a SHA-256 collision; say so in the test)                                                                                                                                                                                                                                | L48                                                    |
| Phase ordering (Figure 2, `count-ops`) | Expired chain; wrong `aud`; L34 rejection                                                                                                                                                                                                                                                                                                                         | 0 pairings in each; 0 resolver calls for the first two |
| Steady-state offline (paper §8.2)      | Warm verifier accepts a chain from known partners                                                                                                                                                                                                                                                                                                                 | 0 resolver and 0 policy-store calls                    |
| Theorem 5, part 2                      | A chain accepted at V1 is presented to V2                                                                                                                                                                                                                                                                                                                         | L08                                                    |

### 11.3 Cache equivalence

- **Setup:** 10,000 randomized chains, valid and mutated.
- **Interleaved events:** revocations, certificate expiry (by advancing the injected clock), and new pins.
- **Assertion:** the uncached verifier and every cached configuration (warm; warm+prefix for arms B and D) return the same accept/reject decision, and the same reject variant.

### 11.4 Fuzzing (optional; do it if time allows)

`cargo-fuzz` targets on the CBOR decoder, the policy parser and `verify` over mutated valid chains. Required properties:

- No panics.
- No accepted mutation, unless it is byte-identical to the original.

---

## 12. Benchmark arms (`dc-baselines`)

Arms A, A-ind, C and C-batch run the **same** generic verifier (§5.1). Phases 1–7 are identical code, except where they verify a signature with the arm's scheme; phase 8 differs by construction. This is the fairness guarantee: any difference between those arms is caused by the signature scheme.

Phases 1–7 use the arm's scheme in two places, and reports must say so wherever it matters:
- certificate signatures in phase 5, which are paid only on a cache miss, so in the cold state;
- receipt signatures in phase 7, which are paid on every call in the medium-approval profile.

| Arm                   | Chain signatures          | Phase 8                             | Purpose                                                 |
| --------------------- | ------------------------- | ----------------------------------- | ------------------------------------------------------- |
| **A** (paper)         | 1 BLS aggregate, 96 B     | `aggregate_verify` multi-pairing    | The protocol as specified                               |
| **A-ind** (VARIANT)   | N+1 BLS signatures        | N+1 individual `verify`             | Isolates the multi-pairing saving (tests §2.2's claim)  |
| **B** (VARIANT)       | as A                      | pairing cache (§5.7) + prefix cache | Best case for aggregation with caching                  |
| **C** (VARIANT)       | N+1 Ed25519 signatures    | N+1 `verify_strict`                 | Non-aggregating baseline, the AIP-style design          |
| **C-batch** (VARIANT) | as C                      | one `verify_batch`                  | Best-case non-aggregating verification                  |
| **D** (VARIANT)       | as C                      | prefix cache: verify σ_N only       | Non-aggregating design with the caching UCAN recommends |
| **E** (external)      | Biscuit, biscuit-auth 6.x | Biscuit verify + authorize          | AIP's chained-mode primitive; positioning only (§12.3)  |
| **A-mt** (supplementary) | as A                   | `aggregate_verify` on `blst`'s thread pool (no `no-threads`) | Shows what the library's default threading does to Q1 latency. Q1 only, never Q6, always labelled "supplementary: multi-threaded blst" (D-29) |

Within an arm, registry certificates use the arm's scheme (BLS for A, A-ind, A-mt and B; Ed25519 for C, C-batch and D).

A-mt needs a separate build, because Cargo unifies features and `no-threads` cannot be switched off for one arm in a binary that has it on (D-29). The harness records in `env.json` which `blst` threading mode each binary was built with, and refuses to run a row whose build does not match its label.

### 12.1 Prefix cache (arms B and D; VARIANT)

- **Key:** `m_{N−1}`. It commits to every prefix body's canonical bytes (§5.4), so a hit means the received prefix is byte-identical to one already processed.
- **Value:**
  - `m_0 … m_{N−1}`
  - resolved `pk_0 … pk_{N−1}` and their certificate serials
  - the identifier and key the last prefix body hands on (`B_0.subject_id`/`subject_pk` if N = 1, else `B_{N−1}.delegatee_id`/`delegatee_pk`; D-36), plus `B_{N−1}`'s `scope` and `exp`
  - the containment results for the ceiling and every prefix link (lines 30–35)
  - the prefix's hop and session checks (line 11) and expiry checks (line 15 for k < N)
  - arm B: the Miller-loop product P (§5.7)
  - arm D: the verified prefix signature bytes `σ_0 … σ_{N−1}`. A hit additionally requires the received prefix signatures to be byte-identical to them; otherwise treat it as a miss. Without this, a chain with valid prefix bodies but garbage prefix signatures would be accepted on a hit and rejected on a miss, and §11.3's equivalence test would rightly fail. Arm B needs no such rule, because its full pairing equation covers every signature.
- **Entry validity:** from the latest prefix-certificate `nbf` to the earliest of every prefix body's `exp` and every prefix certificate's `exp` (D-35). Outside that window, treat a lookup as a miss.
- **Invalidation:** evict on revocation of any listed serial, and on a change to the pins.

**Hit path**, in Algorithm order:

1. Hash the prefix bodies to obtain `m_{N−1}`, and look it up.
2. Strictly decode and canonical-check `B_N` only (line 5); line 7 for `B_N`; lines 8 and 9.
3. Line 13; line 15 for k = N; line 17.
4. The last key link only, identifier and key (D-36): line 18 if N = 1, else line 20 for k = N − 1.
5. Lines 23–28 for k = N only.
6. Lines 36–46.
7. Line 48, `m_N` against the cached digests.
8. Phase 8:
   - arm B: `FE(P · ML(H(m_N), pk_N) · ML(σ_agg, −g1)) == 1`;
   - arm D: `verify_strict(pk_N, m_N, σ_N)`.
9. Line 50.

**Miss path:** run the full algorithm, then populate the cache.

**Soundness:** given SHA-256 collision resistance, the hit path decides exactly what the full algorithm decides. §11.3's equivalence test enforces this.

### 12.2 Why these arms

- A vs A-ind tests the paper's claim that aggregation gives constant-factor savings over individual BLS (§2.2).
- A vs C and C-batch answers whether aggregated BLS beats non-aggregated Ed25519 at all.
- B vs D answers the same question in the deployment pattern that matters: one delegation, many invocations.

The paper itself (§8.3) says a comparison without caching "would not reflect how verifiers are built". Arms B and D exist because of that sentence.

### 12.3 Arm E (Biscuit)

- **Token:** an authority block carrying facts equivalent to the medium profile's session scope, then N−1 appended blocks, each adding checks equivalent to one attenuation.
- **Authorizer:** facts for `aud`, tool, action and parameters, with a policy that mirrors Evaluate as closely as Datalog allows.
- **Documentation:** record the mapping in `DECISIONS.md`.
- **Timing:** time `Biscuit::from` (deserialize and verify) plus authorizer construction plus `authorize`.
- **Reporting:** state E's functional gaps in every table where it appears: no registry resolution, no PoP, no revocation, no receipts, no nonce cache, no parameter binding (paper Table 1). E is a positioning reference, not a like-for-like arm.
- **Depth mapping:** DC's N corresponds to Biscuit depth N−1, since depth 0 is the authority block alone, like DC's N = 1.

---

## 13. Benchmark plan (`dc-bench`)

### 13.1 Pre-registered questions

- **Q1 (primary).** Warm per-invocation verification latency, median and p99, for N ∈ {1, 2, 3, 5, 10}: A vs C vs C-batch, and B vs D. The headline comparison is N = 3 with the medium profile. A-mt appears as a separately labelled supplementary row; it never enters a headline ratio (D-29).
- **Q2 (primary).** Bytes on the wire per chain, by arm, N and profile, with the signature share of the total.
- **Q3.** Does the paper's cost model hold for arm A? Fit `latency = α + β·N` and report α, β, 95% CIs, R², and `10β/α`. Paper §4.6 (revision 2026-09-29) claims that the cost is approximated by α + βN, with β being one hash to G2 plus one Miller loop per hop. It says β "cannot be assumed small relative to α", and that which term dominates is for measurement to settle. Report which dominates for N ≤ 10. (Revision 2026-09-28 claimed that the variation with N is small relative to α for N ≤ 10; that claim was withdrawn, P-21.)
- **Q4.** The multi-pairing saving: A vs A-ind.
- **Q5.** Cold-path latency, with empty caches and a local registry, plus the injected-RTT variants in §13.4.
- **Q6.** Throughput under concurrency (§13.5).
- **Q7.** Signing-side costs: per-hop signing including digest computation, aggregate add, receipt signing, issuance.
- **Q8.** Policy costs: Evaluate and Contains as scope size grows.
- **Q9.** Arm E on this hardware, against AIP's published numbers (§13.10).
- **Q10.** Memory per entry: nonce cache, certificate cache, prefix cache.

### 13.2 Workload profiles

Generate everything from a seeded `ChaCha20Rng`, and record the seed.

- **small**
  - Policy: 1 rule, 2 params (`amount: int`, `to: string`), 1 atom.
  - Delegations: identity (each hop's scope equals its parent's).
- **medium**
  - Policy: the paper's §6.2 example, with `at` clauses, exactly as printed.
  - Delegations: each hop tightens one numeric bound on the transfer rules, so containment does real work.
  - Invocation: hits rule 1 (no approval).
  - Variant `medium-approval`: the invocation hits the approval rule and carries 1 receipt.
- **large**
  - Policy: 16 rules × 4 params × 3 atoms, spread over 2 services and 4 tools.
  - 2 rules require approval, and they are ordered before overlapping permissive rules (the recommended order, paper §6.3).
  - Delegations: each hop drops 2 rules and tightens 1 bound, but never drops below 4 rules. From then on, hops only tighten. With 9 hops at N = 10, hops 1–6 drop rules and hops 7–9 only tighten; smaller N are unaffected (**D-38**).
  - A hop never drops an approval rule while keeping a permissive rule that the approval rule overlaps. That would be a real escalation, and line 34 correctly rejects it.
  - Invocation: matches the last surviving rule, which is Evaluate's worst case.

**Identities (D-40).** Within a chain, every hop uses a distinct agent identity, except in the correctness tests of §11.2. Identities are drawn from a fixed per-organization pool. The warm-up chains of the warm states cover every identity and certificate the measured chains use, so "warm" really means the certificate cache holds every certificate a measured chain needs.

### 13.3 Grid

| Dimension | Values                                                                                         |
| --------- | ---------------------------------------------------------------------------------------------- |
| Arm       | A, A-ind, C, C-batch in states cold and warm; B, D in states warm+prefix (hit) and prefix-miss |
| Supplementary | A-mt in state warm only, same N and profiles as A; separate build; Q1 only (D-29)          |
| N         | 1, 2, 3, 5, 10                                                                                 |
| Profile   | small, medium, large (plus medium-approval at N = 3)                                           |

### 13.4 Cold path with injected latency (Q5)

- For arms A and C at N = 3 (medium profile), run the cold state with resolver and policy-store latency of 0, 1, 20 and 80 ms per call.
- Report latency and call counts.
- Purpose: to quantify the paper's §8.2 claim that verification is local only in the steady state.
- **Iteration counts (D-44).** These configurations are dominated by injected sleeps: cold N = 3 makes 5 registry or store calls per verify, so at 80 ms and full counts each arm would take about 73 minutes per run. They therefore use reduced counts, fixed in the frozen plan. Every configuration still gets at least 200 measured verifications, and results are reported with CIs.

### 13.5 Method

**Isolation.** Pre-generate every chain outside the timed region. Each timed operation is exactly one `verify(&bytes)` call.

**Harness (latency).** Use a custom harness, not criterion, for end-to-end `verify`:

- Per configuration: 1,000 warm-up verifications, then 10,000 measured.
- Each call is timed with `Instant` and recorded in nanoseconds.
- Every sample goes to CSV.
- Chains carry unique nonces, so the nonce cache sees a realistic stream. `InsertIfAbsent` is inside the timed region, because it is part of `verify`.

**States.**

- _cold_: a fresh verifier with empty caches is constructed before each call, outside the timer.
- _warm_: caches are populated by a separate set of chains from the same organizations, policies and identity pools (D-40) before measurement.
- _warm+prefix_: B and D chains share prefixes (**D-39**).
  - Use 10 prefixes with 1,100 invocations each, presented round-robin across the prefixes.
  - The first 100 invocations per prefix are warm-up, including the miss that populates the entry. The remaining 1,000 per prefix are measured, which gives 1,000 warm-up and 10,000 measured, as in every other configuration.
- _prefix-miss_: every chain has a new prefix, and caches are otherwise warm.

**Order and repeats.**

- Randomize the order of configurations with the recorded seed.
- Run the full grid 3 times, in 3 separate processes.
- Report run-to-run variation.

**Environment (`results/env.json`, captured automatically):**

- CPU model, core count, base and boost frequency
- frequency governor and turbo state
- OS and kernel
- `rustc -vV` and `RUSTFLAGS`
- versions of every crate listed in §3.2, read from `Cargo.lock`
- whether the `blst` ADX path is used, and which `curve25519-dalek` backend is active
- `blst` threading mode of each binary (D-29)
- git commit hash, date, and AC or battery power; the macOS power mode (`pmset -g`: `powermode`, low-power mode)
- performance and efficiency core counts

Where possible, set the performance governor and disable turbo. If you cannot, record that.

**This machine (D-45).** macOS on an Apple M4 Max (10 performance + 4 efficiency cores). Record each of these in `env.json` and under threats to validity:
- There is no frequency governor or turbo control.
- There is no ADX path; `blst` uses its armv8 assembly.
- `curve25519-dalek` uses its serial u64 backend; its SIMD backends are x86-only.
- `target-cpu=native` does not reach `blst`'s C code (§3.3).
- Full runs need AC power and an otherwise idle machine. Record the power source and power mode.

**Pinning and QoS (D-42).**
- macOS has no thread-affinity API that works on Apple Silicon, so latency runs are **not pinned**. Record that.
- Instead, every measuring thread, in every arm, sets its QoS class to user-interactive, with `pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0)`, so that macOS schedules it on the performance cores.
- This is the one permitted `unsafe` FFI call in `dc-bench` (§0 rule 9). It is logged in `DECISIONS.md`, and the harness records whether the call succeeded.

**Throughput (Q6):**

- Arms A, B, C and D; medium profile; N = 3. Never A-mt (D-29).
- Threads: 1, 2, 4, 8, 10 (all performance cores), and 14, labelled "includes efficiency cores" (**D-43**).
- Workload: 100 prefixes × 1,000 invocations.
- Measure the wall time to verify all of them. Report accepted/s, plus the p99 per-call latency under load.

**Micro-benchmarks (criterion; Q7, Q8, primitives):**

- BLS: sign, single verify, `aggregate_verify` for 2–11 messages, hash-to-G2, Miller loop, final exponentiation.
- Ed25519: sign, `verify_strict`, `verify_batch` for 2–11 signatures.
- CBOR encode and decode per body type.
- SHA-256 chain digest.
- Evaluate and Contains for rules ∈ {1, 4, 16, 64} × atoms ∈ {1, 4, 8}, in both the typical case and the worst case (last rule matches).

**Memory (Q10).** Measure with a counting global allocator in a dedicated binary. Insert 100,000 entries and report bytes per entry. Use the `stats_alloc` crate, so that our code has no `unsafe impl GlobalAlloc` (**D-41**).

### 13.6 Statistics

- **Per configuration:** median, mean, standard deviation, p95, p99, min, max, and a bootstrap 95% CI for the median (10,000 resamples).
- **Q3 fit:** ordinary least squares over the per-N medians, plus a bootstrap CI for α and β from the raw samples.
- **Ratios:** report every headline comparison as a ratio with a CI, e.g. `median(A)/median(C)` at N = 3.

### 13.7 Bytes accounting (Q2)

For every arm, N and profile, report:

- total chain bytes
- bytes of bodies
- bytes of signatures
- the signature share of the total
- the bytes saved by aggregation (A vs A-ind)

Also compute the actual certificate size in this encoding, and the chain size if all N+1 certificates were carried inline. That checks the arithmetic in paper §8.2, which assumes 48 + 96 bytes per certificate before any other field.

### 13.8 Outputs

- `results/raw/*.csv` with columns `run, arm, state, N, profile, iter, ns` (and the throughput and memory equivalents)
- `results/env.json`
- `results/summary.md`, generated by `cargo run --release -p dc-bench -- report`
- `results/plots/*.png`, generated by `scripts/plot.py`, run from a virtual environment at `scripts/.venv` built from `scripts/requirements.txt` (matplotlib is not installed system-wide on this machine):
  - latency vs N per arm, one plot each for warm and warm+prefix
  - bytes vs N
  - throughput vs threads
  - the Q3 fit with residuals

One command reproduces everything: `cargo run --release -p dc-bench -- all`.

### 13.9 Pre-registration (`BENCH_PLAN_FROZEN.md`)

Before the first full run, write:

- the grid
- iteration counts
- workload definitions and the seed
- the primary outcomes (Q1, Q2)
- the claims in §13.11 that will be checked

Commit it and tag `bench-freeze`. Any later deviation is logged in `BENCH_LOG.md` and repeated in a "Deviations from the frozen plan" section of `BENCHMARKS.md`.

### 13.10 Reference numbers from AIP (published; comparison only)

From Prakash (2026), arXiv:2603.24775, Tables 4–5, measured on an Apple M3 Max under macOS 15.3 with biscuit-auth 6.0:

|                      | Rust verify (ms) | Rust token size (bytes) |
| -------------------- | ---------------- | ----------------------- |
| Compact (JWT, EdDSA) | 0.049            | 356                     |
| Chained, depth 0     | 0.188            | 520                     |
| depth 1              | 0.292            | 940                     |
| depth 2              | 0.403            | 1,316                   |
| depth 3              | 0.516            | 1,696                   |
| depth 4              | 0.625            | 2,072                   |
| depth 5              | 0.745            | 2,448                   |

Never mix these into measured tables without labelling them as published figures from different hardware. Their use is to sanity-check arm E: if arm E on this machine differs from them by more than about 3×, investigate before trusting any result.

These figures come from this spec. The implementer has not re-checked them against arXiv:2603.24775, and reports must say so.

### 13.11 Paper claims to check (report a verdict for each)

| Claim                                                                                         | Paper section  | How it is checked                                      |
| --------------------------------------------------------------------------------------------- | -------------- | ------------------------------------------------------ |
| Aggregation gives significant constant-factor savings over verifying signatures independently | §2.2           | A vs A-ind (Q4)                                        |
| Cost ≈ α + βN, with β = one hash to G2 plus one Miller loop per hop; which term dominates is left to measurement | §4.6 | Q3 fit (R², residuals); `10β/α`, and which term dominates for N ≤ 10; micro-benchmarks of hash-to-G2, Miller loop and final exponentiation, to attribute α and β |
| A chain carries a constant 96-byte signature regardless of N                                  | §2.2, §4.3     | Q2 bytes                                               |
| Carrying certificates inline costs more per hop than aggregation saves                        | §8.2           | §13.7                                                  |
| In the steady state, verification touches no registry                                         | §8.2           | `count-ops` in the warm state (§11.2)                  |
| Cheap checks reject hostile chains before any pairing                                         | §4.6, Figure 2 | `count-ops` ordering tests; latency of rejected chains |
| The case for aggregation must be settled against a non-aggregating baseline                   | §4.6, §8.3     | Q1: A/B vs C/C-batch/D                                 |

Verdicts are _supported_, _not supported_, or _partially supported_, each with the numbers. If none of the checks contradicts the paper, say explicitly that each one was checked.

---

## 14. Deliverables and acceptance criteria

**Code quality**

- `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings` and `cargo test --workspace` all pass.

**Tests**

- Every row of §11.2 has a passing test that asserts the stated `Reject` variant.
- The differential containment test (§9.7) has run at least 100,000 cases with zero soundness violations and zero reflexivity failures, and the completeness rate is reported.
- The pairing-cache equivalence (§5.7) and cache equivalence (§11.3) tests pass.

**Benchmark**

- `cargo run --release -p dc-bench -- all` reproduces `results/` from scratch.

**Documents**

- `DECISIONS.md` is complete, including every D-xx in this spec.
- `PAPER_ISSUES.md` includes every entry of Appendix C, plus anything found during implementation.
- `BENCHMARKS.md` contains:
  1. Environment
  2. Method, with a link to the frozen plan
  3. Results tables, generated
  4. Answers to Q1–Q10, in plain language
  5. Paper claims checked (§13.11), with verdicts
  6. Threats to validity: hardware, the in-process registry, synthetic policies, arm E not being full AIP, laptop thermals if relevant
  7. Deviations from the frozen plan
- **A final summary for the author** at the top of `BENCHMARKS.md`, three paragraphs at most:
  - whether aggregation is a net benefit for verification latency, with and without caching, and at which N;
  - how many bytes it saves, and what share of the chain that is;
  - which paper claims were not supported.

  State these plainly, even when unfavorable.

---

## 15. Milestones

Work through the milestones in order. Each ends with all tests green, a commit, and an entry in `MILESTONES.md`: what was done, which decisions were added, which paper issues were found. Do not start M9 until every M0–M8 test passes.

| #   | Milestone                                                                                                                                | Done when                                                                                  |
| --- | ---------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| M0  | Scaffold: workspace, CI (fmt, clippy, test), empty docs; log Appendix C in `PAPER_ISSUES.md` and all pre-assigned D-xx in `DECISIONS.md` | CI green on an empty workspace                                                             |
| M1  | `dc-cbor`                                                                                                                                | §4.5 tests pass                                                                            |
| M2  | `dc-crypto` (both schemes, DSTs, validation) and `dc-types` (bodies, digests, envelope)                                                  | Unit tests and regression vectors committed                                                |
| M3  | `dc-registry`: certificates, PoP, revocation, resolver, policy store                                                                     | PoP and revocation tests pass                                                              |
| M4  | `dc-policy`: parser, AST, validation, evaluate, implies/unsat, contains. **Do not start until `docs/paper.pdf` is the revision that fixes P-15; if it is not there yet, stop and ask.** | §9.7 passes, including the differential oracle at 100k cases                               |
| M5  | `dc-chain` builders and approval flow                                                                                                    | Chains verify end-to-end in a smoke test                                                   |
| M6  | `dc-verifier`, the full security suite, concurrency, `count-ops` ordering                                                                | All of §11.2 passes                                                                        |
| M7  | `dc-baselines`: A-ind, C, C-batch; prefix caches B and D; arm E                                                                          | §5.7 and §11.3 equivalence pass; arm E runs                                                |
| M8  | `dc-bench`: workloads, harness, criterion benches, env capture, report generator, plots                                                  | A dry run with 10 iterations per configuration completes; its numbers are **not** reported |
| M9  | Freeze and run                                                                                                                           | `BENCH_PLAN_FROZEN.md` committed, tagged `bench-freeze`; three full runs complete          |
| M10 | Report                                                                                                                                   | `BENCHMARKS.md` generated and written; `PAPER_ISSUES.md` final                             |

---

## Appendix A — Algorithms 1 and 2 (from the paper; the PDF is authoritative)

```
 1: procedure Verify(received chain C, current time t)
    ▷ Phase 1 — structure and encoding
 2:   (B0, ..., BN, σagg) ← Decode(C); reject if decoding fails
 3:   reject if N < 1
 4:   for all Bk do
 5:     reject if Canon(Bk) ≠ received bytes of Bk
 6:   end for
 7:   reject if any Bk.kind disagrees with the tag its position implies
 8:   reject if BN.aud ≠ self
 9:   reject if H(Canon(BN.params)) ≠ BN.params_hash
10:   for k ← 1 to N − 1 do
11:     reject unless Bk.hop_index = k and Bk.session_id = B0.session_id
12:   end for
    ▷ Phase 2 — temporal
13:   reject if t ∉ [BN.nbf, BN.exp]
14:   for k ← 1 to N do
15:     reject if Bk.exp > Bk−1.exp
16:   end for
    ▷ Phase 3 — replay
17:   reject if (spk(BN), BN.nonce) ∈ NonceCache
    ▷ Phase 4 — key chain consistency
18:   reject if (B0.subject_id, B0.subject_pk) ≠ (sid(B1), spk(B1))
19:   for k ← 1 to N − 1 do
20:     reject if (Bk.delegatee_id, Bk.delegatee_pk) ≠ (sid(Bk+1), spk(Bk+1))
21:   end for
    ▷ Phase 5 — identity resolution
22:   for k ← 0 to N do
23:     certk ← Resolve(sid(Bk), spk(Bk)); reject if unresolvable
24:     reject unless certk verifies under Root[org(sid(Bk))]
25:     reject unless certk.registry_id = org(sid(Bk))
26:     reject unless certk.kind = role(k)
27:     reject if certk is not yet valid, expired, or revoked at t
28:     pkk ← certk.pk                        ▷ equals spk(Bk) by resolution
29:   end for
    ▷ Phase 6 — policy
30:   reject if B0.policy_hash ∉ Pinned[org(sid(B0))]
31:   S ← LoadPolicy(B0.policy_hash); reject if unavailable
32:   reject if Contains(S, scope(B0)) is false
33:   for k ← 1 to N − 1 do
34:     reject if Contains(scope(Bk−1), scope(Bk)) is false
35:   end for
36:   d ← Evaluate(scope(BN−1), BN.invocation)
37:   reject if d = deny
    ▷ Phase 7 — approvals
38:   if d = allow-with-approval(svcs) then
39:     for all s ∈ svcs do
40:       R ← the receipt in BN with R.approver_id = s; reject if none
41:       certR ← Resolve(s, R.approver_pk); reject if unresolvable
42:       reject unless certR passes the phase-5 checks with kind approver
43:       reject unless R verifies under certR.pk over InvocationDigest(BN)
44:       reject if t ∉ [R.iat, R.exp]
45:     end for
46:   end if
    ▷ Phase 8 — aggregate signature
47:   recompute m0, ..., mN from B0, ..., BN using position-determined tags
48:   reject if mi = mj for some i ≠ j
49:   reject unless e(g1, σagg) = ∏_{k=0}^{N} e(pkk, HashToG2(mk))
    ▷ Commit
50:   reject unless InsertIfAbsent(NonceCache, (pkN, BN.nonce))
51:   accept
52: end procedure
```

`sid(B_k)` is `issuer_id`, `delegator_id` or `invoker_id`, and `spk(B_k)` is `issuer_pk`, `delegator_pk` or `invoker_pk`, by position. `role(k)` is `issuer` for k = 0 and `agent` for k ≥ 1. `self` is the verifier's own service identifier.

The listing above is paper revision 2026-09-29, checked line by line on 2026-09-29. It differs from revision 2026-09-28 only at lines 18 and 20 (D-36, P-16), line 27 (D-35, P-17) and line 41 (D-27, P-14), and the numbering is unchanged.
- The implementation reads line 27 as `t ∈ [certk.nbf, certk.exp]`, closed at both ends (P-26).
- A malformed scope (D-28; paper §6.1) fails decoding at line 2, or makes the policy unavailable at line 31.

---

## Appendix B — File templates

**`DECISIONS.md`**

```
## D-xx — <short title>
Spec section: §x.y     Paper section: §a.b (or "not specified")
Decision: <what was chosen>
Why: <one or two sentences>
Affects benchmarks: yes/no (if yes, how)
```

**`PAPER_ISSUES.md`**

```
## P-xx — <short title>
Paper location: §a.b / Algorithm n line m
Problem: <what is ambiguous, inconsistent, missing or wrong>
Evidence: <test name, example, or reasoning>
What the implementation does: <behaviour chosen, with D-xx reference>
Suggested fix to the paper: <one sentence, or "author to decide">
Severity: soundness / interoperability / clarity
```

**`BENCH_LOG.md`**

```
## <date> — <change>
Reason: <bug found, how>
Configurations re-run: <list>
```

---

## Appendix C — Paper issues (status against revision 2026-09-29)

`PAPER_ISSUES.md` holds the full entries, each with a `Status` line saying where revision 2026-09-29 addresses it.

**Still open in revision 2026-09-29:**

- **P-05. Some digests are untagged.** `policy_hash` and `params_hash` are plain SHA-256 of an encoding, while the chain digests are domain-separated by tags.
- **P-06. Encodings of auxiliary structures are unspecified.** DSTs, field numbering and encodings for PoP challenges, receipts, certificates and revocation assertions are left open, deliberately (§4). The choices are D-04, D-07 and D-09. The InvocationDigest tag is now fixed by §4.5.
- **P-08. "Closed-form" implication and satisfiability for strings is not established.** §6.4 calls the per-atom checks closed-form. Exactness for mixed `starts_with`/`ends_with`/`contains`/`under` constraints without a finite set is not shown. The implementation is sound but incomplete there (§9.5).
- **P-12. Signing-service enforcement is unspecified.** The signing service "applies policy enforcement before signing" (§3.1), but the checks it performs are not specified.
- **P-27. Remark 1 understates where containment is incomplete** (found at M4). Beyond unions, dead child rules (unsatisfiable, or fully shadowed) and step 3(b)'s single-rule, whole-clause skip test also cause misses, and in the M4 oracle they account for almost all of them.
- **P-26. Line 27 does not state its boundary.** "Not yet valid, expired" does not say whether validity is closed at `nbf` and `exp`, while lines 13 and 44 use closed intervals. The implementation uses the closed interval (D-35). Found in revision 2026-09-29.

**Resolved in revision 2026-09-29** (logged at M0, then marked resolved):

- **P-03** InvocationDigest: defined in §4.5 exactly as D-06.
- **P-07** clock skew: §4.6 and Theorem 5 explain the difference between line 13 and the TTL.
- **P-09** `allow all` and audiences: documented in §6.1.
- **P-10** receipt order and multiplicity: fixed in §4.5 (D-14, D-15, D-34).
- **P-14** line 41: now has "reject if unresolvable" (D-27 changed).
- **P-15** containment soundness: §6.1 well-formedness, and the Proposition 2 proof now relies on it (D-28).
- **P-16** lines 18 and 20: compare identifiers and keys (D-36).
- **P-17** line 27: checks "not yet valid" (D-35).
- **P-18** resolution: §5.4 now matches D-26.
- **P-19** T5b: moved to the bounded threats, with the bound stated.
- **P-20** caches: §4.6 and Figure 2 (D-37).
- **P-21** cost model: β includes hash-to-G2, and the "small variation" claim was withdrawn.
- **P-22** approval cost: a two-pairing check per receipt.
- **P-23** grammar: lexical details, `string-value`, and the typing table (D-17, D-20).
- **P-24** signer kind: its role is explained in §5.2.
- **P-25** session `iat`: declared informational in §4.3.

**Resolved before 2026-09-28.** Not logged; listed so the numbering stays stable: P-01 (line 9), P-02 (line 11), P-04 (`issuer_pk`, resolution by key), P-11 (line 41 uses the approver's key), P-13 (containment step 2).

Add new entries (from P-28) as you find them. Finding them is part of the job.
