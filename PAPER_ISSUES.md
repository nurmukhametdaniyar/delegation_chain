# Paper issues

Problems in the paper, _DelegationChain: Aggregatable Capability Chains for Cross-Organizational Agent Authorization_, revision 2026-09-28 (`docs/paper.pdf`, sha256 `bd94cef2…2e81e`). The format is SPEC Appendix B.

- P-03 to P-14 are the open issues from SPEC Appendix C. P-01, P-02, P-04, P-11 and P-13 are resolved in this revision and not logged.
- P-15 to P-25 were found in the pre-M0 review (2026-09-28).
- The author is fixing P-15, P-16 and P-17 in the next revision. Until it lands, the implementation follows the agreed fixes (SPEC §2 exception).

---

## P-03 — InvocationDigest is not defined precisely
Paper location: §4.5; Algorithm 2 line 43; Theorem 6
Problem: §4.5 says the agent "computes a digest over this preliminary body". Which bytes are hashed, and under what tag, is unspecified, so two implementations can compute different digests and reject each other's receipts.
Evidence: The Theorem 6 sketch describes the digest only as "a hash of the invocation body without the approval reference itself".
What the implementation does: `SHA256("TAG_IVD\0" ‖ canon(B_N with key 9 removed))` (D-06). Receipts are omitted when empty (D-14), so this is exactly the preliminary body.
Suggested fix to the paper: Define InvocationDigest as a tagged hash of the canonical invocation body with the receipts field removed.
Severity: interoperability

## P-05 — Some digests are untagged
Paper location: §4.4 (`params_hash`), §5.4 (policy hash)
Problem: `params_hash` and `policy_hash` are plain SHA-256 hashes of a canonical encoding, while every chain digest carries a domain-separation tag. Nothing exploits the gap today: `params_hash` is only compared, and `policy_hash` is content addressing. But it departs from the paper's own discipline, and any future signature over either hash would inherit the ambiguity.
Evidence: Equations (1)–(3) tag every chain message; §4.4 and §5.4 define the other two hashes without a tag.
What the implementation does: Implements them as written, untagged (SPEC §5.4).
Suggested fix to the paper: Tag both, or state why an untagged hash is safe in these two places.
Severity: clarity

## P-06 — Encodings of the auxiliary structures are unspecified
Paper location: §4 (introduction), §4.5, §5.2, §5.3, §5.6
Problem: DSTs, field numbering and encodings for PoP challenges, receipts, certificates and revocation assertions are left open. The paper says so (§4: "field numbering … and the exact byte layout … are not fixed by this paper").
Evidence: §4, first paragraph.
What the implementation does: D-04 (DSTs), D-07 (message tags), D-09 (kind enum), and the layouts in SPEC §6.3–§6.5 and §7.4.
Suggested fix to the paper: Defer to a normative specification, as the paper already says. No change is needed beyond cross-referencing one when it exists.
Severity: interoperability

## P-07 — Clock skew is handled inconsistently
Paper location: Algorithm 1 line 13; §4.6 ("Replay protection"); Theorem 5
Problem: Line 13 checks `t ∈ [B_N.nbf, B_N.exp]` with no tolerance, but the nonce-cache TTL adds "a clock-skew tolerance". If verifiers must tolerate skew, line 13 should too; if they need not, the TTL term is unexplained.
Evidence: Line 13 versus the §4.6 replay paragraph and the Theorem 5 sketch.
What the implementation does: Line 13 without tolerance, as written. The nonce TTL adds 60 s (D-25).
Suggested fix to the paper: State one skew policy and apply it to both.
Severity: clarity

## P-08 — "Closed-form" implication and satisfiability for strings is not established
Paper location: §6.4 (the paragraph before Proposition 2; the Proposition 2 cost argument)
Problem: §6.4 calls the per-atom checks closed-form and each "constant-time in the atom's operands". Exactness for mixed `starts_with`/`ends_with`/`contains`/`under` constraints without a finite value set is not shown, and is not obviously achievable in closed form.
Evidence: SPEC §9.5 gives sound but incomplete rules for that case. The M4 differential oracle will report the completeness rate.
What the implementation does: Sound but incomplete procedures for strings without a finite set; exact for ints, bools, and strings with a finite set (SPEC §9.5).
Suggested fix to the paper: Say that string implication is decided soundly but incompletely, or give the exact procedure.
Severity: clarity (soundness is preserved either way)

## P-09 — `allow all` ignores the audience clause
Paper location: §6.1, §6.3 ("The audience clause")
Problem: `allow all` permits any audience, tool and action. The mandatory `at` clause, which §6.3 presents as a protection, therefore does not constrain a scope written in this form. A pinned `allow all` policy authorizes invocations at every verifier that pins it.
Evidence: §6.3 decides `allow all` directly; §6.1 calls it "a reserved form used for top-level trusted contexts".
What the implementation does: As written.
Suggested fix to the paper: Say that `allow all` is audience-unrestricted and should not be pinned across partners, or give it an audience.
Severity: clarity

## P-10 — Receipt order, multiplicity and extra receipts are unspecified
Paper location: §4.3, §4.5; Algorithm 2 line 40
Problem: The paper does not fix the order of receipts inside the InvocationBody. It says nothing about two receipts for one approver, or about receipts from approvers the policy does not require. Line 40 ("the receipt … with R.approver_id = s") presumes uniqueness.
Evidence: §4.3: "one approval receipt for each approval service the policy requires (possibly none)".
What the implementation does: Receipts are sorted by `approver_id` with at most one per approver (D-15). Violations, and a present-but-empty list, are malformed (`L02`). Receipts from approvers that are not required are ignored (D-34).
Suggested fix to the paper: State the order and multiplicity, and say that extra receipts are ignored.
Severity: interoperability

## P-12 — Signing-service enforcement is unspecified
Paper location: §3.1, §3.2
Problem: The signing service "applies policy enforcement before signing", but the checks it performs are not specified. §3.2's adversary instructs it to sign "within the scope permitted by policy", which presumes some enforcement.
Evidence: §3.1, the signing-service description.
What the implementation does: A pluggable `EnforcementPolicy` hook, accepting by default (SPEC §8.2). The verifier's checks do not depend on it.
Suggested fix to the paper: Specify the minimum checks, or state that security never relies on the signing service's enforcement.
Severity: clarity

## P-14 — Line 41 has no reject clause
Paper location: Algorithm 2 lines 41–42
Problem: `Resolve(s, R.approver_pk)` can fail, and only line 42's "passes the phase-5 checks" covers that implicitly.
Evidence: Line 41 as printed.
What the implementation does: An unresolvable approver is rejected at line 42 (D-27).
Suggested fix to the paper: Add "reject if unresolvable" to line 41, as line 23 has.
Severity: clarity

## P-15 — Containment is unsound when a where clause names an undeclared path
Paper location: §6.1, §6.3 step 1(c), §6.4 (procedure, step 3), Proposition 2 and its proof; Theorems 4 and 6
Problem:
- The Proposition 2 proof says "every path r1's clause mentions is declared and therefore present". The language does not require it, and §6.3 step 1(c) exists precisely for where-paths that resolve absent.
- An atom that is a tautology over its type's domain (`z >= -18446744073709551616`, `f in [true, false]`), written on an undeclared path, makes its rule dead: the rule never matches. Yet §6.4's per-path implication ("the constraint the atoms induce on that path") counts the atom as implied by any clause.
- **Step 3(b), dropping an approval.** A dead child rule r2′ triggers the skip for a parent rule r′ that still decides the invocation, so r′'s approval requirement is never compared.
- **Step 3(a), direct escalation.** A dead parent rule "subsumes" a live child rule.
Evidence: The parent is a pinned policy in the order §6.3 recommends:
```
allow at=orgb:service:payments tool=payments action=transfer
  params { amount: int, to_account: string }
  where amount <= 100000 and to_account in ["acct_vendor_a", "acct_vendor_b"]
  approval requires orga:approver:finance
allow at=orgb:service:payments tool=payments action=transfer
  params { amount: int, to_account: string }
  where amount <= 1000
```
The child is the same two rules, with `and z >= -18446744073709551616` added to rule 1 (`z` is not declared).
- `Contains(parent, child)` returns true.
  - Child rule 2 is subsumed by parent rule 2.
  - Step 3(b) then examines parent rule 1 and skips it. Child rule 1 precedes, has the same head, and `implies(parent1.where, child1.where)` holds, because the `z` atom is a tautology on the unconstrained int domain.
- Child rule 1 never matches, since `z` is always absent. So `{amount: 500, to_account: "acct_vendor_a"}` evaluates to `allow` under the child, and to `allow-with-approval(orga:approver:finance)` under the parent.
- A chain with the parent as session scope and the child as a delegation scope therefore passes lines 32 and 34. Line 36 returns `allow`, and phase 7 never asks for a receipt. Theorem 6 fails, and Theorem 4 fails for that link.
- Parent-side variant: parent `[allow … params {x: int} where z >= -18446744073709551616]` (dead, so it permits nothing) against child `[allow … params {x: int}]`. `Contains` returns true, yet the child permits `{x: 5}`.
- A throwaway model of §6.3/§6.4 reproduced both results during the pre-M0 review. The regression tests are added at M4.
What the implementation does: D-28. An atom on a path its rule does not declare makes the scope malformed: `L31` for a policy, `L02` inside a body. The evaluator keeps step 1(c) as a defensive check. The M4 oracle generator includes undeclared-path atoms, and asserts that the validator rejects them.
Suggested fix to the paper: Require every where-path to be declared (a policy that breaks this is malformed), and repair the Proposition 2 proof, which currently assumes it.
Severity: soundness
Status: The author is fixing this in the next revision (agreed 2026-09-28).

## P-16 — Lines 18 and 20 compare keys, never identifiers
Paper location: Algorithm 1 lines 18–20; §4.6 ("Public key chain consistency"); §3.1 asset (ii); §5.3
Problem:
- The paper says the verifier "checks that each body is signed by the party its predecessor named". Lines 18 and 20 compare only keys: `B0.subject_pk` against `spk(B1)`, and `Bk.delegatee_pk` against `spk(Bk+1)`. `subject_id` and `delegatee_id` are never checked against the next signer's identifier.
- PoP (§5.3) proves possession, not uniqueness. A registrant can register its own key under two identifiers, or at two organizations' registries, which cannot coordinate.
- So a chain can name one party as the recipient of a hop and be signed by another. That breaks provenance: asset (ii), "the chain delivered to a verifier accurately records the parties that authorized each step".
Evidence:
- Registrant R holds key K and registers both `orga:agent:alice` and `orga:agent:mallory` under K; both PoPs are valid.
- `B0` names subject `(orga:agent:alice, K)`, and `B1` is signed as delegator `(orga:agent:mallory, K)`.
- Line 18 passes (the keys are equal), and line 23 resolves `(mallory, K)` to a valid agent certificate.
- The chain is accepted, while recording alice as the session holder and mallory as the first delegator.
What the implementation does: D-36. Line 18 also requires `B0.subject_id = sid(B1)`, and line 20 also requires `Bk.delegatee_id = sid(Bk+1)`. The §11.2 test asserts `L18` and `L20`.
Suggested fix to the paper: Compare identifier and key at lines 18 and 20.
Severity: soundness (provenance)
Status: The author is fixing this in the next revision (agreed 2026-09-28).

## P-17 — Line 27 omits the certificate's not-before time
Paper location: Algorithm 1 line 27; Algorithm 2 line 42; §5.2; §5.4; §5.5
Problem: Certificates carry a not-before timestamp (§5.2), and §5.4 and §5.5 speak of the certificate "valid at verification time". Line 27 rejects only "if cert_k is expired or revoked at t". Read literally, a certificate whose validity has not started is accepted. For example, the next certificate of a scheduled rotation could be used before its window opens.
Evidence: Line 27 as printed, compared with the certificate fields listed in §5.2.
What the implementation does: D-35. Line 27 rejects unless `t ∈ [nbf, exp]`, and rejects revoked serials. Line 42 applies the same window to approvers.
Suggested fix to the paper: "reject unless t ∈ [cert_k.nbf, cert_k.exp] and cert_k is not revoked at t".
Severity: soundness
Status: The author is fixing this in the next revision (agreed 2026-09-28).

## P-18 — §5.4's resolution wording makes line 27 unreachable
Paper location: §5.4 ("Resolution returns the valid certificate …"); Algorithm 1 lines 23 and 27
Problem: If resolution returns only valid certificates, line 27 can fire only on a stale cache entry, and §5.4 already bounds cache entries by certificate expiry and evicts on revocation. The two texts disagree about where validity is checked.
Evidence: §5.4 against lines 23 and 27.
What the implementation does: Resolution returns the latest certificate binding (id, pk), valid or not, and line 27 decides (D-26). This keeps "unknown key" (`L23`) and "expired or revoked" (`L27`) distinguishable.
Suggested fix to the paper: Say that resolution returns the certificate for (id, pk), and that validity is checked at line 27.
Severity: clarity

## P-19 — T5b is listed as prevented, but the analysis assumes an honest root
Paper location: §3.3.1 (T5b under "Threats the protocol prevents"); §7.1 ("Honest registry root"); §7.3
Problem: A holder of a registry's root key can issue certificates for any identifier in that organization, including an issuer certificate. Nothing in Algorithms 1–2 can tell those certificates from genuine ones. §7.1 assumes the threat away, and §7.3 attributes T5a–T5d to PoP, short lifetimes, revocation and transparency logs, none of which stops a root-key holder. §7.3's pinning remark gives only a bound: sessions stay within the organization's pinned policies, and the namespace binding confines the damage to that organization.
Evidence: §3.3.1 against §7.1 and §7.3.
What the implementation does: The §11.2 T5b row tests the bound.
- A stolen `orga` root issues a session within `orga`'s pins: accepted.
- A session scope beyond those pins: `L32`.
- A certificate for an `orgb` identifier signed with `orga`'s root: `L24`.
Suggested fix to the paper: Move T5b to §3.3.2 (bounded) and state the bound.
Severity: clarity (overclaim)

## P-20 — "Leaves the verifier exactly as it found it" ignores caching
Paper location: §4.6 ("The only state the procedure changes is the nonce cache … A chain that fails any check therefore leaves the verifier exactly as it found it"); §5.4 (certificate and policy caches); Figure 2 caption
Problem: §5.4 has verifiers cache resolved certificates and fetched policies. Those caches fill during phases 5 and 6, including for chains later rejected. The decision-relevant state is unchanged, but the statement as written is false.
Evidence: §4.6 against §5.4.
What the implementation does: D-37. Caches fill during verification, and line 50 is the only mutation that can change a later decision. §11.3 checks that the caches never change one.
Suggested fix to the paper: "No state that affects any later decision changes until the final phase; caches may be populated."
Severity: clarity

## P-21 — The cost model leaves out hash-to-G2
Paper location: §4.6 ("Cost")
Problem: "α is the dominant final exponentiation cost and β is the per-Miller-loop cost". But each of the N+1 messages on the right of Eq. (5) also needs one hash-to-G2, which grows with N and costs about as much as a Miller loop in current libraries. β is therefore at least one hash-to-G2 plus one Miller loop per hop. The constant term also includes the Miller loop of `e(g1, σagg)`.
Evidence: Eq. (5) needs `HashToG2(m_k)` for k = 0…N.
What the implementation does: Nothing needs implementing. Q3 fits end-to-end latency, and the M8 micro-benchmarks time hash-to-G2, the Miller loop and the final exponentiation separately, so each term can be attributed.
Suggested fix to the paper: Include hash-to-G2 in β.
Severity: clarity

## P-22 — The approval cost is undercounted
Paper location: §4.5 ("approval verification adds a single pairing operation per approval")
Problem: Checking one BLS receipt means checking `e(g1, σ) = e(pk, HashToG2(m))`: two pairings sharing one final exponentiation, plus a hash-to-G2. §4.6 counts pairings the same way ("N + 2 internal pairings" for N + 1 signers).
Evidence: §4.5 against §4.6.
What the implementation does: Nothing needs implementing. The medium-approval profile measures the cost.
Suggested fix to the paper: "adds one signature verification (two pairings sharing a final exponentiation) per approval".
Severity: clarity

## P-23 — The grammar leaves types and terminals undefined
Paper location: §6.1 (grammar)
Problem:
- `value ::= integer | string | boolean` lets `path numop value` take a string or boolean (`amount < "x"`, `amount < true`).
- `in` lists may mix types.
- The paper never says which operator/operand/declared-type combinations are malformed.
- `string-value`, `integer`, `string`, `boolean`, `letter` and `digit` are undefined.
- Two implementations could accept different policy sets, and hence compute different containment results.
Evidence: §6.1 grammar.
What the implementation does: D-17 (lexical syntax), D-08 (letters are ASCII), D-20 (type compatibility; anything else is malformed).
Suggested fix to the paper: Define the terminals and a typing rule for atoms.
Severity: interoperability

## P-24 — The `signer` kind has no role in verification
Paper location: §5.2 (kinds); §3.1 (the signing service "holds an agent's private key"); Algorithm 1 line 26; Algorithm 2 line 42
Problem: The signing service signs with the agent's key, which is certified as `agent`. `role(k)` is `issuer` or `agent`, and receipts require `approver`. No check accepts a `signer` certificate, so what one certifies, and why §5.2 gives signing services certificate lifetimes, is unclear.
Evidence: §5.2 and §3.1 against lines 26 and 42.
What the implementation does: The registry issues `signer` certificates (D-09), and the verifier never accepts one; one at any position fails line 26.
Suggested fix to the paper: State what a signer certificate is for (for example, the service's own identity for audit), or drop the kind.
Severity: clarity

## P-25 — The session's `iat` is never checked
Paper location: §4.3 (session "issue and expiry timestamps"); Algorithm 1 lines 13–15
Problem: Algorithm 1 checks only `t ∈ [B_N.nbf, B_N.exp]` and that expiry does not grow along the chain. A session whose `iat` is in the future is usable immediately, and a delegation cannot be post-dated. The issuer signs `iat`, so it cannot be forged, but the paper does not say whether it constrains validity.
Evidence: Lines 13–15.
What the implementation does: As written: `iat` is carried and signed, but not checked.
Suggested fix to the paper: Say that `iat` is informational, or check `t ≥ B0.iat`.
Severity: clarity
