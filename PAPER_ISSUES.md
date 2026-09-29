# Paper issues

Problems in the paper, _DelegationChain: Aggregatable Capability Chains for Cross-Organizational Agent Authorization_. The format is SPEC Appendix B, plus a `Status` line.

| Revision | Pages | sha256 | In `docs/` |
| --- | --- | --- | --- |
| 2026-09-28 | 42 | `bd94cef24e50a5bfca09375ef495b54e07aeba986e8c5096a2fc0c329f62e81e` | until 2026-09-29 (commit `e223f05`) |
| 2026-09-29 | 44 | `51eff0ec620940c3062de303f671f5ddeee9907ddb3c06c46e19fc1b6da84e14` | current |

- **Sources:** P-03 to P-14 come from SPEC Appendix C; P-01, P-02, P-04, P-11 and P-13 were resolved before 2026-09-28 and are not logged. P-15 to P-25 were found in the pre-M0 review (2026-09-28). P-26 was found while reconciling revision 2026-09-29, P-27 during M4, P-28 and P-29 during M6, and P-30 while resolving P-29.
- **Status after revision 2026-09-29:**
  - resolved: P-03, P-07, P-09, P-10, P-14, and P-15 to P-25;
  - resolved ahead of the paper: P-29 (D-65);
  - open: P-05, P-06, P-08, P-12, P-26, P-27, P-28, P-30.
- "Location" and "Evidence" below refer to revision 2026-09-28, where the issue was found. Each `Status` line says where revision 2026-09-29 addresses it.

---

## P-03 — InvocationDigest is not defined precisely
Paper location: §4.5; Algorithm 2 line 43; Theorem 6
Problem: §4.5 says the agent "computes a digest over this preliminary body". Which bytes are hashed, and under what tag, is unspecified, so two implementations can compute different digests and reject each other's receipts.
Evidence: The Theorem 6 sketch describes the digest only as "a hash of the invocation body without the approval reference itself".
What the implementation does: `SHA256("TAG_IVD\0" ‖ canon(B_N with key 9 removed))` (D-06). Receipts are omitted when empty (D-14), so this is exactly the preliminary body.
Suggested fix to the paper: Define InvocationDigest as a tagged hash of the canonical invocation body with the receipts field removed.
Severity: interoperability
Status: resolved in revision 2026-09-29. §4.5 defines InvocationDigest(B_N) = H(TAG_IVD ‖ Canon(B_N without its receipts field)), which is D-06 exactly, and says that the receipts field is omitted when empty.

## P-05 — Some digests are untagged
Paper location: §4.4 (`params_hash`), §5.4 (policy hash)
Problem: `params_hash` and `policy_hash` are plain SHA-256 hashes of a canonical encoding, while every chain digest carries a domain-separation tag. Nothing exploits the gap today: `params_hash` is only compared, and `policy_hash` is content addressing. But it departs from the paper's own discipline, and any future signature over either hash would inherit the ambiguity.
Evidence: Equations (1)–(3) tag every chain message; §4.4 and §5.4 define the other two hashes without a tag.
What the implementation does: Implements them as written, untagged (SPEC §5.4).
Suggested fix to the paper: Tag both, or state why an untagged hash is safe in these two places.
Severity: clarity
Status: open in revision 2026-09-29. §4.4 and §5.4 are unchanged.

## P-06 — Encodings of the auxiliary structures are unspecified
Paper location: §4 (introduction), §4.5, §5.2, §5.3, §5.6
Problem: DSTs, field numbering and encodings for PoP challenges, receipts, certificates and revocation assertions are left open. The paper says so (§4: "field numbering … and the exact byte layout … are not fixed by this paper").
Evidence: §4, first paragraph.
What the implementation does: D-04 (DSTs), D-07 (message tags), D-09 (kind enum), and the layouts in SPEC §6.3–§6.5 and §7.4.
Suggested fix to the paper: Defer to a normative specification, as the paper already says. No change is needed beyond cross-referencing one when it exists.
Severity: interoperability
Status: open in revision 2026-09-29, as the paper intends: §4 still leaves field numbering and byte layout to a normative specification. One piece is now fixed: the InvocationDigest tag (§4.5, P-03).

## P-07 — Clock skew is handled inconsistently
Paper location: Algorithm 1 line 13; §4.6 ("Replay protection"); Theorem 5
Problem: Line 13 checks `t ∈ [B_N.nbf, B_N.exp]` with no tolerance, but the nonce-cache TTL adds "a clock-skew tolerance". If verifiers must tolerate skew, line 13 should too; if they need not, the TTL term is unexplained.
Evidence: Line 13 versus the §4.6 replay paragraph and the Theorem 5 sketch.
What the implementation does: Line 13 without tolerance, as written. The nonce TTL adds 60 s (D-25).
Suggested fix to the paper: State one skew policy and apply it to both.
Severity: clarity
Status: resolved in revision 2026-09-29. §4.6 ("Replay protection") now says that line 13 applies no tolerance, and that senders allow for skew when they set `nbf` and `exp`. The TTL's added term has a different purpose: it must be at least the clock disagreement among the verifier instances sharing the cache. Theorem 5 is restated to match. D-25 is consistent.

## P-08 — "Closed-form" implication and satisfiability for strings is not established
Paper location: §6.4 (the paragraph before Proposition 2; the Proposition 2 cost argument)
Problem: §6.4 calls the per-atom checks closed-form and each "constant-time in the atom's operands". Exactness for mixed `starts_with`/`ends_with`/`contains`/`under` constraints without a finite value set is not shown, and is not obviously achievable in closed form.
Evidence: SPEC §9.5 gives sound but incomplete rules for that case. The M4 differential oracle will report the completeness rate.
What the implementation does: Sound but incomplete procedures for strings without a finite set; exact for ints, bools, and strings with a finite set (SPEC §9.5).
Suggested fix to the paper: Say that string implication is decided soundly but incompletely, or give the exact procedure.
Severity: clarity (soundness is preserved either way)
Status: open in revision 2026-09-29. §6.4 still calls the per-atom checks "closed-form", and the Proposition 2 cost argument is unchanged.
Measured at M4 (`docs/test-reports/policy-oracle-m4.json`, 150,000 cases per type, zero soundness violations):
- `implies` and `unsat` are complete, relative to the oracle, for int, bool, and strings with a finite set.
- For strings without a finite set they are not.
  - Against the SPEC enumeration: `implies` 0.841, `unsat` 0.743.
  - Against a richer enumeration (concatenations of up to three constants): 0.919 and 0.855.
- Most of the gap between the two is the SPEC enumeration being too small to show that a constraint is satisfiable, not a flaw in the procedure. What remains includes genuine misses, for example `ends_with "/" ∧ under "/a"`, which is unsatisfiable because canonical paths do not end in `/`. The procedure stays conservative there (D-57).

## P-09 — `allow all` ignores the audience clause
Paper location: §6.1, §6.3 ("The audience clause")
Problem: `allow all` permits any audience, tool and action. The mandatory `at` clause, which §6.3 presents as a protection, therefore does not constrain a scope written in this form. A pinned `allow all` policy authorizes invocations at every verifier that pins it.
Evidence: §6.3 decides `allow all` directly; §6.1 calls it "a reserved form used for top-level trusted contexts".
What the implementation does: As written.
Suggested fix to the paper: Say that `allow all` is audience-unrestricted and should not be pinned across partners, or give it an audience.
Severity: clarity
Status: resolved in revision 2026-09-29, as documentation. §6.1 now says that `allow all` "permits every audience as well as every tool and action, so the mandatory audience clause does not constrain it", and that it "is not meant to be pinned across organizations".

## P-10 — Receipt order, multiplicity and extra receipts are unspecified
Paper location: §4.3, §4.5; Algorithm 2 line 40
Problem: The paper does not fix the order of receipts inside the InvocationBody. It says nothing about two receipts for one approver, or about receipts from approvers the policy does not require. Line 40 ("the receipt … with R.approver_id = s") presumes uniqueness.
Evidence: §4.3: "one approval receipt for each approval service the policy requires (possibly none)".
What the implementation does: Receipts are sorted by `approver_id` with at most one per approver (D-15). Violations, and a present-but-empty list, are malformed (`L02`). Receipts from approvers that are not required are ignored (D-34).
Suggested fix to the paper: State the order and multiplicity, and say that extra receipts are ignored.
Severity: interoperability
Status: resolved in revision 2026-09-29. §4.5 fixes the order (by approver identifier, bytewise ascending) and multiplicity (at most one per approval service). A violation, or an empty receipts field, makes the body malformed, and receipts from approval services the policy does not require are ignored. This is D-14, D-15 and D-34 exactly.

## P-12 — Signing-service enforcement is unspecified
Paper location: §3.1, §3.2
Problem: The signing service "applies policy enforcement before signing", but the checks it performs are not specified. §3.2's adversary instructs it to sign "within the scope permitted by policy", which presumes some enforcement.
Evidence: §3.1, the signing-service description.
What the implementation does: A pluggable `EnforcementPolicy` hook, accepting by default (SPEC §8.2). The verifier's checks do not depend on it.
Suggested fix to the paper: Specify the minimum checks, or state that security never relies on the signing service's enforcement.
Severity: clarity
Status: open in revision 2026-09-29. §3.1 is unchanged. §5.2 now describes a signing service's own `signer` identity (P-24), but not what it checks before signing.

## P-14 — Line 41 has no reject clause
Paper location: Algorithm 2 lines 41–42
Problem: `Resolve(s, R.approver_pk)` can fail, and only line 42's "passes the phase-5 checks" covers that implicitly.
Evidence: Line 41 as printed.
What the implementation does: An unresolvable approver is rejected at line 42 (D-27).
Suggested fix to the paper: Add "reject if unresolvable" to line 41, as line 23 has.
Severity: clarity
Status: resolved in revision 2026-09-29. Line 41 now reads "cert_R ← Resolve(s, R.approver_pk); reject if unresolvable". D-27 was changed to match: an unresolvable approver is now `L41`, not `L42`.

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
Status: resolved in revision 2026-09-29.
- §6.1 adds "Well-formedness". Condition 1 reads "Every path its where clause mentions is declared in its params", which is D-28's rule.
- A malformed policy is rejected by LoadPolicy, and a malformed scope inside a body at line 2.
- §6.4's procedure also returns false on a malformed scope, as a defensive check.
- The Proposition 2 proof now invokes well-formedness in step 3(a) ("r1 is well-formed … so every path its clause mentions is declared and therefore present") and in the skip argument, where it adds the missing step: every path in r2′'s clause is present.
- The counterexample above is rejected as malformed under the revised text.

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
Status: resolved in revision 2026-09-29. Lines 18 and 20 compare identifier and key as pairs. §4.6 ("Public key chain consistency") explains that comparing identifiers ensures "the party that acts is the one that was named, even where one key is certified under more than one identifier". This matches D-36.

## P-17 — Line 27 omits the certificate's not-before time
Paper location: Algorithm 1 line 27; Algorithm 2 line 42; §5.2; §5.4; §5.5
Problem: Certificates carry a not-before timestamp (§5.2), and §5.4 and §5.5 speak of the certificate "valid at verification time". Line 27 rejects only "if cert_k is expired or revoked at t". Read literally, a certificate whose validity has not started is accepted. For example, the next certificate of a scheduled rotation could be used before its window opens.
Evidence: Line 27 as printed, compared with the certificate fields listed in §5.2.
What the implementation does: D-35. Line 27 rejects unless `t ∈ [nbf, exp]`, and rejects revoked serials. Line 42 applies the same window to approvers.
Suggested fix to the paper: "reject unless t ∈ [cert_k.nbf, cert_k.exp] and cert_k is not revoked at t".
Severity: soundness
Status: resolved in revision 2026-09-29. Line 27 reads "reject if cert_k is not yet valid, expired, or revoked at t", and §5.4 uses the same three words. This matches D-35, except that the boundary is not stated (P-26).

## P-18 — §5.4's resolution wording makes line 27 unreachable
Paper location: §5.4 ("Resolution returns the valid certificate …"); Algorithm 1 lines 23 and 27
Problem: If resolution returns only valid certificates, line 27 can fire only on a stale cache entry, and §5.4 already bounds cache entries by certificate expiry and evicts on revocation. The two texts disagree about where validity is checked.
Evidence: §5.4 against lines 23 and 27.
What the implementation does: Resolution returns the latest certificate binding (id, pk), valid or not, and line 27 decides (D-26). This keeps "unknown key" (`L23`) and "expired or revoked" (`L27`) distinguishable.
Suggested fix to the paper: Say that resolution returns the certificate for (id, pk), and that validity is checked at line 27.
Severity: clarity
Status: resolved in revision 2026-09-29. §5.4: "Resolution returns the most recently issued certificate binding that identifier to that key, whether or not it is currently valid", and validity is decided "at line 27 of Algorithm 1, not by the resolver". This is D-26 exactly.

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
Status: resolved in revision 2026-09-29. T5b has moved to §3.3.2 (bounded), with the bound stated: the namespace binding of §5.4 and pinning. §3.3 now says two families are split, T4 and T5. §7.3 addresses "the prevented part of the identity family (T5a, T5c, T5d)" and states T5b's bound separately. The §11.2 T5b row tests that bound.

## P-20 — "Leaves the verifier exactly as it found it" ignores caching
Paper location: §4.6 ("The only state the procedure changes is the nonce cache … A chain that fails any check therefore leaves the verifier exactly as it found it"); §5.4 (certificate and policy caches); Figure 2 caption
Problem: §5.4 has verifiers cache resolved certificates and fetched policies. Those caches fill during phases 5 and 6, including for chains later rejected. The decision-relevant state is unchanged, but the statement as written is false.
Evidence: §4.6 against §5.4.
What the implementation does: D-37. Caches fill during verification, and line 50 is the only mutation that can change a later decision. §11.3 checks that the caches never change one.
Suggested fix to the paper: "No state that affects any later decision changes until the final phase; caches may be populated."
Severity: clarity
Status: resolved in revision 2026-09-29. §4.6: "The only decision-relevant state the procedure changes is the nonce cache … Resolution and policy loading may fill caches (Section 5.4)", which affects cost but not outcomes. A failed chain "leaves the nonce cache exactly as it found it". The Figure 2 caption says the same. This matches D-37.

## P-21 — The cost model leaves out hash-to-G2
Paper location: §4.6 ("Cost")
Problem: "α is the dominant final exponentiation cost and β is the per-Miller-loop cost". But each of the N+1 messages on the right of Eq. (5) also needs one hash-to-G2, which grows with N and costs about as much as a Miller loop in current libraries. β is therefore at least one hash-to-G2 plus one Miller loop per hop. The constant term also includes the Miller loop of `e(g1, σagg)`.
Evidence: Eq. (5) needs `HashToG2(m_k)` for k = 0…N.
What the implementation does: Nothing needs implementing. Q3 fits end-to-end latency, and the M8 micro-benchmarks time hash-to-G2, the Miller loop and the final exponentiation separately, so each term can be attributed.
Suggested fix to the paper: Include hash-to-G2 in β.
Severity: clarity
Status: resolved in revision 2026-09-29. §4.6 ("Cost") now makes β "one hash to G2 plus one Miller loop", and α "the final exponentiation and the terms that do not grow with N". It no longer claims that the variation is small for N ≤ 10: "β cannot be assumed small relative to α … which dominates in practice is for the measurements of Section 8.3 to settle". SPEC §13.1 Q3 and §13.11 were updated to the new claim.

## P-22 — The approval cost is undercounted
Paper location: §4.5 ("approval verification adds a single pairing operation per approval")
Problem: Checking one BLS receipt means checking `e(g1, σ) = e(pk, HashToG2(m))`: two pairings sharing one final exponentiation, plus a hash-to-G2. §4.6 counts pairings the same way ("N + 2 internal pairings" for N + 1 signers).
Evidence: §4.5 against §4.6.
What the implementation does: Nothing needs implementing. The medium-approval profile measures the cost.
Suggested fix to the paper: "adds one signature verification (two pairings sharing a final exponentiation) per approval".
Severity: clarity
Status: resolved in revision 2026-09-29. §4.5 now counts, per receipt, "a hash to G2 and a two-pairing check (two Miller loops and one final exponentiation)", and Figure 2 says "two-pairing check each".

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
Status: resolved in revision 2026-09-29. §6.1 adds `string-value ::= string` to the grammar, and a "Lexical details" paragraph that defines integers, strings, booleans, `letter` and `digit` (D-08, D-17). Well-formedness condition 2 gives a typing table for atoms that matches D-20. The paper also adds that string literals are NFC-normalized (D-17, D-55).

## P-24 — The `signer` kind has no role in verification
Paper location: §5.2 (kinds); §3.1 (the signing service "holds an agent's private key"); Algorithm 1 line 26; Algorithm 2 line 42
Problem: The signing service signs with the agent's key, which is certified as `agent`. `role(k)` is `issuer` or `agent`, and receipts require `approver`. No check accepts a `signer` certificate, so what one certifies, and why §5.2 gives signing services certificate lifetimes, is unclear.
Evidence: §5.2 and §3.1 against lines 26 and 42.
What the implementation does: The registry issues `signer` certificates (D-09), and the verifier never accepts one; one at any position fails line 26.
Suggested fix to the paper: State what a signer certificate is for (for example, the service's own identity for audit), or drop the kind.
Severity: clarity
Status: resolved in revision 2026-09-29. §5.2: the `signer` kind "identifies a signing service in its own right, for operational authentication outside this protocol", and "no position in a chain, and no receipt, accepts a signer certificate".

## P-25 — The session's `iat` is never checked
Paper location: §4.3 (session "issue and expiry timestamps"); Algorithm 1 lines 13–15
Problem: Algorithm 1 checks only `t ∈ [B_N.nbf, B_N.exp]` and that expiry does not grow along the chain. A session whose `iat` is in the future is usable immediately, and a delegation cannot be post-dated. The issuer signs `iat`, so it cannot be forged, but the paper does not say whether it constrains validity.
Evidence: Lines 13–15.
What the implementation does: As written: `iat` is carried and signed, but not checked.
Suggested fix to the paper: Say that `iat` is informational, or check `t ≥ B0.iat`.
Severity: clarity
Status: resolved in revision 2026-09-29. §4.3: "The issue timestamp is informational. No check in the verifier depends on it, since, like every timestamp a signer supplies, it is not evidence of when signing happened." Delegation bodies still have no not-before time; the paper does not treat that as a gap, and neither do we.

## P-26 — Line 27 does not say whether a certificate is valid at t = exp
Paper location: Algorithm 1 line 27 and §5.4 (revision 2026-09-29)
Problem: "not yet valid, expired, or revoked at t" does not say whether validity is closed at `nbf` and at `exp`. The other time checks are explicit closed intervals: line 13 (`t ∉ [B_N.nbf, B_N.exp]`) and line 44 (`t ∉ [R.iat, R.exp]`). Two implementations could disagree about a chain verified exactly at a certificate's `exp`.
Evidence: Line 27 against lines 13 and 44.
What the implementation does: Treats validity as the closed interval `t ∈ [nbf, exp]`, consistent with lines 13 and 44 (D-35). A test covers both boundaries.
Suggested fix to the paper: "reject unless t ∈ [cert_k.nbf, cert_k.exp] and cert_k is not revoked at t".
Severity: interoperability
Status: open in revision 2026-09-29, where it was introduced by the rewording of line 27.

## P-27 — Remark 1 understates where the containment procedure is incomplete
Paper location: §6.4, the containment procedure (steps 3(a) and 3(b)) and Remark 1 (revision 2026-09-29)
Problem: Remark 1 attributes the incompleteness to step 3(a): "a child rule covered only by the union of several parent rules is rejected". Two other sources exist, and Remark 1 names neither.
- **Dead child rules.** Step 3(a) requires every rule of S2 to have a subsumer. That includes a rule that can never decide an invocation, because its clause is unsatisfiable or because earlier rules of S2 catch everything it matches. When S1 has no same-head rule with an approval requirement weak enough, `Contains` returns false, although the rule is harmless.
- **Step 3(b).** The skip test requires the whole of r′'s clause to imply a single earlier child rule's clause. It would suffice that the invocations matched by both r′ and r2 are decided by earlier child rules.
Evidence: `docs/test-reports/policy-oracle-m4.json`, `misses_by_cause` (150,000 generated pairs, seed 56324). A miss is a pair the bounded oracle judges contained but `Contains` rejects.
- Of the 4176 misses:
  - 4138 have an unsatisfiable child rule;
  - 23 have a child rule fully shadowed by earlier child rules;
  - 11 are step 3(b), in every case with the joint region decided by earlier child rules;
  - 3 are string implication;
  - 1 is a union of rules.
- Pairs whose S2 has no unsatisfiable rule reach completeness 0.999 (36156/36188).
- The proportions reflect the generator. It draws atoms independently, which often produces contradictory rules, and it derives children by mutations that rarely split one rule into several. The numbers therefore show that each source exists, not how often each arises in real policies.
What the implementation does: The procedure as written, which is sound. The oracle reports the causes (D-58).
Suggested fix to the paper: Extend Remark 1 to name dead child rules and step 3(b)'s single-rule, whole-clause skip test. Whether to refine the procedure, for example by skipping child rules whose clause is unsatisfiable, is for the author to decide.
Severity: clarity (soundness is unaffected)
Status: open in revision 2026-09-29.

## P-28 — Cold verifiers pair before phase 8, because of line 24
Paper location: §4.6 ("Figure 2 shows why the order matters … only a chain that has survived every structural, temporal, and policy check reaches the pairing computation"); Figure 2 and its caption; Algorithm 1 line 24 (revision 2026-09-29)
Problem:
- Line 24 verifies each signer's certificate under its registry root. With BLS roots, the paper's own scheme, that is a two-pairing check (hash-to-G2, two Miller loops, one final exponentiation).
- Phase 5 precedes phase 6, so on a cold verifier a chain rejected by the policy checks (lines 30–37), and any chain that reaches phase 5, has already cost N + 1 pairing checks.
- Figure 2 lists pairings only for phase 7 (receipts) and phase 8 (the aggregate).
- The inputs this needs are public: bodies naming real identities and their certified keys, with any aggregate. So an adversary can make a cold verifier resolve and pair for every such chain.
- A warm verifier, with the certificates cached, does not pair before phase 7, as Figure 2 says.
- How much an adversary can force (added at the M6 checkpoint):
  1. Certificate verifications are cached per binding once line 24 passes, for min(exp, 1 hour). An adversary naming real identities therefore forces at most one line-24 pairing check per distinct certified binding per cache lifetime, and at most N + 1 per chain.
  2. Failures are not cached. An adversary on the resolution channel, one that can make resolution return a certificate of its choosing for (identifier, key), can feed a certificate for that binding with an invalid signature and force a line-24 pairing on every attempt, up to N + 1 per chain. A certificate for another binding is rejected at line 23 before any pairing (D-60). The implementation does not cache negative results; this is documented, not fixed.
- SPEC §13.11's verdict on the phase-ordering claim is given separately for warm and cold verifiers.
Evidence: `tests/security.rs::phase_ordering_count_ops`, with `count-ops`.
- A cold verifier rejects a line-34 chain with N = 2 after 3 signature verifications, 3 hash-to-G2, 6 Miller loops and 3 final exponentiations, all from line 24.
- A warm verifier rejects the same chain with 0 pairings and 0 resolver calls.
- The expired and wrong-audience chains are rejected with 0 pairings and 0 resolver calls, cold or warm.
What the implementation does: The algorithm as written. The test asserts the actual counts (D-61).
Suggested fix to the paper: State that the cheap-checks-first ordering bounds pairing work only for cached certificates. Account for line 24's verifications in Figure 2 (phase 5: "may query registry and verify certificates"). Note the cold-path cost in §8.2.
Severity: clarity (a performance and denial-of-service claim; soundness is unaffected)
Status: open in revision 2026-09-29.

## P-29 — Revocation by serial, "most recent certificate" resolution, and caching disagree when a key is renewed
Paper location: §5.4 (resolution returns the most recently issued certificate for an identifier and key; a revocation "immediately evicts the corresponding cached entry"); §5.6 (a revocation assertion names one certificate, by serial); §5.5 (revision 2026-09-29)
Problem:
- When a registry renews a certificate for the same key, one identifier–key binding has two unexpired certificates. That is the usual practice with short lifetimes.
- A revocation assertion names one serial. If it names the renewal, resolution (which returns the most recent certificate) yields the revoked certificate, and a verifier that resolves afresh rejects.
- A verifier that cached the older certificate still holds it. Eviction touches only the revoked serial, so it keeps accepting chains under that key until the older certificate expires or its cache TTL ends.
- Caching therefore changes outcomes: §4.6 says caches change cost, "not, within the propagation bound of Section 5.6, their outcome", and this can last up to the one-hour TTL.
- More generally, revoking one certificate does not revoke a compromised key that other certificates still bind.
Evidence: `tests/cache_equivalence.rs::renewal_of_the_same_key_then_revocation_diverges`. The uncached verifier returns L27; the warm verifier accepts. The SPEC §11.3 equivalence run, whose events are revocations, expiry, new pins and new-key rotations, never renews a key, and found no divergence in 10,000 chains.
What the implementation does: Since D-65, the first option below, ahead of the paper: a revocation assertion names the binding (identifier and key) and keeps the serial for audit. Lines 27 and 42 reject any certificate of a revoked binding, eviction is by binding, and a registry refuses to certify a revoked binding. The probe test became two equivalence tests in which both verifiers reject at L27: `renewal_then_revocation_of_the_newer_certificate_rejects_in_both`, and its mirror `renewal_then_revocation_of_the_older_certificate_rejects_in_both`. Under serial revocation, the mirror case accepted even uncached. The §11.3 run now includes same-key renewal and renewal followed by revocation of either certificate (`docs/test-reports/cache-equivalence-d65.json`: 10,000 chains, no disagreement). Before D-65 the implementation followed the paper and the divergence was recorded by the probe.
Suggested fix to the paper: Author to decide. Options:
- revoke by identifier and key rather than by serial (implemented, D-65);
- require a registry to revoke every unexpired certificate of a binding when it revokes one;
- forbid renewing a binding while an unexpired certificate for it exists;
- have verifiers evict every cached entry for the binding a revoked serial belongs to. This needs the assertion to name the binding.
Severity: soundness (a revoked renewal can leave the key accepted by caching verifiers; bounded by the cache TTL and the older certificate's expiry)
Status: resolved ahead of the paper (D-65). Open in revision 2026-09-29, whose §5.6 still revokes by serial.

## P-30 — "Most recent certificate" resolution and caching disagree on a renewal that does not cover the older certificate's window
Paper location: §5.4 (resolution returns the most recently issued certificate for an identifier and key, "whether or not it is currently valid"; certificate cache TTL min(exp, one hour)); §4.6 (caches change cost, "not, within the propagation bound of Section 5.6, their outcome"); Algorithm 1 line 27 (revision 2026-09-29)
Problem:
- A same-key renewal gives one binding two certificates, and resolution returns the newer one even when it is not valid at t (D-26, adopted by the paper).
- **Future-dated renewal** (nbf after now):
  - an uncached verifier rejects at line 27 until the renewal's nbf, although the older certificate is valid and unrevoked;
  - a verifier that cached the older certificate accepts.
- **Shortening renewal** (exp before the older certificate's exp):
  - once the renewal expires, the uncached verifier rejects;
  - a verifier caching the older certificate accepts until its cache entry ends, which is at most one hour and no later than the older certificate's exp.
- In both cases the caches change outcomes, contrary to §4.6. The problem does not involve revocation, so D-65 does not fix it.
- Without any cache, a pre-issued renewal shadows the older, valid certificate: the binding cannot be used until the renewal's nbf. Pre-issuing renewals before expiry is common practice.
Evidence: `tests/cache_equivalence.rs::future_dated_renewal_diverges` and `::shortening_renewal_diverges`. In both, the uncached verifier rejects at L27 and the warm verifier accepts.
What the implementation does: The paper as written (D-26); the probe tests record the divergence.
- The §11.3 run renews from the current time with the registry's default lifetime (24 hours). Every earlier certificate was issued earlier with a lifetime of at most 24 hours, so those renewals never shorten or defer a binding's validity, and the caches are transparent for them.
- Future-dated and shortening renewals are left out of the run, and this entry is the record of why.
Suggested fix to the paper: Author to decide. Options:
- resolution returns the most recent certificate valid at t if there is one, and otherwise the most recent certificate, so line 27 still fires for expired or not-yet-valid bindings;
- require renewals to be monotone: nbf no later than issuance, and exp no earlier than that of every unexpired certificate for the binding. This rules out pre-issued renewals;
- state the exception in §4.6.
Severity: liveness and clarity. The warm verifier accepts only under a certificate that is valid and unrevoked. The uncached verifier rejects a binding that has one. The §4.6 claim that caches do not change outcomes is false for these renewals.
Status: open in revision 2026-09-29.
