# Questions

Open questions that block a milestone (SPEC §0 rule 11). Each entry records the milestone it blocks, the question, and how it was answered.

### Q-02 — Blocks step 3 (reconciliation and the flip of defaults): which paper is the rewrite?
Asked 2026-10-04. The author asked for step 3 against "the rewritten paper" in `docs/paper.pdf`: commit it, reconcile §4–§7 and Algorithms 1–2, and make Ed25519 per-hop the protocol path with BLS aggregate a variant. The file now in `docs/paper.pdf` (dated October 4, 2026; 45 pages; sha256 `d4fd47d665928acf9bce28431d7c4a8f459b61072cc77d63565d0bd6d012d60a`; uncommitted) does not match that description.
- **Its protocol is still BLS aggregate.** The abstract, §4.2 and Algorithm 2's phase 8 (the aggregate multi-pairing) are unchanged in substance. Ed25519 appears four times, as in revision 2026-09-29.
- **Its §8 is unchanged.** It has no `\pending` placeholder, and the abstract still says that no empirical evaluation exists.
- **What did change.** 29 changes against revision 2026-09-29, all small:
  - line 27 checks a closed interval and a revoked binding;
  - the cold-path pairings (P-28): Figure 2's phase 5 label, §4.6's argument, and a §8 paragraph;
  - revocation by binding (P-29), in §5.5;
  - the string implication and satisfiability checks are stated as sound but incomplete (M4's oracle);
  - Table 1 moved.

**Question.** Is this the intended file? If so, the flip contradicts it: the paper wins (CLAUDE.md), so its protocol path stays BLS aggregate. If not, which PDF is the rewrite? Until this is answered, the file is not committed and step 3 has not started.

## Answered

### Pre-M0 review (2026-09-28)
Answered by the author the same day. The answers are recorded in the SPEC changelog and as D-28 to D-47.

### Q-01 — Blocked M4: revised paper not yet in `docs/`
Asked 2026-09-29, after M3. **Resolved 2026-09-29:** the author placed revision 2026-09-29 (44 pages, sha256 `51eff0ec620940c3062de303f671f5ddeee9907ddb3c06c46e19fc1b6da84e14`) in `docs/paper.pdf`. It was reconciled before M4 began (MILESTONES.md).
