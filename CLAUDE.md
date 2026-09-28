# DelegationChain — reference implementation and benchmark

- The specification is SPEC.md. The protocol source of truth is docs/paper.pdf. Where they conflict, the paper wins; log it.
- Before starting any work, read SPEC.md §0 (rules of engagement) and the section for the milestone you are on.
- Progress lives in MILESTONES.md. Read it first to see where the last session stopped.
- Non-negotiable:
  - Implement the paper as written. Record every open choice in DECISIONS.md and every paper problem in PAPER_ISSUES.md.
  - VARIANT code stays in dc-baselines or behind feature flags, never on the default protocol path.
  - Never tune the benchmark toward any arm. Never type a measured number by hand.
  - Never weaken, ignore, or delete a failing test without logging why.
  - Report results that contradict the paper. That is a successful outcome, not a bug to engineer away.
- Commands: `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`.
