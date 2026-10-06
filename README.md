# DelegationChain: reference implementation and benchmark

This repository contains two things:
- the reference implementation of DelegationChain, the protocol specified in _DelegationChain: Parameter-Bound Delegation Chains for Cross-Organizational Agent Authorization_ ([docs/paper.pdf](docs/paper.pdf));
- the benchmark behind the paper's evaluation.

- **The implementation** follows paper §4–§6 and Algorithms 1–2. It covers:
  - canonical encoding, token bodies and the chain envelope;
  - the identity registry, with proof-of-possession and revocation;
  - the policy language and its containment procedure;
  - chain construction and the verifier.

  Its default instantiation is Ed25519, one signature per hop. BLS aggregation (paper §4.8) is a variant behind a feature flag.
- **The security suite** ([tests/security.rs](tests/security.rs)) covers the paper's threats and theorems. Each test asserts the Algorithm line that rejects. The suite runs over both instantiations.
- **The benchmark** ([crates/dc-bench](crates/dc-bench)) asks whether BLS aggregation is a net benefit for per-invocation verification once caching is taken into account. It compares aggregation with per-hop Ed25519 and other baselines ([BENCH_PLAN_FROZEN.md](BENCH_PLAN_FROZEN.md) §2). The plan was frozen before anything was measured.

## Where to start

- **For the results, read [BENCHMARKS.md](BENCHMARKS.md).** Its summary comes first. `dc-bench` generates every number in it from the measurement data; none is typed by hand.
- **To reproduce them, read [ARTIFACT.md](ARTIFACT.md).** It explains how to:
  - fetch and verify the archived measurements;
  - regenerate BENCHMARKS.md and every table and figure in the paper's evaluation;
  - re-measure.

  The benchmark was measured while BLS aggregation was still the protocol's default. To re-measure under the frozen plan, use the commits named in ARTIFACT.md §5, not the current one.
- **For the protocol, read [docs/paper.pdf](docs/paper.pdf).** It is the source of truth: where SPEC.md disagrees with it, the paper wins.

To build and test (the toolchain is pinned by [rust-toolchain.toml](rust-toolchain.toml)):

```sh
cargo test --workspace                                      # the default instantiation, Ed25519 per hop
cargo test -p delegationchain --features aggregate-variant  # the workspace suites over the BLS aggregate variant
scripts/ci.sh                                               # all checks: the local equivalent of the CI workflow
```

| Path | Contents |
| --- | --- |
| `crates/dc-cbor` | Strict deterministic CBOR subset |
| `crates/dc-types` | Identifiers, bodies, certificates, receipts, wire format, digests |
| `crates/dc-crypto` | Signature schemes: Ed25519 per hop; BLS behind the `variant-bls` feature |
| `crates/dc-registry` | In-memory registry, proof-of-possession, certificates, revocation, resolution, policy store |
| `crates/dc-policy` | Policy language: parser, validation, evaluation, containment |
| `crates/dc-chain` | Issuer, signing service, approval service, chain builder |
| `crates/dc-verifier` | Algorithms 1–2, line by line; caches; nonce cache |
| `crates/dc-baselines` | Benchmark-only arms; nothing here is on the protocol path |
| `crates/dc-bench` | Benchmark harness, workloads, report and paper-artifact generators |
| `tests/` | Workspace-level suites: security, cache and prefix-cache equivalence, concurrency, the benchmark arms |
| `fuzz/` | Fuzz target and seed corpus for the CBOR decoder |
| `results/` | The raw measurements as zstd archives, with their manifests; machine records, bytes, memory and the generated summary. Criterion's output is `criterion.tar.zst` at the root |
| `paper/` | The paper's tables and figures, as generated |
| `docs/` | The paper, its section map, and test reports |
| `scripts/` | Plotting, CI and checks |

## How it was built

The paper's author wrote and directed the specification, [SPEC.md](SPEC.md), with model assistance. Claude Code, Anthropic's coding agent, wrote the implementation, the tests and the benchmark harness from it. It reported to the author at checkpoints, and every commit carries its `Co-Authored-By` trailer.

At the checkpoints, the author:
- answered the questions that blocked a milestone;
- approved the frozen benchmark plan and each deviation from it;
- decided the changes to the specification.

The SPEC.md changelog, MILESTONES.md and QUESTIONS.md date each of these.

## The audit trail

These files are kept as they stood at the end of the work, with no edits for release:

| File | What it records |
| --- | --- |
| [SPEC.md](SPEC.md) | The specification Claude Code worked from. It covers every engineering choice the paper leaves open, the test plan and the benchmark plan. Its changelog dates each change agreed with the author. |
| [DECISIONS.md](DECISIONS.md) | Every open choice, as numbered entries D-01 onward. Each entry gives what was chosen, why, the sections it implements, and whether it affects the benchmark. |
| [PAPER_ISSUES.md](PAPER_ISSUES.md) | Every problem the work found in the paper (P-xx), with its evidence, what the implementation did, and its status in each paper revision. |
| [MILESTONES.md](MILESTONES.md) | The progress log, session by session: what each milestone did, what was verified, and what was not. |
| [QUESTIONS.md](QUESTIONS.md) | The questions that blocked a milestone, and the author's answers. |
| [BENCH_PLAN_FROZEN.md](BENCH_PLAN_FROZEN.md) | The benchmark plan fixed before any measurement (tags `bench-freeze` and `bench-freeze-2`): arms, workloads, grid, statistics and verdict rules. |
| [BENCH_LOG.md](BENCH_LOG.md) | Everything that happened to the benchmark after the freeze, with reasons. It holds the two amendments made before measurement, the deviations made after it, the throttling re-runs the harness logged itself, a report correction, and the exploratory runs outside the frozen plan. |
| [CLAUDE.md](CLAUDE.md) | The standing instructions Claude Code read at the start of every session. |

They are not tidied because they are the evidence for how the results were produced:
- the benchmark plan was fixed before any measurement;
- the record shows what changed afterwards, and why;
- it shows how each choice the paper left open was made;
- it shows where the implementation found problems in the paper.

Editing these files for presentation would rewrite that record after the fact. As a result, they read as working documents:
- SPEC.md and CLAUDE.md are addressed to Claude Code.
- They cite earlier paper revisions. SPEC.md §12–§13 cite revision 2026-09-29, against which the benchmark was frozen. [docs/paper-sections.json](docs/paper-sections.json) maps its section numbers to the current revision.
- They use internal identifiers: D- for decisions, P- for paper issues, Q- for questions, M0–M10 for milestones.

Read them as dated records. A later entry can supersede an earlier one, and where anything conflicts with the paper, the paper wins (SPEC.md §2). Git history has every change made to them.

## License

The code in this repository is licensed under the Apache License, Version 2.0 ([LICENSE](LICENSE)).

The measurement data is licensed under the Creative Commons Attribution 4.0 International license (CC-BY-4.0): the zstd archives under `results/` and `criterion.tar.zst`, in this repository and in the Zenodo deposit.
