# Frozen benchmark plan

**Status: DRAFT for the author's approval (M8 checkpoint).** It is not frozen and not tagged. Once approved, it is committed and tagged `bench-freeze` (SPEC §13.9), and from then on any deviation is logged in `BENCH_LOG.md` and repeated in `BENCHMARKS.md` under "Deviations from the frozen plan".

The grid, counts and seeds below are those of `crates/dc-bench/src/plan.rs`, which the harness runs; `cargo run --release -p dc-bench -- plan` prints them. The workloads are those of `crates/dc-bench/src/workload.rs` (D-71).

## 1. The question

Is BLS aggregation a net benefit for DelegationChain once caching is accounted for? "No" is an acceptable answer and will be reported as such.

The answer rests on two comparisons, decided by the rules in §6:
- **The deployment pattern:** arm B (BLS aggregate with pairing and prefix caches) against arm D (Ed25519 with prefix cache), warm+prefix. One delegation carries many invocations here, and paper §8.3 says a comparison without caching "would not reflect how verifiers are built".
- **Every call a new chain:** arm A (the protocol) against arms C and C-batch, warm.

## 2. Arms

| Arm | What | Build |
|---|---|---|
| A | The protocol: 1 BLS aggregate, `aggregate_verify` | default (`blst` `no-threads`) |
| A-ind | N+1 BLS signatures, N+1 single verifications | default |
| B | A's wire format; pairing cache (§5.7) and prefix cache (§12.1, D-67) | default |
| C | N+1 Ed25519 signatures, `verify_strict` each | default |
| C-batch | As C, one `verify_batch`; different edge semantics (D-66) | default |
| D | As C, prefix cache: σ_N alone on a hit (§12.1) | default |
| E | Biscuit (biscuit-auth 6.0.0), a positioning reference with functional gaps (D-68) | default |
| A-mt | A with `blst`'s thread pool. **Supplementary, Q1 only, never in a headline ratio or Q6** | `--no-default-features`, `target/a-mt` (D-29) |

A, A-ind, C and C-batch run the same generic verifier; only line 49 and the base scheme's signatures differ (SPEC §12). Registries use the arm's base scheme.

## 3. Workloads (seed `0xDC_2026_0929`; D-71)

- **Parties.** Issuer, finance approver and 12 agents in `orga`; 12 agents in `orgc`; the services in `orgb`. Hops alternate between `orga` and `orgc` agents; no identity repeats within a chain; the warm-up covers every agent at every position (D-40).
- **small.** 1 rule, 2 parameters, 1 atom. Identity delegations. The invocation is a 500 transfer.
- **medium.** The paper's §6.2 policy verbatim. Each hop tightens one bound (odd hops rule 1 by 10, even hops rule 2 by 1,000). The invocation hits rule 1 (500, no approval).
- **medium-approval** (N = 3 only). As medium, with an invocation of 5,000 that hits rule 2 and carries 1 finance receipt.
- **large.** 16 rules × 4 parameters × 3 atoms, over 2 services and 4 tools.
  - 2 approval rules, each before the permissive rule it overlaps.
  - Hops 1–6 drop 2 rules each, in a seeded order that never drops an approval rule or the target; from 4 rules on, hops only tighten (D-38).
  - Every hop tightens the target's size bound. The invocation matches only the last rule.
- **Time.** Every chain is issued and verified at T0 = 1,790,000,000. Bodies live 3,600 s, the invocation window is 600 s, and certificates last 24 h.
- **Nonces.** Every chain carries a unique nonce, so the nonce cache sees a realistic stream, and line 50's insert is inside the timed call.

## 4. Grid and iteration counts

N ∈ {1, 2, 3, 5, 10}; profiles small, medium and large, plus medium-approval at N = 3. That is 16 cells per (arm, state).

| Arm | States | Cells | Warm-up / measured per configuration |
|---|---|---|---|
| A, A-ind, C, C-batch | cold, warm | 16 each | 1,000 / 10,000 |
| B, D | warm+prefix, prefix-miss | 16 each | 1,000 / 10,000 |
| A-mt | warm | 16 | 1,000 / 10,000 |
| E | stateless | 15 (no medium-approval: Biscuit has no receipts) | 1,000 / 10,000 |
| A, C (Q5) | cold with 0 / 1 / 20 / 80 ms per resolver or policy-store call, N = 3, medium | 4 each | 1,000 / 10,000; 100 / 2,000; 20 / 300; 20 / 200 (D-44) |

That is 231 latency configurations per run.

### States (SPEC §13.5)

- **cold.** A new verifier with empty caches, built before each call, outside the timer.
- **warm.** Caches are filled by the configuration's 1,000 warm-up chains, which are separate chains from the same organizations, policies and identity pools.
- **warm+prefix.** 10 prefixes × 1,100 invocations, round-robin. The first 100 per prefix are warm-up, including the miss that fills the entry; the other 1,000 per prefix are measured (D-39). Every measured call must be a hit.
- **prefix-miss.** Every chain has a new prefix; the caches are otherwise warm. Every measured call must be a miss.
- **stateless.** Arm E.

### Other measurements

- **Q6 (throughput).** Arms A, B, C and D; medium, N = 3; threads 1, 2, 4, 8, 10 and 14. 14 is labelled "includes efficiency cores" (D-43).
  - 100 prefixes × 1,000 invocations, after 1,000 warm-up chains.
  - One shared verifier per (arm, threads).
  - Reported: wall time, accepted/s, and p99 per call under load.
- **Q2 (bytes).** Every arm, N and profile, from 20 sampled chains per cell. Also the certificate size in this encoding, and each chain's size with N+1 certificates carried inline (§13.7).
- **Q10 (memory).** 100,000 entries each: the nonce cache (both key sizes), the certificate cache (BLS and Ed25519) and the prefix cache (B and D at N = 3, medium). Measured with `stats_alloc`, by difference (D-41, D-72).
- **Q7, Q8, primitives.** Criterion 0.5.1 with default settings (100 samples; 3 s warm-up; 5 s measurement), one pass per full run (D-73):
  - BLS: sign, verify, `aggregate_verify` over 2–11 messages, the hash-to-G2 proxy, the Miller loop, the final exponentiation;
  - Ed25519: sign, `verify_strict`, `verify_batch` over 2–11;
  - CBOR encode and decode per body type, and SHA-256 chain digests;
  - Evaluate and Contains for rules ∈ {1, 4, 16, 64} × atoms ∈ {1, 4, 8}, typical and worst case;
  - signing costs (per hop, aggregate add, receipt, issuance) for both schemes.

## 5. Method

- **Isolation.** Every chain is generated before measurement starts. Each timed operation is exactly one `verify(&bytes)` call, timed with `Instant` and recorded in nanoseconds; every sample goes to CSV. Any rejection, or any unexpected hit or miss, aborts the run (D-72).
- **Runs.** 3 full runs, each in its own process, each preceded by chain generation and a 30 s settle. Configurations run in a random order per run, seeded by the order seeds `0xdc2dc30928`, `0xdc2dc3092b` and `0xdc2dc3092a` for runs 1–3. A-mt runs in its own process after each main run.
- **Build.** Release profile per SPEC §3.3 (`lto = "fat"`, `codegen-units = 1`, `panic = "abort"`), with `RUSTFLAGS="-C target-cpu=native"` for all arms; `env.json` records the flags. Rust 1.97.1. The measurement-affecting crates are pinned exactly (D-47): blst 0.3.17, ed25519-dalek 2.2.0 (curve25519-dalek 4.1.3), sha2 0.10.9, biscuit-auth 6.0.0.
- **Machine** (D-45): Apple M4 Max, 10 performance + 4 efficiency cores, macOS.
  - No governor or turbo control, and no core pinning. Every measuring thread sets QoS user-interactive (D-42), and the harness records whether that succeeded.
  - **Full runs need AC power** and an otherwise idle machine. `env.json` records the power source and power mode. The M8 dry run ran on battery; it is not reported.
- **One command.** `RUSTFLAGS="-C target-cpu=native" cargo run --release -p dc-bench -- all` produces `results/raw/*.csv`, `env.json`, `bytes.json`, `memory.json`, `summary.md`, `summary.json` and `plots/`.

## 6. Statistics and decision rules (SPEC §13.6)

- **Per configuration.** Median, mean, SD, p95, p99, min and max, with a bootstrap 95% CI for the median (10,000 resamples, seeded per configuration). Samples are pooled over the 3 runs, and each run's median is reported for run-to-run variation.
- **Ratios.** Ratios of medians, with a paired-draw bootstrap CI.
  - **A ratio is "lower" or "higher" only if its whole 95% CI lies below or above 1.** Otherwise the comparison is reported as no detectable difference.
  - A run-to-run spread larger than the effect is reported alongside the result.
- **Q3.** OLS over the per-N medians of arm A (warm and cold, per profile). α, β and 10β/α come with bootstrap CIs, plus R² and residuals.
  - The per-hop term is said to dominate by N = 10 if 10β/α's CI lies above 1, the fixed term if it lies below, and neither otherwise. The crossover is N = α/β.

### Primary outcomes

- **Q1.** Warm median latency. The headlines are at N = 3, medium:
  - **B/D (warm+prefix)**, the deployment pattern: this answers §1;
  - **A/C and A/C-batch (warm)**: every call a new chain.

  Also reported: the same ratios at every N and profile, B/D in prefix-miss, and cold latency.
- **Q2.** Bytes per chain by arm, N and profile, with the signature share, and the bytes aggregation saves (A against A-ind).

### Verdict on §1

- **Net benefit:** B/D's CI lies below 1 at N = 3, medium.
- **Not a net benefit:** it lies above 1.
- **Inconclusive:** it straddles 1.

The verdict is repeated for each N and profile, then for A against C and C-batch; the bytes (Q2) are reported beside it. If the latency and bytes answers disagree, both are stated; neither is traded against the other.

## 7. Paper claims to check (SPEC §13.11; a verdict for each)

| Claim | Paper | Check |
|---|---|---|
| Aggregation gives significant constant-factor savings over independent verification | §2.2 | Q4: A/A-ind, warm and cold, every N ≥ 2 |
| Cost ≈ α + βN, with β one hash to G2 plus one Miller loop per hop; which term dominates is left to measurement | §4.6 | Q3 (fit, R², residuals, 10β/α); β compared with the hash-to-G2 proxy plus the Miller loop from the micro-benchmarks |
| A chain carries a constant 96-byte signature regardless of N | §2.2, §4.3 | Q2: arm A's signature bytes at every N |
| Carrying certificates inline costs more per hop than aggregation saves | §8.2 | Q2: the certificate size against the 96 bytes per hop A saves over A-ind |
| In the steady state, verification touches no registry | §8.2 | `count-ops` in the warm state (§11.2 tests), and Q5's call counts |
| Cheap checks reject hostile chains before any pairing | §4.6, Figure 2 | `count-ops` ordering tests. **Separate verdicts for warm and cold verifiers** (P-28, D-61) |
| The case for aggregation must be settled against a non-aggregating baseline | §4.6, §8.3 | Q1: A and B against C, C-batch and D |

Verdicts are supported, not supported, or partially supported, each with its numbers. If no check contradicts the paper, the report says explicitly that each one was checked.

## 8. Threats to validity, known before the run

- **P-28.** A cold verifier pays N+1 certificate pairings at line 24; the cold rows include them.
- **P-30.** Caches can change outcomes on non-monotone renewals. The workloads have none.
- **D-66.** C-batch's semantics differ from C's at the edges.
- **D-67.** Prefix entries live no longer than the certificate cache TTL; SPEC §12.1 gives no such bound. It binds nothing in these runs, which take far less than an hour of verifier time.
- **Rust-only flags.** `target-cpu=native` reaches the Rust arms but not `blst`'s C and assembly (§3.3).
- **Arm E** lacks resolution, PoP, revocation, receipts, nonces and parameter binding. It is compared with AIP's published figures only as labelled reference numbers from other hardware, not re-checked against arXiv:2603.24775 (§13.10).
- **Machine.** No pinning or frequency control on macOS; the timer is `mach_absolute_time`.
- **Q5.** Injected sleeps are "at least" the delay.

## 9. Not in this plan

Numbers from the M8 dry run (`results/dry-run/`, not committed) are never reported. The dry run's only purpose was to show that the pipeline completes.
