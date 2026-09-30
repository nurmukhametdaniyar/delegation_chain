# Frozen benchmark plan

**Status: approved by the author at the M8 checkpoint (2026-09-30), with the changes requested there. Frozen at the tag `bench-freeze-2`** (SPEC §13.9). That is the plan first frozen at `bench-freeze`, plus two amendments the author made before any measurement existed: the calibration probe in §5, and the corrected §8 line on D-67. Both are logged in `BENCH_LOG.md`. The tag `bench-freeze` stays where it was. From `bench-freeze-2` on, any deviation is logged in `BENCH_LOG.md` and repeated in `BENCHMARKS.md` under "Deviations from the frozen plan".

The grid, counts and seeds below are those of `crates/dc-bench/src/plan.rs`, which the harness runs; `cargo run --release -p dc-bench -- plan` prints them. The workloads are those of `crates/dc-bench/src/workload.rs` (D-71).

## 1. The question

Is BLS aggregation a net benefit for DelegationChain once caching is accounted for? "No" is an acceptable answer and will be reported as such.

The answer rests on two comparisons, decided by the rules in §6 (a ±10% margin, and agreement of all three runs):
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
- **Q2 (bytes).** Arms A, A-ind and C (whose wire format C-batch and D share) at every N from 1 to 10, in every profile including medium-approval; arm E on the grid's N. 20 sampled chains per cell. Also the certificate size in this encoding, and each chain's size with N+1 certificates carried inline (§13.7).
- **Q10 (memory).** 100,000 entries each: the nonce cache (both key sizes), the certificate cache (BLS and Ed25519) and the prefix cache (B and D at N = 3, medium). Measured with `stats_alloc`, by difference (D-41, D-72).
- **Q7, Q8, primitives.** Criterion 0.5.1 with default settings (100 samples; 3 s warm-up; 5 s measurement), one pass per full run (D-73):
  - BLS: sign, verify, `aggregate_verify` over 2–11 messages, the hash-to-G2 proxy, the Miller loop, the final exponentiation;
  - Ed25519: sign, `verify_strict`, `verify_batch` over 2–11;
  - CBOR encode and decode per body type, and SHA-256 chain digests;
  - Evaluate and Contains for rules ∈ {1, 4, 16, 64} × atoms ∈ {1, 4, 8}, typical and worst case;
  - signing costs (per hop, aggregate add, receipt, issuance) for both schemes.

## 5. Method

- **Isolation.** Every chain is generated before measurement starts. Each timed operation is exactly one `verify(&bytes)` call, timed with `Instant` and recorded in nanoseconds; every sample goes to CSV. Any rejection, or any unexpected hit or miss, aborts the run (D-72).
- **Throttling and interference.** Two signals are read before and after every configuration, Q6's included, and every reading goes to `run*-thermal.csv`. These rules are fixed before any numbers exist.
  - **pmset.** `pmset -g therm` counts as throttled if it reports a CPU speed limit below 100, or records a thermal or performance warning level. On this machine it reports no `CPU_Speed_Limit` at all, only "no warning level has been recorded" notes.
  - **Calibration probe** (amendment of 2026-09-30, D-76). A fixed, deterministic, CPU-bound probe of about 100 ms: 100 BLS verifications plus 1,000 Ed25519 `verify_strict` calls, on fixed valid inputs. It runs on the measuring thread, with the same QoS, before and after every configuration; for Q6 it runs single-threaded on that thread.
  - **Baseline.** The median of 5 probes at the start of each run process, after the settle.
  - **Flagging.** A configuration is flagged if either of its probes is more than 5% slower than the run's baseline, or if pmset records a warning before or after it.
  - **Re-runs.** Flagged configurations are re-run after the main runs, and logged in `BENCH_LOG.md` whatever the re-run's result. The report uses the re-run's samples for that run, and marks the configuration.
  - **Safety valve.** If more than 10% of a run's configurations are flagged, the run aborts and is reported instead of being re-run: the machine is not in a usable state. A re-run process records its flags but has no valve.
  - **Reporting.** The report states how many configurations were flagged, and by which signal.
- **Runs.** 3 full runs, each in its own process, each preceded by chain generation and a 30 s settle. Configurations run in a random order per run, seeded by the order seeds `0xdc2dc30928`, `0xdc2dc3092b` and `0xdc2dc3092a` for runs 1–3. A-mt runs in its own process after each main run.
- **Build.** Release profile per SPEC §3.3 (`lto = "fat"`, `codegen-units = 1`, `panic = "abort"`), with `RUSTFLAGS="-C target-cpu=native"` for all arms; `env.json` records the flags. Rust 1.97.1. The measurement-affecting crates are pinned exactly (D-47): blst 0.3.17, ed25519-dalek 2.2.0 (curve25519-dalek 4.1.3), sha2 0.10.9, biscuit-auth 6.0.0.
- **Machine** (D-45): Apple M4 Max, 10 performance + 4 efficiency cores, macOS.
  - No governor or turbo control, and no core pinning. Every measuring thread sets QoS user-interactive (D-42), and the harness records whether that succeeded.
  - **Required machine state; any failure aborts, and nothing is run.**
    - AC power (`pmset -g batt`).
    - High Power mode (`pmset -g` `powermode 2`).
    - An idle machine: a 1-minute load average below 2.0, and no other process using more than 25% of a core.
  - **When it is checked.** AC power and High Power mode are checked before anything is built. Idleness is checked after the harness's own builds, with up to 10 minutes allowed for it to hold, then again at the start of every run process. `env.json` must confirm all three, or `all` aborts.
  - The M8 dry runs ran on battery; they are not reported.
- **Raw data.** Raw CSVs stay out of git. After the runs, every file in `results/raw/` is compressed with zstd into `results/archive/`, and `results/archive/MANIFEST.sha256` (SHA-256 of each archive, `shasum -a 256 -c` format) is committed with `summary.json` and `summary.md`. The report generator verifies every archive against the manifest before it reads any raw data, and reads raw data only from the verified archives. The author keeps the archives.
- **One command.** `RUSTFLAGS="-C target-cpu=native" cargo run --release -p dc-bench -- all` produces `results/raw/*.csv`, `env.json`, `bytes.json`, `memory.json`, `summary.md`, `summary.json` and `plots/`.

## 6. Statistics and decision rules (SPEC §13.6)

- **Per configuration.** Median, mean, SD, p95, p99, min and max, with a bootstrap 95% CI for the median (10,000 resamples, seeded per configuration). Samples are pooled over the 3 runs, and each run's median is reported for run-to-run variation.
- **Ratios.** Every ratio is the aggregating arm's median over the non-aggregating arm's (B/D, A/C, A/C-batch; A/A-ind in Q4), with a bootstrap 95% CI whose draws are paired by index.

### Verdict rule for every ratio

There is a practical-significance margin of ±10% around 1. From the pooled 95% CI [lo, hi]:

| Verdict | Condition |
|---|---|
| **net benefit** | hi < 0.90 |
| **not a net benefit** | lo > 1.10 |
| **no material difference** | 0.90 ≤ lo and hi ≤ 1.10 |
| **inconclusive** | otherwise |

**Run agreement.** A net benefit, not a net benefit, or no material difference verdict stands only if each of the three runs' own ratio of medians falls on the same side of the margin: below 0.90, above 1.10, or within [0.90, 1.10], respectively. Otherwise the verdict is **inconclusive (runs disagree)**.

The rule applies to:
- §1's verdict;
- every per-N and per-profile repetition of it;
- A against C and against C-batch.

It also applies to B/D in prefix-miss and to Q4's A/A-ind, as secondary verdicts.

### Q3

OLS over the per-N medians of arm A, warm and cold, per profile. α, β and 10β/α come with bootstrap CIs, plus R² and residuals. The per-hop term is said to dominate by N = 10 if 10β/α's CI lies above 1, the fixed term if it lies below, and neither otherwise. The crossover is N = α/β.

### Primary outcomes

- **Q1.** Warm median latency, with verdicts by the rule above. The headlines are at N = 3, medium:
  - **B/D (warm+prefix)**, the deployment pattern: this answers §1;
  - **A/C and A/C-batch (warm)**: every call a new chain.

  The same verdicts are given at every N and profile. Also reported: B/D in prefix-miss, and cold latency.
- **Q2.** Bytes per chain.
  - **The primary comparison is A against C**, per N and profile, including medium-approval, where the receipt's key and signature sizes also differ (48 + 96 bytes under BLS against 32 + 64 under Ed25519). Each profile states its **break-even N**: the first N in 1–10 at which A and C swap order, or "none in range".
  - A against A-ind stays as the aggregation ablation.
  - Bytes are exact means, not samples, so no margin applies.

### Verdict on §1

B/D (warm+prefix) at N = 3, medium, by the rule above: net benefit, not a net benefit, no material difference, inconclusive, or inconclusive (runs disagree). It is repeated for each N and profile, then for A against C and C-batch; Q2's comparison is reported beside it. If the latency and bytes answers disagree, both are stated; neither is traded against the other.

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

Claims are evaluated **against paper revision 2026-09-29**, the revision this plan is frozen against. If a later revision changes a claim, `BENCHMARKS.md` says so beside the verdict.

Verdicts are supported, not supported, or partially supported, each with its numbers. If no check contradicts the paper, the report says explicitly that each one was checked.

## 8. Threats to validity, known before the run

- **P-28.** A cold verifier pays N+1 certificate pairings at line 24; the cold rows include them.
- **P-30.** Fixed before the freeze (D-26, revised). The workloads renew no certificates anyway.
- **D-66.** C-batch's semantics differ from C's at the edges.
- **D-67.** Prefix entries live no longer than the certificate cache TTL. SPEC §12.1 includes this cap since the M8 checkpoint (D-67, approved). It binds nothing in these runs, which take far less than an hour of verifier time.
- **Rust-only flags.** `target-cpu=native` reaches the Rust arms but not `blst`'s C and assembly (§3.3).
- **Arm E** lacks resolution, PoP, revocation, receipts, nonces and parameter binding. It is compared with AIP's published figures only as labelled reference numbers from other hardware, not re-checked against arXiv:2603.24775 (§13.10).
  - **Sanity rule** (SPEC §13.10): if arm E differs from AIP's published figures by more than about 3× at matching depth (DC's N against Biscuit depth N − 1), that is investigated before anything about arm E is reported.
  - Reports note that the hardware differs: an M4 Max here, an M3 Max in AIP.
- **Machine.** No pinning or frequency control on macOS; the timer is `mach_absolute_time`.
- **Q5.** Injected sleeps are "at least" the delay.

## 9. Not in this plan

Numbers from the M8 dry run (`results/dry-run/`, not committed) are never reported. The dry run's only purpose was to show that the pipeline completes.
