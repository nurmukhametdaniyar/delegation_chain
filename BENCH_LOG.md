# Benchmark log

Harness changes made after the `bench-freeze` tag, one entry per change, in the format of SPEC Appendix B (SPEC §0 rule 6). Each entry names the bug, how it was found, and the configurations re-run.

The plan was first frozen at the tag `bench-freeze` (2026-09-30), and is frozen at `bench-freeze-2` after the two amendments below, which were made before any measurement. Entries follow, oldest first. Throttling re-runs (frozen plan §5) are appended by the harness.

## 2026-09-30 — Amendment before any measurement: a calibration probe as a second throttling signal
Reason:
- **How it arose.** The first M9 attempt aborted at its machine-state check (battery, automatic power mode, not idle) before any configuration ran, so no measured number existed. The author then asked for a second throttling and interference signal, because `pmset -g therm` on this machine reports no CPU speed limit.
- **The probe.** A fixed, deterministic probe of about 100 ms (100 BLS verifications plus 1,000 Ed25519 `verify_strict` calls) runs on the measuring thread before and after every configuration, Q6 included.
- **The rule.** A configuration is flagged if a probe is more than 5% slower than its run's baseline, the median of 5 probes after the settle, or if pmset records a warning. If more than 10% of a run's configurations are flagged, the run aborts.
- **References.** Frozen plan §5; D-76.

Configurations re-run: none; nothing had been measured.

## 2026-09-30 — Amendment before any measurement: the stale §8 line on D-67
Reason: §8 said SPEC §12.1 gave no bound for the prefix-entry TTL cap. Since the M8 checkpoint, SPEC §12.1 includes it (D-67, approved). This corrects the text only; the method does not change.

Configurations re-run: none; nothing had been measured.

## 2026-10-01 — Post-measurement deviation: the safety valve counts per run, across the main and A-mt processes
Reason:
- **What happened.** M9's `all` completed run 1 (main and A-mt) and run 2's main process. It then aborted in run 2's A-mt process: 2 of that process's 16 configurations were flagged, 12.5% against the valve's 10%.
- **Why the valve tripped.** The implementation (D-76 as first written) counted each run process on its own. The plan says "a run's configurations", and §5 defines a run as a main process plus its A-mt process.
- **The decision.** With the author's approval, the valve now counts per run, over its 255 configurations (231 latency plus 24 Q6); the A-mt process continues the count from its main process. Counted that way, run 1 has 6 + 1 = 7 flagged, and run 2 has 6 + 2 = 8, both far from 26.

Evidence. It is computed from `run*-thermal.csv` and `run*-meta.json` only, in the copy at `backups/m9-raw-20261001T010020Z`. Each figure is a probe time over its process's baseline.

| Process | Probes | Median: all / before / after | Max outside Q5 | pmset warnings | Flagged |
|---|---|---|---|---|---|
| run 1, main | 478 | 0.999 / 0.998 / 1.001 | 1.045 | 0 | 6 (all Q5, probe) |
| run 1, A-mt | 32 | 1.019 / 1.016 / 1.025 | 1.064 | 0 | 1 (probe) |
| run 2, main | 478 | 0.998 / 0.998 / 0.998 | 1.032 | 0 | 6 (all Q5, probe) |
| run 2, A-mt (aborted after 15 of 16) | 30 | 1.039 / 1.037 / 1.041 | 1.052 | 0 | 2 (probe) |

- **Main runs.** Outside Q5, the largest drift was 4.5% in run 1 and 3.2% in run 2, and pmset recorded no warning anywhere.
- **Q5.** The probes that followed Q5's injected-latency configurations (1, 20, 80 ms per call; the measuring thread mostly sleeps) ran 1.070–1.286 in run 1 and 1.081–1.365 in run 2, and only those probes, never the ones before a configuration.
- **A-mt.** In the A-mt processes, the whole distribution shifted, "before" probes included: medians 1.019 in run 1 and 1.039 in run 2. The cause is A-mt's own all-core load: it runs `blst`'s thread pool on every core, which warms the chip and lowers single-thread speed afterwards. Two of run 2's A-mt probes crossed 1.05, the larger at 1.052.
- **No latency result was opened before deciding.** The evidence is from `run*-thermal.csv` and `run*-meta.json` only. During the runs, the harness's console printed per-configuration durations and Q6 throughput rates; they were not used.

- **An earlier loss of files.** A second `all` invocation had overwritten the first attempt's run-1 files, from an attempt that had aborted the same way. To prevent a repeat:
  - a run process now refuses to overwrite a completed process;
  - an aborted or partial process's files are moved to `results/aborted/` before its redo;
  - a fresh `all` refuses to start over measured data;
  - `all --resume` skips completed processes and re-runs.

Configurations re-run: run 2's A-mt process, in full (16 configurations). Its aborted attempt is set aside in `results/aborted/run2-amt-attempt-1/` and never read. Run 3 follows. Runs 1 and 2's completed processes are kept as measured.

## 2026-10-01 — Post-measurement deviation: a 200 ms busy spin before every probe
Reason: probes that followed Q5's sleep-dominated configurations ran slow because the core had been idle, not because of throttling (evidence above). With the author's approval, a fixed busy spin of about 200 ms now runs on the probing thread before every probe, baseline probes included, outside the probe's timing. Its duration is recorded in a new last column of `run*-thermal.csv` (`warmup_ns`).

The spin applies to run 2's A-mt redo, run 3 and every re-run. Runs 1 and 2's processes ran without it, so their Q5 flags still trigger their re-runs, as the rule says.

Configurations re-run: none because of this change itself.


## 2026-10-01 — throttling re-run, run 1
Reason: before or after these configurations, `pmset -g therm` recorded a warning, or a calibration probe ran more than 5% slower than the run's baseline (frozen plan §5). They were re-run after the main runs; the report uses the re-run samples, and the originals stay in the archive.
Configurations re-run:
- `A cold+rtt1ms N=3 medium`: flagged by probe; original median 17742688 ns, re-run median 17424312 ns; re-run not flagged
- `A cold+rtt20ms N=3 medium`: flagged by probe; original median 168086646 ns, re-run median 166962542 ns; re-run not flagged
- `A cold+rtt80ms N=3 medium`: flagged by probe; original median 470803688 ns, re-run median 469798062 ns; re-run not flagged
- `C cold+rtt1ms N=3 medium`: flagged by probe; original median 9451042 ns, re-run median 9465980 ns; re-run not flagged
- `C cold+rtt20ms N=3 medium`: flagged by probe; original median 146185042 ns, re-run median 146540916 ns; re-run not flagged
- `C cold+rtt80ms N=3 medium`: flagged by probe; original median 445771000 ns, re-run median 446448896 ns; re-run not flagged

## 2026-10-01 — throttling re-run, run 1 (A-mt build)
Reason: before or after these configurations, `pmset -g therm` recorded a warning, or a calibration probe ran more than 5% slower than the run's baseline (frozen plan §5). They were re-run after the main runs; the report uses the re-run samples, and the originals stay in the archive.
Configurations re-run:
- `A-mt warm N=5 medium`: flagged by probe; original median 554084 ns, re-run median 556708 ns; re-run not flagged

## 2026-10-01 — throttling re-run, run 2
Reason: before or after these configurations, `pmset -g therm` recorded a warning, or a calibration probe ran more than 5% slower than the run's baseline (frozen plan §5). They were re-run after the main runs; the report uses the re-run samples, and the originals stay in the archive.
Configurations re-run:
- `A cold+rtt1ms N=3 medium`: flagged by probe; original median 17651270 ns, re-run median 17322000 ns; re-run not flagged
- `A cold+rtt20ms N=3 medium`: flagged by probe; original median 167413979 ns, re-run median 167031792 ns; re-run not flagged
- `A cold+rtt80ms N=3 medium`: flagged by probe; original median 471735625 ns, re-run median 470965834 ns; re-run not flagged
- `C cold+rtt1ms N=3 medium`: flagged by probe; original median 9437417 ns, re-run median 9462730 ns; re-run not flagged
- `C cold+rtt20ms N=3 medium`: flagged by probe; original median 146780042 ns, re-run median 146564583 ns; re-run not flagged
- `C cold+rtt80ms N=3 medium`: flagged by probe; original median 447222374 ns, re-run median 444507167 ns; re-run not flagged

## 2026-10-01 — throttling re-run, run 2 (A-mt build)
Reason: before or after these configurations, `pmset -g therm` recorded a warning, or a calibration probe ran more than 5% slower than the run's baseline (frozen plan §5). They were re-run after the main runs; the report uses the re-run samples, and the originals stay in the archive.
Configurations re-run:
- `A-mt warm N=1 large`: flagged by probe; original median 534792 ns, re-run median 521333 ns; re-run flagged again, by probe
- `A-mt warm N=1 medium`: flagged by probe; original median 483166 ns, re-run median 465375 ns; re-run not flagged
- `A-mt warm N=1 small`: flagged by probe; original median 476250 ns, re-run median 460917 ns; re-run not flagged
- `A-mt warm N=10 large`: flagged by probe; original median 1015292 ns, re-run median 969875 ns; re-run not flagged
- `A-mt warm N=10 small`: flagged by probe; original median 757542 ns, re-run median 748583 ns; re-run flagged again, by probe
- `A-mt warm N=2 large`: flagged by probe; original median 600750 ns, re-run median 585958 ns; re-run not flagged
- `A-mt warm N=2 medium`: flagged by probe; original median 500625 ns, re-run median 486417 ns; re-run not flagged
- `A-mt warm N=2 small`: flagged by probe; original median 495042 ns, re-run median 478375 ns; re-run not flagged
- `A-mt warm N=3 large`: flagged by probe; original median 671042 ns, re-run median 635958 ns; re-run not flagged
- `A-mt warm N=3 medium-approval`: flagged by probe; original median 981875 ns, re-run median 977541 ns; re-run not flagged

## 2026-10-01 — throttling re-run, run 3
Reason: before or after these configurations, `pmset -g therm` recorded a warning, or a calibration probe ran more than 5% slower than the run's baseline (frozen plan §5). They were re-run after the main runs; the report uses the re-run samples, and the originals stay in the archive.
Configurations re-run:
- `B prefix-miss N=3 small`: flagged by probe; original median 1720250 ns, re-run median 1705958 ns; re-run not flagged
- `C-batch warm N=5 small`: flagged by probe; original median 86334 ns, re-run median 86417 ns; re-run not flagged

## 2026-10-01 — throttling re-run, run 3 (A-mt build)
Reason: before or after these configurations, `pmset -g therm` recorded a warning, or a calibration probe ran more than 5% slower than the run's baseline (frozen plan §5). They were re-run after the main runs; the report uses the re-run samples, and the originals stay in the archive.
Configurations re-run:
- `A-mt warm N=2 medium`: flagged by probe; original median 502584 ns, re-run median 484583 ns; re-run not flagged

## 2026-10-01 — Report correction after M10: arm E's token sizes in Q9
Reason:
- **The error.** M10's `BENCHMARKS.md` said that arm E's token sizes matched AIP's published sizes at the same depth. AIP's published sizes are base64 string lengths: its `bench_chained.rs` measures `to_base64().len()` (github.com/sunilp/aip at `ad2faa6`, the commit that prepared the arXiv submission). Arm E's are raw token bytes, so the M10 comparison set raw bytes against base64.
- **How it was found.** The author asked for AIP's evaluation section to be checked against D-68's timed scope (Q9). The paper does not say what it measures, so its benchmark code was read too.
- **The fix.** The report generator now converts arm E's sizes to Biscuit's base64 length (URL-safe, padded: 4·⌈n/3⌉) before comparing them with AIP's. Arm E's tokens turn out to be the larger ones. `summary.md`'s Q9 note now says the AIP figures were checked against arXiv:2603.24775v1 (they match SPEC §13.10), instead of "not re-checked".
- **What did not change.** No measurement, statistic, verdict or harness path. Q9's latency figures and the 3× flags are unchanged.

Configurations re-run: none.

## 2026-10-04 — Exploratory run (not pre-registered): the phase breakdown
Reason: the author asked, after M10, what share of a warm verification goes to decoding, policy (Contains and Evaluate), identity and cryptography.
- **What ran.** 3 runs, each in its own process, of the frozen grid's configurations `A warm N=3 large`, `A warm N=3 medium`, `A warm N=3 small`, `C warm N=3 large`, `C warm N=3 medium`, `C warm N=3 small`, with M9's chain sets and counts.
- **The build.** `dc-bench` with `--features phase-timing` (D-77). Such a build refuses `all` and `run`, so it never makes a headline run (SPEC §10.3).
- **Machine state.** M9's: AC power, High Power mode and an idle machine, checked before the first run and recorded in `results/exploratory/phases/env.json`.
- **Thermal readings.** pmset and the calibration probe were recorded around each configuration, as in M9, but not acted on: 4 were flagged and not re-run: run 1: `A warm N=3 large` (probe); run 1: `C warm N=3 large` (probe); run 3: `A warm N=3 large` (probe); run 3: `C warm N=3 small` (probe).
- **Where the results go.** `BENCHMARKS.md` §8 (exploratory) only, never the summary or a verdict. The raw data are in 9 archives under `results/exploratory/phases/archive/`, pinned by the committed `MANIFEST.sha256`.

Configurations re-run: none. This run measured configurations M9 had already measured, with a different build, and replaces none of M9's samples.

## 2026-10-04 — Exploratory run (not pre-registered): the phase breakdown
Reason: the author asked, after M10, what share of a warm verification goes to decoding, policy (Contains and Evaluate), identity and cryptography.
- **What ran.** 3 runs, each in its own process, of the frozen grid's configurations `A warm N=3 large`, `A warm N=3 medium`, `A warm N=3 small`, `C warm N=3 large`, `C warm N=3 medium`, `C warm N=3 small`, with M9's chain sets and counts.
- **The build.** `dc-bench` with `--features phase-timing` (D-77). Such a build refuses `all` and `run`, so it never makes a headline run (SPEC §10.3).
- **Machine state.** M9's: AC power, High Power mode and an idle machine, checked before the first run and recorded in `results/exploratory/phases/env.json`.
- **Thermal readings.** pmset and the calibration probe were recorded around each configuration, as in M9, but not acted on: 5 were flagged and not re-run: run 1: `C warm N=3 large` (probe); run 1: `C warm N=3 medium` (probe); run 2: `A warm N=3 medium` (probe); run 2: `C warm N=3 small` (probe); run 3: `A warm N=3 medium` (probe).
- **Where the results go.** `BENCHMARKS.md` §8 (exploratory) only, never the summary or a verdict. The raw data are in 9 archives under `results/exploratory/phases/archive/`, pinned by the committed `MANIFEST.sha256`.

Configurations re-run: none. This run measured configurations M9 had already measured, with a different build, and replaces none of M9's samples.

## 2026-10-04 — Exploratory run (not pre-registered): AIP's own benchmark on this machine
Reason: the author asked for AIP's chained-mode benchmark to be run unmodified here, to separate the hardware from the timed scope in Q9's gap.
- **What ran.** `bench_chained` from https://github.com/sunilp/aip at `ad2faa6`, 3 runs each of the unmodified build and the timings build, alternating which went first. The timings build only prints each timing after the timed loop (`scripts/aip-timings.patch`, sha256 `09a898f340b2845de16715a77e346bf6fba10477aa9ae6e37a32638c9703d84a`), for the median.
- **The build.** `cargo build --release --bin bench_chained`, no RUSTFLAGS, one resolved Cargo.lock for both builds; the timings build adds `scripts/aip-timings.patch`. Cargo resolved biscuit-auth 6.0.0, ed25519-dalek 2.2.0 and curve25519-dalek 4.1.3; toolchain rustc 1.97.1 (8bab26f4f 2026-07-14). The unmodified source was checked: rust/aip-token/src/bin/bench_chained.rs and rust/aip-token/src/chained.rs identical to the commit's.
- **Machine state.** M9's: AC power, High Power mode and an idle machine, checked before the run and recorded in `results/exploratory/aip/env.json`. It ran in the same session as the phase breakdown, from `scripts/exploratory-session.sh`.
- **Thermal readings.** Recorded around each invocation, not acted on: none was flagged.
- **Where the results go.** `BENCHMARKS.md` §8 (exploratory) only, never the summary or a verdict. The raw outputs and the resolved `Cargo.lock` are in 15 archives under `results/exploratory/aip/archive/`, pinned by the committed `MANIFEST.sha256`.

Configurations re-run: none.

## 2026-10-04 — Note on the two phase-breakdown entries above
Reason:
- **What happened.** The first of the two phase-breakdown entries above records a complete run of three processes. Its data were removed before the rerun, for an unknown reason, and are not reported. Both entries are kept unchanged.
- **It was not a dry run.**
  - A dry run makes one run, and it logs to its own `BENCH_LOG.dry.md`. The 2026-10-01 dry run's log is still in `results/dry-run/exploratory/phases/` ("1 run", no flags).
  - The first entry is dated 2026-10-04, says 3 runs, and lists flags in runs 1 and 3.
- **The session script ran twice that day.**
  - The phase-timing build dates from 2026-10-04T04:31Z.
  - The session whose data exist started at 05:30:58Z (`results/exploratory/phases/env.json`); the AIP copies were re-extracted at its start.
  - The first session logged no AIP entry.
- **The archived data belong to the second entry.** `results/exploratory/phases/archive/` verifies against its manifest. Its thermal readings flag exactly the configurations that the second entry lists, not the first entry's.
- **Nothing in the harness removed them.**
  - Neither `dc-bench` nor `scripts/exploratory-session.sh` deletes anything under `results/`. An unfinished attempt is moved to `aborted/`, and no `aborted/` exists here.
  - M9's archives (all verified), raw data, criterion output and backup are intact.
- **Reporting.** BENCHMARKS.md §8 reports the second run only, and says so.

Configurations re-run: none.

## 2026-10-04 — Follow-up to the note above: why the first phase run's data were removed
Reason: the author reports that their shell history shows they deleted `results/exploratory/phases` between the two sessions (the second began at 05:29Z), to re-run the session script after the first session's AIP step had failed. They had not opened the results. The note above stands; this replaces its "for an unknown reason". The first run is still not reported.

Configurations re-run: none.

## 2026-10-04 — Further note: the first phase run's deletion
Reason: the author deleted the first session's phase data themselves, between the two sessions, because they believed the session had not finished properly (its AIP step did not run). They then re-ran the whole session. The notes above stand unchanged; this closes the matter.

Configurations re-run: none.

## 2026-10-04 — Exploratory run (not pre-registered): the cost of D-81's encoding checks
Reason: D-81 added decode-time canonical-encoding checks to the default instantiation after M9, so the measured binaries did not have them. The author asked what they add to the latencies the paper reads as the protocol's cost.
- **What ran.** 3 runs, each in its own process, timing the checks as the decoders call them, on honest inputs and on the worst passing inputs, and the whole decoders for context (D-87).
- **The build.** The default `dc-bench` build with `target-cpu=native`, as M9, at commit `25242b8`, which has D-81's checks.
- **Machine state.** M9's: AC power, High Power mode and an idle machine, checked before the first run and recorded in `results/exploratory/encoding/env.json`.
- **Thermal readings.** Recorded around each operation, not acted on: none was flagged.
- **Where the results go.** `BENCHMARKS.md` §8 (exploratory) only. No measured result changes. The raw batch timings are in 9 archives under `results/exploratory/encoding/archive/`, pinned by the committed `MANIFEST.sha256`.

Configurations re-run: none.

## 2026-11-01 — Exploratory run (not pre-registered): the cost of D-94's reorder
Reason: D-94 moved the chain signatures ahead of policy after M9, and the author asked whether that changes the measured latencies (D-96).
- **What ran.** `scripts/reorder-check.sh`: the frozen grid's B and D warm+prefix and A and C warm configurations at N = 3, medium, by `dc-bench run` with M9's counts, three runs, in three builds: measured `b175599`, pre-reorder `4239168` and reordered `e6c885b`, rotating which ran first.
- **Machine state.** M9's: AC power, High Power mode and an idle machine, checked by each of the nine run processes at its start and recorded in its run metadata; all nine passed. Each build's `env.json` was written right after that build compiled, before the machine was idle, so its `m9_requirements` reads not ok; the runs' own checks are the record (D-96).
- **Thermal readings.** The calibration probe flagged one configuration, the measured build's A warm in run 3. It was not re-run.
- **An earlier attempt** the same day was refused by that check before any measurement: the machine did not become idle within 10 minutes. It wrote only the three `env.json` files, which were set aside.
- **Where the results go.** `BENCHMARKS.md` §8 (exploratory) only. The raw data are archived under `results/exploratory/reorder/<build>/archive/`, each pinned by its `MANIFEST.sha256`.

Configurations re-run: none.

## 2026-11-01 — Exploratory run (not pre-registered): Contains at the scope-size bounds
Reason: after D-94 the author asked what the scope-size bounds still let a compromised signer force (D-95).
- **What ran.** `scripts/bounds-check.sh`, run by the author: `cargo bench -p dc-bench --bench bounds` at `f75b706`, with `target-cpu=native` as M9, ten samples of one call each per cell (criterion's flat sampling; small cells take several calls per sample). All 17 cells that fit a body were measured.
- **Machine state.** AC power, High Power mode and an idle machine, checked by the script before the bench and recorded in `results/exploratory/bounds/env.json`. Its `git.dirty` is true only because of untracked files; the script had checked that no tracked file was modified. Nothing monitored the machine during the pass.
- **Completed by hand.** The script gave criterion a relative `CRITERION_HOME`, and cargo runs a bench from its package directory, so the output landed under `crates/dc-bench/results/exploratory/bounds/criterion/`. Packing then failed and the script stopped. The output was moved, unchanged, to `results/exploratory/bounds/criterion/`, packed as the script packs it, and this entry written. Nothing was re-measured. The script now passes an absolute path.
- **Where the results go.** `BENCHMARKS.md` §8 (exploratory) only. Criterion's output is `results/exploratory/bounds/criterion.tar.zst`, pinned by its `.sha256`.

Configurations re-run: none.

## 2026-11-02 — Exploratory run (not pre-registered): Contains after the memoization, and a work budget
Reason: after D-95 the author asked for the cost of Contains after D-97's memoization at sizes up to the bounds, a search for costlier inputs, and a prototype work budget, to choose the scope-size bounds (D-98, D-99).
- **What ran.** `scripts/contains-cost.sh` at `7d71b92`, with `target-cpu=native` as M9: the search (`examples/contains_search.rs`), `benches/contains_cost.rs`, `benches/contains_budget.rs` (a `work-budget` build), `dc-bench budget` and the differential oracle under budgets.
- **Machine state.** AC power, High Power mode and an idle machine, checked before the run and recorded in `results/exploratory/contains-cost/env.json`. Nothing monitored the machine during it.
- **Where the results go.** `BENCHMARKS.md` §8 (exploratory) only. Criterion's output is `results/exploratory/contains-cost/criterion.tar.zst`, pinned by its `.sha256`; the counts, the oracle's report and the search's ranking sit beside it.

Configurations re-run: none.

## 2026-11-04 — Exploratory run (not pre-registered): the work budget's ceiling and cost
Reason: D-100 put a work budget on Contains on the protocol path, and the author asked for its measured ceiling (Contains at the default budget, and line 2 on a 64 KiB scope body), the frozen generator's shapes it admits, and its cost on the headline cells.
- **What ran.** `scripts/budget-check.sh` at `42b84ec`, with `target-cpu=native` as M9: `dc-bench budget-counts`, the differential oracle (150,000 pairs, seed 56324), `benches/budget_cost.rs`, and the frozen grid's B and D warm+prefix and A and C warm configurations at N = 3, medium, by `dc-bench run` with M9's counts, three runs, in three builds: measured `b175599`, pre-budget `2df8b53` and budgeted `42b84ec`, rotating which ran first.
- **Machine state.** M9's, awaited before the criterion pass and recorded in `results/exploratory/budget/env.json` after it; each headline run checked it at its start (its run metadata). Nothing monitored the machine during the criterion pass.
- **Where the results go.** `BENCHMARKS.md` §8 (exploratory) only. Criterion's output is `results/exploratory/budget/criterion.tar.zst`, pinned by its `.sha256`; the headline runs' raw data are archived under `results/exploratory/budget/headline/<build>/archive/`, each pinned by its `MANIFEST.sha256`.
- **An earlier attempt the same day** (at `a64efbb`) built everything and wrote the counts and the oracle's report, then waited ten minutes for an idle machine and stopped: `mediaanalysisd` was at about 319% CPU, with a 1-minute load average of 25. Nothing was timed. Its files were deterministic and this run wrote them again; its machine record was set aside. The script now lets such an attempt be re-run, takes `--wait`, and names what keeps the machine busy (`42b84ec`).
- **The record after the criterion pass** reads not idle: `XprotectService` at 34% CPU, load average 1.3. Nothing monitored the machine during the pass, so whether XProtect ran during it is unknown. The pass itself began only after the machine-state check passed. The record also reads `dirty`, because `dc-bench env` counts untracked files and the run's own output directory was untracked; the script refuses to start with tracked files modified.
- **Headline runs.** All nine passed M9's machine-state check at their start. The calibration probe flagged one configuration (pre-budget, B warm+prefix, run 1); as in D-77, D-87 and D-96, it was not re-run.

Configurations re-run: none.

## 2026-11-06 — Exploratory run (not pre-registered): D-101's unit, its derived ceiling, and the proposed size limits
Reason: D-101 made the work budget's unit a sound over-approximation of Contains's work, and the author asked for the ceiling it implies, a search against it, size limits aligned with the budget and their unsigned decoding cost, and the headline cells.
- **What ran.** `scripts/ceiling-check.sh` at `1126b57`, with `target-cpu=native` as M9: `dc-bench ceiling-counts`, the differential oracle (150,000 pairs, seed 56324), `benches/ceiling.rs`, and the frozen grid's B and D warm+prefix and A and C warm configurations at N = 3, medium, by `dc-bench run` with M9's counts, three runs, in three builds: measured `b175599`, pre-budget `2df8b53` and budgeted `1126b57`, rotating which ran first.
- **Machine state.** M9's, awaited before the criterion pass and recorded in `results/exploratory/ceiling/env.json` after it; each headline run checked it at its start (its run metadata). Nothing monitored the machine during the criterion pass.
- **Where the results go.** `BENCHMARKS.md` §8 (exploratory) only. Criterion's output is `results/exploratory/ceiling/criterion.tar.zst`, pinned by its `.sha256`; the headline runs' raw data are archived under `results/exploratory/ceiling/headline/<build>/archive/`, each pinned by its `MANIFEST.sha256`.
- **The record after the criterion pass** reads not idle: `XprotectService` at 32% CPU, load average 2.6. Nothing monitored the machine during the pass. As before, it reads `dirty` because `dc-bench env` counts the run's own untracked output directory.
- **Headline runs.** All nine passed M9's machine-state check at their start, with 1-minute load averages close to its 2.0 limit (1.66–1.98). The calibration probe flagged two configurations (pre-budget, B warm+prefix, run 2; pre-budget, C warm, run 3); as before, not re-run.
- **The derived ceiling's check failed** (D-101's run notes; D-102).

Configurations re-run: none.

## 2026-11-06 — Exploratory run (not pre-registered): the budget's unit, its derived ceiling, and the proposed size limits (ceiling2)
Reason: D-101 made the work budget's unit a sound over-approximation of Contains's work, and the author asked for the ceiling it implies, a search against it, size limits aligned with the budget and their unsigned decoding cost, and the headline cells.
- **What ran.** `scripts/ceiling-check.sh` at `7f1f149`, with `target-cpu=native` as M9: `dc-bench ceiling-counts`, the differential oracle (150,000 pairs, seed 56324), `benches/ceiling.rs`, and the frozen grid's B and D warm+prefix and A and C warm configurations at N = 3, medium, by `dc-bench run` with M9's counts, three runs, in three builds: measured `b175599`, pre-budget `2df8b53` and budgeted `7f1f149`, rotating which ran first.
- **Machine state.** M9's, awaited before the criterion pass and recorded in `results/exploratory/ceiling2/env.json` after it; each headline run checked it at its start (its run metadata). Nothing monitored the machine during the criterion pass.
- **Where the results go.** `BENCHMARKS.md` §8 (exploratory) only. Criterion's output is `results/exploratory/ceiling2/criterion.tar.zst`, pinned by its `.sha256`; the headline runs' raw data are archived under `results/exploratory/ceiling2/headline/<build>/archive/`, each pinned by its `MANIFEST.sha256`.
- **The record after the criterion pass** reads not idle: `XprotectService` at 31% CPU, load average 2.7. It is the same process (pid 38952) that the first run's record showed after its pass, so it ran for hours, and may have run through both passes; nothing monitored the machine during them. As before, the record reads `dirty` because of the run's own untracked output directory.
- **Headline runs.** All nine passed M9's machine-state check at their start (1-minute load averages 1.54–1.96). The calibration probe flagged six configurations: pre-budget run 1, A warm; pre-budget run 2, all four; budgeted run 3, C warm. As before, none re-run.
- **The author's 5% stop rule fired** on D warm+prefix (budgeted against measured; D-102's run notes). The measured build's own D warm+prefix medians fall from run to run by more than that move.

Configurations re-run: none.

## 2026-11-15 — Exploratory run (not pre-registered), not completed: the headline cells re-run (ceiling2)
Reason: D-102's headline check stopped on the author's 5% rule; the author asked for the four cells to be re-run on a quieter machine, beside the stopped run (D-103).
- **What ran.** `scripts/headline-rerun.sh --wait 180` at `97b147e`. Before each run it waits for M9's machine state, a 1-minute load average below 1.0 and XprotectService idle.
- **An earlier attempt** (2026-11-07, `--wait 30`, at `a8a5408`) waited 30 minutes before its first run and stopped with nothing measured: Spotlight indexing, XProtect's scans, `mediaanalysisd` and `apfsd` kept the load average above 1.0. Its empty directory made the next attempt refuse; the script now allows that (`97b147e`).
- **This attempt** completed run 1 of the measured build (quiet at its start, load average 0.99; logged in `quiet.log`), then waited 180 minutes before run 1 of the pre-budget build without the load average falling below 1.0, and stopped.
- **What is kept.** The one run's raw data, archived under `results/exploratory/ceiling2/headline-rerun/measured/archive/` with its manifest, and `quiet.log`. One build's runs cannot be compared, so no result is reported. At the author's request the work continues without the re-run (D-103).

Configurations re-run: none of the frozen grid.

