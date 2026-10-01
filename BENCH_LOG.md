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

