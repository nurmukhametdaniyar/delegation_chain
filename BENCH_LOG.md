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
