# Benchmarks

**Status: no results.** This file is written at M10. Every number in it will be generated from `results/` by `cargo run --release -p dc-bench -- report` (SPEC §0 rule 7).

## Deviations from the frozen plan

`BENCH_LOG.md` has the full entries and their evidence.

1. **The safety valve counts per run** (2026-10-01, after runs 1 and 2 were measured). The calibration probe's valve now counts a run's main and A-mt processes together, over 255 configurations, instead of each process alone (D-76, revised). Under the per-process count, run 2's A-mt process (16 configurations) aborted on 2 flags.
   - Those flags came from A-mt's own all-core load warming the chip, not from the machine: pmset recorded no warnings, and outside Q5 the main runs' probes stayed within 4.5%.
   - Run 2's A-mt process was redone in full.
   - No latency result was opened before the decision.
2. **A 200 ms busy spin before every probe** (2026-10-01). It applies from run 2's A-mt redo on, because probes after Q5's sleep-dominated configurations measured the idle core's ramp-up. Runs 1 and 2's Q5 flags still trigger their re-runs.

