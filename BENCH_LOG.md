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

