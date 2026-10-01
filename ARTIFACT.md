# Artifact: reproducing the DelegationChain benchmark's figures and tables

This repository is the reference implementation of DelegationChain (paper revision 2026-09-29, `docs/paper.pdf`) and the benchmark of whether BLS aggregation is a net benefit once caching is accounted for. This file explains how to regenerate, from the archived raw measurements:
- every figure and table in the paper's evaluation;
- `BENCHMARKS.md`;
- the results summary.

Nothing in them is typed by hand. Every number is computed from the archives by `dc-bench`, the harness in `crates/dc-bench`.

## 1. What the deposit contains

| Item | Where | In git? |
|---|---|---|
| Source code, tests, specification and logs | this repository, at the commit the deposit names | yes |
| M9's raw measurements: per-call latencies, thermal and probe readings, throughput, run metadata | `results/archive/*.zst` | no: in the deposit |
| Their SHA-256 manifest | `results/archive/MANIFEST.sha256` | yes |
| Criterion's output for the micro-benchmarks (Q7, Q8, primitives) | `results/criterion/` | no: in the deposit, as `criterion.tar.zst` |
| The exploratory phase breakdown's raw measurements, once run | `results/exploratory/phases/archive/*.zst` | no: in the deposit |
| Their manifest, and the machine record | `results/exploratory/phases/archive/MANIFEST.sha256`, `results/exploratory/phases/env.json` | yes |
| Bytes on the wire (Q2), memory (Q10), the machine records | `results/bytes.json`, `results/memory.json`, `results/env.json`, `results/env-resume.json` | yes |
| The generated summary, document and paper artifacts | `results/summary.{md,json}`, `BENCHMARKS.md`, `paper/` | yes |

The frozen measurement plan is `BENCH_PLAN_FROZEN.md` (tag `bench-freeze-2`). Every change after the freeze is in `BENCH_LOG.md`, and every open choice in `DECISIONS.md`.

## 2. Requirements

- **Rust.** The toolchain pinned by `rust-toolchain.toml`; `rustup` installs it on first use. Crate versions are pinned by `Cargo.lock`.
- **zstd** on `PATH`. The generators decompress the archives with it.
- **Python 3**, for the figures only. `scripts/plot.sh` and `scripts/paper_figures.sh` build a virtual environment from `scripts/requirements.txt` on first use.
- **LaTeX,** to typeset the tables: `booktabs` for all of them, and `longtable` for the security suite.
- **Time.** Regenerating everything takes a few minutes, mostly the bootstrap. The paper command also builds and runs the security tests.

## 3. Unpack and verify

From the repository root:

```sh
# Put the deposit's archives where the manifests expect them.
cp /path/to/deposit/archive/*.zst results/archive/
mkdir -p results/criterion && zstd -dc /path/to/deposit/criterion.tar.zst | tar -x -C results
cp /path/to/deposit/phases/*.zst results/exploratory/phases/archive/   # if deposited

# Check every archive against its committed manifest.
(cd results/archive && shasum -a 256 -c MANIFEST.sha256)
(cd results/exploratory/phases/archive && shasum -a 256 -c MANIFEST.sha256)
```

The generators check every archive themselves and refuse to run on a missing manifest or a mismatch. They also refuse to run without criterion's output, rather than write a summary without its micro-benchmark section.

## 4. Regenerate

| Command (from the repository root) | Writes | From |
|---|---|---|
| `cargo run --release -p dc-bench -- report` | `results/summary.md`, `results/summary.json` | the verified archives, `results/criterion/`, `results/bytes.json`, `results/memory.json` |
| `cargo run --release -p dc-bench -- benchmarks` | `BENCHMARKS.md` (regenerates the summary first) | the above, the phase breakdown's verified archives, and `crates/dc-bench/BENCHMARKS.template.md` |
| `cargo run --release -p dc-bench -- paper` | `paper/tables/*.tex`, `paper/figures/*.pdf` (regenerates the summary first) | the above, the test sources, and `docs/test-reports/policy-oracle-m4.json` |
| `bash scripts/plot.sh results` | `results/plots/*.png` | `results/summary.json` |

The summary, `BENCHMARKS.md`, the tables and the PDF figures regenerate byte-identically: the bootstrap is seeded, and the PDFs carry no timestamps. The one exception is the security table's "Passed" column, which records the test run that produced it.

### Each paper artifact

| File | What it shows | Data | Code |
|---|---|---|---|
| `paper/figures/latency_warm_medium.pdf` | Warm median latency against N: A, A-ind, C, C-batch (medium, log scale) | `summary.json` ← M9 archives | `scripts/paper_figures.py` |
| `paper/figures/prefix_hit_medium.pdf` | Prefix-cache hit latency against N: B, D (medium, log scale) | `summary.json` ← M9 archives | `scripts/paper_figures.py` |
| `paper/figures/bytes_medium.pdf` | Chain bytes against N: A, A-ind, C (medium), with Q2's break-even | `summary.json` ← `bytes.json` | `scripts/paper_figures.py` |
| `paper/tables/verdicts.tex` | The frozen plan's §1 verdicts: B/D, A/C, A/C-batch at every N and profile, with CIs | M9 archives | `crates/dc-bench/src/paper.rs`, `verdicts` |
| `paper/tables/breakeven.tex` | Q2: break-even N per profile | `bytes.json` | `paper.rs`, `breakeven` |
| `paper/tables/claims.tex` | The paper claims and their verdicts (BENCHMARKS.md §5) | everything above, through the template | `paper.rs`, `claims` |
| `paper/tables/primitives.tex` | BLS and Ed25519 primitive costs | `results/criterion/` | `paper.rs`, `primitives` |
| `paper/tables/security.tex` | The security suite: each test's asserted Algorithm line, and whether it passed | `tests/security.rs`, `tests/concurrency.rs`, and a run of them | `paper.rs`, `security` |
| `paper/tables/oracle.tex` | The M4 differential oracle for Contains, Implies and Unsat | `docs/test-reports/policy-oracle-m4.json` | `paper.rs`, `oracle` |

`bytes.json` is regenerated by `cargo run --release -p dc-bench -- bytes`. The chains are generated from fixed seeds, so it is deterministic.

The oracle's report is regenerated by:

```sh
DC_ORACLE_CASES=150000 DC_ORACLE_LOGIC_CASES=150000 DC_ORACLE_SEED=56324 \
  DC_ORACLE_REPORT=docs/test-reports/policy-oracle-m4.json \
  cargo test --release -p dc-policy --test oracle
```

## 5. Re-measuring (optional)

The archives come from one Apple M4 Max laptop (`results/env.json`). A new measurement on other hardware gives new numbers, and should be read against the same frozen plan.

- **The full benchmark (M9).** Run it with the machine on AC power, in High Power mode (`pmset powermode 2`) and idle. The harness checks all three and aborts otherwise.

  ```sh
  RUSTFLAGS="-C target-cpu=native" cargo run --release -p dc-bench -- all
  ```

  If it is interrupted, `all --resume` continues it. It writes raw data, archives with their manifest, the summary and plots under `results/`, and appends any throttling re-runs to `BENCH_LOG.md`.
- **The exploratory phase breakdown.** It runs with a separate build, which is never used for headline results (SPEC §10.3; D-77). It requires the same machine state.

  ```sh
  RUSTFLAGS="-C target-cpu=native" cargo run --release -p dc-bench \
    --features phase-timing --target-dir target/phase-timing -- phases
  ```

  It writes `results/exploratory/phases/` and appends its `BENCH_LOG.md` entry.

## 6. Packing a deposit

```sh
tar -C results -cf - criterion | zstd -19 -o criterion.tar.zst
shasum -a 256 criterion.tar.zst results/archive/*.zst results/exploratory/phases/archive/*.zst > DEPOSIT.sha256
git archive --format=tar.gz -o source.tar.gz HEAD
```

Upload the source archive, the `.zst` files, `criterion.tar.zst` and `DEPOSIT.sha256`. Name the commit in the deposit's description.
