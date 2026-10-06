# Artifact: reproducing the DelegationChain benchmark's figures and tables

This repository is the reference implementation of DelegationChain (paper revision 2026-10-06, published separately) and the benchmark of whether BLS aggregation is a net benefit once caching is accounted for. This file explains how to regenerate, from the archived raw measurements:
- every figure and table in the paper's evaluation;
- `BENCHMARKS.md`;
- the results summary.

Nothing in them is typed by hand. Every number is computed from the archives by `dc-bench`, the harness in `crates/dc-bench`.

## 1. What the deposit contains

The deposit is a snapshot of this repository at the commit its description names, with a checksum file. The repository itself holds every file below (D-89), so a clone of that commit is the same.

| Item | Where |
|---|---|
| Source code, tests, specification and logs | the repository |
| M9's raw measurements, as zstd archives: per-call latencies, thermal and probe readings, throughput, run metadata | `results/archive/*.zst` |
| Their SHA-256 manifest | `results/archive/MANIFEST.sha256` |
| Criterion's output for the micro-benchmarks (Q7, Q8, primitives) | `criterion.tar.zst`, which unpacks to `results/criterion/` |
| The exploratory phase breakdown: its archives and their manifest, and the machine record | `results/exploratory/phases/archive/`, `results/exploratory/phases/env.json` |
| AIP's own benchmark run here: its outputs and resolved `Cargo.lock` as archives, their manifest, and the machine record | `results/exploratory/aip/archive/`, `results/exploratory/aip/env.json` |
| The encoding checks' micro-benchmark (D-87): its batch timings and thermal readings as archives, their manifest, and the machine record | `results/exploratory/encoding/archive/`, `results/exploratory/encoding/env.json` |
| Bytes on the wire (Q2), memory (Q10), the machine records | `results/bytes.json`, `results/memory.json`, `results/env.json`, `results/env-resume.json` |
| M9's console log: the safety-valve abort and the three refused resumes that BENCHMARKS.md §7 cites | `results/logs/m9.log` |
| The generated summary, document and paper artifacts | `results/summary.{md,json}`, `BENCHMARKS.md`, `paper/` |

The raw CSVs stay out of git (frozen plan §5): the archives are their zstd compression, and the generators read only the verified archives. The first version of the Zenodo record (doi:10.5281/zenodo.23192309) is the snapshot of tag `v0.1.0`, made before the archives were committed, so it holds no measurement data; use a version made from a later commit.

The frozen measurement plan is `BENCH_PLAN_FROZEN.md` (tag `bench-freeze-2`). The paper is not in the repository (D-90); the revisions the work used, up to 2026-10-06's final text, are in git history as `docs/paper.pdf`. `docs/paper-sections.json` maps the section numbers that the claims table and the positioning caption cite, for that final text, which it pins by sha256 (D-86, D-88). With a copy of the paper at `docs/paper.pdf`, `dc-bench paper` refuses a map that is not for it; without one, it uses the map as committed. Nothing under `paper/` carries an identifier internal to this repository, and `crates/dc-bench/tests/paper_text.rs` checks it (D-88). Every change after the freeze is in `BENCH_LOG.md`, and every open choice in `DECISIONS.md`.

## 2. Requirements

- **Rust.** The toolchain pinned by `rust-toolchain.toml`; `rustup` installs it on first use. Crate versions are pinned by `Cargo.lock`.
- **zstd** on `PATH`. The generators decompress the archives with it.
- **Python 3**, for the figures only. `scripts/plot.sh` and `scripts/paper_figures.sh` build a virtual environment from `scripts/requirements.txt` on first use.
- **LaTeX,** to typeset the tables: `booktabs` for all of them, and `longtable` for the security suite.
- **Time.** Regenerating everything takes a few minutes, mostly the bootstrap. The paper command also builds and runs the security tests.

## 3. Unpack and verify

```sh
# From the deposit: check the snapshot and unpack it. From a clone, skip these two lines.
shasum -a 256 -c DEPOSIT.sha256
tar -xzf source.tar.gz && cd delegation_chain

# Criterion's output, which the report needs.
mkdir -p results && zstd -dc criterion.tar.zst | tar -x -C results

# Check every archive against its committed manifest.
(cd results/archive && shasum -a 256 -c MANIFEST.sha256)
(cd results/exploratory/phases/archive && shasum -a 256 -c MANIFEST.sha256)
(cd results/exploratory/aip/archive && shasum -a 256 -c MANIFEST.sha256)
(cd results/exploratory/encoding/archive && shasum -a 256 -c MANIFEST.sha256)
```

The generators check every archive themselves and refuse to run on a missing manifest or a mismatch. They also refuse to run without criterion's output, rather than write a summary without its micro-benchmark section.

## 4. Regenerate

| Command (from the repository root) | Writes | From |
|---|---|---|
| `cargo run --release -p dc-bench -- report` | `results/summary.md`, `results/summary.json` | the verified archives, `results/criterion/`, `results/bytes.json`, `results/memory.json` |
| `cargo run --release -p dc-bench -- benchmarks` | `BENCHMARKS.md` (regenerates the summary first) | the above, the exploratory runs' verified archives, and `crates/dc-bench/BENCHMARKS.template.md` |
| `cargo run --release -p dc-bench -- paper` | `paper/tables/*.tex`, `paper/figures/*` (regenerates the summary first) | the above, the test sources, and `docs/test-reports/policy-oracle-m4.json` |
| `bash scripts/plot.sh results` | `results/plots/*.png` | `results/summary.json` |

The summary, `BENCHMARKS.md`, the tables and the PDF figures regenerate byte-identically: the bootstrap is seeded, and the PDFs carry no timestamps. The one exception is the security table's "Passed" column, which records the test run that produced it.

### Each paper artifact

| File | What it shows | Data | Code |
|---|---|---|---|
| `paper/figures/latency_warm_medium.pdf` | Warm median latency against N: A, A-ind, C, C-batch (medium, log scale) | `summary.json` ← M9 archives | `scripts/paper_figures.py` |
| `paper/figures/prefix_hit_medium.pdf` | Prefix-cache hit latency against N: B, D (medium, log scale) | `summary.json` ← M9 archives | `scripts/paper_figures.py` |
| `paper/figures/bytes_medium.pdf` | Chain bytes against N: A, A-ind, C (medium), with Q2's break-even | `summary.json` ← `bytes.json` | `scripts/paper_figures.py` |
| `paper/figures/ratios.pdf`, `ratios.png` | The pre-registered verdict ratios, A/C and B/D, against N in every profile, with the ±10% band | `summary.json` ← M9 archives | `scripts/paper_figures.py` |
| `paper/figures/captions.tex` | A caption macro per figure, stating what its error bars are | as each figure | `scripts/paper_figures.py` |
| `paper/tables/verdicts.tex` | The frozen plan's §1 verdicts: B/D, A/C, A/C-batch at every N and profile, with CIs | M9 archives | `crates/dc-bench/src/paper.rs`, `verdicts` |
| `paper/tables/breakeven.tex` | Q2: break-even N per profile | `bytes.json` | `paper.rs`, `breakeven` |
| `paper/tables/claims.tex` | The paper claims and their verdicts (BENCHMARKS.md §5), citing the current paper's sections | everything above, through the template, and `docs/paper-sections.json` | `paper.rs`, `claims` |
| `paper/tables/primitives.tex` | BLS and Ed25519 primitive costs | `results/criterion/` | `paper.rs`, `primitives` |
| `paper/tables/positioning.tex` | Exploratory: C (warm) and D (warm+prefix) against arm E, medium, at matching depth | M9 archives | `paper.rs`, `positioning` |
| `paper/tables/captions.tex` | The positioning table's caption, with arm E's functional gaps | `docs/paper-sections.json` | `paper.rs`, `captions` |
| `paper/tables/security.tex` | The security suite: each test's asserted Algorithm line, and whether it passed in each instantiation | `tests/security.rs`, `tests/concurrency.rs`, and a run of them for the default instantiation and for the aggregate variant | `paper.rs`, `security` |
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

**Re-measuring under the frozen plan uses the measured commit.**
- **M9** was measured at `4e134dc` (tag `bench-freeze-2`; runs 1 and 2) and `b175599` (the resume: run 2's A-mt redo, run 3 and the re-runs). The measured code path is the same at both (BENCH_LOG.md, 2026-10-01).
- **The exploratory session** was measured at `b1cc711`.
- **Why later commits don't qualify.** From step 3 (2026-10-04) on, the protocol's default instantiation is Ed25519 per hop, BLS aggregation a variant, and the Ed25519 decoder checks canonical encodings (D-80, D-81). Builds of later commits are therefore not the measured binaries, although the arms verify the same chains.
- **How.** Check the measured commit out in its own worktree (`git worktree add ../dc-m9 b175599`) and run the commands below there. The generators of this and later commits read the archives either way.

- **The full benchmark (M9).** Run it with the machine on AC power, in High Power mode (`pmset powermode 2`) and idle. The harness checks all three and aborts otherwise.

  ```sh
  RUSTFLAGS="-C target-cpu=native" cargo run --release -p dc-bench -- all
  ```

  If it is interrupted, `all --resume` continues it. It writes raw data, archives with their manifest, the summary and plots under `results/`, and appends any throttling re-runs to `BENCH_LOG.md`.
- **The exploratory session.** One script runs the phase breakdown (D-77) and AIP's own benchmark at its arXiv commit (D-79), one after the other. It first builds everything, which needs the network to fetch AIP's code and crates. Each run then requires the same machine state as M9.

  ```sh
  scripts/exploratory-session.sh
  ```

  It writes `results/exploratory/phases/` and `results/exploratory/aip/`, and each run appends its own `BENCH_LOG.md` entry. The phase breakdown's build is never used for headline results (SPEC §10.3).
- **The cost of D-81's encoding checks (D-87).** This one is the exception to the measured-commit rule. It times checks that M9's commits lack, so it runs at the commit its `BENCH_LOG.md` entry names, or a later one, and requires the same machine state as M9.

  ```sh
  RUSTFLAGS="-C target-cpu=native" cargo run --release -p dc-bench -- encoding
  ```

  It writes `results/exploratory/encoding/` and appends its own `BENCH_LOG.md` entry. `--resume` continues an interrupted run.

## 6. Packing a deposit

```sh
mkdir -p deposit
git archive --format=tar.gz --prefix=delegation_chain/ -o deposit/source.tar.gz HEAD
(cd deposit && shasum -a 256 source.tar.gz > DEPOSIT.sha256)
```

Upload `deposit/source.tar.gz` and `deposit/DEPOSIT.sha256` as a new version of the Zenodo record, and name the commit in its description. The snapshot keeps the archives in their folders. Do not upload the `.zst` files one by one: Zenodo lists a record's files without folders, and the archives of M9, the phase breakdown and the encoding checks share nine file names (`run1.csv.zst`, `run1-meta.json.zst`, …). A GitHub release of the commit also reaches Zenodo through its GitHub integration, which archives the tracked files, archives included, as a zip without `DEPOSIT.sha256`.

`criterion.tar.zst` is criterion's output, packed with `COPYFILE_DISABLE=1 tar -C results -cf - criterion | zstd -19 -o criterion.tar.zst`. Repack and commit it only if the micro-benchmarks are re-run.
