# Artifact: reproducing the DelegationChain benchmark's figures and tables

This repository is the reference implementation of DelegationChain (paper revision 2026-10-06, published separately) and the benchmark of whether BLS aggregation is a net benefit once caching is accounted for. The paper's IEEE Access version describes the specification at tag v0.1.2: Algorithm 2 in D-94's order, the work budget of D-100 to D-103, and the MCP binding of D-104 (SPEC §10.6). Its Supplementary Material, Section S12, reports the exploratory measurements from D-96 on, and §5's table lists their commits. This file explains how to regenerate, from the archived raw measurements:
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
| The reorder check (D-96): each build's raw data as archives with its manifest, and its machine record | `results/exploratory/reorder/<build>/archive/`, `results/exploratory/reorder/<build>/env.json` |
| Criterion's output for `Contains` at the scope-size bounds (D-95), and the machine record | `results/exploratory/bounds/criterion.tar.zst` with its `.sha256`, `results/exploratory/bounds/env.json` |
| `Contains` after D-97 and the prototype work budget (D-98, D-99): criterion's output, the atom-level counts, the oracle under budgets, the search's ranking, and the machine record | `results/exploratory/contains-cost/` (`criterion.tar.zst` with its `.sha256`, `work.json`, `oracle-budget.json`, `search.txt`, `env.json`) |
| The work budget on the protocol path (D-100): criterion's output for `Contains` at the default budget and lines 2 and 5, the counts, the oracle's report, the machine record, and the headline check's three builds as archives with their manifests | `results/exploratory/budget/` (`criterion.tar.zst` with its `.sha256`, `work.json`, `oracle.json`, `env.json`, `headline/<build>/archive/`, `headline/<build>/env.json`) |
| D-101's unit: criterion's output for each charged class, the fixed cost, the search and lines 2 and 5 under the proposed limits, the counts, the oracle's report, the machine record, and the headline check's three builds as archives with their manifests | `results/exploratory/ceiling/` (`criterion.tar.zst` with its `.sha256`, `work.json`, `oracle.json`, `env.json`, `headline/<build>/archive/`, `headline/<build>/env.json`) |
| D-102's run of the same, and the re-run of its headline cells (D-103) | `results/exploratory/ceiling2/`, as `ceiling/`, and `ceiling2/headline-rerun/<build>/` (`archive/`, `env.json`) with `quiet.log` |
| The MCP expressiveness study (D-105): the corpus pin, one class per probed tool, the cross-check, the summary and the machine record; the corpus itself is downloaded at its frozen revision and checked by SHA-256 | `results/exploratory/mcp-expressiveness/` (`corpus.json`, `classify.json`, `tools.csv.gz`, `crosscheck.json`, `summary.json`, `summary.md`, `env.json`) |
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
for b in measured pre-reorder reordered; do (cd results/exploratory/reorder/$b/archive && shasum -a 256 -c MANIFEST.sha256); done

# The bounds pass's criterion output (D-95).
(cd results/exploratory/bounds && shasum -a 256 -c criterion.tar.zst.sha256)
zstd -dc results/exploratory/bounds/criterion.tar.zst | tar -x -C results/exploratory/bounds

# Contains after D-97 and the work budget (D-98, D-99), once measured.
(cd results/exploratory/contains-cost && shasum -a 256 -c criterion.tar.zst.sha256)
zstd -dc results/exploratory/contains-cost/criterion.tar.zst | tar -x -C results/exploratory/contains-cost

# The work budget on the protocol path (D-100), once measured.
(cd results/exploratory/budget && shasum -a 256 -c criterion.tar.zst.sha256)
zstd -dc results/exploratory/budget/criterion.tar.zst | tar -x -C results/exploratory/budget
for b in measured pre-budget budgeted; do (cd results/exploratory/budget/headline/$b/archive && shasum -a 256 -c MANIFEST.sha256); done

# D-101's unit, once measured.
(cd results/exploratory/ceiling && shasum -a 256 -c criterion.tar.zst.sha256)
zstd -dc results/exploratory/ceiling/criterion.tar.zst | tar -x -C results/exploratory/ceiling
for b in measured pre-budget budgeted; do (cd results/exploratory/ceiling/headline/$b/archive && shasum -a 256 -c MANIFEST.sha256); done
# and the same for results/exploratory/ceiling2/, and for its headline-rerun/ once it exists.
```

The generators check every archive themselves and refuse to run on a missing manifest or a mismatch. They also refuse to run without criterion's output, rather than write a summary without its micro-benchmark section.

## 4. Regenerate

| Command (from the repository root) | Writes | From |
|---|---|---|
| `cargo run --release -p dc-bench -- report` | `results/summary.md`, `results/summary.json` | the verified archives, `results/criterion/`, `results/bytes.json`, `results/memory.json` |
| `cargo run --release -p dc-bench -- benchmarks` | `BENCHMARKS.md` (regenerates the summary first) | the above, the exploratory runs' verified archives, and `crates/dc-bench/BENCHMARKS.template.md` |
| `cargo run --release -p dc-bench -- paper` | `paper/tables/*.tex`, `paper/figures/*` (regenerates the summary first); with `--paper-dir DIR`, into DIR, with `--map FILE`, citing the sections FILE names (D-91), and with `--figure-width IN`, with every figure drawn to fit a column IN inches wide (D-93) | the above, the test sources, and `docs/test-reports/policy-oracle-m4.json` |
| `bash scripts/plot.sh results` | `results/plots/*.png` | `results/summary.json` |
| `scripts/mcp-expressiveness.sh` | `results/exploratory/mcp-expressiveness/*`, `paper/tables/mcp_expressiveness.tex` (D-105; needs network for the corpus, once) | MCP-Eco's `mcp_tools.parquet` at its frozen revision, checked by SHA-256 |

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
| `paper/tables/verdicts_summary.tex` | The same verdicts condensed to one row per profile: the range of each comparison's ratios and the verdicts of its cells | M9 archives | `paper.rs`, `verdicts_summary` |
| `paper/tables/breakeven.tex` | Q2: break-even N per profile | `bytes.json` | `paper.rs`, `breakeven` |
| `paper/tables/claims.tex` | The paper claims and their verdicts (BENCHMARKS.md §5), citing the current paper's sections | everything above, through the template, and `docs/paper-sections.json` | `paper.rs`, `claims` |
| `paper/tables/primitives.tex` | BLS and Ed25519 primitive costs, and the containment procedure in the worst case (D-92) | `results/criterion/` | `paper.rs`, `primitives` |
| `paper/tables/positioning.tex` | Exploratory: C (warm) and D (warm+prefix) against arm E, medium, at matching depth | M9 archives | `paper.rs`, `positioning` |
| `paper/tables/captions.tex` | The positioning table's caption, with arm E's functional gaps | `docs/paper-sections.json` | `paper.rs`, `captions` |
| `paper/tables/security.tex` | The security suite: each test's asserted Algorithm line, and whether it passed in each instantiation | `tests/security.rs`, `tests/concurrency.rs`, a run of them for the default instantiation and for the aggregate variant, and `docs/paper-sections.json` (the theorem the concurrent test checks) | `paper.rs`, `security` |
| `paper/tables/oracle.tex` | The M4 differential oracle for Contains, Implies and Unsat | `docs/test-reports/policy-oracle-m4.json` | `paper.rs`, `oracle` |
| `paper/tables/oracle_contains.tex` | The same, Contains only, with its reflexivity line | `docs/test-reports/policy-oracle-m4.json` | `paper.rs`, `oracle` |

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
- **The measured commits predate D-94.** They verify the chain signatures after policy and approvals (paper revision 2026-10-06's order); from `1f5f4fa` on, the chain signatures come first (SPEC Appendix A). An accepted chain runs the same checks in either order, so the measured chains, all of which are accepted, do the same work. The exploratory re-run of four cells in both orders is in `results/exploratory/reorder/` (D-96; BENCHMARKS.md §8).
- **The measured commits have no work budget on `Contains`.** From D-100 on, lines 35 and 37 run `Contains` under a budget of 65,536 units of work (SPEC §9.6.1), and `pin` checks a policy's reflexive containment against it. Every measured chain's counts are far below the budget, so its decisions are the same. The exploratory measurements of the budget, each including four headline cells with and without it, are in `results/exploratory/budget/` (D-100), `ceiling/` (D-101) and `ceiling2/` (D-102, the final unit); the numbers in BENCHMARKS.md §8's "The budget as adopted" come from `ceiling2/`.
- **How.** Check the measured commit out in its own worktree (`git worktree add ../dc-m9 b175599`) and run the commands below there. The generators of this and later commits read the archives either way.

**The commit each measurement ran at,** as `BENCH_LOG.md` and BENCHMARKS.md §8 record them. The exploratory measurements after M9 run at the commit that holds their tooling, and compare builds of other commits where they say so.

| Measurement | Ran at | Builds compared | Data |
|---|---|---|---|
| M9, the frozen grid | `4e134dc` (runs 1, 2), `b175599` (the resume) | — | `results/` |
| The exploratory session (D-77, D-79) | `b1cc711` | — | `results/exploratory/phases/`, `aip/` |
| D-81's encoding checks (D-87) | `25242b8` | — | `results/exploratory/encoding/` |
| The reorder check (D-96) | `e6c885b` | measured `b175599`, pre-reorder `4239168`, reordered `e6c885b` | `results/exploratory/reorder/` |
| `Contains` at the size bounds (D-95) | `f75b706` | — | `results/exploratory/bounds/` |
| `Contains` after D-97, the prototype budget (D-98, D-99) | `7d71b92` | — | `results/exploratory/contains-cost/` |
| The budget on the protocol path (D-100) | `42b84ec` | measured `b175599`, pre-budget `2df8b53`, budgeted `42b84ec` | `results/exploratory/budget/` |
| D-101's unit (its ceiling check failed) | `1126b57` | measured `b175599`, pre-budget `2df8b53`, budgeted `1126b57` | `results/exploratory/ceiling/` |
| The final unit (D-102) | `7f1f149` | measured `b175599`, pre-budget `2df8b53`, budgeted `7f1f149` | `results/exploratory/ceiling2/` |
| Its headline re-run (D-103), not completed | `97b147e` | measured `b175599` (one run only); pre-budget `2df8b53` and budgeted `97b147e` not reached | `results/exploratory/ceiling2/headline-rerun/` |

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
- **The reorder check (D-96).** Four cells (B and D warm+prefix, A and C warm; N = 3, medium), three runs each, in three builds: the measured commit `b175599`; `4239168`, the commit before D-94 (the pre-reorder build); and `e6c885b`, a commit with D-94 (the reordered build), at which the check also ran. The script builds each in its own worktree under `target/exploratory/reorder/` (remove them afterwards with `git worktree remove`), and each run requires M9's machine state.

  ```sh
  scripts/reorder-check.sh
  ```

  It writes `results/exploratory/reorder/` and appends a `BENCH_LOG.md` entry; `dc-bench reorder` prints the comparison.
- **Contains at the scope-size bounds (D-95).** An exploratory criterion pass at a commit with `benches/bounds.rs`, on M9's machine state. Its largest cell takes minutes per call, so it takes about an hour and a quarter.

  ```sh
  scripts/bounds-check.sh
  ```

  It writes `results/exploratory/bounds/` and appends a `BENCH_LOG.md` entry.
- **Contains after D-97, and the work budget (D-98, D-99).** An exploratory pass at a commit with `benches/contains_cost.rs`, on M9's machine state; about 45 minutes.

  ```sh
  scripts/contains-cost.sh
  ```

  It writes `results/exploratory/contains-cost/` and appends a `BENCH_LOG.md` entry. Its run was at `7d71b92`, where the budget was a prototype behind a feature; at a later commit the script measures the protocol path's budget.
- **The work budget on the protocol path (D-100).** At a commit with D-100, on M9's machine state; about an hour. It runs the counts and the 150,000-pair oracle first, then awaits an idle machine for the criterion pass (`benches/budget_cost.rs`), and again for D-96's four headline cells in three builds (the measured commit `b175599`, `2df8b53` before the budget, and the commit with it), each built in its own worktree under `target/exploratory/budget/` (remove them afterwards with `git worktree remove`).

  ```sh
  scripts/budget-check.sh
  ```

  It writes `results/exploratory/budget/` and appends a `BENCH_LOG.md` entry; `dc-bench budget-report` prints its BENCHMARKS.md block. `--wait MINUTES` waits longer for an idle machine (default 10); while it waits it names what keeps the machine busy. An attempt that stops before measuring can simply be run again. `--dry` checks the pipeline under `results/dry-run/`. Its run was at `42b84ec`, with D-99's unit.
- **D-101's unit, its derived ceiling and the proposed size limits.** At a commit with D-101, on M9's machine state; about an hour. Like the budget's measurement: the counts and the oracle first, then the criterion pass (`benches/ceiling.rs`), then the headline cells in three builds, each in its own worktree under `target/exploratory/ceiling/`. The same options.

  ```sh
  scripts/ceiling-check.sh
  ```

  It writes `results/exploratory/ceiling/` and appends a `BENCH_LOG.md` entry; `dc-bench ceiling-report` prints its BENCHMARKS.md block. Its run was at `1126b57`, with D-101's unit; its derived ceiling's check failed, and it stays recorded as it is.
- **The final unit's run (D-102).** The same script, `scripts/ceiling-check.sh --name ceiling2`, into `results/exploratory/ceiling2/` (`dc-bench ceiling-report --name ceiling2`). It ran at `7f1f149`, the commit with D-102's unit, which is also its budgeted build. It gives the numbers BENCHMARKS.md §8's "The budget as adopted" cites: the derived ceiling and the search against it, the admitted shapes, lines 2 and 5 under the proposed and the adopted limits, and the oracle. Its headline check stopped on the 5% rule; the analysis within each run is beside it.
- **The headline cells re-run (D-103).** D-96's four cells in three builds, three runs: the measured commit `b175599`, `2df8b53` before the budget, and the commit it is run from (HEAD) as the budgeted build. Each run starts only once the 1-minute load average is below 1.0 and XprotectService is idle, besides M9's machine state; about half an hour once the machine is quiet.

  ```sh
  caffeinate -i scripts/headline-rerun.sh --wait 180
  ```

  It writes `results/exploratory/ceiling2/headline-rerun/` and appends a `BENCH_LOG.md` entry. `--wait MINUTES` is how long it waits before each run (default 30), naming what keeps the machine busy; an attempt that measured nothing can be run again. Its attempt of 2026-11-15 ran at `97b147e` (D-102's unit with D-103's rule limit, the budgeted build). It completed one run of the measured build before the machine stayed too busy; that run is archived as a record and not compared (BENCH_LOG.md). To try again, move `results/exploratory/ceiling2/headline-rerun/` aside first: the script refuses to overwrite a run.

## 6. Packing a deposit

```sh
mkdir -p deposit
git archive --format=tar.gz --prefix=delegation_chain/ -o deposit/source.tar.gz HEAD
(cd deposit && shasum -a 256 source.tar.gz > DEPOSIT.sha256)
```

Upload `deposit/source.tar.gz` and `deposit/DEPOSIT.sha256` as a new version of the Zenodo record, and name the commit in its description. The snapshot keeps the archives in their folders. Do not upload the `.zst` files one by one: Zenodo lists a record's files without folders, and the archives of M9, the phase breakdown and the encoding checks share nine file names (`run1.csv.zst`, `run1-meta.json.zst`, …). A GitHub release of the commit also reaches Zenodo through its GitHub integration, which archives the tracked files, archives included, as a zip without `DEPOSIT.sha256`.

`criterion.tar.zst` is criterion's output, packed with `COPYFILE_DISABLE=1 tar -C results -cf - criterion | zstd -19 -o criterion.tar.zst`. Repack and commit it only if the micro-benchmarks are re-run.
