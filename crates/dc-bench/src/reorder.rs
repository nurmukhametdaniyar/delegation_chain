//! The exploratory check of D-94's cost (D-96): four of the frozen grid's
//! cells, N = 3, medium, measured by `dc-bench run` in three builds on M9's
//! machine state, three runs each. Not in the frozen plan; no measured
//! result changes.
//!
//! - **measured**: M9's resume commit `b175599`, a measured build
//!   (ARTIFACT.md), with revision 2026-10-06's order.
//! - **pre-reorder**: the commit before D-94, with D-80's and D-81's changes
//!   but the old order, so that the reorder's own effect can be told apart
//!   from theirs.
//! - **reordered**: a commit with D-94.
//!
//! `scripts/reorder-check.sh` runs them, each into its own directory under
//! `results/exploratory/reorder/`, and archives each directory's raw data
//! under its own manifest. This module reads only the verified archives.
//!
//! D-100's check of the work budget's cost has the same shape ([`BUDGET`]):
//! the measured build, the commit before the budget, and a build with it,
//! under `results/exploratory/budget/headline/`.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use serde_json::Value;

use crate::report::{decompress, hex, read_json, us};

/// A three-build check: M9's measured build, the commit before a change,
/// and a build with it, in the order the tables list them.
#[derive(Clone, Copy)]
pub struct Check {
    pub builds: [&'static str; 3],
}

/// D-96: D-94's reorder.
pub const REORDER: Check = Check {
    builds: ["measured", "pre-reorder", "reordered"],
};

/// D-100: the work budget on `Contains`.
pub const BUDGET: Check = Check {
    builds: ["measured", "pre-budget", "budgeted"],
};

/// The cells (arm, state), all at N = 3 in the medium profile: B against D
/// with prefix caches, A against C without. C warm and D warm+prefix are
/// the default instantiation without and with the prefix cache.
pub const CELLS: [(&str, &str); 4] = [
    ("B", "warm+prefix"),
    ("D", "warm+prefix"),
    ("A", "warm"),
    ("C", "warm"),
];

/// The `--only` ids of [`CELLS`], as `dc-bench run` names them.
pub fn ids() -> Vec<String> {
    CELLS
        .iter()
        .map(|(arm, state)| format!("{arm} {state} N=3 medium"))
        .collect()
}

/// How far a median may move, the new build against measured, before the
/// author's instruction is to stop and report.
pub const THRESHOLD: f64 = 0.05;

/// One build's verified data.
pub struct Build {
    pub name: &'static str,
    /// The commit its `env.json` names, and whether the tree was dirty.
    pub commit: String,
    pub dirty: bool,
    pub archives: usize,
    /// (arm, state) → run → nanoseconds per call.
    pub samples: BTreeMap<(String, String), BTreeMap<usize, Vec<u64>>>,
    /// Configurations the thermal monitor flagged, per run.
    pub flagged: BTreeMap<usize, Vec<String>>,
}

pub struct Data {
    pub check: Check,
    pub builds: Vec<Build>,
}

fn median(v: &[u64]) -> f64 {
    let mut s = v.to_vec();
    s.sort_unstable();
    let n = s.len();
    if n % 2 == 1 {
        s[n / 2] as f64
    } else {
        (s[n / 2 - 1] as f64 + s[n / 2] as f64) / 2.0
    }
}

fn load_build(dir: &Path, name: &'static str) -> Result<Build, String> {
    let adir = dir.join("archive");
    let manifest = fs::read_to_string(adir.join("MANIFEST.sha256"))
        .map_err(|_| format!("no {}", adir.join("MANIFEST.sha256").display()))?;
    let env = read_json(&dir.join("env.json"))
        .ok_or_else(|| format!("no {}", dir.join("env.json").display()))?;
    let mut b = Build {
        name,
        commit: env["git"]["commit"].as_str().unwrap_or("?").to_owned(),
        dirty: env["git"]["dirty"] != Value::Bool(false),
        archives: 0,
        samples: BTreeMap::new(),
        flagged: BTreeMap::new(),
    };
    for line in manifest.lines().filter(|l| !l.trim().is_empty()) {
        let (want, file) = line
            .split_once("  ")
            .ok_or_else(|| format!("malformed manifest line: {line}"))?;
        let path = adir.join(file);
        let bytes = fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let got = hex(&dc_types::digest::sha256(&[&bytes]));
        if got != want {
            return Err(format!(
                "{name}: manifest mismatch for {file}: expected {want}, got {got}"
            ));
        }
        b.archives += 1;
        let file = file.strip_suffix(".zst").unwrap_or(file);
        let run = |stem: &str| -> Result<usize, String> {
            stem.strip_prefix("run")
                .and_then(|r| r.parse().ok())
                .ok_or_else(|| format!("{name}: unexpected archive {file}"))
        };
        if let Some(stem) = file.strip_suffix("-meta.json") {
            let meta: Value =
                serde_json::from_slice(&decompress(&path)?).map_err(|e| e.to_string())?;
            let flagged = meta["flagged"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|f| f["config"].as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default();
            b.flagged.insert(run(stem)?, flagged);
        } else if let Some(stem) = file.strip_suffix(".csv")
            && !stem.contains('-')
        {
            let r = run(stem)?;
            let data = decompress(&path)?;
            let mut rd = csv::Reader::from_reader(&data[..]);
            for rec in rd.records() {
                let rec = rec.map_err(|e| format!("{name}/{file}: {e}"))?;
                if &rec[3] != "3" || &rec[4] != "medium" {
                    continue;
                }
                let ns: u64 = rec[6]
                    .parse()
                    .map_err(|_| format!("{name}/{file}: bad ns"))?;
                b.samples
                    .entry((rec[1].to_owned(), rec[2].to_owned()))
                    .or_default()
                    .entry(r)
                    .or_default()
                    .push(ns);
            }
        }
    }
    for (arm, state) in CELLS {
        if !b.samples.contains_key(&(arm.to_owned(), state.to_owned())) {
            return Err(format!("{name}: no samples for {arm} {state} N=3 medium"));
        }
    }
    Ok(b)
}

/// Reads `dir`'s three builds, each from its verified archives.
pub fn load(dir: &Path, check: Check) -> Result<Data, String> {
    let builds = check
        .builds
        .iter()
        .map(|&b| load_build(&dir.join(b), b))
        .collect::<Result<_, _>>()?;
    Ok(Data { check, builds })
}

impl Build {
    fn runs(&self, arm: &str, state: &str) -> &BTreeMap<usize, Vec<u64>> {
        &self.samples[&(arm.to_owned(), state.to_owned())]
    }

    /// The median over every run's samples.
    pub fn pooled(&self, arm: &str, state: &str) -> f64 {
        let all: Vec<u64> = self.runs(arm, state).values().flatten().copied().collect();
        median(&all)
    }

    /// Each run's median.
    pub fn per_run(&self, arm: &str, state: &str) -> BTreeMap<usize, f64> {
        self.runs(arm, state)
            .iter()
            .map(|(r, v)| (*r, median(v)))
            .collect()
    }

    fn samples_per_run(&self) -> String {
        let counts: Vec<usize> = self
            .samples
            .values()
            .flat_map(|runs| runs.values().map(Vec::len))
            .collect();
        match (counts.iter().min(), counts.iter().max()) {
            (Some(a), Some(b)) if a == b => format!("{a}"),
            (Some(a), Some(b)) => format!("{a}–{b}"),
            _ => "0".into(),
        }
    }
}

impl Data {
    fn build(&self, name: &str) -> &Build {
        self.builds.iter().find(|b| b.name == name).expect("build")
    }

    /// The largest relative move of a pooled median, the new build against
    /// measured: (cell, relative change).
    pub fn largest_move(&self) -> (String, f64) {
        let [base, _, new] = self.check.builds;
        let (m, r) = (self.build(base), self.build(new));
        CELLS
            .iter()
            .map(|(arm, state)| {
                (
                    format!("{arm} {state}"),
                    r.pooled(arm, state) / m.pooled(arm, state) - 1.0,
                )
            })
            .max_by(|a, b| a.1.abs().total_cmp(&b.1.abs()))
            .expect("cells")
    }

    /// The order the builds ran in run `r`: the builds rotated by r − 1.
    fn order(&self, r: usize) -> Vec<&'static str> {
        let b = self.check.builds;
        (0..3).map(|i| b[(i + r - 1) % 3]).collect()
    }

    /// Each cell's new ÷ base within each run, and the base build's own
    /// spread across runs: what separates a change between builds from the
    /// machine's drift during the session (D-102's stopped check).
    pub fn within_runs(&self) -> String {
        let mut w = String::new();
        let [base, _, new] = self.check.builds;
        let (m, n) = (self.build(base), self.build(new));
        let pct = |x: f64| format!("{:+.1}%", 100.0 * x);
        let runs: Vec<usize> = m.per_run(CELLS[0].0, CELLS[0].1).keys().copied().collect();
        let head: Vec<String> = runs
            .iter()
            .map(|r| format!("Run {r} ({})", self.order(*r).join(", ")))
            .collect();
        writeln!(
            w,
            "| Cell | {} | {base}'s own spread across runs |\n|---|{}---|",
            head.join(" | "),
            "---|".repeat(runs.len())
        )
        .unwrap();
        for (arm, state) in CELLS {
            let (mr, nr) = (m.per_run(arm, state), n.per_run(arm, state));
            let cells: Vec<String> = runs
                .iter()
                .map(|r| match (mr.get(r), nr.get(r)) {
                    (Some(a), Some(b)) => pct(b / a - 1.0),
                    _ => "—".into(),
                })
                .collect();
            let (lo, hi) = mr
                .values()
                .fold((f64::MAX, f64::MIN), |(lo, hi), v| (lo.min(*v), hi.max(*v)));
            writeln!(
                w,
                "| {arm} {state} | {} | {} |",
                cells.join(" | "),
                pct(hi / lo - 1.0)
            )
            .unwrap();
        }
        w
    }

    /// The tables of BENCHMARKS.md §8's block for the check (D-96, D-100).
    /// `m9` gives M9's pooled median for a cell (arm, state) at N = 3,
    /// medium, in ns.
    pub fn markdown(&self, m9: &dyn Fn(&str, &str) -> Option<f64>) -> String {
        let mut w = String::new();
        let [base, mid, new] = self.check.builds;
        let pct = |x: f64| format!("{:+.1}%", 100.0 * x);
        writeln!(
            w,
            "| Build | Commit | Archives | Samples per cell and run |"
        )
        .unwrap();
        writeln!(w, "|---|---|---|---|").unwrap();
        for b in &self.builds {
            writeln!(
                w,
                "| {} | `{}`{} | {} | {} |",
                b.name,
                &b.commit[..b.commit.len().min(7)],
                if b.dirty { " (dirty)" } else { "" },
                b.archives,
                b.samples_per_run()
            )
            .unwrap();
        }
        writeln!(
            w,
            "\n**Medians** (µs; N = 3, medium; pooled over the three runs):\n"
        )
        .unwrap();
        writeln!(
            w,
            "| Cell | M9 (frozen) | {base} | {mid} | {new} | {new} ÷ {base} | {new} ÷ {mid} |"
        )
        .unwrap();
        writeln!(w, "|---|---|---|---|---|---|---|").unwrap();
        let (m, p, r) = (self.build(base), self.build(mid), self.build(new));
        for (arm, state) in CELLS {
            let (a, b, c) = (
                m.pooled(arm, state),
                p.pooled(arm, state),
                r.pooled(arm, state),
            );
            writeln!(
                w,
                "| {arm} {state} | {} | {} | {} | {} | {} | {} |",
                m9(arm, state).map_or("—".into(), us),
                us(a),
                us(b),
                us(c),
                pct(c / a - 1.0),
                pct(c / b - 1.0)
            )
            .unwrap();
        }
        writeln!(
            w,
            "\n**Ratios** (pooled medians; each run's ratio in brackets):\n"
        )
        .unwrap();
        writeln!(w, "| Ratio | {base} | {mid} | {new} |").unwrap();
        writeln!(w, "|---|---|---|---|").unwrap();
        for (label, num, den) in [
            (
                "B / D, warm+prefix",
                ("B", "warm+prefix"),
                ("D", "warm+prefix"),
            ),
            ("A / C, warm", ("A", "warm"), ("C", "warm")),
        ] {
            let cells: Vec<String> = self
                .builds
                .iter()
                .map(|b| {
                    let runs: Vec<String> = b
                        .per_run(num.0, num.1)
                        .iter()
                        .map(|(k, x)| format!("{:.2}", x / b.per_run(den.0, den.1)[k]))
                        .collect();
                    format!(
                        "{:.2} [{}]",
                        b.pooled(num.0, num.1) / b.pooled(den.0, den.1),
                        runs.join(", ")
                    )
                })
                .collect();
            writeln!(w, "| {label} | {} |", cells.join(" | ")).unwrap();
        }
        writeln!(w, "\n**Each run's median** (µs):\n").unwrap();
        writeln!(w, "| Cell | {base} | {mid} | {new} |").unwrap();
        writeln!(w, "|---|---|---|---|").unwrap();
        for (arm, state) in CELLS {
            let cells: Vec<String> = self
                .builds
                .iter()
                .map(|b| {
                    b.per_run(arm, state)
                        .values()
                        .map(|x| us(*x))
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .collect();
            writeln!(w, "| {arm} {state} | {} |", cells.join(" | ")).unwrap();
        }
        let (cell, mv) = self.largest_move();
        writeln!(
            w,
            "\n**The largest move**, {new} against {base}, is {} ({cell}): {} the {:.0}% at which the author asked for a stop.",
            pct(mv),
            if mv.abs() > THRESHOLD { "beyond" } else { "within" },
            100.0 * THRESHOLD
        )
        .unwrap();
        let flagged: Vec<String> = self
            .builds
            .iter()
            .flat_map(|b| {
                b.flagged.iter().flat_map(move |(r, cs)| {
                    cs.iter().map(move |c| format!("{} run {r}: {c}", b.name))
                })
            })
            .collect();
        writeln!(
            w,
            "\n**Thermal flags** (the calibration probe or pmset, around each configuration; none re-run): {}.",
            if flagged.is_empty() {
                "none".to_owned()
            } else {
                flagged.join("; ")
            }
        )
        .unwrap();
        w
    }
}
