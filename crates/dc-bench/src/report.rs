//! `results/summary.md` and `results/summary.json` (SPEC §13.6–§13.8; the
//! frozen plan §6). Every number comes from the files the harness wrote.
//!
//! The raw data are read only from the zstd archives in `results/archive/`,
//! after every archive's SHA-256 has been checked against
//! `archive/MANIFEST.sha256`. A missing manifest or a mismatch stops the
//! report. Samples from a thermal re-run replace that run's samples of the
//! configuration.
//!
//! Per configuration, samples are pooled over runs for the headline
//! statistics, and each run's median is reported for run-to-run variation
//! (D-72). Ratio verdicts use the ±10% margin and require all runs to agree
//! (frozen plan §6).

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde::Serialize;
use serde_json::{Value, json};

use crate::plan::{BOOTSTRAP, NS, PROFILES, RTT_MS, THREADS, THROUGHPUT_ARMS};
use crate::stats::{Fit, Ratio, Summary, bootstrap_medians, fit, interval, ratio, summarize};
use crate::workload::{Profile, SEED};

/// A configuration's key in the raw CSV.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Key {
    pub arm: String,
    pub state: String,
    pub n: usize,
    pub profile: String,
}

impl Key {
    fn new(arm: &str, state: &str, n: usize, profile: &str) -> Key {
        Key {
            arm: arm.into(),
            state: state.into(),
            n,
            profile: profile.into(),
        }
    }

    fn seed(&self) -> u64 {
        let h = dc_types::digest::sha256(&[
            &SEED.to_le_bytes(),
            self.arm.as_bytes(),
            self.state.as_bytes(),
            &self.n.to_le_bytes(),
            self.profile.as_bytes(),
        ]);
        u64::from_le_bytes(h[..8].try_into().expect("8 bytes"))
    }
}

/// One configuration's statistics.
#[derive(Clone, Debug, Serialize)]
pub struct Row {
    pub key: Key,
    pub pooled: Summary,
    /// Run number → that run's median.
    pub run_medians: BTreeMap<usize, f64>,
    /// Runs whose samples came from a thermal re-run.
    pub rerun_runs: Vec<usize>,
    #[serde(skip)]
    pub draws: Vec<f64>,
}

type Samples = BTreeMap<Key, BTreeMap<usize, Vec<u64>>>;
/// (arm, state, run) → (verifications, resolver calls, store calls).
type Calls = BTreeMap<(String, String, usize), (u64, u64, u64)>;
/// (arm, threads, run) → (accepted/s, p99 ns).
type Throughput = BTreeMap<(String, usize, usize), (f64, f64)>;

/// The raw data, read from verified archives.
#[derive(Default)]
pub struct Raw {
    pub latency: Samples,
    pub reruns: Samples,
    pub calls: Calls,
    pub throughput: Throughput,
    /// Thermal rows: (file stem, config, phase, throttled).
    pub thermal: Vec<(String, String, String, bool)>,
    pub archives: usize,
}

fn hex(h: &[u8]) -> String {
    h.iter().map(|b| format!("{b:02x}")).collect()
}

fn decompress(path: &Path) -> Result<Vec<u8>, String> {
    let out = Command::new("zstd")
        .arg("-dcq")
        .arg(path)
        .output()
        .map_err(|e| format!("zstd: {e}"))?;
    if !out.status.success() {
        return Err(format!("zstd could not decompress {}", path.display()));
    }
    Ok(out.stdout)
}

/// Checks every archive against the manifest, then reads it.
pub fn load_raw(results: &Path) -> Result<Raw, String> {
    let dir = results.join("archive");
    let manifest = fs::read_to_string(dir.join("MANIFEST.sha256")).map_err(|_| {
        format!(
            "no {}: run `dc-bench archive` first; the report reads raw data only from verified archives",
            dir.join("MANIFEST.sha256").display()
        )
    })?;
    let mut raw = Raw::default();
    for line in manifest.lines().filter(|l| !l.trim().is_empty()) {
        let (want, name) = line
            .split_once("  ")
            .ok_or_else(|| format!("malformed manifest line: {line}"))?;
        let path = dir.join(name);
        let bytes = fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let got = hex(&dc_types::digest::sha256(&[&bytes]));
        if got != want {
            return Err(format!(
                "manifest mismatch for {name}: expected {want}, got {got}"
            ));
        }
        raw.archives += 1;
        let file = name.strip_suffix(".zst").unwrap_or(name);
        if file.ends_with(".json") {
            continue;
        }
        let data = decompress(&path)?;
        let mut rd = csv::Reader::from_reader(&data[..]);
        let recs: Vec<csv::StringRecord> = rd
            .records()
            .collect::<Result<_, _>>()
            .map_err(|e| format!("{file}: {e}"))?;
        let rerun = file.contains("-rerun");
        let num = |s: &str| s.parse::<f64>().unwrap_or(f64::NAN);
        if let Some(stem) = file.strip_suffix("-thermal.csv") {
            for r in &recs {
                raw.thermal.push((
                    stem.to_owned(),
                    r[1].to_owned(),
                    r[2].to_owned(),
                    &r[6] == "true",
                ));
            }
        } else if file.ends_with("-calls.csv") {
            for r in &recs {
                let run = num(&r[0]) as usize;
                let v = (num(&r[5]) as u64, num(&r[6]) as u64, num(&r[7]) as u64);
                // A re-run's counts replace the original's.
                if rerun
                    || !raw
                        .calls
                        .contains_key(&(r[1].to_owned(), r[2].to_owned(), run))
                {
                    raw.calls.insert((r[1].to_owned(), r[2].to_owned(), run), v);
                }
            }
        } else if file.ends_with("-throughput.csv") {
            for r in &recs {
                let run = num(&r[0]) as usize;
                let k = (r[1].to_owned(), num(&r[2]) as usize, run);
                let v = (num(&r[4]) / (num(&r[5]) / 1e9), num(&r[7]));
                if rerun || !raw.throughput.contains_key(&k) {
                    raw.throughput.insert(k, v);
                }
            }
        } else {
            let target = if rerun {
                &mut raw.reruns
            } else {
                &mut raw.latency
            };
            for r in &recs {
                let run = num(&r[0]) as usize;
                let key = Key::new(&r[1], &r[2], num(&r[3]) as usize, &r[4]);
                target
                    .entry(key)
                    .or_default()
                    .entry(run)
                    .or_default()
                    .push(num(&r[6]) as u64);
            }
        }
    }
    Ok(raw)
}

/// Statistics for every configuration, with re-run samples in place of the
/// throttled originals, bootstrapped on `threads` threads.
pub fn rows(raw: &Raw, threads: usize) -> BTreeMap<Key, Row> {
    let mut merged = raw.latency.clone();
    let mut rerun_runs: BTreeMap<Key, Vec<usize>> = BTreeMap::new();
    for (key, runs) in &raw.reruns {
        for (run, v) in runs {
            merged
                .entry(key.clone())
                .or_default()
                .insert(*run, v.clone());
            rerun_runs.entry(key.clone()).or_default().push(*run);
        }
    }
    let data: Vec<(Key, BTreeMap<usize, Vec<u64>>)> = merged.into_iter().collect();
    let next = AtomicUsize::new(0);
    let out = Mutex::new(BTreeMap::new());
    std::thread::scope(|s| {
        for _ in 0..threads.max(1) {
            s.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some((key, runs)) = data.get(i) else {
                        break;
                    };
                    let pooled: Vec<u64> = runs.values().flatten().copied().collect();
                    let draws = bootstrap_medians(&pooled, BOOTSTRAP, key.seed());
                    let summary = summarize(&pooled, &draws);
                    let run_medians = runs
                        .iter()
                        .map(|(r, v)| (*r, summarize(v, &[summary.median]).median))
                        .collect();
                    out.lock().unwrap().insert(
                        key.clone(),
                        Row {
                            key: key.clone(),
                            pooled: summary,
                            run_medians,
                            rerun_runs: rerun_runs.get(key).cloned().unwrap_or_default(),
                            draws,
                        },
                    );
                }
            });
        }
    });
    out.into_inner().unwrap()
}

// ---- verdicts (frozen plan §6) ----

/// The practical-significance margin around 1.
pub const MARGIN: f64 = 0.10;

/// A ratio verdict: aggregating arm over non-aggregating arm.
#[derive(Clone, Debug, Serialize)]
pub struct Verdict {
    pub ratio: Ratio,
    /// Each run's ratio of medians.
    pub runs: BTreeMap<usize, f64>,
    pub verdict: &'static str,
}

/// The ±10% rule on the pooled CI, then run agreement.
pub fn verdict(r: &Ratio, runs: &BTreeMap<usize, f64>) -> &'static str {
    let (lo, hi) = r.ci;
    let (lower, upper) = (1.0 - MARGIN, 1.0 + MARGIN);
    let pooled = if hi < lower {
        "net benefit"
    } else if lo > upper {
        "not a net benefit"
    } else if lo >= lower && hi <= upper {
        "no material difference"
    } else {
        return "inconclusive";
    };
    let same_side = |x: f64| match pooled {
        "net benefit" => x < lower,
        "not a net benefit" => x > upper,
        _ => (lower..=upper).contains(&x),
    };
    if !runs.is_empty() && runs.values().all(|&x| same_side(x)) {
        pooled
    } else {
        "inconclusive (runs disagree)"
    }
}

struct Ctx<'a> {
    rows: &'a BTreeMap<Key, Row>,
}

impl Ctx<'_> {
    fn get(&self, arm: &str, state: &str, n: usize, profile: &str) -> Option<&Row> {
        self.rows.get(&Key::new(arm, state, n, profile))
    }

    fn verdict(
        &self,
        a: (&str, &str),
        b: (&str, &str),
        n: usize,
        profile: &str,
    ) -> Option<Verdict> {
        let x = self.get(a.0, a.1, n, profile)?;
        let y = self.get(b.0, b.1, n, profile)?;
        let r = ratio(&x.pooled, &x.draws, &y.pooled, &y.draws);
        let runs: BTreeMap<usize, f64> = x
            .run_medians
            .iter()
            .filter_map(|(run, mx)| y.run_medians.get(run).map(|my| (*run, mx / my)))
            .collect();
        let v = verdict(&r, &runs);
        Some(Verdict {
            ratio: r,
            runs,
            verdict: v,
        })
    }

    fn fit(&self, arm: &str, state: &str, profile: &str) -> Option<Fit> {
        let rows: Vec<&Row> = NS
            .iter()
            .map(|&n| self.get(arm, state, n, profile))
            .collect::<Option<_>>()?;
        let ns: Vec<f64> = NS.iter().map(|&n| n as f64).collect();
        let medians: Vec<f64> = rows.iter().map(|r| r.pooled.median).collect();
        let draws: Vec<&[f64]> = rows.iter().map(|r| r.draws.as_slice()).collect();
        Some(fit(&ns, &medians, &draws))
    }
}

fn us(ns: f64) -> String {
    if ns >= 100_000.0 {
        format!("{:.0}", ns / 1000.0)
    } else {
        format!("{:.1}", ns / 1000.0)
    }
}

fn cell(r: Option<&Row>) -> String {
    match r {
        Some(r) => format!(
            "{} [{}, {}] / {}{}",
            us(r.pooled.median),
            us(r.pooled.median_ci.0),
            us(r.pooled.median_ci.1),
            us(r.pooled.p99),
            if r.rerun_runs.is_empty() { "" } else { " †" }
        ),
        None => "—".into(),
    }
}

fn fmt_ratio(r: &Ratio) -> String {
    format!("{:.3} [{:.3}, {:.3}]", r.value, r.ci.0, r.ci.1)
}

fn fmt_verdict(v: &Option<Verdict>) -> String {
    match v {
        Some(v) => format!(
            "{} — **{}** (runs: {})",
            fmt_ratio(&v.ratio),
            v.verdict,
            v.runs
                .values()
                .map(|x| format!("{x:.3}"))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        None => "—".into(),
    }
}

/// AIP's published Rust verify times for biscuit-auth 6.0 chained mode on
/// an Apple M3 Max (Prakash 2026, arXiv:2603.24775, Tables 4–5, as quoted
/// in SPEC §13.10; not re-checked against the paper). Depth → ms.
pub const AIP_CHAINED_MS: [(usize, f64); 6] = [
    (0, 0.188),
    (1, 0.292),
    (2, 0.403),
    (3, 0.516),
    (4, 0.625),
    (5, 0.745),
];

fn read_json(path: &Path) -> Option<Value> {
    serde_json::from_str(&fs::read_to_string(path).ok()?).ok()
}

/// Criterion's estimates under `dir`: (benchmark id, median ns, CI).
fn criterion_estimates(dir: &Path) -> Vec<(String, f64, (f64, f64))> {
    let mut out = vec![];
    let mut stack = vec![dir.to_owned()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = fs::read_dir(&d) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                if p.file_name().is_some_and(|n| n == "new") {
                    let (Some(b), Some(est)) = (
                        read_json(&p.join("benchmark.json")),
                        read_json(&p.join("estimates.json")),
                    ) else {
                        continue;
                    };
                    let id = b["full_id"].as_str().unwrap_or("?").to_owned();
                    let m = &est["median"];
                    out.push((
                        id,
                        m["point_estimate"].as_f64().unwrap_or(f64::NAN),
                        (
                            m["confidence_interval"]["lower_bound"]
                                .as_f64()
                                .unwrap_or(f64::NAN),
                            m["confidence_interval"]["upper_bound"]
                                .as_f64()
                                .unwrap_or(f64::NAN),
                        ),
                    ));
                } else {
                    stack.push(p);
                }
            }
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// The first N at which A's bytes cross C's, from N = 1 upward.
fn break_even(pts: &[(usize, f64, f64)]) -> String {
    let Some(&(n0, a0, c0)) = pts.first() else {
        return "—".into();
    };
    let start = (a0 - c0).signum();
    for &(n, a, c) in pts {
        if (a - c).signum() != start && a != c {
            return format!(
                "N = {n}: A is {} than C from N = {n} on (A {} C at N = {n0})",
                if a < c { "smaller" } else { "larger" },
                if start > 0.0 { ">" } else { "<" }
            );
        }
    }
    format!(
        "none in range (N = 1–10): A is {} than C throughout",
        if start > 0.0 { "larger" } else { "smaller" }
    )
}

/// Writes `summary.md` and `summary.json` into `results`.
pub fn report(results: &Path, criterion: &Path, threads: usize, dry: bool) -> Result<(), String> {
    let raw = load_raw(results)?;
    let rows = rows(&raw, threads);
    let cx = Ctx { rows: &rows };
    let env = read_json(&results.join("env.json")).unwrap_or(Value::Null);
    let mut md = String::new();
    let mut js = serde_json::Map::new();
    let w = &mut md;

    let runs: std::collections::BTreeSet<usize> = rows
        .values()
        .flat_map(|r| r.run_medians.keys().copied())
        .collect();
    writeln!(w, "# Benchmark summary\n").unwrap();
    if dry {
        writeln!(
            w,
            "> **Dry run. These numbers are not results and must not be reported.**\n"
        )
        .unwrap();
    }
    writeln!(w, "Generated by `dc-bench report` from {} archives verified against `archive/MANIFEST.sha256`. Latency cells are the median in µs, its bootstrap 95% CI, and p99 (µs): `median [lo, hi] / p99`, pooled over runs {:?}. † marks a configuration with samples from a thermal re-run.\n", raw.archives, runs).unwrap();
    writeln!(
        w,
        "- CPU: {} ({} performance + {} efficiency cores)",
        env["cpu"]["model"], env["cpu"]["performance_cores"], env["cpu"]["efficiency_cores"]
    )
    .unwrap();
    writeln!(
        w,
        "- OS: macOS {} ({}); power source {}, powermode {}",
        env["os"]["product"], env["os"]["build"], env["power"]["source"], env["power"]["powermode"]
    )
    .unwrap();
    writeln!(
        w,
        "- Run requirements (AC power, High Power mode, idle) confirmed: {}",
        env["m9_requirements"]["ok"]
    )
    .unwrap();
    writeln!(
        w,
        "- rustc: {}",
        env["toolchain"]["rustc"]
            .as_str()
            .and_then(|s| s.lines().next())
            .unwrap_or("?")
    )
    .unwrap();
    writeln!(
        w,
        "- RUSTFLAGS at build: `{}`; target-cpu=native: {}",
        env["toolchain"]["rustflags_at_build"]
            .as_str()
            .unwrap_or(""),
        env["toolchain"]["target_cpu_native"]
    )
    .unwrap();
    writeln!(
        w,
        "- blst: {}; curve25519-dalek: {}",
        env["blst"]["path"], env["curve25519_dalek_backend"]
    )
    .unwrap();
    writeln!(
        w,
        "- git: {} (dirty: {})\n",
        env["git"]["commit"], env["git"]["dirty"]
    )
    .unwrap();

    // ---- verdicts ----
    writeln!(w, "## Verdicts (frozen plan §6)\n").unwrap();
    writeln!(w, "Ratios are the aggregating arm over the non-aggregating one: `median [95% CI]`. With a ±{:.0}% margin: **net benefit** if the CI's upper bound < {:.2}; **not a net benefit** if the lower bound > {:.2}; **no material difference** if the CI lies within [{:.2}, {:.2}]; **inconclusive** otherwise. A verdict stands only if every run's own ratio of medians is on the same side of the margin; otherwise **inconclusive (runs disagree)**.\n",
        100.0 * MARGIN, 1.0 - MARGIN, 1.0 + MARGIN, 1.0 - MARGIN, 1.0 + MARGIN).unwrap();
    let headline = cx.verdict(("B", "warm+prefix"), ("D", "warm+prefix"), 3, "medium");
    writeln!(
        w,
        "**§1, the deployment pattern (B/D, warm+prefix, N = 3, medium):** {}\n",
        fmt_verdict(&headline)
    )
    .unwrap();
    writeln!(
        w,
        "**Every call a new chain (N = 3, medium, warm):** A/C {}; A/C-batch {}\n",
        fmt_verdict(&cx.verdict(("A", "warm"), ("C", "warm"), 3, "medium")),
        fmt_verdict(&cx.verdict(("A", "warm"), ("C-batch", "warm"), 3, "medium"))
    )
    .unwrap();
    let mut profiles: Vec<Profile> = PROFILES.to_vec();
    profiles.push(Profile::MediumApproval);
    writeln!(
        w,
        "| profile | N | B/D warm+prefix | A/C warm | A/C-batch warm | B/D prefix-miss |"
    )
    .unwrap();
    writeln!(w, "|---|---|---|---|---|---|").unwrap();
    let mut verdicts_js = vec![];
    for profile in &profiles {
        let ns: Vec<usize> = if *profile == Profile::MediumApproval {
            vec![3]
        } else {
            NS.to_vec()
        };
        for n in ns {
            let pl = profile.label();
            let v = [
                cx.verdict(("B", "warm+prefix"), ("D", "warm+prefix"), n, pl),
                cx.verdict(("A", "warm"), ("C", "warm"), n, pl),
                cx.verdict(("A", "warm"), ("C-batch", "warm"), n, pl),
                cx.verdict(("B", "prefix-miss"), ("D", "prefix-miss"), n, pl),
            ];
            writeln!(
                w,
                "| {pl} | {n} | {} |",
                v.iter().map(fmt_verdict).collect::<Vec<_>>().join(" | ")
            )
            .unwrap();
            verdicts_js.push(json!({"profile": pl, "n": n, "b_over_d_hit": v[0], "a_over_c": v[1], "a_over_cbatch": v[2], "b_over_d_miss": v[3]}));
        }
    }
    writeln!(w).unwrap();
    js.insert("headline".into(), json!(headline));
    js.insert("verdicts".into(), json!(verdicts_js));

    // ---- Q1 ----
    writeln!(w, "## Q1. Warm per-invocation latency\n").unwrap();
    let q1_cols: [(&str, &str, &str); 9] = [
        ("A", "warm", "A warm"),
        ("A-ind", "warm", "A-ind warm"),
        ("C", "warm", "C warm"),
        ("C-batch", "warm", "C-batch warm"),
        ("B", "warm+prefix", "B warm+prefix"),
        ("D", "warm+prefix", "D warm+prefix"),
        ("B", "prefix-miss", "B prefix-miss"),
        ("D", "prefix-miss", "D prefix-miss"),
        (
            "A-mt",
            "warm",
            "A-mt warm (supplementary: multi-threaded blst)",
        ),
    ];
    for profile in &profiles {
        let ns: Vec<usize> = if *profile == Profile::MediumApproval {
            vec![3]
        } else {
            NS.to_vec()
        };
        writeln!(w, "### {}\n", profile.label()).unwrap();
        writeln!(
            w,
            "| N | {} |",
            q1_cols.iter().map(|c| c.2).collect::<Vec<_>>().join(" | ")
        )
        .unwrap();
        writeln!(w, "|---|{}", "---|".repeat(q1_cols.len())).unwrap();
        for n in ns {
            let cells: Vec<String> = q1_cols
                .iter()
                .map(|(a, s, _)| cell(cx.get(a, s, n, profile.label())))
                .collect();
            writeln!(w, "| {n} | {} |", cells.join(" | ")).unwrap();
        }
        writeln!(w).unwrap();
    }

    // ---- cold ----
    writeln!(w, "## Cold state\n").unwrap();
    for profile in &profiles {
        let ns: Vec<usize> = if *profile == Profile::MediumApproval {
            vec![3]
        } else {
            NS.to_vec()
        };
        writeln!(w, "### {}\n", profile.label()).unwrap();
        writeln!(w, "| N | A cold | A-ind cold | C cold | C-batch cold |").unwrap();
        writeln!(w, "|---|---|---|---|---|").unwrap();
        for n in ns {
            let c: Vec<String> = ["A", "A-ind", "C", "C-batch"]
                .iter()
                .map(|a| cell(cx.get(a, "cold", n, profile.label())))
                .collect();
            writeln!(w, "| {n} | {} |", c.join(" | ")).unwrap();
        }
        writeln!(w).unwrap();
    }

    // ---- Q2 ----
    writeln!(w, "## Q2. Bytes on the wire\n").unwrap();
    if let Some(b) = read_json(&results.join("bytes.json")) {
        let get = |arm: &str, profile: &str, n: usize| -> Option<(f64, f64)> {
            b["rows"]
                .as_array()?
                .iter()
                .find(|r| {
                    r["arm"].as_str().is_some_and(|a| a.starts_with(arm))
                        && (arm != "A" || !r["arm"].as_str().unwrap_or("").starts_with("A-ind"))
                        && r["profile"] == profile
                        && r["n"] == n
                })
                .map(|r| {
                    (
                        r["total_mean"].as_f64().unwrap_or(f64::NAN),
                        r["sigs_mean"].as_f64().unwrap_or(f64::NAN),
                    )
                })
        };
        writeln!(w, "Bytes are exact means over 20 sampled chains per cell (they vary only with identifier lengths).\n").unwrap();
        writeln!(w, "### Primary: A against C\n").unwrap();
        let mut be_js = vec![];
        for profile in Profile::ALL {
            let pl = profile.label();
            let pts: Vec<(usize, f64, f64)> = (1..=10)
                .filter_map(|n| Some((n, get("A", pl, n)?.0, get("C", pl, n)?.0)))
                .collect();
            if pts.is_empty() {
                continue;
            }
            let be = break_even(&pts);
            writeln!(w, "**{pl}** — break-even: {be}\n").unwrap();
            writeln!(
                w,
                "| N | A total | C total | A − C | A / C | A signatures | C signatures |"
            )
            .unwrap();
            writeln!(w, "|---|---|---|---|---|---|---|").unwrap();
            for &(n, a, c) in &pts {
                let (sa, sc) = (get("A", pl, n).map(|x| x.1), get("C", pl, n).map(|x| x.1));
                writeln!(
                    w,
                    "| {n} | {a:.0} | {c:.0} | {:+.0} | {:.3} | {} | {} |",
                    a - c,
                    a / c,
                    sa.map_or("—".into(), |x| format!("{x:.0}")),
                    sc.map_or("—".into(), |x| format!("{x:.0}"))
                )
                .unwrap();
            }
            writeln!(w).unwrap();
            be_js.push(json!({"profile": pl, "break_even": be}));
        }
        writeln!(w, "medium-approval chains also carry the receipt: its approver key and signature are 48 + 96 bytes under BLS and 32 + 64 under Ed25519.\n").unwrap();
        writeln!(w, "### Aggregation ablation: A against A-ind\n").unwrap();
        writeln!(
            w,
            "| profile | N | A total | A-ind total | saved by aggregation | A-ind / A |"
        )
        .unwrap();
        writeln!(w, "|---|---|---|---|---|---|").unwrap();
        for profile in Profile::ALL {
            for n in NS {
                if let (Some(a), Some(i)) = (
                    get("A", profile.label(), n),
                    get("A-ind", profile.label(), n),
                ) {
                    writeln!(
                        w,
                        "| {} | {n} | {:.0} | {:.0} | {:.0} | {:.3} |",
                        profile.label(),
                        a.0,
                        i.0,
                        i.0 - a.0,
                        i.0 / a.0
                    )
                    .unwrap();
                }
            }
        }
        writeln!(w).unwrap();
        writeln!(w, "### Arm E (Biscuit tokens)\n").unwrap();
        writeln!(w, "| profile | N (depth N−1) | token bytes |").unwrap();
        writeln!(w, "|---|---|---|").unwrap();
        for r in b["rows"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|r| r["arm"] == "E")
        {
            writeln!(
                w,
                "| {} | {} | {:.0} |",
                r["profile"].as_str().unwrap_or(""),
                r["n"],
                r["total_mean"].as_f64().unwrap_or(f64::NAN)
            )
            .unwrap();
        }
        writeln!(w, "\nCertificate size in this encoding: BLS {} bytes, Ed25519 {} bytes. Paper §8.2 assumes 48 + 96 bytes per BLS certificate before any other field; `bytes.json` also gives every chain's size with N + 1 certificates inline.\n", b["certificate_bytes"]["bls"], b["certificate_bytes"]["ed25519"]).unwrap();
        js.insert("break_even".into(), json!(be_js));
        js.insert("bytes".into(), b);
    } else {
        writeln!(w, "_No `bytes.json`._\n").unwrap();
    }

    // ---- Q3 ----
    writeln!(w, "## Q3. Cost model for arm A: latency = α + β·N\n").unwrap();
    writeln!(w, "| state | profile | α (µs) [CI] | β (µs) [CI] | R² | 10β/α [CI] | residuals (µs, N = 1, 2, 3, 5, 10) |").unwrap();
    writeln!(w, "|---|---|---|---|---|---|---|").unwrap();
    let mut fits_js = vec![];
    for state in ["warm", "cold"] {
        for profile in PROFILES {
            if let Some(f) = cx.fit("A", state, profile.label()) {
                writeln!(w, "| {state} | {} | {} [{}, {}] | {} [{}, {}] | {:.4} | {:.3} [{:.3}, {:.3}] | {} |",
                    profile.label(), us(f.alpha), us(f.alpha_ci.0), us(f.alpha_ci.1),
                    us(f.beta), us(f.beta_ci.0), us(f.beta_ci.1), f.r2,
                    f.ten_beta_over_alpha, f.ten_beta_over_alpha_ci.0, f.ten_beta_over_alpha_ci.1,
                    f.residuals.iter().map(|r| format!("{:.1}", r / 1000.0)).collect::<Vec<_>>().join(", ")).unwrap();
                fits_js.push(
                    json!({"arm": "A", "state": state, "profile": profile.label(), "fit": f}),
                );
            }
        }
    }
    writeln!(w, "\nThe per-hop term dominates by N = 10 if 10β/α's CI lies above 1, the fixed term if it lies below, neither otherwise; the crossover is N = α/β.\n").unwrap();
    js.insert("fits".into(), json!(fits_js));

    // ---- Q4 ----
    writeln!(w, "## Q4. Multi-pairing saving: A / A-ind\n").unwrap();
    writeln!(w, "| profile | N | warm | cold |").unwrap();
    writeln!(w, "|---|---|---|---|").unwrap();
    for profile in PROFILES {
        for n in NS {
            let pl = profile.label();
            writeln!(
                w,
                "| {pl} | {n} | {} | {} |",
                fmt_verdict(&cx.verdict(("A", "warm"), ("A-ind", "warm"), n, pl)),
                fmt_verdict(&cx.verdict(("A", "cold"), ("A-ind", "cold"), n, pl))
            )
            .unwrap();
        }
    }
    writeln!(w).unwrap();

    // ---- Q5 ----
    writeln!(
        w,
        "## Q5. Cold path with injected latency (N = 3, medium)\n"
    )
    .unwrap();
    writeln!(w, "| arm | injected per call | latency | resolver calls / verify | policy-store calls / verify |").unwrap();
    writeln!(w, "|---|---|---|---|---|").unwrap();
    for arm in ["A", "C"] {
        for ms in RTT_MS {
            let state = format!("cold+rtt{ms}ms");
            let (v, rc, sc) = raw
                .calls
                .iter()
                .filter(|((a, s, _), _)| a == arm && *s == state)
                .fold((0, 0, 0), |acc, (_, x)| {
                    (acc.0 + x.0, acc.1 + x.1, acc.2 + x.2)
                });
            let per = |x: u64| {
                if v == 0 {
                    "—".into()
                } else {
                    format!("{:.2}", x as f64 / v as f64)
                }
            };
            writeln!(
                w,
                "| {arm} | {ms} ms | {} | {} | {} |",
                cell(cx.get(arm, &state, 3, "medium")),
                per(rc),
                per(sc)
            )
            .unwrap();
        }
    }
    writeln!(w).unwrap();

    // ---- Q6 ----
    writeln!(
        w,
        "## Q6. Throughput (medium, N = 3; 14 threads includes efficiency cores)\n"
    )
    .unwrap();
    writeln!(w, "| arm | threads | accepted/s (median over runs) | per run | p99 per call under load (µs), per run |").unwrap();
    writeln!(w, "|---|---|---|---|---|").unwrap();
    let mut tp_js = vec![];
    for arm in THROUGHPUT_ARMS {
        for t in THREADS {
            let v: Vec<(usize, f64, f64)> = raw
                .throughput
                .iter()
                .filter(|((a, th, _), _)| a == arm.label() && *th == t)
                .map(|((_, _, r), (rate, p99))| (*r, *rate, *p99))
                .collect();
            if v.is_empty() {
                continue;
            }
            let mut rates: Vec<f64> = v.iter().map(|x| x.1).collect();
            rates.sort_by(f64::total_cmp);
            let med = crate::stats::quantile_sorted(&rates, 0.5);
            writeln!(
                w,
                "| {} | {t}{} | {:.0} | {} | {} |",
                arm.label(),
                if t == 14 {
                    " (includes efficiency cores)"
                } else {
                    ""
                },
                med,
                v.iter()
                    .map(|x| format!("{:.0}", x.1))
                    .collect::<Vec<_>>()
                    .join(", "),
                v.iter().map(|x| us(x.2)).collect::<Vec<_>>().join(", ")
            )
            .unwrap();
            tp_js.push(
                json!({"arm": arm.label(), "threads": t, "accepted_per_s": rates, "median": med}),
            );
        }
    }
    writeln!(w).unwrap();
    js.insert("throughput".into(), json!(tp_js));

    // ---- Q9 ----
    writeln!(
        w,
        "## Q9. Arm E (Biscuit) against AIP's published figures\n"
    )
    .unwrap();
    writeln!(w, "AIP's figures are **published numbers from different hardware**: an Apple M3 Max under macOS 15.3, against this machine's M4 Max (SPEC §13.10). They are quoted from SPEC and not re-checked against arXiv:2603.24775. Arm E lacks registry resolution, PoP, revocation, receipts, the nonce cache and parameter binding (paper Table 1). **Sanity rule (frozen plan §8):** a ratio outside about 3× at matching depth is investigated before anything about arm E is reported.\n").unwrap();
    writeln!(
        w,
        "| profile | N (depth N−1) | E here | AIP published (ms) | E / AIP |"
    )
    .unwrap();
    writeln!(w, "|---|---|---|---|---|").unwrap();
    let mut e_flags = vec![];
    for profile in PROFILES {
        for n in NS {
            let r = cx.get("E", "stateless", n, profile.label());
            let aip = AIP_CHAINED_MS
                .iter()
                .find(|(d, _)| *d == n - 1)
                .map(|x| x.1);
            let q = match (r, aip) {
                (Some(r), Some(a)) => {
                    let x = r.pooled.median / (a * 1e6);
                    let out = !(1.0 / 3.0..=3.0).contains(&x);
                    if out {
                        e_flags.push(json!({"profile": profile.label(), "n": n, "ratio": x}));
                    }
                    format!(
                        "{x:.2}{}",
                        if out {
                            " (**outside 3×: investigate before reporting**)"
                        } else {
                            ""
                        }
                    )
                }
                _ => "—".into(),
            };
            writeln!(
                w,
                "| {} | {n} | {} | {} | {q} |",
                profile.label(),
                cell(r),
                aip.map_or("—".into(), |a| format!("{a}"))
            )
            .unwrap();
        }
    }
    writeln!(w).unwrap();
    js.insert("arm_e_outside_3x".into(), json!(e_flags));

    // ---- Q10 ----
    writeln!(w, "## Q10. Memory per entry\n").unwrap();
    if let Some(m) = read_json(&results.join("memory.json")) {
        writeln!(
            w,
            "| structure | entries | bytes retained | bytes per entry |"
        )
        .unwrap();
        writeln!(w, "|---|---|---|---|").unwrap();
        for r in m["rows"].as_array().into_iter().flatten() {
            writeln!(
                w,
                "| {} | {} | {} | {:.1} |",
                r["structure"].as_str().unwrap_or(""),
                r["entries"],
                r["bytes"],
                r["bytes_per_entry"].as_f64().unwrap_or(f64::NAN)
            )
            .unwrap();
        }
        writeln!(w).unwrap();
        js.insert("memory".into(), m);
    } else {
        writeln!(w, "_No `memory.json`._\n").unwrap();
    }

    // ---- criterion ----
    writeln!(w, "## Q7, Q8 and primitives (criterion)\n").unwrap();
    let est = criterion_estimates(criterion);
    if est.is_empty() {
        writeln!(
            w,
            "_No criterion estimates under `{}`._\n",
            criterion.display()
        )
        .unwrap();
    } else {
        writeln!(w, "| benchmark | median (µs) [95% CI] |").unwrap();
        writeln!(w, "|---|---|").unwrap();
        for (id, m, (lo, hi)) in &est {
            writeln!(w, "| {id} | {} [{}, {}] |", us(*m), us(*lo), us(*hi)).unwrap();
        }
        writeln!(w).unwrap();
    }
    js.insert(
        "criterion".into(),
        json!(
            est.iter()
                .map(|(id, m, ci)| json!({"id": id, "median_ns": m, "ci": ci}))
                .collect::<Vec<_>>()
        ),
    );

    // ---- thermal ----
    writeln!(w, "## Thermal state (frozen plan §5)\n").unwrap();
    let throttled: Vec<&(String, String, String, bool)> = raw
        .thermal
        .iter()
        .filter(|t| t.3 && !t.0.contains("-rerun"))
        .collect();
    let rerun_throttled: Vec<&(String, String, String, bool)> = raw
        .thermal
        .iter()
        .filter(|t| t.3 && t.0.contains("-rerun"))
        .collect();
    writeln!(w, "{} thermal readings; {} throttled readings in the main runs (their configurations were re-run; see `BENCH_LOG.md`); {} throttled readings in the re-runs.\n",
        raw.thermal.len(), throttled.len(), rerun_throttled.len()).unwrap();
    for t in throttled.iter().chain(&rerun_throttled) {
        writeln!(w, "- {} `{}` ({})", t.0, t.1, t.2).unwrap();
    }
    writeln!(w).unwrap();

    // ---- claims ----
    writeln!(w, "## Paper claims (SPEC §13.11)\n").unwrap();
    writeln!(w, "Claims are evaluated against paper revision **2026-09-29**, the revision the plan is frozen against. `BENCHMARKS.md` gives each verdict, and says beside it if a later revision changed the claim.\n").unwrap();

    // ---- run-to-run ----
    writeln!(w, "## Run-to-run variation\n").unwrap();
    writeln!(
        w,
        "Per configuration, each run's median (µs) and the spread (max − min) / pooled median.\n"
    )
    .unwrap();
    writeln!(w, "| configuration | run medians | spread |").unwrap();
    writeln!(w, "|---|---|---|").unwrap();
    let mut spreads: Vec<f64> = vec![];
    for r in rows.values() {
        let meds: Vec<f64> = r.run_medians.values().copied().collect();
        let (lo, hi) = meds
            .iter()
            .fold((f64::MAX, f64::MIN), |(a, b), &x| (a.min(x), b.max(x)));
        let spread = (hi - lo) / r.pooled.median;
        spreads.push(spread);
        writeln!(
            w,
            "| {} {} N={} {} | {} | {:.1}% |",
            r.key.arm,
            r.key.state,
            r.key.n,
            r.key.profile,
            meds.iter().map(|m| us(*m)).collect::<Vec<_>>().join(", "),
            100.0 * spread
        )
        .unwrap();
    }
    if !spreads.is_empty() {
        let (lo, hi) = interval(&spreads);
        writeln!(w, "\nAcross configurations, the spread's 2.5th–97.5th percentile range is {:.1}%–{:.1}%.\n", 100.0 * lo, 100.0 * hi).unwrap();
    }

    js.insert(
        "configurations".into(),
        json!(rows.values().collect::<Vec<_>>()),
    );
    js.insert("dry".into(), json!(dry));
    fs::write(results.join("summary.md"), md).map_err(|e| e.to_string())?;
    fs::write(
        results.join("summary.json"),
        serde_json::to_string_pretty(&Value::Object(js)).unwrap() + "\n",
    )
    .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(lo: f64, hi: f64) -> Ratio {
        Ratio {
            value: (lo + hi) / 2.0,
            ci: (lo, hi),
        }
    }

    fn runs(v: &[f64]) -> BTreeMap<usize, f64> {
        v.iter().enumerate().map(|(i, x)| (i + 1, *x)).collect()
    }

    #[test]
    fn the_margin_rule() {
        assert_eq!(
            verdict(&r(0.70, 0.89), &runs(&[0.8, 0.8, 0.85])),
            "net benefit"
        );
        assert_eq!(
            verdict(&r(1.11, 1.30), &runs(&[1.2, 1.2, 1.2])),
            "not a net benefit"
        );
        assert_eq!(
            verdict(&r(0.95, 1.05), &runs(&[1.0, 0.97, 1.02])),
            "no material difference"
        );
        // The CI straddles a margin edge.
        assert_eq!(
            verdict(&r(0.85, 0.95), &runs(&[0.9, 0.9, 0.9])),
            "inconclusive"
        );
        assert_eq!(
            verdict(&r(0.95, 1.15), &runs(&[1.0, 1.0, 1.0])),
            "inconclusive"
        );
    }

    #[test]
    fn runs_must_agree() {
        assert_eq!(
            verdict(&r(0.70, 0.89), &runs(&[0.8, 0.8, 0.92])),
            "inconclusive (runs disagree)"
        );
        assert_eq!(
            verdict(&r(1.11, 1.30), &runs(&[1.2, 1.05, 1.2])),
            "inconclusive (runs disagree)"
        );
        assert_eq!(
            verdict(&r(0.95, 1.05), &runs(&[1.0, 1.12, 1.0])),
            "inconclusive (runs disagree)"
        );
    }

    #[test]
    fn break_even_is_the_first_crossing() {
        let pts = [
            (1, 500.0, 400.0),
            (2, 520.0, 500.0),
            (3, 540.0, 600.0),
            (4, 560.0, 700.0),
        ];
        assert!(break_even(&pts).starts_with("N = 3: A is smaller"));
        let none = [(1, 300.0, 400.0), (2, 320.0, 500.0)];
        assert!(break_even(&none).starts_with("none in range"));
    }
}
