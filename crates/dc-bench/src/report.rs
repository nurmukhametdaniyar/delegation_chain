//! `results/summary.md` and `results/summary.json` (SPEC §13.6–§13.8),
//! generated from `results/raw/*.csv`, `results/bytes.json`,
//! `results/memory.json`, `results/env.json` and criterion's estimates.
//! Every number in the summary comes from those files.
//!
//! Per configuration, samples are pooled over runs for the headline
//! statistics, and each run's median is reported for run-to-run variation
//! (D-72).

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
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
    #[serde(skip)]
    pub draws: Vec<f64>,
}

fn read_latency(raw: &Path) -> Result<BTreeMap<Key, BTreeMap<usize, Vec<u64>>>, String> {
    let mut out: BTreeMap<Key, BTreeMap<usize, Vec<u64>>> = BTreeMap::new();
    let mut files: Vec<PathBuf> = fs::read_dir(raw)
        .map_err(|e| format!("{}: {e}", raw.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            name.starts_with("run")
                && name.ends_with(".csv")
                && !name.contains("-calls")
                && !name.contains("-throughput")
        })
        .collect();
    files.sort();
    for f in files {
        let mut r = csv::Reader::from_path(&f).map_err(|e| format!("{}: {e}", f.display()))?;
        for rec in r.records() {
            let rec = rec.map_err(|e| format!("{}: {e}", f.display()))?;
            let get = |i: usize| rec.get(i).unwrap_or("");
            let run: usize = get(0).parse().map_err(|_| "bad run")?;
            let key = Key::new(get(1), get(2), get(3).parse().map_err(|_| "bad N")?, get(4));
            let ns: u64 = get(6).parse().map_err(|_| "bad ns")?;
            out.entry(key).or_default().entry(run).or_default().push(ns);
        }
    }
    Ok(out)
}

/// Statistics for every configuration, bootstrapped on `threads` threads.
pub fn rows(raw: &Path, threads: usize) -> Result<BTreeMap<Key, Row>, String> {
    let data: Vec<(Key, BTreeMap<usize, Vec<u64>>)> = read_latency(raw)?.into_iter().collect();
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
                            draws,
                        },
                    );
                }
            });
        }
    });
    Ok(out.into_inner().unwrap())
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
            "{} [{}, {}] / {}",
            us(r.pooled.median),
            us(r.pooled.median_ci.0),
            us(r.pooled.median_ci.1),
            us(r.pooled.p99)
        ),
        None => "—".into(),
    }
}

fn fmt_ratio(r: &Ratio) -> String {
    format!("{:.3} [{:.3}, {:.3}]", r.value, r.ci.0, r.ci.1)
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

struct Ctx<'a> {
    rows: &'a BTreeMap<Key, Row>,
}

impl Ctx<'_> {
    fn get(&self, arm: &str, state: &str, n: usize, profile: &str) -> Option<&Row> {
        self.rows.get(&Key::new(arm, state, n, profile))
    }

    fn ratio(&self, a: (&str, &str), b: (&str, &str), n: usize, profile: &str) -> Option<Ratio> {
        let x = self.get(a.0, a.1, n, profile)?;
        let y = self.get(b.0, b.1, n, profile)?;
        Some(ratio(&x.pooled, &x.draws, &y.pooled, &y.draws))
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

/// Writes `summary.md` and `summary.json` into `results`.
pub fn report(results: &Path, criterion: &Path, threads: usize, dry: bool) -> Result<(), String> {
    let rows = rows(&results.join("raw"), threads)?;
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
            "> **Dry run (M8). These numbers are not results and must not be reported.**\n"
        )
        .unwrap();
    }
    writeln!(w, "Generated by `dc-bench report` from `{}`. Latency cells are the median in µs, its bootstrap 95% CI, and p99 (µs): `median [lo, hi] / p99`, pooled over runs {:?}.\n", results.display(), runs).unwrap();
    writeln!(
        w,
        "- CPU: {} ({} performance + {} efficiency cores)",
        env["cpu"]["model"], env["cpu"]["performance_cores"], env["cpu"]["efficiency_cores"]
    )
    .unwrap();
    writeln!(
        w,
        "- OS: macOS {} ({}); power source {}, lowpowermode {}",
        env["os"]["product"],
        env["os"]["build"],
        env["power"]["source"],
        env["power"]["lowpowermode"]
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
    let mut profiles: Vec<Profile> = PROFILES.to_vec();
    profiles.push(Profile::MediumApproval);
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
    writeln!(w, "### Ratios of medians (bootstrap 95% CI)\n").unwrap();
    writeln!(
        w,
        "| profile | N | A/C warm | A/C-batch warm | B/D warm+prefix | B/D prefix-miss |"
    )
    .unwrap();
    writeln!(w, "|---|---|---|---|---|---|").unwrap();
    let mut ratios_js = vec![];
    for profile in &profiles {
        for n in NS {
            let pl = profile.label();
            let r = [
                cx.ratio(("A", "warm"), ("C", "warm"), n, pl),
                cx.ratio(("A", "warm"), ("C-batch", "warm"), n, pl),
                cx.ratio(("B", "warm+prefix"), ("D", "warm+prefix"), n, pl),
                cx.ratio(("B", "prefix-miss"), ("D", "prefix-miss"), n, pl),
            ];
            if r.iter().all(Option::is_none) {
                continue;
            }
            let s: Vec<String> = r
                .iter()
                .map(|x| x.as_ref().map_or("—".into(), fmt_ratio))
                .collect();
            writeln!(w, "| {pl} | {n} | {} |", s.join(" | ")).unwrap();
            ratios_js.push(json!({"profile": pl, "n": n, "a_over_c": r[0], "a_over_cbatch": r[1], "b_over_d_hit": r[2], "b_over_d_miss": r[3]}));
        }
    }
    writeln!(
        w,
        "\nHeadline (N = 3, medium): A/C = {}, A/C-batch = {}, B/D (warm+prefix) = {}.\n",
        cx.ratio(("A", "warm"), ("C", "warm"), 3, "medium")
            .as_ref()
            .map_or("—".into(), fmt_ratio),
        cx.ratio(("A", "warm"), ("C-batch", "warm"), 3, "medium")
            .as_ref()
            .map_or("—".into(), fmt_ratio),
        cx.ratio(("B", "warm+prefix"), ("D", "warm+prefix"), 3, "medium")
            .as_ref()
            .map_or("—".into(), fmt_ratio)
    )
    .unwrap();
    js.insert("ratios".into(), json!(ratios_js));

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
        writeln!(
            w,
            "| arm | profile | N | total | bodies | signatures | signature share |"
        )
        .unwrap();
        writeln!(w, "|---|---|---|---|---|---|---|").unwrap();
        for r in b["rows"].as_array().into_iter().flatten() {
            let total = r["total_mean"].as_f64().unwrap_or(0.0);
            let sigs = r["sigs_mean"].as_f64();
            writeln!(
                w,
                "| {} | {} | {} | {:.0} | {} | {} | {} |",
                r["arm"].as_str().unwrap_or(""),
                r["profile"].as_str().unwrap_or(""),
                r["n"],
                total,
                r["bodies_mean"]
                    .as_f64()
                    .map_or("—".into(), |x| format!("{x:.0}")),
                sigs.map_or("—".into(), |x| format!("{x:.0}")),
                sigs.map_or("—".into(), |x| format!("{:.1}%", 100.0 * x / total))
            )
            .unwrap();
        }
        writeln!(w, "\nCertificate size in this encoding: BLS {} bytes, Ed25519 {} bytes. Paper §8.2 assumes 48 + 96 bytes per BLS certificate before any other field.\n", b["certificate_bytes"]["bls"], b["certificate_bytes"]["ed25519"]).unwrap();
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
    writeln!(w, "\n10β/α > 1 means the per-hop term exceeds the fixed term by N = 10; the crossover is N = α/β.\n").unwrap();
    js.insert("fits".into(), json!(fits_js));

    // ---- Q4 ----
    writeln!(w, "## Q4. Multi-pairing saving: A / A-ind\n").unwrap();
    writeln!(w, "| profile | N | warm | cold |").unwrap();
    writeln!(w, "|---|---|---|---|").unwrap();
    for profile in PROFILES {
        for n in NS {
            let pl = profile.label();
            let a = cx.ratio(("A", "warm"), ("A-ind", "warm"), n, pl);
            let b = cx.ratio(("A", "cold"), ("A-ind", "cold"), n, pl);
            writeln!(
                w,
                "| {pl} | {n} | {} | {} |",
                a.as_ref().map_or("—".into(), fmt_ratio),
                b.as_ref().map_or("—".into(), fmt_ratio)
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
    let calls = read_calls(&results.join("raw"));
    writeln!(w, "| arm | injected per call | latency | resolver calls / verify | policy-store calls / verify |").unwrap();
    writeln!(w, "|---|---|---|---|---|").unwrap();
    for arm in ["A", "C"] {
        for ms in RTT_MS {
            let state = format!("cold+rtt{ms}ms");
            let r = cx.get(arm, &state, 3, "medium");
            let c = calls.get(&(arm.to_owned(), state.clone()));
            let per = |x: u64, v: u64| {
                if v == 0 {
                    "—".into()
                } else {
                    format!("{:.2}", x as f64 / v as f64)
                }
            };
            writeln!(
                w,
                "| {arm} | {ms} ms | {} | {} | {} |",
                cell(r),
                c.map_or("—".into(), |c| per(c.1, c.0)),
                c.map_or("—".into(), |c| per(c.2, c.0))
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
    let tp = read_throughput(&results.join("raw"));
    writeln!(
        w,
        "| arm | threads | accepted/s (median over runs) | per run | p99 per call under load (µs) |"
    )
    .unwrap();
    writeln!(w, "|---|---|---|---|---|").unwrap();
    let mut tp_js = vec![];
    for arm in THROUGHPUT_ARMS {
        for t in THREADS {
            let Some(v) = tp.get(&(arm.label().to_owned(), t)) else {
                continue;
            };
            let mut rates: Vec<f64> = v.iter().map(|x| x.1).collect();
            rates.sort_by(f64::total_cmp);
            let med = crate::stats::quantile_sorted(&rates, 0.5);
            let p99s: Vec<String> = v.iter().map(|x| us(x.2)).collect();
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
                rates
                    .iter()
                    .map(|r| format!("{r:.0}"))
                    .collect::<Vec<_>>()
                    .join(", "),
                p99s.join(", ")
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
    writeln!(w, "AIP's figures are **published numbers from different hardware** (Apple M3 Max, macOS 15.3; SPEC §13.10), quoted from SPEC and not re-checked against arXiv:2603.24775. Arm E lacks registry resolution, PoP, revocation, receipts, the nonce cache and parameter binding (paper Table 1).\n").unwrap();
    writeln!(
        w,
        "| profile | N (depth N−1) | E here | AIP published (ms) | E / AIP |"
    )
    .unwrap();
    writeln!(w, "|---|---|---|---|---|").unwrap();
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
                    format!(
                        "{x:.2}{}",
                        if !(1.0 / 3.0..=3.0).contains(&x) {
                            " (outside 3×: investigate)"
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

/// (arm, state) → (verifications, resolver calls, store calls), over runs.
fn read_calls(raw: &Path) -> BTreeMap<(String, String), (u64, u64, u64)> {
    let mut out: BTreeMap<(String, String), (u64, u64, u64)> = BTreeMap::new();
    for e in fs::read_dir(raw).into_iter().flatten().flatten() {
        let p = e.path();
        if !p.to_string_lossy().ends_with("-calls.csv") {
            continue;
        }
        let Ok(mut r) = csv::Reader::from_path(&p) else {
            continue;
        };
        for rec in r.records().flatten() {
            let n = |i: usize| rec.get(i).and_then(|x| x.parse::<u64>().ok()).unwrap_or(0);
            let e = out
                .entry((
                    rec.get(1).unwrap_or("").into(),
                    rec.get(2).unwrap_or("").into(),
                ))
                .or_default();
            e.0 += n(5);
            e.1 += n(6);
            e.2 += n(7);
        }
    }
    out
}

/// Per run: (run, accepted/s, p99 ns).
type ThroughputRuns = Vec<(usize, f64, f64)>;

/// (arm, threads) → per-run throughput.
fn read_throughput(raw: &Path) -> BTreeMap<(String, usize), ThroughputRuns> {
    let mut out: BTreeMap<(String, usize), ThroughputRuns> = BTreeMap::new();
    for e in fs::read_dir(raw).into_iter().flatten().flatten() {
        let p = e.path();
        if !p.to_string_lossy().ends_with("-throughput.csv") {
            continue;
        }
        let Ok(mut r) = csv::Reader::from_path(&p) else {
            continue;
        };
        for rec in r.records().flatten() {
            let f = |i: usize| {
                rec.get(i)
                    .and_then(|x| x.parse::<f64>().ok())
                    .unwrap_or(f64::NAN)
            };
            let run = f(0) as usize;
            let accepted = f(4);
            let wall = f(5);
            out.entry((rec.get(1).unwrap_or("").into(), f(2) as usize))
                .or_default()
                .push((run, accepted / (wall / 1e9), f(7)));
        }
    }
    out
}
