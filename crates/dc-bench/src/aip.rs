//! AIP's own chained-mode benchmark, run on this machine (D-79; exploratory,
//! not pre-registered).
//!
//! - **What runs.** `bench_chained` from AIP's repository at [`COMMIT`],
//!   the commit that prepared arXiv:2603.24775v1. It is built twice by
//!   `scripts/exploratory-session.sh`, with `cargo build --release` and no
//!   build flags, against one resolved `Cargo.lock` (AIP commits none):
//!   - **unmodified**, whose printed means are AIP's own statistic;
//!   - **timings**, which differs only by `scripts/aip-timings.patch`: after
//!     the timed loop, it prints each depth's 100 timings to stderr. They
//!     give the median, which AIP does not report.
//! - **How.** Three runs of each, alternating which goes first, with pmset
//!   and the calibration probe read around each, on M9's machine state.
//! - **Reading.** Like the M9 report, raw outputs are read only from the
//!   zstd archives under `archive/`, after checking each against
//!   `archive/MANIFEST.sha256`.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use serde_json::Value;

use crate::report::{AIP_CHAINED_MS, decompress, hex};
use crate::stats::quantile_sorted;

/// AIP's repository and the commit that prepared its arXiv submission.
pub const URL: &str = "https://github.com/sunilp/aip.git";
pub const COMMIT: &str = "ad2faa62420af75ca26b235fb698a671281d1ade";
/// The two builds, by directory name.
pub const VARIANTS: [&str; 2] = ["unmodified", "timings"];
/// Runs of each build.
pub const RUNS: usize = 3;
/// The crates whose resolved versions are recorded.
pub const CRATES: [&str; 3] = ["biscuit-auth", "ed25519-dalek", "curve25519-dalek"];

/// `name → version` for `names` in a `Cargo.lock`.
pub fn lock_versions(lock: &str, names: &[&str]) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut name: Option<String> = None;
    for l in lock.lines() {
        if let Some(n) = l.strip_prefix("name = ") {
            name = Some(n.trim_matches('"').to_owned());
        } else if let Some(v) = l.strip_prefix("version = ")
            && let Some(n) = name.take()
            && names.contains(&n.as_str())
        {
            out.entry(n)
                .and_modify(|e: &mut String| {
                    e.push_str(", ");
                    e.push_str(v.trim_matches('"'))
                })
                .or_insert_with(|| v.trim_matches('"').to_owned());
        }
    }
    out
}

/// One process's output.
#[derive(Clone, Debug, Default)]
pub struct Output {
    /// depth → (mean token size in base64 characters, mean verify ms), as
    /// AIP's binary prints them.
    pub means: BTreeMap<usize, (f64, f64)>,
    /// depth → each verify timing in ms (the timings build only).
    pub timings: BTreeMap<usize, Vec<f64>>,
}

/// The raw outputs, read from verified archives.
#[derive(Default)]
pub struct Data {
    /// (run, variant) → output.
    pub runs: BTreeMap<(usize, String), Output>,
    pub meta: Value,
    /// (configuration, signal) of each flagged invocation (recorded, not
    /// re-run).
    pub flagged: Vec<(String, String)>,
    pub archives: usize,
}

fn parse_stdout(file: &str, data: &[u8]) -> Result<BTreeMap<usize, (f64, f64)>, String> {
    let v: Value = serde_json::from_slice(data).map_err(|e| format!("{file}: {e}"))?;
    let mut out = BTreeMap::new();
    for d in v["depths"].as_array().ok_or(format!("{file}: no depths"))? {
        let depth = d["depth"].as_u64().ok_or(format!("{file}: depth"))? as usize;
        let size = d["token_size_bytes"]
            .as_f64()
            .ok_or(format!("{file}: size"))?;
        let ms = d["verify_ms"]
            .as_f64()
            .ok_or(format!("{file}: verify_ms"))?;
        out.insert(depth, (size, ms));
    }
    Ok(out)
}

fn parse_stderr(file: &str, data: &[u8]) -> Result<BTreeMap<usize, Vec<f64>>, String> {
    let text = String::from_utf8_lossy(data);
    let mut out = BTreeMap::new();
    for l in text.lines() {
        let Some(rest) = l.strip_prefix("verify_ms depth=") else {
            continue;
        };
        let (d, list) = rest
            .split_once(' ')
            .ok_or_else(|| format!("{file}: malformed line {l}"))?;
        let depth: usize = d.parse().map_err(|_| format!("{file}: depth {d}"))?;
        let v: Vec<f64> = list
            .trim()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .split(',')
            .map(|x| x.trim().parse::<f64>().map_err(|_| format!("{file}: {x}")))
            .collect::<Result<_, _>>()?;
        out.insert(depth, v);
    }
    Ok(out)
}

/// Checks every archive under `dir/archive` against its manifest, then
/// reads it.
pub fn load(dir: &Path) -> Result<Data, String> {
    let adir = dir.join("archive");
    let manifest = fs::read_to_string(adir.join("MANIFEST.sha256"))
        .map_err(|_| format!("no {}", adir.join("MANIFEST.sha256").display()))?;
    let mut d = Data::default();
    for line in manifest.lines().filter(|l| !l.trim().is_empty()) {
        let (want, name) = line
            .split_once("  ")
            .ok_or_else(|| format!("malformed manifest line: {line}"))?;
        let path = adir.join(name);
        let bytes = fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let got = hex(&dc_types::digest::sha256(&[&bytes]));
        if got != want {
            return Err(format!(
                "manifest mismatch for {name}: expected {want}, got {got}"
            ));
        }
        d.archives += 1;
        let file = name.strip_suffix(".zst").unwrap_or(name);
        let data = decompress(&path)?;
        // run{r}-{variant}.json / run{r}-{variant}.stderr.txt
        let key = |stem: &str| -> Result<(usize, String), String> {
            let (r, v) = stem
                .strip_prefix("run")
                .and_then(|s| s.split_once('-'))
                .ok_or_else(|| format!("unexpected archive {name}"))?;
            Ok((
                r.parse()
                    .map_err(|_| format!("unexpected archive {name}"))?,
                v.to_owned(),
            ))
        };
        if file == "meta.json" {
            d.meta = serde_json::from_slice(&data).map_err(|e| format!("{file}: {e}"))?;
        } else if file == "thermal.csv" {
            let mut m: BTreeMap<String, (bool, bool)> = BTreeMap::new();
            for r in csv::Reader::from_reader(&data[..]).records() {
                let r = r.map_err(|e| format!("{file}: {e}"))?;
                if &r[2] == "before" || &r[2] == "after" {
                    let e = m.entry(r[1].to_owned()).or_default();
                    e.0 |= &r[6] == "true";
                    e.1 |= &r[9] == "true";
                }
            }
            for (cfg, (pm, pr)) in m {
                let sig = match (pm, pr) {
                    (true, true) => "pmset and probe",
                    (true, false) => "pmset",
                    (false, true) => "probe",
                    (false, false) => continue,
                };
                d.flagged.push((cfg, sig.to_owned()));
            }
        } else if let Some(stem) = file.strip_suffix(".stderr.txt") {
            d.runs.entry(key(stem)?).or_default().timings = parse_stderr(file, &data)?;
        } else if let Some(stem) = file.strip_suffix(".json") {
            d.runs.entry(key(stem)?).or_default().means = parse_stdout(file, &data)?;
        }
        // aip-Cargo.lock is archived for the record; versions are in meta.
    }
    Ok(d)
}

fn median(v: &mut [f64]) -> f64 {
    v.sort_by(f64::total_cmp);
    quantile_sorted(v, 0.5)
}

/// One depth's statistics on this machine.
#[derive(Clone, Debug)]
pub struct Depth {
    /// The unmodified build's printed means, by run (AIP's own statistic).
    pub run_means: BTreeMap<usize, f64>,
    /// The timings build: each run's median, and the median and mean of all
    /// its timings pooled.
    pub run_medians: BTreeMap<usize, f64>,
    pub median: f64,
    pub mean: f64,
    /// The mean token size in base64 characters, as the binary prints it.
    pub size: f64,
}

impl Data {
    pub fn depths(&self) -> Vec<usize> {
        let mut v: Vec<usize> = self
            .runs
            .values()
            .flat_map(|o| o.means.keys().copied())
            .collect();
        v.sort();
        v.dedup();
        v
    }

    pub fn depth(&self, depth: usize) -> Result<Depth, String> {
        let mut run_means = BTreeMap::new();
        let mut run_medians = BTreeMap::new();
        let mut pooled = vec![];
        let mut size = f64::NAN;
        for ((run, variant), o) in &self.runs {
            if variant == VARIANTS[0] {
                let (s, m) = *o
                    .means
                    .get(&depth)
                    .ok_or_else(|| format!("run {run}: no depth {depth}"))?;
                run_means.insert(*run, m);
                size = s;
            } else {
                let mut t = o
                    .timings
                    .get(&depth)
                    .cloned()
                    .ok_or_else(|| format!("run {run}: no timings at depth {depth}"))?;
                pooled.extend_from_slice(&t);
                run_medians.insert(*run, median(&mut t));
            }
        }
        if run_means.is_empty() || pooled.is_empty() {
            return Err(format!("no AIP data at depth {depth}"));
        }
        let mean = pooled.iter().sum::<f64>() / pooled.len() as f64;
        Ok(Depth {
            run_means,
            run_medians,
            median: median(&mut pooled),
            mean,
            size,
        })
    }

    fn published(depth: usize) -> Option<f64> {
        AIP_CHAINED_MS.iter().find(|x| x.0 == depth).map(|x| x.1)
    }

    /// The generated block of BENCHMARKS.md §8. `e(profile, n)` gives arm
    /// E's pooled M9 median in ns at DC's N; `published_size(depth)` AIP's
    /// published size.
    pub fn markdown(
        &self,
        e: &dyn Fn(&str, usize) -> Option<f64>,
        published_size: &dyn Fn(usize) -> Option<f64>,
    ) -> Result<String, String> {
        let m = &self.meta;
        let s = |v: &Value| v.as_str().unwrap_or("?").to_owned();
        let mut w = String::new();
        let _ = writeln!(
            w,
            "Built from `{}` at `{}`: {}. Cargo resolved biscuit-auth {}, ed25519-dalek {} and curve25519-dalek {}; toolchain: {}. {} of each build; the unmodified source was checked against the commit ({}).\n",
            s(&m["url"]),
            &COMMIT[..7],
            s(&m["build"]),
            s(&m["resolved"]["biscuit-auth"]),
            s(&m["resolved"]["ed25519-dalek"]),
            s(&m["resolved"]["curve25519-dalek"]),
            s(&m["toolchain"]),
            match m["runs"].as_u64() {
                Some(1) => "1 run".to_owned(),
                Some(k) => format!("{k} runs"),
                None => "? runs".to_owned(),
            },
            s(&m["source_check"]),
        );
        let _ = writeln!(
            w,
            "| Depth (DC's N) | Token, base64 chars: here / published | AIP published, ms (mean of 100, M3 Max) | AIP here, ms: mean of 100, unmodified, per run | AIP here, ms: median of 100, per run | AIP here, ms: median / mean of all runs' timings | Here ÷ published (means) | E here, ms (median; small / medium) | E ÷ AIP here (medians; small / medium) |\n|---|---|---|---|---|---|---|---|---|"
        );
        let f3 = |x: f64| format!("{x:.3}");
        let list =
            |v: &BTreeMap<usize, f64>| v.values().map(|x| f3(*x)).collect::<Vec<_>>().join(", ");
        for depth in self.depths() {
            let d = self.depth(depth)?;
            let mut means: Vec<f64> = d.run_means.values().copied().collect();
            let here_mean = median(&mut means);
            let pubm = Self::published(depth);
            let n = depth + 1;
            let es = e("small", n);
            let em = e("medium", n);
            let opt = |x: Option<f64>, f: &dyn Fn(f64) -> String| x.map_or("—".to_owned(), f);
            let _ = writeln!(
                w,
                "| {depth} ({n}) | {:.0} / {} | {} | {} | {} | {} / {} | {} | {} / {} | {} / {} |",
                d.size,
                opt(published_size(depth), &|x| format!("{x:.0}")),
                opt(pubm, &|x| format!("{x}")),
                list(&d.run_means),
                list(&d.run_medians),
                f3(d.median),
                f3(d.mean),
                opt(pubm, &|p| format!("{:.2}", here_mean / p)),
                opt(es, &|x| f3(x / 1e6)),
                opt(em, &|x| f3(x / 1e6)),
                opt(es, &|x| format!("{:.2}", x / 1e6 / d.median)),
                opt(em, &|x| format!("{:.2}", x / 1e6 / d.median)),
            );
        }
        let _ = writeln!(
            w,
            "\n\"Here ÷ published\" uses the median of the unmodified runs' means. Thermal readings around each invocation: {}.",
            self.flags()
        );
        Ok(w.trim_end().to_owned())
    }

    pub fn flags(&self) -> String {
        if self.flagged.is_empty() {
            return "none was flagged".into();
        }
        format!(
            "flagged and not re-run: {}",
            self.flagged
                .iter()
                .map(|(c, s)| format!("`{c}` ({s})"))
                .collect::<Vec<_>>()
                .join("; ")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outputs_parse() {
        let out = br#"{
  "language": "rust",
  "mode": "chained",
  "iterations_per_depth": 100,
  "depths": [
    {"depth": 0, "token_size_bytes": 520, "create_ms": 0.0872, "verify_ms": 0.1877},
    {"depth": 1, "token_size_bytes": 940, "append_ms": 0.0726, "verify_ms": 0.2922}
  ]
}"#;
        let m = parse_stdout("x", out).unwrap();
        assert_eq!(m[&1], (940.0, 0.2922));
        let err = b"verify_ms depth=0 [0.1, 0.25, 0.3]\nverify_ms depth=1 [0.5]\n";
        let t = parse_stderr("x", err).unwrap();
        assert_eq!(t[&0], vec![0.1, 0.25, 0.3]);
        let lock = "[[package]]\nname = \"biscuit-auth\"\nversion = \"6.0.0\"\n\n[[package]]\nname = \"other\"\nversion = \"1.0.0\"\n";
        assert_eq!(
            lock_versions(lock, &CRATES)["biscuit-auth"],
            "6.0.0".to_owned()
        );
    }
}
