//! The exploratory phase breakdown (not pre-registered; D-77, BENCH_LOG.md).
//!
//! - **What runs.** Arms A and C, warm, N = 3, in the small, medium and large
//!   profiles: the frozen grid's own configurations, on the same chain sets,
//!   with the same warm-up and measured counts. Three runs, each in its own
//!   process, on the machine state M9 required.
//! - **The build.** `dc-bench` with the `phase-timing` feature, which times
//!   each verification's phases ([`dc_crypto::phases`]). It is never the
//!   build of a headline run (SPEC §10.3), so these numbers never enter the
//!   summary or the verdicts.
//! - **What is recorded.** Per measured call, the outer `Instant` time (as
//!   in M9) and the nanoseconds of each phase. The phases partition the
//!   instrumented call, so their sum is the call less the outer timer's
//!   own overhead.
//! - **Reading.** Like the M9 report, the analysis reads raw data only from
//!   the zstd archives under `archive/`, after checking each against
//!   `archive/MANIFEST.sha256`.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;
use std::time::Instant;

use dc_crypto::phases::{self as ph, ALL, COUNT, Phase};
use serde_json::Value;

use crate::arms::{Arm, State, Worlds, subject};
use crate::plan::{Config, Mode, PROFILES, grid};
use crate::report::{decompress, hex, us};
use crate::stats::quantile_sorted;

/// The arms the breakdown covers.
pub const ARMS: [Arm; 2] = [Arm::A, Arm::C];

/// The runs, each in its own process, as in M9.
pub const RUNS: usize = 3;

/// The categories the question asks about, and the phases each one sums
/// (D-77). "Other" holds everything the four named categories do not.
pub const GROUPS: [(&str, &[Phase]); 5] = [
    (
        "Decoding",
        &[
            Phase::Envelope,
            Phase::Bodies,
            Phase::Scopes,
            Phase::Canonical,
        ],
    ),
    ("Policy", &[Phase::Contains, Phase::Evaluate]),
    ("Identity", &[Phase::Identity]),
    (
        "Cryptography",
        &[Phase::PointValidation, Phase::Digests, Phase::Signatures],
    ),
    (
        "Other",
        &[
            Phase::Structure,
            Phase::Temporal,
            Phase::Replay,
            Phase::KeyChain,
            Phase::PolicyLoad,
            Phase::Approvals,
            Phase::Commit,
        ],
    ),
];

/// The Algorithm lines a phase covers (D-77).
pub fn lines(p: Phase) -> &'static str {
    match p {
        Phase::Envelope => "2 (envelope)",
        Phase::Bodies => "2 (bodies, signature container)",
        Phase::Scopes => "2 (scopes, D-28)",
        Phase::Canonical => "4–6",
        Phase::Structure => "3, 7–12",
        Phase::Temporal => "13–16",
        Phase::Replay => "17, 50",
        Phase::KeyChain => "18–21",
        Phase::Identity => "23–28",
        Phase::PolicyLoad => "30–31",
        Phase::Contains => "32–35",
        Phase::Evaluate => "36–37",
        Phase::Approvals => "38–46",
        Phase::Digests => "47–48",
        Phase::PointValidation => "2, 24 (inside decoding and resolution)",
        Phase::Signatures => "24, 43, 49",
        Phase::Commit => "after 50",
    }
}

fn group_of(p: Phase) -> &'static str {
    GROUPS
        .iter()
        .find(|(_, ps)| ps.contains(&p))
        .map_or("?", |g| g.0)
}

/// The breakdown's configurations, taken from the frozen grid so that they
/// are M9's own: arms A and C, warm, N = 3, small, medium and large.
pub fn configs(mode: Mode) -> Vec<Config> {
    grid(mode)
        .into_iter()
        .filter(|c| {
            ARMS.contains(&c.arm)
                && c.state == State::Warm
                && c.n == 3
                && PROFILES.contains(&c.profile)
        })
        .collect()
}

/// One measured call.
#[derive(Clone, Copy, Debug)]
pub struct Sample {
    /// The outer `Instant` time, as M9 records it.
    pub ns: u64,
    /// Each phase's nanoseconds, indexed like [`ALL`].
    pub phases: [u64; COUNT],
}

impl Sample {
    fn total(&self) -> u64 {
        self.phases.iter().sum()
    }

    fn group(&self, g: usize) -> u64 {
        GROUPS[g].1.iter().map(|&p| self.phases[p as usize]).sum()
    }
}

/// Runs one configuration as `harness::measure` does in the warm state (one
/// verifier, warm-up first, then measured), keeping each call's phases.
pub fn measure(w: &Worlds, c: &Config, chains: &[Vec<u8>]) -> Result<Vec<Sample>, String> {
    if !ph::ENABLED {
        return Err("this build does not time phases (`--features phase-timing`)".into());
    }
    assert_eq!(chains.len(), c.chains(), "{}: wrong set", c.id());
    let s = subject(w, c.arm, c.state, c.profile);
    let mut out = Vec::with_capacity(c.measured);
    for (i, chain) in chains.iter().enumerate() {
        let t0 = Instant::now();
        let o = s.verify(std::hint::black_box(chain));
        let dt = t0.elapsed();
        let phases = ph::snapshot();
        std::hint::black_box(o);
        if !o.accepted {
            return Err(format!("{}: chain {i} was rejected", c.id()));
        }
        if i >= c.warmup {
            out.push(Sample {
                ns: dt.as_nanos() as u64,
                phases,
            });
        }
    }
    Ok(out)
}

/// The CSV header of a phase run.
pub fn header() -> Vec<&'static str> {
    let mut h = vec!["run", "arm", "state", "N", "profile", "iter", "ns"];
    h.extend(ALL.iter().map(|p| p.label()));
    h
}

/// The raw data, read from verified archives.
#[derive(Default)]
pub struct Data {
    /// (arm, profile) → run → samples.
    pub samples: BTreeMap<(String, String), BTreeMap<usize, Vec<Sample>>>,
    /// (run, configuration, signal) of each configuration that the thermal
    /// readings flag (frozen plan §5's rule; recorded, not re-run).
    pub flagged: Vec<(usize, String, String)>,
    /// Each run process's meta file.
    pub metas: BTreeMap<usize, Value>,
    pub archives: usize,
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
        let run_of = |stem: &str| -> Result<usize, String> {
            stem.strip_prefix("run")
                .and_then(|r| r.parse().ok())
                .ok_or_else(|| format!("unexpected archive {name}"))
        };
        if let Some(stem) = file.strip_suffix("-meta.json") {
            let v: Value = serde_json::from_slice(&data).map_err(|e| format!("{file}: {e}"))?;
            d.metas.insert(run_of(stem)?, v);
            continue;
        }
        let mut rd = csv::Reader::from_reader(&data[..]);
        if let Some(stem) = file.strip_suffix("-thermal.csv") {
            let run = run_of(stem)?;
            let mut m: BTreeMap<String, (bool, bool)> = BTreeMap::new();
            for r in rd.records() {
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
                d.flagged.push((run, cfg, sig.to_owned()));
            }
            continue;
        }
        let stem = file
            .strip_suffix(".csv")
            .ok_or_else(|| format!("unexpected archive {name}"))?;
        let run = run_of(stem)?;
        let head = rd.headers().map_err(|e| format!("{file}: {e}"))?.clone();
        if head.iter().collect::<Vec<_>>() != header() {
            return Err(format!("{file}: unexpected columns"));
        }
        for r in rd.records() {
            let r = r.map_err(|e| format!("{file}: {e}"))?;
            let n = |i: usize| -> Result<u64, String> {
                r[i].parse()
                    .map_err(|_| format!("{file}: bad number {}", &r[i]))
            };
            let mut phases = [0u64; COUNT];
            for (k, p) in phases.iter_mut().enumerate() {
                *p = n(7 + k)?;
            }
            d.samples
                .entry((r[1].to_owned(), r[4].to_owned()))
                .or_default()
                .entry(run)
                .or_default()
                .push(Sample { ns: n(6)?, phases });
        }
    }
    Ok(d)
}

fn median(v: impl Iterator<Item = u64>) -> f64 {
    let mut v: Vec<f64> = v.map(|x| x as f64).collect();
    v.sort_by(f64::total_cmp);
    quantile_sorted(&v, 0.5)
}

/// One configuration's breakdown. Medians pool every run's samples, like
/// the M9 report's headline statistics.
#[derive(Clone, Debug)]
pub struct Breakdown {
    pub samples: usize,
    /// The median call, outer timer.
    pub median_ns: f64,
    /// The median instrumented call: the sum of its phases.
    pub median_total: f64,
    /// Each phase's median, indexed like [`ALL`].
    pub phase: [f64; COUNT],
    /// Each category's median (its phases summed per call), indexed like
    /// [`GROUPS`].
    pub group: [f64; 5],
    /// Each category's median over the sum of the category medians.
    pub share: [f64; 5],
    pub run_median_ns: BTreeMap<usize, f64>,
    pub run_share: BTreeMap<usize, [f64; 5]>,
}

impl Breakdown {
    /// The largest difference between runs in any category's share, as a
    /// fraction.
    pub fn share_spread(&self) -> f64 {
        (0..5)
            .map(|g| {
                let v: Vec<f64> = self.run_share.values().map(|s| s[g]).collect();
                v.iter().copied().fold(f64::MIN, f64::max)
                    - v.iter().copied().fold(f64::MAX, f64::min)
            })
            .fold(0.0, f64::max)
    }

    /// A phase's median as a share of the sum of the category medians.
    pub fn phase_share(&self, k: usize) -> f64 {
        self.phase[k] / self.group.iter().sum::<f64>()
    }
}

fn shares(samples: &[&Sample]) -> ([f64; 5], [f64; 5]) {
    let mut group = [0.0; 5];
    for (g, x) in group.iter_mut().enumerate() {
        *x = median(samples.iter().map(|s| s.group(g)));
    }
    let sum: f64 = group.iter().sum();
    let mut share = [0.0; 5];
    for (g, x) in share.iter_mut().enumerate() {
        *x = group[g] / sum;
    }
    (group, share)
}

impl Data {
    pub fn breakdown(&self, arm: &str, profile: &str) -> Result<Breakdown, String> {
        let runs = self
            .samples
            .get(&(arm.to_owned(), profile.to_owned()))
            .ok_or_else(|| format!("no phase samples for {arm} {profile}"))?;
        let all: Vec<&Sample> = runs.values().flatten().collect();
        let mut phase = [0.0; COUNT];
        for (k, x) in phase.iter_mut().enumerate() {
            *x = median(all.iter().map(|s| s.phases[k]));
        }
        let (group, share) = shares(&all);
        Ok(Breakdown {
            samples: all.len(),
            median_ns: median(all.iter().map(|s| s.ns)),
            median_total: median(all.iter().map(|s| s.total())),
            phase,
            group,
            share,
            run_median_ns: runs
                .iter()
                .map(|(r, v)| (*r, median(v.iter().map(|s| s.ns))))
                .collect(),
            run_share: runs
                .iter()
                .map(|(r, v)| (*r, shares(&v.iter().collect::<Vec<_>>()).1))
                .collect(),
        })
    }

    /// The group index of a category name.
    pub fn group_index(name: &str) -> Result<usize, String> {
        GROUPS
            .iter()
            .position(|g| g.0 == name)
            .ok_or_else(|| format!("unknown category {name}"))
    }

    /// The generated tables of BENCHMARKS.md's phase breakdown. `headline`
    /// gives M9's pooled median for (arm, profile), warm, N = 3.
    pub fn markdown(
        &self,
        headline: &dyn Fn(&str, &str) -> Result<f64, String>,
    ) -> Result<String, String> {
        let cols: Vec<(&str, &str)> = ARMS
            .iter()
            .flat_map(|a| PROFILES.iter().map(move |p| (a.label(), p.label())))
            .collect();
        let b: Vec<Breakdown> = cols
            .iter()
            .map(|(a, p)| self.breakdown(a, p))
            .collect::<Result<_, _>>()?;
        let pct = |x: f64| format!("{:.1}%", 100.0 * x);
        let mut w = String::new();
        let head = |w: &mut String, first: &str| {
            let _ = writeln!(
                w,
                "| {first} | {} |\n|---|{}",
                cols.iter()
                    .map(|(a, p)| format!("{a}, {p}"))
                    .collect::<Vec<_>>()
                    .join(" | "),
                "---|".repeat(cols.len())
            );
        };

        let samples: Vec<String> = b.iter().map(|x| x.samples.to_string()).collect();
        let _ = writeln!(
            w,
            "#### By category\n\nMedian µs per call, and each category's share of the sum of the five category medians. Samples per configuration: {}.\n",
            if samples.iter().all(|s| *s == samples[0]) {
                samples[0].clone()
            } else {
                samples.join(", ")
            }
        );
        head(&mut w, "Category");
        for (g, (name, _)) in GROUPS.iter().enumerate() {
            let _ = writeln!(
                w,
                "| {name} | {} |",
                b.iter()
                    .map(|x| format!("{} ({})", us(x.group[g]), pct(x.share[g])))
                    .collect::<Vec<_>>()
                    .join(" | ")
            );
        }
        let row = |w: &mut String,
                   label: &str,
                   f: &dyn Fn(usize, &Breakdown) -> Result<String, String>|
         -> Result<(), String> {
            let cells: Vec<String> = b
                .iter()
                .enumerate()
                .map(|(i, x)| f(i, x))
                .collect::<Result<_, _>>()?;
            let _ = writeln!(w, "| {label} | {} |", cells.join(" | "));
            Ok(())
        };
        row(&mut w, "Sum of the category medians", &|_, x| {
            Ok(us(x.group.iter().sum()))
        })?;
        row(
            &mut w,
            "Median instrumented call (sum of its phases)",
            &|_, x| Ok(us(x.median_total)),
        )?;
        row(&mut w, "Median call, outer timer (this build)", &|_, x| {
            Ok(us(x.median_ns))
        })?;
        row(&mut w, "M9 median, default build", &|i, _| {
            Ok(us(headline(cols[i].0, cols[i].1)?))
        })?;
        row(&mut w, "This build ÷ M9", &|i, x| {
            Ok(format!(
                "{:.3}",
                x.median_ns / headline(cols[i].0, cols[i].1)?
            ))
        })?;

        let _ = writeln!(
            w,
            "\n#### By phase\n\nMedian µs per call. A phase's median can be zero when the phase takes less than the timer's 41.7 ns tick on most calls.\n"
        );
        let _ = writeln!(
            w,
            "| Phase | Algorithm lines | Category | {} |\n|---|---|---|{}",
            cols.iter()
                .map(|(a, p)| format!("{a}, {p}"))
                .collect::<Vec<_>>()
                .join(" | "),
            "---|".repeat(cols.len())
        );
        for (k, p) in ALL.iter().enumerate() {
            let _ = writeln!(
                w,
                "| `{}` | {} | {} | {} |",
                p.label(),
                lines(*p),
                group_of(*p),
                b.iter()
                    .map(|x| us(x.phase[k]))
                    .collect::<Vec<_>>()
                    .join(" | ")
            );
        }

        let _ = writeln!(
            w,
            "\n#### Run agreement\n\nEach run's median call (outer timer, µs), and the largest difference between runs in any category's share, in percentage points.\n"
        );
        let runs: Vec<usize> = b[0].run_median_ns.keys().copied().collect();
        let _ = writeln!(
            w,
            "| Configuration | {} | Largest share difference |\n|---|{}---|",
            runs.iter()
                .map(|r| format!("run {r}"))
                .collect::<Vec<_>>()
                .join(" | "),
            "---|".repeat(runs.len())
        );
        for (i, x) in b.iter().enumerate() {
            let spread = x.share_spread();
            let _ = writeln!(
                w,
                "| {} warm N=3 {} | {} | {:.1} |",
                cols[i].0,
                cols[i].1,
                runs.iter()
                    .map(|r| x.run_median_ns.get(r).map_or("—".into(), |m| us(*m)))
                    .collect::<Vec<_>>()
                    .join(" | "),
                100.0 * spread
            );
        }
        Ok(w.trim_end().to_owned())
    }

    /// Every (arm, profile) breakdown.
    pub fn breakdowns(&self) -> Result<Vec<Breakdown>, String> {
        self.samples
            .keys()
            .map(|(a, p)| self.breakdown(a, p))
            .collect()
    }

    /// (flagged, measured) configuration counts over every run process.
    pub fn flag_count(&self) -> (usize, usize) {
        let measured = self
            .metas
            .values()
            .map(|m| m["order"].as_array().map_or(0, Vec::len))
            .sum();
        (self.flagged.len(), measured)
    }

    /// Whether M9's per-run safety valve would have tripped at this rate:
    /// more than 10% of the configurations flagged (D-76).
    pub fn valve_would_trip(&self) -> bool {
        let (flagged, measured) = self.flag_count();
        flagged * 10 > measured
    }

    /// The flagged configurations, as a list: "run 1: `id` (probe); …".
    pub fn flag_list(&self) -> String {
        self.flagged
            .iter()
            .map(|(r, c, s)| format!("run {r}: `{c}` ({s})"))
            .collect::<Vec<_>>()
            .join("; ")
    }

    /// The flagged configurations, as a sentence.
    pub fn flags(&self) -> String {
        if self.flagged.is_empty() {
            return "none was flagged".into();
        }
        let parts: Vec<String> = self
            .flagged
            .iter()
            .map(|(r, c, s)| format!("run {r}: `{c}` ({s})"))
            .collect();
        format!(
            "{} {} flagged and not re-run: {}",
            parts.len(),
            if parts.len() == 1 { "was" } else { "were" },
            parts.join("; ")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn categories_partition_the_phases() {
        let mut seen: Vec<Phase> = GROUPS.iter().flat_map(|g| g.1.iter().copied()).collect();
        seen.sort_by_key(|p| *p as usize);
        assert_eq!(seen, ALL);
    }

    #[test]
    fn the_tables_render() {
        let mut d = Data::default();
        for arm in ARMS {
            for p in PROFILES {
                for run in 1..=RUNS {
                    let v = (0..5)
                        .map(|i| {
                            let mut phases = [100u64; COUNT];
                            phases[Phase::Signatures as usize] = 1_000 + i;
                            Sample {
                                ns: phases.iter().sum::<u64>() + 50,
                                phases,
                            }
                        })
                        .collect();
                    d.samples
                        .entry((arm.label().to_owned(), p.label().to_owned()))
                        .or_default()
                        .insert(run, v);
                }
            }
        }
        let md = d.markdown(&|_, _| Ok(2_000.0)).unwrap();
        assert!(md.contains("| Cryptography | 1.2 (46.2%)"), "{md}");
        assert!(
            md.contains("| `signatures` | 24, 43, 49 | Cryptography |"),
            "{md}"
        );
        assert!(md.contains("| This build ÷ M9 | 1.326 |"), "{md}");
        assert_eq!(d.flags(), "none was flagged");
    }
}
