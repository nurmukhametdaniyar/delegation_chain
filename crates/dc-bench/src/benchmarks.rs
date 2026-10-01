//! `BENCHMARKS.md` (SPEC §14; the frozen plan). Every number in it comes
//! from the verified archives through the report generator: this module
//! loads them with [`report::load_raw`], which checks every archive against
//! `archive/MANIFEST.sha256`, and computes with the report's own statistics.
//!
//! The prose lives in a template, `crates/dc-bench/BENCHMARKS.template.md`,
//! whose numbers are all placeholders:
//! - `{{kind:args}}` is replaced by a value computed here;
//! - `{{section:Heading}}` splices a section of the freshly generated
//!   `summary.md`.
//!
//! An unknown or unresolvable placeholder is an error, so the document can
//! never carry a number typed by hand.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use serde_json::Value;

use crate::report::{
    self, AIP_CHAINED_MS, Key, Raw, Row, criterion_estimates, read_json, us, verdict,
};
use crate::stats::{Ratio, quantile_sorted, ratio};

/// AIP's published token sizes for biscuit-auth 6.0 chained mode (SPEC
/// §13.10, quoted, not re-checked): depth → bytes.
pub const AIP_CHAINED_BYTES: [(usize, f64); 6] = [
    (0, 520.0),
    (1, 940.0),
    (2, 1316.0),
    (3, 1696.0),
    (4, 2072.0),
    (5, 2448.0),
];

const NS: [usize; 5] = [1, 2, 3, 5, 10];

struct Doc<'a> {
    rows: &'a BTreeMap<Key, Row>,
    raw: &'a Raw,
    bytes: Value,
    memory: Value,
    env: Value,
    env_resume: Value,
    criterion: Vec<(String, f64, (f64, f64))>,
    summary: String,
}

/// The two arms and states of each verdict kind.
/// An (arm, state) pair.
type ArmState = (&'static str, &'static str);

fn kind(k: &str) -> Result<(ArmState, ArmState), String> {
    Ok(match k {
        "bd" => (("B", "warm+prefix"), ("D", "warm+prefix")),
        "bdm" => (("B", "prefix-miss"), ("D", "prefix-miss")),
        "ac" => (("A", "warm"), ("C", "warm")),
        "acb" => (("A", "warm"), ("C-batch", "warm")),
        "aai" => (("A", "warm"), ("A-ind", "warm")),
        "aaic" => (("A", "cold"), ("A-ind", "cold")),
        "acc" => (("A", "cold"), ("C", "cold")),
        "amtc" => (("A-mt", "warm"), ("C", "warm")),
        _ => return Err(format!("unknown verdict kind {k}")),
    })
}

fn cells() -> Vec<(usize, &'static str)> {
    let mut v: Vec<(usize, &'static str)> = NS
        .iter()
        .flat_map(|&n| ["small", "medium", "large"].map(|p| (n, p)))
        .collect();
    v.push((3, "medium-approval"));
    v
}

fn num<T: std::str::FromStr>(s: &str) -> Result<T, String> {
    s.parse().map_err(|_| format!("bad number {s}"))
}

impl Doc<'_> {
    fn row(&self, arm: &str, state: &str, n: usize, profile: &str) -> Result<&Row, String> {
        self.rows
            .get(&Key {
                arm: arm.into(),
                state: state.into(),
                n,
                profile: profile.into(),
            })
            .ok_or_else(|| format!("no configuration {arm} {state} N={n} {profile}"))
    }

    /// Ratio, its CI, each run's ratio of medians, and the frozen verdict.
    fn verdict(
        &self,
        k: &str,
        n: usize,
        profile: &str,
    ) -> Result<(Ratio, BTreeMap<usize, f64>, &'static str), String> {
        let ((a, sa), (b, sb)) = kind(k)?;
        let x = self.row(a, sa, n, profile)?;
        let y = self.row(b, sb, n, profile)?;
        let r = ratio(&x.pooled, &x.draws, &y.pooled, &y.draws);
        let runs: BTreeMap<usize, f64> = x
            .run_medians
            .iter()
            .filter_map(|(run, mx)| y.run_medians.get(run).map(|my| (*run, mx / my)))
            .collect();
        let v = verdict(&r, &runs);
        Ok((r, runs, v))
    }

    fn bytes_row(&self, arm: &str, n: usize, profile: &str) -> Result<&Value, String> {
        self.bytes["rows"]
            .as_array()
            .and_then(|rows| {
                rows.iter().find(|r| {
                    let label = r["arm"].as_str().unwrap_or("");
                    let ok = match arm {
                        "A" => label.starts_with("A (") || label == "A",
                        "A-ind" => label == "A-ind",
                        "C" => label.starts_with("C (") || label == "C",
                        "E" => label == "E",
                        _ => false,
                    };
                    ok && r["n"] == n && r["profile"] == profile
                })
            })
            .ok_or_else(|| format!("no bytes row {arm} N={n} {profile}"))
    }

    fn total(&self, arm: &str, n: usize, profile: &str) -> Result<f64, String> {
        self.bytes_row(arm, n, profile)?["total_mean"]
            .as_f64()
            .ok_or("bytes".into())
    }

    fn crit(&self, id: &str) -> Result<f64, String> {
        self.criterion
            .iter()
            .find(|c| c.0 == id)
            .map(|c| c.1)
            .ok_or_else(|| format!("no criterion estimate {id}"))
    }

    fn fit(&self, state: &str, profile: &str) -> Result<crate::stats::Fit, String> {
        let rows: Vec<&Row> = NS
            .iter()
            .map(|&n| self.row("A", state, n, profile))
            .collect::<Result<_, _>>()?;
        let ns: Vec<f64> = NS.iter().map(|&n| n as f64).collect();
        let medians: Vec<f64> = rows.iter().map(|r| r.pooled.median).collect();
        let draws: Vec<&[f64]> = rows.iter().map(|r| r.draws.as_slice()).collect();
        Ok(crate::stats::fit(&ns, &medians, &draws))
    }

    fn hash_ml(&self) -> Result<f64, String> {
        Ok(
            self.crit("bls/hash_to_g2_proxy")? - self.crit("bls/pairing_context")?
                + self.crit("bls/miller_loop")?,
        )
    }

    /// Q6: per run (accepted/s, p99 ns) for an arm and thread count.
    fn tp(&self, arm: &str, threads: usize) -> Result<Vec<(f64, f64)>, String> {
        let v: Vec<(f64, f64)> = self
            .raw
            .throughput
            .iter()
            .filter(|((a, t, _), _)| a == arm && *t == threads)
            .map(|(_, v)| *v)
            .collect();
        if v.is_empty() {
            return Err(format!("no Q6 rows for {arm} x{threads}"));
        }
        Ok(v)
    }

    fn e_aip(&self, n: usize, profile: &str) -> Result<f64, String> {
        let e = self.row("E", "stateless", n, profile)?.pooled.median;
        let aip = AIP_CHAINED_MS
            .iter()
            .find(|(d, _)| *d == n - 1)
            .ok_or(format!("no AIP figure at depth {}", n - 1))?
            .1;
        Ok(e / (aip * 1e6))
    }

    fn json_path<'v>(v: &'v Value, path: &str) -> Result<&'v Value, String> {
        let mut cur = v;
        for part in path.split('.') {
            cur = &cur[part];
        }
        if cur.is_null() {
            return Err(format!("no value at {path}"));
        }
        Ok(cur)
    }

    fn section(&self, heading: &str) -> Result<String, String> {
        let start = self
            .summary
            .find(&format!("\n## {heading}\n"))
            .ok_or_else(|| format!("summary.md has no section {heading}"))?;
        let body = &self.summary[start + heading.len() + 5..];
        let end = body.find("\n## ").unwrap_or(body.len());
        // One heading level down, under BENCHMARKS.md's own section headings.
        Ok(format!("\n{}", body[..end].trim())
            .replace("\n### ", "\n#### ")
            .trim()
            .to_owned())
    }

    fn resolve(&self, key: &str) -> Result<String, String> {
        let p: Vec<&str> = key.split(':').collect();
        let f1 = |x: f64| format!("{x:.1}");
        let f3 = |x: f64| format!("{x:.3}");
        Ok(match p.as_slice() {
            ["section", heading @ ..] => self.section(&heading.join(":"))?,
            ["lat", arm, state, n, profile] => {
                us(self.row(arm, state, num(n)?, profile)?.pooled.median)
            }
            ["p99", arm, state, n, profile] => {
                us(self.row(arm, state, num(n)?, profile)?.pooled.p99)
            }
            ["v", k, n, profile] => self.verdict(k, num(n)?, profile)?.2.to_owned(),
            ["vr", k, n, profile] => {
                let r = self.verdict(k, num(n)?, profile)?.0;
                format!("{:.3} [{:.3}, {:.3}]", r.value, r.ci.0, r.ci.1)
            }
            ["vx", k, n, profile] => f1(self.verdict(k, num(n)?, profile)?.0.value),
            ["vruns", k, n, profile] => self
                .verdict(k, num(n)?, profile)?
                .1
                .values()
                .map(|x| format!("{x:.3}"))
                .collect::<Vec<_>>()
                .join(", "),
            ["vcount", k, which] => {
                let all = cells();
                let mut hit = 0;
                for (n, p) in &all {
                    if self.verdict(k, *n, p)?.2 == *which {
                        hit += 1;
                    }
                }
                format!("{hit} of {}", all.len())
            }
            // Range of the ratio over the grid's cells, as "min–max" (×, 1 dp).
            ["vxrange", k] | ["vxrange", k, _] => {
                let skip_n1 = p.len() == 3 && p[2] == "n2plus";
                let mut v = vec![];
                for (n, prof) in cells() {
                    if skip_n1 && n == 1 {
                        continue;
                    }
                    v.push(self.verdict(k, n, prof)?.0.value);
                }
                let lo = v.iter().copied().fold(f64::MAX, f64::min);
                let hi = v.iter().copied().fold(f64::MIN, f64::max);
                format!("{}–{}", f1(lo), f1(hi))
            }
            ["v3range", k] | ["v3range", k, _] => {
                let skip_n1 = p.len() == 3 && p[2] == "n2plus";
                let mut v = vec![];
                for (n, prof) in cells() {
                    if skip_n1 && n == 1 {
                        continue;
                    }
                    v.push(self.verdict(k, n, prof)?.0.value);
                }
                let lo = v.iter().copied().fold(f64::MAX, f64::min);
                let hi = v.iter().copied().fold(f64::MIN, f64::max);
                format!("{}–{}", f3(lo), f3(hi))
            }
            ["latrange", arm, state, profile] => {
                let v: Vec<f64> = NS
                    .iter()
                    .map(|&n| self.row(arm, state, n, profile).map(|r| r.pooled.median))
                    .collect::<Result<_, _>>()?;
                let lo = v.iter().copied().fold(f64::MAX, f64::min);
                let hi = v.iter().copied().fold(f64::MIN, f64::max);
                format!("{}–{}", us(lo), us(hi))
            }
            ["bytes", arm, n, profile] => format!("{:.0}", self.total(arm, num(n)?, profile)?),
            ["sig", arm, n, profile] => format!(
                "{:.0}",
                self.bytes_row(arm, num(n)?, profile)?["sigs_mean"]
                    .as_f64()
                    .ok_or("sigs")?
            ),
            ["share", arm, n, profile] => {
                let r = self.bytes_row(arm, num(n)?, profile)?;
                let s = r["sigs_mean"].as_f64().ok_or("sigs")?;
                let t = r["total_mean"].as_f64().ok_or("total")?;
                f1(100.0 * s / t)
            }
            ["bdiff", n, profile] => {
                let n = num(n)?;
                format!(
                    "{:+.0}",
                    self.total("A", n, profile)? - self.total("C", n, profile)?
                )
            }
            ["bsave", n, profile] => {
                let n = num(n)?;
                f1(100.0 * (1.0 - self.total("A", n, profile)? / self.total("C", n, profile)?))
            }
            ["abl", n, profile] => {
                let n = num(n)?;
                format!(
                    "{:.0}",
                    self.total("A-ind", n, profile)? - self.total("A", n, profile)?
                )
            }
            ["ablshare", n, profile] => {
                let n = num(n)?;
                let (a, i) = (
                    self.total("A", n, profile)?,
                    self.total("A-ind", n, profile)?,
                );
                f1(100.0 * (i - a) / i)
            }
            ["ablhop", profile] => {
                let d = |n| -> Result<f64, String> {
                    Ok(self.total("A-ind", n, profile)? - self.total("A", n, profile)?)
                };
                f1((d(10)? - d(1)?) / 9.0)
            }
            ["breakeven", profile] => {
                let pts: Vec<(usize, f64, f64)> = (1..=10)
                    .map(|n| {
                        Ok((
                            n,
                            self.total("A", n, profile)?,
                            self.total("C", n, profile)?,
                        ))
                    })
                    .collect::<Result<_, String>>()?;
                let start = (pts[0].1 - pts[0].2).signum();
                match pts
                    .iter()
                    .find(|(_, a, c)| (a - c).signum() != start && a != c)
                {
                    Some((n, _, _)) => format!("N = {n}"),
                    None => "none in range (N = 1–10)".into(),
                }
            }
            ["cert", which] => format!(
                "{}",
                self.bytes["certificate_bytes"][*which]
                    .as_u64()
                    .ok_or("certificate bytes")?
            ),
            ["crit", id] => us(self.crit(id)?),
            ["critns", id] => format!("{:.0}", self.crit(id)?),
            ["hashml"] => us(self.hash_ml()?),
            ["fit", state, profile, field] => {
                let f = self.fit(state, profile)?;
                match *field {
                    "alpha" => us(f.alpha),
                    "beta" => us(f.beta),
                    "alphaci" => format!("[{}, {}]", us(f.alpha_ci.0), us(f.alpha_ci.1)),
                    "betaci" => format!("[{}, {}]", us(f.beta_ci.0), us(f.beta_ci.1)),
                    "r2" => format!("{:.4}", f.r2),
                    "tba" => f3(f.ten_beta_over_alpha),
                    "tbaci" => format!(
                        "[{}, {}]",
                        f3(f.ten_beta_over_alpha_ci.0),
                        f3(f.ten_beta_over_alpha_ci.1)
                    ),
                    "cross" => f1(f.alpha / f.beta),
                    "betafrac" => format!("{:.2}", f.beta / self.hash_ml()?),
                    _ => return Err(format!("unknown fit field {field}")),
                }
            }
            ["tp", arm, t] => {
                let mut v: Vec<f64> = self.tp(arm, num(t)?)?.iter().map(|x| x.0).collect();
                v.sort_by(f64::total_cmp);
                format!("{:.0}", quantile_sorted(&v, 0.5))
            }
            ["tpp99", arm, t] => {
                let mut v: Vec<f64> = self.tp(arm, num(t)?)?.iter().map(|x| x.1).collect();
                v.sort_by(f64::total_cmp);
                us(quantile_sorted(&v, 0.5))
            }
            ["tprat", a, b, t] => {
                let m = |arm: &str| -> Result<f64, String> {
                    let mut v: Vec<f64> = self.tp(arm, num(t)?)?.iter().map(|x| x.0).collect();
                    v.sort_by(f64::total_cmp);
                    Ok(quantile_sorted(&v, 0.5))
                };
                f1(m(a)? / m(b)?)
            }
            ["calls", arm, ms, which] => {
                let state = format!("cold+rtt{ms}ms");
                let (v, r, s) = self
                    .raw
                    .calls
                    .iter()
                    .filter(|((a, st, _), _)| a == arm && *st == state)
                    .fold((0u64, 0u64, 0u64), |acc, (_, x)| {
                        (acc.0 + x.0, acc.1 + x.1, acc.2 + x.2)
                    });
                if v == 0 {
                    return Err(format!("no Q5 calls for {arm} {state}"));
                }
                let x = if *which == "resolver" { r } else { s };
                let per = x as f64 / v as f64;
                if per.fract() == 0.0 {
                    format!("{per:.0}")
                } else {
                    format!("{per:.2}")
                }
            }
            ["mem", i] => {
                let r = &self.memory["rows"][num::<usize>(i)?];
                format!("{:.0}", r["bytes_per_entry"].as_f64().ok_or("memory row")?)
            }
            ["e", n, profile] => us(self.row("E", "stateless", num(n)?, profile)?.pooled.median),
            ["eaip", n, profile] => format!("{:.2}", self.e_aip(num(n)?, profile)?),
            ["eaiprange", profile, ns] => {
                let v: Vec<f64> = ns
                    .split(',')
                    .map(|n| num(n).and_then(|n| self.e_aip(n, profile)))
                    .collect::<Result<_, _>>()?;
                let lo = v.iter().copied().fold(f64::MAX, f64::min);
                let hi = v.iter().copied().fold(f64::MIN, f64::max);
                format!("{lo:.2}–{hi:.2}")
            }
            // The cells where arm E is more than 3× from AIP, by profile.
            ["eflagged"] => {
                let mut parts = vec![];
                for profile in ["small", "medium", "large"] {
                    let mut ns = vec![];
                    for n in [1usize, 2, 3, 5] {
                        let x = self.e_aip(n, profile)?;
                        if !(1.0 / 3.0..=3.0).contains(&x) {
                            ns.push(n.to_string());
                        }
                    }
                    if !ns.is_empty() {
                        parts.push(format!("the {profile} profile at N = {}", ns.join(", ")));
                    }
                }
                if parts.is_empty() {
                    "no cell".into()
                } else {
                    parts.join(" and ")
                }
            }
            ["aip", depth] => {
                let d: usize = num(depth)?;
                format!(
                    "{}",
                    AIP_CHAINED_MS.iter().find(|x| x.0 == d).ok_or("depth")?.1
                )
            }
            ["aipsize", depth] => {
                let d: usize = num(depth)?;
                format!(
                    "{:.0}",
                    AIP_CHAINED_BYTES
                        .iter()
                        .find(|x| x.0 == d)
                        .ok_or("depth")?
                        .1
                )
            }
            ["estep", profile] => {
                let e = |n| {
                    self.row("E", "stateless", n, profile)
                        .map(|r| r.pooled.median)
                };
                us((e(5)? - e(1)?) / 4.0)
            }
            ["aipstep"] => {
                let a = |d: usize| {
                    AIP_CHAINED_MS
                        .iter()
                        .find(|x| x.0 == d)
                        .map(|x| x.1)
                        .unwrap_or(f64::NAN)
                };
                us((a(4) - a(0)) / 4.0 * 1e6)
            }
            ["esize", n, profile] => format!("{:.0}", self.total("E", num(n)?, profile)?),
            ["env", path] => Self::json_path(&self.env, path)?
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| {
                    Self::json_path(&self.env, path)
                        .map(|v| v.to_string())
                        .unwrap_or_default()
                }),
            ["envline", path] => Self::json_path(&self.env, path)?
                .as_str()
                .and_then(|x| x.lines().next())
                .ok_or(format!("no text at {path}"))?
                .to_owned(),
            ["envr", path] => Self::json_path(&self.env_resume, path)?
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| {
                    Self::json_path(&self.env_resume, path)
                        .map(|v| v.to_string())
                        .unwrap_or_default()
                }),
            ["reruns"] => {
                // Every throttling re-run, by run process, with its signal and
                // whether the re-run was flagged again.
                let flagged = |stem: &str| -> Vec<(String, bool, bool)> {
                    let mut m: BTreeMap<String, (bool, bool)> = BTreeMap::new();
                    for t in self
                        .raw
                        .thermal
                        .iter()
                        .filter(|t| t.stem == stem && t.config != "baseline")
                    {
                        let e = m.entry(t.config.clone()).or_default();
                        e.0 |= t.pmset_warning;
                        e.1 |= t.probe_slow;
                    }
                    m.into_iter()
                        .filter(|(_, v)| v.0 || v.1)
                        .map(|(k, v)| (k, v.0, v.1))
                        .collect()
                };
                let mut out = String::new();
                for stem in ["run1", "run1-amt", "run2", "run2-amt", "run3", "run3-amt"] {
                    let again: Vec<String> = flagged(&format!("{stem}-rerun"))
                        .into_iter()
                        .map(|x| x.0)
                        .collect();
                    for (cfg, pm, pr) in flagged(stem) {
                        let sig = match (pm, pr) {
                            (true, true) => "pmset and probe",
                            (true, false) => "pmset",
                            _ => "probe",
                        };
                        out.push_str(&format!(
                            "- {stem}: `{cfg}`, flagged by {sig}; re-run {}\n",
                            if again.contains(&cfg) {
                                "**flagged again** (the report uses the re-run samples; marked †)"
                            } else {
                                "not flagged"
                            }
                        ));
                    }
                }
                out.trim_end().to_owned()
            }
            ["rerun_count"] => {
                let mut n = 0;
                for stem in ["run1", "run1-amt", "run2", "run2-amt", "run3", "run3-amt"] {
                    let mut set = std::collections::BTreeSet::new();
                    for t in self.raw.thermal.iter().filter(|t| {
                        t.stem == stem
                            && t.config != "baseline"
                            && (t.pmset_warning || t.probe_slow)
                    }) {
                        set.insert(t.config.clone());
                    }
                    n += set.len();
                }
                n.to_string()
            }
            ["runs"] => {
                let runs: std::collections::BTreeSet<usize> = self
                    .rows
                    .values()
                    .flat_map(|r| r.run_medians.keys().copied())
                    .collect();
                runs.len().to_string()
            }
            ["configs"] => self.rows.len().to_string(),
            ["archives"] => self.raw.archives.to_string(),
            _ => return Err(format!("unknown placeholder {{{{{key}}}}}")),
        })
    }
}

/// Renders `template` into `out`, from the results in `results`.
pub fn render(
    results: &Path,
    criterion: &Path,
    template: &Path,
    out: &Path,
    threads: usize,
) -> Result<(), String> {
    // The summary first, from the same verified archives.
    report::report(results, criterion, threads, false)?;
    let raw = report::load_raw(results)?;
    let rows = report::rows(&raw, threads);
    let doc = Doc {
        rows: &rows,
        raw: &raw,
        bytes: read_json(&results.join("bytes.json")).ok_or("no bytes.json")?,
        memory: read_json(&results.join("memory.json")).ok_or("no memory.json")?,
        env: read_json(&results.join("env.json")).ok_or("no env.json")?,
        env_resume: read_json(&results.join("env-resume.json")).unwrap_or(Value::Null),
        criterion: criterion_estimates(criterion),
        summary: fs::read_to_string(results.join("summary.md")).map_err(|e| e.to_string())?,
    };
    let tpl = fs::read_to_string(template).map_err(|e| format!("{}: {e}", template.display()))?;
    let mut outtext = String::with_capacity(tpl.len() * 2);
    let mut rest = tpl.as_str();
    let mut errors = vec![];
    while let Some(i) = rest.find("{{") {
        outtext.push_str(&rest[..i]);
        let Some(j) = rest[i..].find("}}") else {
            return Err("unterminated placeholder".into());
        };
        let key = &rest[i + 2..i + j];
        match doc.resolve(key) {
            Ok(v) => outtext.push_str(&v),
            Err(e) => errors.push(format!("{{{{{key}}}}}: {e}")),
        }
        rest = &rest[i + j + 2..];
    }
    outtext.push_str(rest);
    if !errors.is_empty() {
        return Err(format!(
            "unresolved placeholders:\n  {}",
            errors.join("\n  ")
        ));
    }
    fs::write(out, outtext).map_err(|e| e.to_string())
}
