//! BENCHMARKS.md §8's blocks for D-98 (`Contains` after D-97's
//! memoization) and D-99 (the prototype work budget, and the candidate
//! configurations), from `results/exploratory/contains-cost/`: criterion's
//! estimates of `benches/contains_cost.rs` and `benches/contains_budget.rs`,
//! `work.json` (`dc-bench budget`) and `oracle-budget.json` (the oracle with
//! budgets). Not in the frozen plan; exploratory.

use std::fmt::Write as _;
use std::path::Path;

use serde_json::Value;

use crate::bounds::{COST_CELLS, SWEEP_BOUNDS};
use crate::report::{criterion_estimates, read_json};

/// Links whose parent a compromised agent signed, at N = 16
/// ([`crate::bounds::ALTERNATING_LINKS`]).
const LINKS: f64 = crate::bounds::ALTERNATING_LINKS as f64;

pub struct Data {
    /// (criterion id, median ns, CI).
    est: Vec<(String, f64, (f64, f64))>,
    work: Value,
    oracle: Value,
}

/// A configuration D-99 puts to the author: size bounds, and a budget or
/// none.
pub struct Candidate {
    pub name: &'static str,
    pub rules: usize,
    pub atoms: usize,
    /// The longest `in` list (D-21: 64).
    pub list: usize,
    pub budget: Option<u64>,
}

/// D-99's three candidates, after the configuration as it stands.
pub const CANDIDATES: [Candidate; 4] = [
    Candidate {
        name: "As now: D-21's bounds, memoization only",
        rules: 256,
        atoms: 32,
        list: 64,
        budget: None,
    },
    Candidate {
        name: "1. D-21's bounds, budget 16,384",
        rules: 256,
        atoms: 32,
        list: 64,
        budget: Some(16_384),
    },
    Candidate {
        name: "2. D-21's bounds, budget 1,048,576",
        rules: 256,
        atoms: 32,
        list: 64,
        budget: Some(1 << 20),
    },
    Candidate {
        name: "3. At most 16 rules, 8 atoms a rule and 8-element lists, no budget",
        rules: 16,
        atoms: 8,
        list: 8,
        budget: None,
    },
];

pub fn load(dir: &Path) -> Result<Data, String> {
    let est = criterion_estimates(&dir.join("criterion"));
    if est.is_empty() {
        return Err(format!(
            "no criterion estimates under {}/criterion: unpack criterion.tar.zst (ARTIFACT.md §3)",
            dir.display()
        ));
    }
    let need = |f: &str| read_json(&dir.join(f)).ok_or_else(|| format!("no {}/{f}", dir.display()));
    Ok(Data {
        est,
        work: need("work.json")?,
        oracle: need("oracle-budget.json")?,
    })
}

fn ms(ns: f64) -> String {
    let v = ns / 1e6;
    if v >= 100.0 {
        format!("{v:.0}")
    } else if v >= 10.0 {
        format!("{v:.1}")
    } else if v >= 0.1 {
        format!("{v:.2}")
    } else {
        format!("{v:.4}")
    }
}

/// The longest `in` list of an input, from its label: `intlistN`,
/// `xlistN`, `strlistNxB`; 0 for the others.
fn list_len(key: &str) -> usize {
    let label = key
        .trim_start_matches("sweep/")
        .split('/')
        .next()
        .unwrap_or("");
    ["intlist", "xlist", "strlist"]
        .iter()
        .find_map(|p| label.strip_prefix(p))
        .and_then(|rest| rest.split('x').next()?.parse().ok())
        .unwrap_or(0)
}

/// `rN_aM` → (N, M).
fn size(id: &str) -> Option<(usize, usize)> {
    let (r, a) = id.rsplit('/').next()?.split_once("_a")?;
    let r = r.rsplit('r').next()?.parse().ok()?;
    Some((r, a.parse().ok()?))
}

impl Data {
    fn get(&self, id: &str) -> Option<(f64, (f64, f64))> {
        self.est.iter().find(|e| e.0 == id).map(|e| (e.1, e.2))
    }

    /// Every timed full `Contains` call: (id without the group, median ns,
    /// rules, atoms, atom-level count).
    fn inputs(&self) -> Vec<(String, f64, usize, usize, Option<u64>)> {
        self.est
            .iter()
            .filter_map(|(id, m, _)| {
                let key = id.strip_prefix("contains-cost/")?;
                let (r, a) = size(key)?;
                let work = self.work["inputs"][key].as_u64();
                Some((key.to_owned(), *m, r, a, work))
            })
            .collect()
    }

    /// The costliest input of the search measured in full: (id, ns).
    fn worst_input(&self) -> (String, f64) {
        self.inputs()
            .into_iter()
            .map(|i| (i.0, i.1))
            .max_by(|a, b| a.1.total_cmp(&b.1))
            .expect("inputs")
    }

    /// The costliest call under `budget`: (description, ns).
    fn at_budget(&self, budget: u64) -> Option<(String, f64)> {
        let prefix = format!("contains-budget/b{budget}/");
        self.est
            .iter()
            .filter_map(|(id, m, _)| Some((id.strip_prefix(&prefix)?.to_owned(), *m)))
            .max_by(|a, b| a.1.total_cmp(&b.1))
    }

    /// A candidate's worst measured `Contains` call: (what, ns).
    fn worst(&self, c: &Candidate) -> Option<(String, f64)> {
        let full = self
            .inputs()
            .into_iter()
            .filter(|i| i.2 <= c.rules && i.3 <= c.atoms && list_len(&i.0) <= c.list)
            .filter(|i| match (c.budget, i.4) {
                (None, _) => true,
                (Some(b), Some(w)) => w <= b,
                (Some(_), None) => false,
            })
            .map(|i| (i.0, i.1))
            .max_by(|a, b| a.1.total_cmp(&b.1));
        let capped = c
            .budget
            .and_then(|b| self.at_budget(b))
            .map(|(id, ns)| (format!("{id}, cut off by the budget"), ns));
        [full, capped]
            .into_iter()
            .flatten()
            .max_by(|a, b| a.1.total_cmp(&b.1))
    }

    /// The tables of D-98's block.
    pub fn markdown_cost(&self) -> String {
        let mut w = String::new();
        let cell = |kind: &str, r: usize, a: usize| {
            let key = format!("{kind}/r{r}_a{a}");
            match self.get(&format!("contains-cost/{key}")) {
                Some((m, (lo, hi))) => format!("{} [{}, {}]", ms(m), ms(lo), ms(hi)),
                None if self.work["inputs"][&key].is_u64() => "not measured".into(),
                None => "larger than a body".into(),
            }
        };
        w.push_str("| Rules × atoms | frozen-worst (ms) | alternating (ms) | intlist2 (ms) |\n|---|---|---|---|\n");
        for (r, a) in COST_CELLS {
            writeln!(
                w,
                "| {r} × {a} | {} | {} | {} |",
                cell("frozen-worst", r, a),
                cell("alternating", r, a),
                cell("intlist2", r, a)
            )
            .unwrap();
        }
        w.push_str("\n**The search's runners-up**, at the most rules that fit (ms):\n\n| Input | Median [95% CI] |\n|---|---|\n");
        for (id, m, ci) in &self.est {
            let Some(key) = id.strip_prefix("contains-cost/") else {
                continue;
            };
            if key.starts_with("sweep/")
                || ["frozen-worst/", "alternating/", "intlist2/"]
                    .iter()
                    .any(|p| key.starts_with(p))
            {
                continue;
            }
            writeln!(w, "| {key} | {} [{}, {}] |", ms(*m), ms(ci.0), ms(ci.1)).unwrap();
        }
        w.push_str("\n**At smaller bounds,** every padding of the search that fits; the costliest at each (ms):\n\n| Bounds (rules × atoms) | Costliest input | Median |\n|---|---|---|\n");
        for (r, a) in SWEEP_BOUNDS {
            let suffix = format!("/r{r}_a{a}");
            let best = self
                .est
                .iter()
                .filter(|(id, ..)| id.starts_with("contains-cost/sweep/") && id.ends_with(&suffix))
                .max_by(|x, y| x.1.total_cmp(&y.1));
            if let Some((id, m, _)) = best {
                let label = id
                    .trim_start_matches("contains-cost/sweep/")
                    .trim_end_matches(&suffix);
                writeln!(w, "| {r} × {a} | {label} | {} |", ms(*m)).unwrap();
            }
        }
        let (id, m) = self.worst_input();
        writeln!(
            w,
            "\n**The worst input found** is {id}: {} ms for one `Contains` call. It is a lower bound on the worst case: the inputs are constructions and a small search, not a proof.",
            ms(m)
        )
        .unwrap();
        w
    }

    /// The tables of D-99's block: counts, the cost at each budget, the
    /// oracle's completeness, and the candidates.
    pub fn markdown_budget(&self, strict: f64) -> String {
        let mut w = String::new();
        let o = &self.oracle["work_budget"];
        w.push_str("**Atom-level counts** of the largest `Contains` call, which a budget must clear:\n\n| Workload | Largest count |\n|---|---|\n");
        if let Some(p) = self.work["profiles"].as_object() {
            for (name, v) in p {
                writeln!(w, "| profile {name} | {} |", v["max"]).unwrap();
            }
        }
        writeln!(
            w,
            "| oracle, well-formed pairs | {} |\n| oracle, reflexivity checks | {} |",
            o["max_work_wellformed_pairs"], o["max_work_reflexivity"]
        )
        .unwrap();
        w.push_str("\n**The cost at a budget:** the costliest of the measured inputs, each far above the budget, until `Contains` gives up (ms):\n\n| Budget | Costliest input | Median |\n|---|---|---|\n");
        let mut budgets: Vec<u64> = self
            .est
            .iter()
            .filter_map(|(id, ..)| {
                id.strip_prefix("contains-budget/b")?
                    .split('/')
                    .next()?
                    .parse()
                    .ok()
            })
            .collect();
        budgets.sort_unstable();
        budgets.dedup();
        for b in &budgets {
            if let Some((id, ns)) = self.at_budget(*b) {
                writeln!(w, "| {b} | {id} | {} |", ms(ns)).unwrap();
            }
        }
        let none = &self.oracle["contains"]["completeness_overall"]["completeness"];
        w.push_str("\n**The oracle's completeness** with a budget (150,000 pairs, seed 56324):\n\n| Budget | Completeness |\n|---|---|\n");
        writeln!(w, "| none | {:.4} |", none.as_f64().unwrap_or(f64::NAN)).unwrap();
        if let Some(by) = o["completeness_overall_by_budget"].as_object() {
            let mut rows: Vec<(u64, f64)> = by
                .iter()
                .filter_map(|(b, v)| Some((b.parse().ok()?, v["completeness"].as_f64()?)))
                .collect();
            rows.sort_by_key(|r| r.0);
            for (b, c) in rows {
                writeln!(w, "| {b} | {c:.4} |").unwrap();
            }
        }
        writeln!(
            w,
            "\n**Candidate configurations.** The worst measured `Contains` call per link; per chain, the {LINKS} links at N = 16 whose parent a compromised agent signed; and each against one strict Ed25519 verification ({:.1} µs).\n",
            strict / 1e3
        )
        .unwrap();
        w.push_str("| Configuration | Worst input | Per link (ms) | Per chain (ms) | Per link ÷ Ed25519 |\n|---|---|---|---|---|\n");
        for c in &CANDIDATES {
            if let Some((what, ns)) = self.worst(c) {
                writeln!(
                    w,
                    "| {} | {what} | {} | {} | {:.0} |",
                    c.name,
                    ms(ns),
                    ms(LINKS * ns),
                    ns / strict
                )
                .unwrap();
            }
        }
        w
    }
}
