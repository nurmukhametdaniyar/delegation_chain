//! D-101's exploratory measurement, not in the frozen plan: the ceiling
//! that the work budget of `Contains` implies once its unit bounds every
//! operation's work (SPEC §9.6.1), and size bounds aligned with it.
//!
//! - **Classes** ([`probes`]): each charged operation, run alone on inputs
//!   at the size bounds through the counted functions dc-policy exports.
//!   Its time divided by its charge is its time per unit.
//! - **The fixed per-call cost** ([`overhead_inputs`]): `Contains` on the
//!   largest scopes with a budget of 0, which stops at its first charge.
//! - **The derived ceiling:** the budget times the worst time per unit, plus
//!   the largest fixed cost; per chain, [`LINKS`] links at N = 16.
//! - **The search** ([`contains_inputs`]): D-100's inputs and paddings aimed
//!   at what the unit newly charges, each at the default budget. Each must
//!   stay at or below the derived ceiling.
//! - **Admitted shapes** ([`admitted`]): for the frozen generator's shape and
//!   two string-heavy ones, the most rules, and the encoded bytes, whose
//!   pin-time check, link and child reflexive check stay within the budget;
//!   and limits proposed from them ([`proposed`]) with about 2× headroom.
//! - **Lines 2 and 5** on bodies filled up to the proposed limits.

use std::fmt::Write as _;
use std::path::Path;

use dc_policy::logic::{implies_path_counted, unsat_counted, unsat_path_counted};
use dc_policy::meter::{Meter, search, size, walk};
use dc_policy::{
    Atom, DEFAULT_BUDGET, Leaf, Rule, Scope, ScopeForm, Type, atom_holds, contains_within,
    subsumes_counted,
};
use serde_json::{Value, json};

use crate::bounds::{BODY_SPARE, frozen_worst};
use crate::budget::{
    LINKS, SCOPE_BODIES, body_scopes_within, contains_inputs_for, pads_d101, rule_count,
};
use crate::contains_cost::ms;
use crate::reorder;
use crate::report::{criterion_estimates, read_json};
use crate::workload::{Profile, hop_scopes};

/// One charged operation class, run alone at the size bounds.
pub struct Probe {
    /// The class, as SPEC §9.6.1's table names its charges.
    pub class: &'static str,
    /// The class and the input, as criterion's id.
    pub label: String,
    /// What one run charges; deterministic.
    pub charge: u64,
    run: Box<dyn Fn() -> bool>,
}

impl Probe {
    pub fn run(&self) -> bool {
        (self.run)()
    }
}

/// A probe of a counted function, with a fresh meter each run.
fn probe(class: &'static str, input: &str, run: impl Fn(&Meter) -> bool + 'static) -> Probe {
    let m = Meter::unlimited();
    run(&m);
    Probe {
        class,
        label: format!("{class}/{input}"),
        charge: m.spent(),
        run: Box::new(move || run(&Meter::unlimited())),
    }
}

/// The one rule of `text`.
fn rule(text: &str) -> Rule {
    match Scope::parse(text).expect("well formed").form() {
        ScopeForm::Rules(r) => r[0].clone(),
        _ => unreachable!("a rule"),
    }
}

/// A rule over one path `s: string` or `x: int` with these atoms.
fn on(path: &str, ty: &str, atoms: &[String]) -> Rule {
    rule(&format!(
        "allow at=o:service:s tool=t action=a params {{ {path}: {ty} }} where {}",
        atoms.join(" and ")
    ))
}

fn refs(r: &Rule) -> Vec<&Atom> {
    r.atoms.iter().collect()
}

/// `n` members of `bytes` bytes sharing all but a 3-digit tail.
fn members(n: usize, bytes: usize) -> String {
    (0..n)
        .map(|k| format!("\"{}{k:03}\"", "a".repeat(bytes)))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Every class at the size bounds: D-21's (32 atoms and 32 paths a rule,
/// 64-element lists, text of 1,024 bytes), with each rule within a 64 KiB
/// body.
pub fn probes() -> Vec<Probe> {
    let mut v = vec![];
    // ---- Tests, heads and approvals (`subsumes_counted`: no atoms).
    let decl = |n: usize, len: usize| {
        (0..n)
            .map(|k| format!("{}p{k:02}: int", "a".repeat(len)))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let short = rule(&format!(
        "allow at=o:service:s tool=t action=a params {{ {} }}",
        decl(32, 0)
    ));
    let (a, b) = (short.clone(), short);
    v.push(probe("head", "short32", move |m| {
        subsumes_counted(&a, &b, m)
    }));
    let long = rule(&format!(
        "allow at=o:service:s{x} tool=t{x} action=a{x} params {{ {} }}",
        decl(32, 990),
        x = "a".repeat(1000)
    ));
    let (a, b) = (long.clone(), long);
    v.push(probe("head", "long32", move |m| {
        subsumes_counted(&a, &b, m)
    }));
    let approvers = |ks: &mut dyn Iterator<Item = usize>, len: usize| {
        ks.map(|k| format!("o:approver:a{}{k:05}", "a".repeat(len)))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let with = |list: String| {
        rule(&format!(
            "{} approval requires {list}",
            crate::bounds::SHORT_HEAD
        ))
    };
    let all = with(approvers(&mut (0..3000), 0));
    let (a, b) = (all.clone(), all.clone());
    v.push(probe("approvals", "merge3000", move |m| {
        subsumes_counted(&a, &b, m)
    }));
    let sparse = with(approvers(&mut (0..3000).step_by(16), 0));
    v.push(probe("approvals", "lookup188of3000", move |m| {
        subsumes_counted(&sparse, &all, m)
    }));
    let longs = with(approvers(&mut (0..56), 990));
    let (a, b) = (longs.clone(), longs);
    v.push(probe("approvals", "long56", move |m| {
        subsumes_counted(&a, &b, m)
    }));
    // ---- Selecting atoms by path, and sorting paths (`unsat_counted`).
    for (name, len) in [("short", 0), ("long", 990)] {
        let paths: Vec<String> = (0..32)
            .map(|k| format!("{}p{k:02}", "a".repeat(len)))
            .collect();
        let decl = paths
            .iter()
            .map(|p| format!("{p}: int"))
            .collect::<Vec<_>>()
            .join(", ");
        let half = |op: &str| {
            rule(&format!(
                "allow at=o:service:s tool=t action=a params {{ {decl} }} where {}",
                paths
                    .iter()
                    .map(|p| format!("{p} {op}"))
                    .collect::<Vec<_>>()
                    .join(" and ")
            ))
        };
        let (lo, hi) = (half(">= 0"), half("<= 9"));
        v.push(probe("select", &format!("{name}64"), move |m| {
            let mut c = refs(&lo);
            c.extend(refs(&hi));
            unsat_counted(&lo.params, &c, m)
        }));
    }
    // ---- Integer paths.
    let ints = (0..64)
        .map(|k| k.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let lists = on("x", "int", &vec![format!("x in [{ints}]"); 32]);
    let b = rule(&format!(
        "allow at=o:service:s tool=t action=a params {{ x: int }} where x in [{ints}]"
    ));
    let l = lists.clone();
    v.push(probe("int-build", "lists32x64", move |m| {
        unsat_path_counted(Type::Int, &refs(&l), m)
    }));
    let bounds: Vec<String> = (0..32)
        .map(|k| {
            if k % 2 == 0 {
                format!("x >= {}", -(k as i64))
            } else {
                format!("x <= {}", 100 + k)
            }
        })
        .collect();
    let bounds = on("x", "int", &bounds);
    v.push(probe("int-build", "bounds32", move |m| {
        unsat_path_counted(Type::Int, &refs(&bounds), m)
    }));
    let (l, bb) = (lists, b.clone());
    v.push(probe("int-implies", "set64x64", move |m| {
        implies_path_counted(Type::Int, &refs(&l), &bb.atoms[0], m)
    }));
    let range = on("x", "int", &["x >= 0".into(), "x <= 63".into()]);
    v.push(probe("int-implies", "interval-in64", move |m| {
        implies_path_counted(Type::Int, &refs(&range), &b.atoms[0], m)
    }));
    // Set-forming atoms of one literal: each builds a set and intersects it
    // with the previous one, for a charge of one.
    for (name, atom) in [("eq32", "x == 0"), ("in1x32", "x in [0]")] {
        let r = on("x", "int", &vec![atom.to_owned(); 32]);
        v.push(probe("int-build", name, move |m| {
            unsat_path_counted(Type::Int, &refs(&r), m)
        }));
    }
    for (name, atom) in [("eq32", "s == \"a\""), ("in1x32", "s in [\"a\"]")] {
        let r = on("s", "string", &vec![atom.to_owned(); 32]);
        v.push(probe("str-build", name, move |m| {
            unsat_path_counted(Type::String, &refs(&r), m)
        }));
    }
    let bools = on("f", "bool", &vec!["f in [true, false]".to_owned(); 32]);
    v.push(probe("bool", "implies32", move |m| {
        implies_path_counted(Type::Bool, &refs(&bools), &bools.atoms[0], m)
    }));
    // ---- String paths.
    let sets = on(
        "s",
        "string",
        &vec![format!("s in [{}]", members(2, 960)); 30],
    );
    v.push(probe("str-sets", "30x2x963", move |m| {
        unsat_path_counted(Type::String, &refs(&sets), m)
    }));
    let mut contains = vec![format!("s in [{}]", members(8, 1016))];
    contains.extend((1..32).map(|k| format!("s contains \"{}\"", "a".repeat(1016 - k))));
    let contains = on("s", "string", &contains);
    let c = contains.clone();
    v.push(probe("str-admissible", "contains8x1019", move |m| {
        unsat_path_counted(Type::String, &refs(&c), m)
    }));
    let paths = (0..8)
        .map(|k| format!("\"{}/m{k:03}\"", "/a".repeat(508)))
        .collect::<Vec<_>>()
        .join(", ");
    let mut under = vec![format!("s in [{paths}]")];
    under.extend((1..32).map(|k| format!("s under \"{}\"", "/a".repeat(508 - k))));
    let under = on("s", "string", &under);
    v.push(probe("str-admissible", "under8x1021", move |m| {
        unsat_path_counted(Type::String, &refs(&under), m)
    }));
    // The scans alone (D-102): one value against one atom, as the
    // admissible set's filter and the implication with a set run them, for
    // that check's charge: the atom's check and the value's scan. Nothing
    // cheaper is mixed in, so these bound their class from above.
    let one = |atom: String| on("s", "string", &[atom]).atoms[0].clone();
    let value = format!("{}/m000", "/a".repeat(508));
    let q = "/a".repeat(500);
    let under_atom = one(format!("s under \"{q}\""));
    let charge = (size(&q) + walk(&value) - 1) as u64;
    v.push(Probe {
        class: "scan",
        label: "scan/under1000-in1021".into(),
        charge,
        run: Box::new(move || atom_holds(&under_atom, &Leaf::Str(&value))),
    });
    let hay = format!("{}000", "a".repeat(1016));
    for (name, x) in [
        ("contains-hit1016-in1019", "a".repeat(1016)),
        ("contains-miss501-in1019", format!("{}b", "a".repeat(500))),
    ] {
        let atom = one(format!("s contains \"{x}\""));
        let charge = (search(&x) + search(&hay) - 1) as u64;
        let hay = hay.clone();
        v.push(Probe {
            class: "scan",
            label: format!("scan/{name}"),
            charge,
            run: Box::new(move || atom_holds(&atom, &Leaf::Str(&hay))),
        });
    }
    // The same with 16 members, so that building the constraint is a
    // smaller share of the charge.
    let paths16 = (0..16)
        .map(|k| format!("\"{}/m{k:03}\"", "/a".repeat(508)))
        .collect::<Vec<_>>()
        .join(", ");
    let mut under16 = vec![format!("s in [{paths16}]")];
    under16.extend((1..32).map(|k| format!("s under \"{}\"", "/a".repeat(508 - k))));
    let under16 = on("s", "string", &under16);
    v.push(probe("str-admissible", "under16x1021", move |m| {
        unsat_path_counted(Type::String, &refs(&under16), m)
    }));
    let pairs =
        |atom: &dyn Fn(usize) -> String| on("s", "string", &(0..32).map(atom).collect::<Vec<_>>());
    let prefix = pairs(&|k| format!("s starts_with \"{}\"", "a".repeat(990 + k)));
    let suffix = pairs(&|k| format!("s ends_with \"{}{}\"", "b".repeat(k), "a".repeat(990)));
    let unders = pairs(&|k| format!("s under \"{}\"", "/a".repeat(480 + k)));
    for (name, r) in [
        ("prefix32", prefix.clone()),
        ("suffix32", suffix),
        ("under32", unders),
    ] {
        v.push(probe("str-pairs", name, move |m| {
            unsat_path_counted(Type::String, &refs(&r), m)
        }));
    }
    let distinct = on(
        "s",
        "string",
        &(0..31)
            .map(|k| format!("s contains \"{}{k:03}\"", "a".repeat(990)))
            .collect::<Vec<_>>(),
    );
    v.push(probe("str-implies", "contains31", move |m| {
        implies_path_counted(Type::String, &refs(&distinct), &distinct.atoms[30], m)
    }));
    let b = rule(&format!(
        "allow at=o:service:s tool=t action=a params {{ s: string }} where s starts_with \"{}\"",
        "a".repeat(990)
    ));
    v.push(probe("str-implies", "prefix32", move |m| {
        implies_path_counted(Type::String, &refs(&prefix), &b.atoms[0], m)
    }));
    let set = on("s", "string", &[format!("s in [{}]", members(8, 1016))]);
    let b = rule(&format!(
        "allow at=o:service:s tool=t action=a params {{ s: string }} where s contains \"{}\"",
        "a".repeat(1000)
    ));
    v.push(probe("str-implies", "set-contains8x1019", move |m| {
        implies_path_counted(Type::String, &refs(&set), &b.atoms[0], m)
    }));
    // ---- Step 3(a)'s scan, through `contains_within`: every test fails at
    // the head, the tool differing in its last byte.
    for (name, rules, tail) in [
        ("short256", 256, String::new()),
        ("long56", 56, "a".repeat(990)),
    ] {
        let tool = |end: char| {
            format!("allow at=o:service:s tool=t{tail}{end} action=a params {{ x: int }}")
        };
        let parent = Scope::parse(&vec![tool('1'); rules].join("\n")).expect("well formed");
        let child = Scope::parse(&tool('2')).expect("well formed");
        v.push(Probe {
            class: "test",
            label: format!("test/{name}"),
            charge: contains_within(&parent, &child, u64::MAX).work,
            run: Box::new(move || !contains_within(&parent, &child, u64::MAX).answer),
        });
    }
    v
}

/// D-101's search: D-100's inputs and the paddings aimed at what the unit
/// newly charges.
pub fn contains_inputs() -> Vec<(String, Scope, Scope)> {
    contains_inputs_for(&pads_d101())
}

/// Inputs whose fixed per-call cost is largest: the most rules, and the
/// largest heads and approval sets.
pub fn overhead_inputs() -> Vec<(String, Scope, Scope)> {
    let keep = [
        "bounds/r256_a4",
        "approvals16/",
        "head1000/",
        "decl8/",
        "longapprovals32/",
    ];
    let mut seen = vec![];
    contains_inputs()
        .into_iter()
        .filter(|(l, ..)| {
            let k = keep.iter().find(|k| l.starts_with(**k)).copied();
            match k {
                Some(k) if !seen.contains(&k) => {
                    seen.push(k);
                    true
                }
                _ => false,
            }
        })
        .collect()
}

// ------------------------------------------------------------ shapes

/// A shape whose admitted size D-101 reports.
#[derive(Clone, Copy, Debug)]
pub struct Shape {
    /// `frozen` (the frozen generator's, integers), `string-prefix` or
    /// `string-list`.
    pub family: &'static str,
    pub atoms: usize,
    /// The length of the string literals (0 for `frozen`).
    pub bytes: usize,
}

/// Every shape of the table.
pub fn shapes() -> Vec<Shape> {
    let mut v = vec![];
    for atoms in [1, 2, 4, 8, 16, 32] {
        v.push(Shape {
            family: "frozen",
            atoms,
            bytes: 0,
        });
    }
    for bytes in [16, 64, 256, 1024] {
        for atoms in [1, 4, 8, 16, 32] {
            v.push(Shape {
                family: "string-prefix",
                atoms,
                bytes,
            });
        }
    }
    for bytes in [16, 64, 256] {
        for atoms in [1, 8] {
            v.push(Shape {
                family: "string-list",
                atoms,
                bytes,
            });
        }
    }
    v
}

/// The frozen generator's shape with strings: rule i bounds x0 … x(a−2) by
/// `starts_with` a prefix of `bytes` − 1 bytes (`bytes` in the tighter
/// child), and requires x(a−1) == a `bytes`-byte value ending in i, or, for
/// `string-list`, x(a−1) in 8 such values.
fn string_scope(s: Shape, rules: usize, tight: bool) -> Scope {
    let params: Vec<String> = (0..s.atoms.max(8))
        .map(|j| format!("x{j}: string"))
        .collect();
    let prefix = "a".repeat(s.bytes - 1 + usize::from(tight));
    let text: Vec<String> = (0..rules)
        .map(|i| {
            let mut conds: Vec<String> = (0..s.atoms - 1)
                .map(|j| format!("x{j} starts_with \"{prefix}\""))
                .collect();
            let last = s.atoms - 1;
            conds.push(if s.family == "string-list" {
                let l: Vec<String> = (0..8)
                    .map(|m| format!("\"{}{i:04}{m}\"", "v".repeat(s.bytes - 5)))
                    .collect();
                format!("x{last} in [{}]", l.join(", "))
            } else {
                format!("x{last} == \"{}{i:04}\"", "v".repeat(s.bytes - 4))
            });
            format!(
                "allow at=orgb:service:s tool=t action=a params {{ {} }} where {}",
                params.join(", "),
                conds.join(" and ")
            )
        })
        .collect();
    Scope::parse(&text.join("\n")).expect("well formed")
}

/// The policy and a child one tighter, of `rules` rules.
pub fn shape_pair(s: Shape, rules: usize) -> (Scope, Scope) {
    if s.family == "frozen" {
        (
            frozen_worst(rules, s.atoms, 1000),
            frozen_worst(rules, s.atoms, 999),
        )
    } else {
        (string_scope(s, rules, false), string_scope(s, rules, true))
    }
}

fn fits(s: &Scope) -> bool {
    crate::bounds::fits(s)
}

/// The most rules of `s` whose three checks stay within the default budget,
/// within D-21's bounds but whatever the body size, so that the budget and
/// not today's 64 KiB body decides; and the most that fit today's body.
fn admitted_rules(s: Shape) -> (usize, usize) {
    let ok = |r: usize| {
        let (p, c) = shape_pair(s, r);
        let within = |a: &Scope, b: &Scope| !contains_within(a, b, DEFAULT_BUDGET).exhausted;
        within(&p, &p) && within(&p, &c) && within(&c, &c)
    };
    let fit = |r: usize| {
        let (p, c) = shape_pair(s, r);
        fits(&p) && fits(&c)
    };
    let search = |pred: &dyn Fn(usize) -> bool| {
        if !pred(1) {
            return 0;
        }
        let (mut lo, mut hi) = (1usize, 256usize);
        while lo < hi {
            let mid = (lo + hi).div_ceil(2);
            if pred(mid) {
                lo = mid;
            } else {
                hi = mid - 1;
            }
        }
        lo
    };
    (search(&ok), search(&fit))
}

/// One row of the admitted-shapes table.
pub fn admitted() -> Vec<Value> {
    shapes()
        .into_iter()
        .map(|s| {
            let (max, fitting) = admitted_rules(s);
            let work = |r: usize| {
                let (p, c) = shape_pair(s, r);
                [
                    contains_within(&p, &p, u64::MAX).work,
                    contains_within(&p, &c, u64::MAX).work,
                    contains_within(&c, &c, u64::MAX).work,
                ]
            };
            let bytes = (max > 0).then(|| shape_pair(s, max).0.canonical_bytes().len());
            json!({
                "family": s.family,
                "atoms": s.atoms,
                "bytes_per_string": s.bytes,
                "max_admitted_rules": max,
                "scope_bytes_at_max": bytes,
                "work_at_max": (max > 0).then(|| work(max)),
                "largest_fitting_rules": fitting,
                "fits_todays_body": max <= fitting,
            })
        })
        .collect()
}

/// Proposed limits: about twice the largest admitted scope, in rules
/// (rounded up to a multiple of 16) and in a body's bytes (twice the
/// largest admitted scope's encoding, plus [`BODY_SPARE`] for the body's
/// other fields, rounded up to a multiple of 4 KiB). The body limit can come
/// out above today's 64 KiB; it is reported as it comes out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub rules: usize,
    pub body: usize,
    /// What they are twice: the largest admitted rules and scope bytes.
    pub admitted_rules: usize,
    pub admitted_bytes: usize,
}

pub fn proposed(rows: &[Value]) -> Limits {
    let max = |k: &str| rows.iter().filter_map(|r| r[k].as_u64()).max().unwrap_or(0) as usize;
    let (r, b) = (max("max_admitted_rules"), max("scope_bytes_at_max"));
    Limits {
        rules: (2 * r).next_multiple_of(16),
        body: (2 * b + BODY_SPARE).next_multiple_of(4096),
        admitted_rules: r,
        admitted_bytes: b,
    }
}

/// The line-2 bodies under `limits`.
pub fn bodies(limits: Limits) -> Vec<(String, Scope)> {
    body_scopes_within(limits.rules, limits.body)
}

/// The line-2 bodies under the proposed rule limit and today's 64 KiB body.
pub fn bodies_today(limits: Limits) -> Vec<(String, Scope)> {
    body_scopes_within(limits.rules, dc_cbor::MAX_BODY_SIZE)
}

/// The deterministic part, for `work.json`: the probes' charges, the
/// admitted shapes and proposed limits, the bodies under them, every
/// search input's count, and the workload profiles' largest counts.
pub fn counts() -> Value {
    let probes: serde_json::Map<String, Value> = probes()
        .iter()
        .map(|p| {
            (
                p.label.clone(),
                json!({ "class": p.class, "charge": p.charge }),
            )
        })
        .collect();
    let rows = admitted();
    let limits = proposed(&rows);
    let setting = crate::workload::Setting::<dc_crypto::Ed25519>::new();
    let describe = |set: Vec<(String, Scope)>, max: usize| -> serde_json::Map<String, Value> {
        set.into_iter()
            .map(|(label, s)| {
                let body = crate::budget::delegation_body_within(&setting, &s, max);
                (
                    label,
                    json!({ "rules": rule_count(&s), "scope_bytes": s.canonical_bytes().len(), "body_bytes": body.len() }),
                )
            })
            .collect()
    };
    let bodies = describe(bodies(limits), limits.body);
    let bodies_today = describe(bodies_today(limits), dc_cbor::MAX_BODY_SIZE);
    let inputs: serde_json::Map<String, Value> = contains_inputs()
        .into_iter()
        .map(|(label, p, c)| {
            let w = contains_within(&p, &c, DEFAULT_BUDGET);
            (
                label,
                json!({ "work": w.work, "exhausted": w.exhausted, "answer": w.answer }),
            )
        })
        .collect();
    let profiles: serde_json::Map<String, Value> = Profile::ALL
        .iter()
        .map(|&p| {
            let s = hop_scopes(p);
            let mut w = vec![contains_within(&s[0], &s[0], u64::MAX).work];
            w.extend((1..s.len()).map(|k| contains_within(&s[k - 1], &s[k], u64::MAX).work));
            (p.label().to_owned(), json!(w.into_iter().max()))
        })
        .collect();
    json!({
        "label": "D-101: counts under the default work budget; deterministic, not timings",
        "default_budget": DEFAULT_BUDGET,
        "probes": probes,
        "admitted": rows,
        "proposed": { "rules": limits.rules, "body_bytes": limits.body, "admitted_rules": limits.admitted_rules, "admitted_scope_bytes": limits.admitted_bytes },
        "bodies": bodies,
        "bodies_today": bodies_today,
        "inputs": inputs,
        "profiles_max_work": profiles,
    })
}

// ------------------------------------------------------------ report

/// D-101's results, from `results/exploratory/ceiling/`.
pub struct Data {
    est: Vec<(String, f64, (f64, f64))>,
    work: Value,
    oracle: Value,
    pub headline: Option<reorder::Data>,
}

pub fn load(dir: &Path) -> Result<Data, String> {
    let est = criterion_estimates(&dir.join("criterion"));
    if est.is_empty() {
        return Err(format!(
            "no criterion estimates under {}/criterion: unpack criterion.tar.zst (ARTIFACT.md §3)",
            dir.display()
        ));
    }
    let need = |f: &str| read_json(&dir.join(f)).ok_or_else(|| format!("no {}/{f}", dir.display()));
    let hdir = dir.join("headline");
    let headline = if hdir.join("budgeted/archive/MANIFEST.sha256").exists() {
        Some(reorder::load(&hdir, reorder::BUDGET)?)
    } else {
        None
    };
    Ok(Data {
        est,
        work: need("work.json")?,
        oracle: need("oracle.json")?,
        headline,
    })
}

impl Data {
    fn of(&self, kind: &str) -> Vec<(&str, f64, (f64, f64))> {
        let prefix = format!("ceiling/{kind}/");
        let mut v: Vec<_> = self
            .est
            .iter()
            .filter_map(|(id, m, ci)| Some((id.strip_prefix(&prefix)?, *m, *ci)))
            .collect();
        v.sort_by(|a, b| b.1.total_cmp(&a.1));
        v
    }

    /// Each probe's (label, class, charge, median ns, ns per unit), worst
    /// per unit first.
    fn classes(&self) -> Vec<(String, String, u64, f64, f64)> {
        let mut v: Vec<_> = self
            .of("class")
            .into_iter()
            .filter_map(|(k, m, _)| {
                let p = &self.work["probes"][k];
                let charge = p["charge"].as_u64()?;
                Some((
                    k.to_owned(),
                    p["class"].as_str()?.to_owned(),
                    charge,
                    m,
                    m / charge as f64,
                ))
            })
            .collect();
        v.sort_by(|a, b| b.4.total_cmp(&a.4));
        v
    }

    /// (worst ns per unit, its probe, largest fixed cost in ns, its input).
    fn derivation(&self) -> Option<(f64, String, f64, String)> {
        let c = self.classes();
        let worst = c.first()?;
        let o = self.of("overhead");
        let fixed = o.first()?;
        Some((worst.4, worst.0.clone(), fixed.1, fixed.0.to_owned()))
    }

    /// The derived per-link ceiling, in ns.
    pub fn ceiling(&self) -> Option<f64> {
        let budget = self.work["default_budget"].as_f64()?;
        self.derivation().map(|(u, _, f, _)| budget * u + f)
    }

    /// Search inputs whose median passes the derived ceiling.
    pub fn above(&self) -> Vec<(String, f64)> {
        let Some(c) = self.ceiling() else {
            return vec![];
        };
        self.of("contains")
            .into_iter()
            .filter(|e| e.1 > c)
            .map(|e| (e.0.to_owned(), e.1))
            .collect()
    }

    pub fn markdown(&self, strict: f64, m9: &dyn Fn(&str, &str) -> Option<f64>) -> String {
        let mut w = String::new();
        let x = |ns: f64| format!("{:.0}", ns / strict);
        let budget = self.work["default_budget"].as_u64().unwrap_or(0);
        w.push_str("**Each charged operation class at the size bounds,** run alone; worst time per unit first:\n\n| Probe | Charge | Median (µs) | ns per unit |\n|---|---|---|---|\n");
        for (label, _, charge, m, u) in self.classes() {
            writeln!(w, "| {label} | {charge} | {:.2} | {u:.1} |", m / 1e3).unwrap();
        }
        w.push_str("\n**The fixed per-call cost,** `Contains` with a budget of 0 on the largest scopes (µs):\n\n| Input | Median |\n|---|---|\n");
        for (k, m, _) in self.of("overhead") {
            writeln!(w, "| {k} | {:.2} |", m / 1e3).unwrap();
        }
        let contains = self.of("contains");
        if let (Some((u, uk, f, fk)), Some(c)) = (self.derivation(), self.ceiling()) {
            writeln!(
                w,
                "\n**The derived ceiling** at the default budget ({budget}): {budget} × {u:.1} ns ({uk}) + {:.2} µs ({fk}), per link; per chain, the {LINKS} links at N = 16 whose child a compromised agent signs.\n\n| | Per link (ms) | Per chain (ms) | Per link ÷ one strict Ed25519 verification |\n|---|---|---|---|\n| Derived ceiling | {} | {} | {} |",
                f / 1e3,
                ms(c),
                ms(LINKS as f64 * c),
                x(c)
            )
            .unwrap();
            if let Some((k, m, ci)) = contains.first() {
                writeln!(
                    w,
                    "| Worst input found: {k} | {} [{}, {}] | {} | {} |",
                    ms(*m),
                    ms(ci.0),
                    ms(ci.1),
                    ms(LINKS as f64 * m),
                    x(*m)
                )
                .unwrap();
            }
            let above = self.above();
            writeln!(
                w,
                "\n**The search:** {} inputs at the default budget, the costliest at {:.0}% of the derived ceiling. {}",
                contains.len(),
                contains.first().map_or(0.0, |e| 100.0 * e.1 / c),
                if above.is_empty() {
                    "None passes it.".to_owned()
                } else {
                    format!(
                        "**{} pass it, so a charge is wrong:** {}.",
                        above.len(),
                        above
                            .iter()
                            .map(|(k, m)| format!("{k} ({} ms)", ms(*m)))
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                }
            )
            .unwrap();
        }
        w.push_str(
            "\nThe ten costliest inputs (ms):\n\n| Input | W | Median [95% CI] |\n|---|---|---|\n",
        );
        for (k, m, ci) in contains.iter().take(10) {
            let i = &self.work["inputs"][*k];
            let count = match (i["exhausted"].as_bool(), i["work"].as_u64()) {
                (Some(true), _) => "over the budget".into(),
                (Some(false), Some(n)) => n.to_string(),
                _ => "?".into(),
            };
            writeln!(
                w,
                "| {k} | {count} | {} [{}, {}] |",
                ms(*m),
                ms(ci.0),
                ms(ci.1)
            )
            .unwrap();
        }
        w.push_str("\n**Admitted shapes:** the most rules whose pin-time check, link to a child one tighter and child reflexive check stay within the budget, within D-21's bounds but whatever the body size, and the policy's encoded size there (counts, not timings). The last column is the most that fit today's 64 KiB body:\n\n| Shape | Atoms per rule | String bytes | Most rules admitted | Scope bytes | W (pin, link, child) | Most that fit today's body |\n|---|---|---|---|---|---|---|\n");
        if let Some(rows) = self.work["admitted"].as_array() {
            for r in rows {
                let triple = r["work_at_max"].as_array().map_or("—".into(), |a| {
                    a.iter()
                        .map(|v| v.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                });
                let bytes = r["bytes_per_string"]
                    .as_u64()
                    .filter(|b| *b > 0)
                    .map_or("—".into(), |b| b.to_string());
                writeln!(
                    w,
                    "| {} | {} | {bytes} | {} | {} | {triple} | {} |",
                    r["family"].as_str().unwrap_or("?"),
                    r["atoms"],
                    r["max_admitted_rules"],
                    r["scope_bytes_at_max"],
                    r["largest_fitting_rules"]
                )
                .unwrap();
            }
        }
        let p = &self.work["proposed"];
        writeln!(
            w,
            "\n**Proposed limits:** at most {} rules a scope (twice the {} admitted at most, rounded up to a multiple of 16) and {} bytes a body (twice the largest admitted scope's {} bytes, plus 1 KiB for the body's other fields, rounded up to 4 KiB), against D-21's 256 rules and D-03's 65536 bytes. D-21's other bounds stay. Not adopted: the author decides.",
            p["rules"], p["admitted_rules"], p["body_bytes"], p["admitted_scope_bytes"]
        )
        .unwrap();
        for (kind, key, what) in [
            ("", "bodies", "the proposed limits"),
            (
                "-64k",
                "bodies_today",
                "the proposed rule limit and today's 64 KiB body",
            ),
        ] {
            writeln!(
                w,
                "\n**Lines 2 and 5 under {what},** each body filled toward them (ms):\n\n| Body | Rules | Bytes | Line 2 | Line 5 |\n|---|---|---|---|---|"
            )
            .unwrap();
            let (l2, l5) = (
                self.of(&format!("line2{kind}")),
                self.of(&format!("line5{kind}")),
            );
            for (k, m, ci) in &l2 {
                let b = &self.work[key][*k];
                let five = l5
                    .iter()
                    .find(|e| e.0 == *k)
                    .map_or("—".into(), |e| ms(e.1));
                writeln!(
                    w,
                    "| {k} | {} | {} | {} [{}, {}] | {five} |",
                    b["rules"],
                    b["body_bytes"],
                    ms(*m),
                    ms(ci.0),
                    ms(ci.1)
                )
                .unwrap();
            }
            if let (Some(a), Some(b)) = (l2.first(), l5.first()) {
                let n = SCOPE_BODIES as f64;
                writeln!(
                    w,
                    "\n**Unsigned decoding per chain** under {what}, the {SCOPE_BODIES} scope bodies at N = 16, before any signature: line 2 {} ms ({}), line 5 {} ms ({}), both {} ms; {} strict Ed25519 verifications.",
                    ms(n * a.1),
                    a.0,
                    ms(n * b.1),
                    b.0,
                    ms(n * (a.1 + b.1)),
                    x(n * (a.1 + b.1))
                )
                .unwrap();
            }
        }
        let o = &self.oracle;
        let wb = &o["work_budget"];
        let pct = |v: &Value| v.as_f64().map_or("?".into(), |c| format!("{c:.4}"));
        let profiles = self.work["profiles_max_work"]
            .as_object()
            .map(|m| {
                m.iter()
                    .map(|(k, v)| format!("{k} {v}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default();
        writeln!(
            w,
            "\n**Legitimate inputs.** The workload profiles' largest `Contains` counts: {profiles}, against the budget of {budget}. The differential oracle ({} pairs, seed {}): completeness {} without a budget and {} at the default; {} well-formed pairs and {} reflexivity checks pass the budget; the largest counts are {} (pairs) and {} (reflexivity); soundness violations: {}.",
            o["contains"]["cases"],
            o["seed"],
            pct(&o["contains"]["completeness_overall"]["completeness"]),
            pct(&wb["completeness_overall_at_default_budget"]["completeness"]),
            wb["exhausted_at_default_budget"]["wellformed_pairs"],
            wb["exhausted_at_default_budget"]["reflexivity_checks"],
            wb["max_work_wellformed_pairs"],
            wb["max_work_reflexivity"],
            o["contains"]["soundness_violations"]
        )
        .unwrap();
        w.push_str("\n**The headline cells** with D-101's unit, against the measured build:\n\n");
        match &self.headline {
            Some(h) => w.push_str(&h.markdown(m9)),
            None => w.push_str("_Not run yet: there is no verified archive under `results/exploratory/ceiling/headline/`._\n"),
        }
        w
    }
}
