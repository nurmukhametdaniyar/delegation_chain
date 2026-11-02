//! Scopes at D-21's size bounds, for the exploratory measurement of
//! `Contains` there (`benches/bounds.rs`; D-95). Not in the frozen plan.
//!
//! - [`frozen_worst`] is the frozen Q8 generator's worst case
//!   (`benches/policy.rs`; D-73), with as many declared parameters as atoms.
//! - [`alternating`] builds X and Y, two scopes a compromised agent can sign
//!   in turn, so that every link it controls passes and does the most work
//!   this construction finds. X is R − 1 rules over a path's [0, 5] and a
//!   last rule over [0, 6]; Y is R − 1 rules over [1, 6] and the same last
//!   rule. In Contains(Y, X) and Contains(X, Y) alike, every child rule's
//!   first subsuming parent is the last one; every earlier parent is jointly
//!   satisfiable with it and shadowed by no earlier child, so step 3(b)
//!   calls `implies` (R − 1) × j times for child j. Padding atoms hold on
//!   [0, 6], and each rule's failing atom comes last, so every `implies`
//!   call checks all of them.
//!
//! The alternating construction was found by reading the procedure; it is
//! not a proof of the worst case.

use dc_cbor::MAX_BODY_SIZE;
use dc_policy::Scope;

/// Bytes left in a 64 KiB body (D-03) for its fields other than the scope.
pub const BODY_SPARE: usize = 1024;

/// The shortest well-formed rule head, so that the most atoms fit a body.
pub const SHORT_HEAD: &str = "allow at=o:service:s tool=t action=a params { x: int }";

/// Does a body carrying `s` stay within D-03's 64 KiB, with `BODY_SPARE`
/// bytes to spare?
pub fn fits(s: &Scope) -> bool {
    s.canonical_bytes().len() + BODY_SPARE <= MAX_BODY_SIZE
}

/// `benches/policy.rs`'s scope with `max(8, atoms)` declared parameters, so
/// that every atom has its own. Rule i bounds x0 … x(a−2) by `bound` and
/// requires x(a−1) == i.
pub fn frozen_worst(rules: usize, atoms: usize, bound: u64) -> Scope {
    let params: Vec<String> = (0..atoms.max(8)).map(|j| format!("x{j}: int")).collect();
    let text: Vec<String> = (0..rules)
        .map(|i| {
            let mut conds: Vec<String> =
                (0..atoms - 1).map(|j| format!("x{j} <= {bound}")).collect();
            conds.push(format!("x{} == {i}", atoms - 1));
            format!(
                "allow at=orgb:service:s\n  tool=t action=a\n  params {{ {} }}\n  where {}",
                params.join(", "),
                conds.join(" and ")
            )
        })
        .collect();
    Scope::parse(&text.join("\n")).expect("well formed")
}

/// A rule `head` over `path` ∈ [lo, hi], with `atoms` atoms: padding that
/// holds on [0, 6], then the bound that holds against the other scope's
/// rules, then the one that fails against them.
fn interval(head: &str, path: &str, atoms: usize, (lo, hi): (i64, i64), lo_last: bool) -> String {
    let mut a: Vec<String> = (0..atoms - 2)
        .map(|k| {
            if k % 2 == 0 {
                format!("{path} >= {}", -1 - k as i64)
            } else {
                format!("{path} <= {}", 7 + k)
            }
        })
        .collect();
    let (lo, hi) = (format!("{path} >= {lo}"), format!("{path} <= {hi}"));
    if lo_last {
        a.extend([hi, lo]);
    } else {
        a.extend([lo, hi]);
    }
    format!("{head} where {}", a.join(" and "))
}

/// X (`low`) or Y, with `rules` rules of `atoms` atoms on the int `path`,
/// each with rule head `head` (which must declare `path`).
pub fn alternating(head: &str, path: &str, rules: usize, atoms: usize, low: bool) -> Scope {
    let most = if low {
        interval(head, path, atoms, (0, 5), false)
    } else {
        interval(head, path, atoms, (1, 6), true)
    };
    let mut text = vec![most; rules - 1];
    text.push(interval(head, path, atoms, (0, 6), false));
    Scope::parse(&text.join("\n")).expect("well formed")
}

/// The rules × atoms cells of `benches/bounds.rs`.
pub const CELLS: [(usize, usize); 9] = [
    (64, 8),
    (64, 16),
    (64, 32),
    (128, 8),
    (128, 16),
    (128, 32),
    (256, 8),
    (256, 16),
    (256, 32),
];

/// Links a compromised agent can make alternate at N = 16 (D-16): it signs
/// delegations 1–15, and every link but the first, whose parent is the
/// issuer's session scope, has a parent it signed.
pub const ALTERNATING_LINKS: usize = 14;

fn ms(ns: f64) -> String {
    let v = ns / 1e6;
    if v >= 100.0 {
        format!("{v:.0}")
    } else if v >= 10.0 {
        format!("{v:.1}")
    } else {
        format!("{v:.2}")
    }
}

/// BENCHMARKS.md §8's block for D-95, from criterion's estimates of
/// `benches/bounds.rs` (median ns and CI, by id). `strict` and `frozen` are
/// the frozen pass's medians of one strict Ed25519 verification and of
/// `Contains` at 64 rules × 8 atoms, worst case, in ns.
pub fn markdown(est: &[(String, f64, (f64, f64))], strict: f64, frozen: f64) -> String {
    let get = |kind: &str, r: usize, a: usize| {
        let id = format!("bounds/contains/{kind}/r{r}_a{a}");
        est.iter().find(|e| e.0 == id).map(|e| (e.1, e.2))
    };
    let cell = |kind: &str, r: usize, a: usize| match get(kind, r, a) {
        Some((m, (lo, hi))) => format!("{} [{}, {}]", ms(m), ms(lo), ms(hi)),
        None => "larger than a body".into(),
    };
    let mut w =
        String::from("| Rules × atoms | frozen-worst (ms) | alternating (ms) |\n|---|---|---|\n");
    for (r, a) in CELLS {
        w.push_str(&format!(
            "| {r} × {a} | {} | {} |\n",
            cell("frozen-worst", r, a),
            cell("alternating", r, a)
        ));
    }
    let worst = CELLS
        .iter()
        .filter_map(|&(r, a)| get("alternating", r, a).map(|(m, _)| (r, a, m)))
        .max_by(|x, y| x.2.total_cmp(&y.2));
    if let Some((r, a, m)) = worst {
        w.push_str(&format!(
            "\n**Per link.** The costliest cell is alternating at {r} × {a}: {} ms for one `Contains` call, {:.0}× one strict Ed25519 verification ({:.1} µs) and {:.0}× the frozen matrix's worst case at 64 × 8 ({} ms).\n",
            ms(m),
            m / strict,
            strict / 1e3,
            m / frozen,
            ms(frozen)
        ));
        w.push_str(&format!(
            "\n**Per chain at N = 16.** {ALTERNATING_LINKS} alternating links of that size cost {:.1} s of `Contains`, and the chain still passes every link.\n",
            ALTERNATING_LINKS as f64 * m / 1e9
        ));
    }
    w
}

/// What fills a rule's atoms besides the two on x that decide which rule
/// subsumes which, for D-98's search for inputs costlier than
/// [`alternating`]. Every rule carries the same padding, which every rule's
/// clause therefore implies and which never makes a clause unsatisfiable,
/// so the answers are [`alternating`]'s; only the work per `implies` and
/// `unsat` call changes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pad {
    /// `x >= −1−k` and `x <= 7+k` in turn: [`alternating`] itself.
    Bounds,
    /// `y in [0, …, len − 1]`.
    IntList(usize),
    /// `s starts_with` nested prefixes: `bytes` × "a", then k × "b" for the
    /// k-th atom, so every pair is compared over its full length.
    StrPrefix(usize),
    /// `s in [len strings of bytes bytes]`.
    StrList(usize, usize),
    /// `x in [0, …, len − 1]` on the deciding path itself, `len` ≥ 7 so that
    /// every list holds [0, 6].
    XList(usize),
    /// D-100, slow per counted unit: `s contains` a string of `bytes` bytes,
    /// a different one in each atom, so that each implication searches the
    /// rule's other operands.
    StrContains(usize),
    /// `s ends_with` nested suffixes of `bytes` + k bytes.
    StrSuffix(usize),
    /// `s under` nested canonical paths of about `bytes` + 2k bytes.
    StrUnder(usize),
    /// `s in` a list of `len` strings of about `bytes` bytes, then `s
    /// contains` substrings every member holds: each counted unit filters a
    /// member through one atom.
    SetContains(usize, usize),
    /// As `SetContains`, with `s under` paths every member lies under: each
    /// unit checks a long path's canonical form.
    SetUnder(usize, usize),
    /// [`Pad::Bounds`]' atoms, under 31 more declared parameters of `len` + 2
    /// bytes each, which every head comparison reads and the unit does not
    /// count.
    Decl(usize),
    /// [`Pad::Bounds`]' atoms, with `len` approvers on every rule, which every
    /// approval comparison reads and the unit does not count.
    Approvals(usize),
}

impl Pad {
    pub fn label(self) -> String {
        match self {
            Pad::Bounds => "bounds".into(),
            Pad::IntList(n) => format!("intlist{n}"),
            Pad::StrPrefix(b) => format!("prefix{b}"),
            Pad::StrList(n, b) => format!("strlist{n}x{b}"),
            Pad::XList(n) => format!("xlist{n}"),
            Pad::StrContains(b) => format!("contains{b}"),
            Pad::StrSuffix(b) => format!("suffix{b}"),
            Pad::StrUnder(b) => format!("under{b}"),
            Pad::SetContains(n, b) => format!("setcontains{n}x{b}"),
            Pad::SetUnder(n, b) => format!("setunder{n}x{b}"),
            Pad::Decl(n) => format!("decl{n}"),
            Pad::Approvals(n) => format!("approvals{n}"),
        }
    }

    fn head(self) -> String {
        match self {
            Pad::Bounds | Pad::XList(_) | Pad::Approvals(_) => SHORT_HEAD.into(),
            Pad::IntList(_) => {
                "allow at=o:service:s tool=t action=a params { x: int, y: int }".into()
            }
            Pad::StrPrefix(_)
            | Pad::StrList(..)
            | Pad::StrContains(_)
            | Pad::StrSuffix(_)
            | Pad::StrUnder(_)
            | Pad::SetContains(..)
            | Pad::SetUnder(..) => {
                "allow at=o:service:s tool=t action=a params { x: int, s: string }".into()
            }
            Pad::Decl(n) => {
                let extra: Vec<String> = (0..31)
                    .map(|k| format!("p{k:02}{}: int", "a".repeat(n)))
                    .collect();
                format!(
                    "allow at=o:service:s tool=t action=a params {{ x: int, {} }}",
                    extra.join(", ")
                )
            }
        }
    }

    /// What follows the where clause.
    fn tail(self) -> String {
        match self {
            Pad::Approvals(n) => {
                let a: Vec<String> = (0..n).map(|k| format!("o:approver:a{k:04}")).collect();
                format!(" approval requires {}", a.join(", "))
            }
            _ => String::new(),
        }
    }

    /// The member strings of a `Set*` padding's list: `bytes` bytes each,
    /// sharing everything but a 3-digit tail.
    fn members(n: usize, b: usize, under: bool) -> Vec<String> {
        (0..n)
            .map(|i| {
                if under {
                    format!("{}/m{i:03}", "/a".repeat(b / 2))
                } else {
                    format!("{}{i:03}", "a".repeat(b))
                }
            })
            .collect()
    }

    fn atom(self, k: usize) -> String {
        match self {
            Pad::Bounds | Pad::Decl(_) | Pad::Approvals(_) if k.is_multiple_of(2) => {
                format!("x >= {}", -1 - k as i64)
            }
            Pad::Bounds | Pad::Decl(_) | Pad::Approvals(_) => format!("x <= {}", 7 + k),
            Pad::IntList(n) | Pad::XList(n) => {
                let l: Vec<String> = (0..n).map(|v| v.to_string()).collect();
                let path = if matches!(self, Pad::XList(_)) {
                    "x"
                } else {
                    "y"
                };
                format!("{path} in [{}]", l.join(", "))
            }
            Pad::StrPrefix(b) => format!("s starts_with \"{}{}\"", "a".repeat(b), "b".repeat(k)),
            Pad::StrList(n, b) => {
                let l: Vec<String> = (0..n).map(|v| format!("\"{v:0>b$}\"")).collect();
                format!("s in [{}]", l.join(", "))
            }
            // Equal lengths, a common prefix of `b` bytes: no operand
            // contains another, and every search reads to the end.
            Pad::StrContains(b) => format!("s contains \"{}{k:03}\"", "a".repeat(b)),
            Pad::StrSuffix(b) => format!("s ends_with \"{}{}\"", "b".repeat(k), "a".repeat(b)),
            Pad::StrUnder(b) => format!("s under \"{}\"", "/a".repeat(b / 2 + k)),
            Pad::SetContains(n, b) | Pad::SetUnder(n, b) if k == 0 => {
                let under = matches!(self, Pad::SetUnder(..));
                let l: Vec<String> = Pad::members(n, b, under)
                    .into_iter()
                    .map(|m| format!("\"{m}\""))
                    .collect();
                format!("s in [{}]", l.join(", "))
            }
            Pad::SetContains(_, b) => format!("s contains \"{}\"", "a".repeat(b - k)),
            Pad::SetUnder(_, b) => format!("s under \"{}\"", "/a".repeat(b / 2 - k)),
        }
    }
}

/// X (`low`) or Y of [`alternating`] with `atoms − 2` atoms of `pad` in every
/// rule before the two on x.
pub fn padded(pad: Pad, rules: usize, atoms: usize, low: bool) -> Scope {
    let rule = |(lo, hi): (i64, i64), lo_last: bool| {
        let mut a: Vec<String> = (0..atoms - 2).map(|k| pad.atom(k)).collect();
        let (lo, hi) = (format!("x >= {lo}"), format!("x <= {hi}"));
        if lo_last {
            a.extend([hi, lo]);
        } else {
            a.extend([lo, hi]);
        }
        format!("{} where {}{}", pad.head(), a.join(" and "), pad.tail())
    };
    let most = if low {
        rule((0, 5), false)
    } else {
        rule((1, 6), true)
    };
    let mut text = vec![most; rules - 1];
    text.push(rule((0, 6), false));
    Scope::parse(&text.join("\n")).expect("well formed")
}

/// The rules × atoms cells of D-98's measurement (`benches/contains_cost.rs`).
pub const COST_CELLS: [(usize, usize); 15] = [
    (16, 8),
    (16, 16),
    (16, 32),
    (32, 8),
    (32, 16),
    (32, 32),
    (64, 8),
    (64, 16),
    (64, 32),
    (128, 8),
    (128, 16),
    (128, 32),
    (256, 8),
    (256, 16),
    (256, 32),
];

/// Every padding D-98's search tries.
pub fn search_pads() -> Vec<Pad> {
    let mut pads = vec![Pad::Bounds];
    pads.extend([1, 2, 4, 8, 16, 32, 64].map(Pad::IntList));
    pads.extend([7, 8, 16, 64].map(Pad::XList));
    // The k-th prefix is `bytes` + k long, within D-21's 1,024 bytes.
    pads.extend([1, 8, 64, 256, 992].map(Pad::StrPrefix));
    for n in [1, 2, 8, 32, 64] {
        pads.extend([2, 32, 256].map(|b| Pad::StrList(n, b)));
    }
    pads
}

/// Smaller bounds at which D-98 measures every padding that fits, for
/// D-99's candidate configurations: (rules, atoms).
pub const SWEEP_BOUNDS: [(usize, usize); 3] = [(16, 8), (32, 8), (64, 16)];

/// The costliest padding D-98's search found (`examples/contains_search.rs`):
/// `y in [0, 1]` in every rule.
pub const WORST_FOUND: Pad = Pad::IntList(2);

/// The search's next costliest finds, measured at their largest size.
pub const RUNNERS_UP: [(Pad, usize); 3] = [
    (Pad::IntList(1), 32),
    (Pad::StrList(1, 2), 32),
    (Pad::XList(7), 24),
];

/// The most rules, up to 256, for which both of `pad`'s scopes with `atoms`
/// atoms fit a body, if any.
pub fn max_rules(pad: Pad, atoms: usize) -> Option<usize> {
    let ok = |r: usize| fits(&padded(pad, r, atoms, true)) && fits(&padded(pad, r, atoms, false));
    if !ok(1) {
        return None;
    }
    let (mut lo, mut hi) = (1usize, 256usize);
    while lo < hi {
        let mid = (lo + hi).div_ceil(2);
        if ok(mid) {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    Some(lo)
}

/// D-99: the atom-level count of every `Contains` call that a verification
/// of each workload profile makes (the ceiling, and each link up to
/// N = 10), and of the inputs D-98 measures. Deterministic.
pub fn work_counts() -> serde_json::Value {
    use crate::workload::{Profile, hop_scopes};
    use dc_policy::contains_within;
    use serde_json::json;

    let count = |s1: &Scope, s2: &Scope| {
        let w = contains_within(s1, s2, u64::MAX);
        assert!(w.answer, "every measured input is contained");
        w.work
    };
    let profiles: serde_json::Map<String, serde_json::Value> = Profile::ALL
        .iter()
        .map(|&p| {
            let s = hop_scopes(p);
            let mut calls = vec![("ceiling".to_owned(), count(&s[0], &s[0]))];
            calls.extend((1..s.len()).map(|k| (format!("link {k}"), count(&s[k - 1], &s[k]))));
            let max = calls.iter().map(|c| c.1).max().unwrap_or(0);
            let calls: serde_json::Map<String, serde_json::Value> =
                calls.into_iter().map(|(k, v)| (k, json!(v))).collect();
            (p.label().to_owned(), json!({ "max": max, "calls": calls }))
        })
        .collect();
    let mut inputs = serde_json::Map::new();
    for (rules, atoms) in COST_CELLS {
        let id = format!("r{rules}_a{atoms}");
        let (p, c) = (
            frozen_worst(rules, atoms, 1000),
            frozen_worst(rules, atoms, 999),
        );
        if fits(&p) && fits(&c) {
            inputs.insert(format!("frozen-worst/{id}"), json!(count(&p, &c)));
        }
        for (name, pad) in [("alternating", Pad::Bounds), ("intlist2", WORST_FOUND)] {
            let (x, y) = (
                padded(pad, rules, atoms, true),
                padded(pad, rules, atoms, false),
            );
            if fits(&x) && fits(&y) {
                inputs.insert(format!("{name}/{id}"), json!(count(&y, &x)));
            }
        }
    }
    for (rules, atoms) in SWEEP_BOUNDS {
        for pad in search_pads() {
            let (x, y) = (
                padded(pad, rules, atoms, true),
                padded(pad, rules, atoms, false),
            );
            if fits(&x) && fits(&y) {
                inputs.insert(
                    format!("sweep/{}/r{rules}_a{atoms}", pad.label()),
                    json!(count(&y, &x)),
                );
            }
        }
    }
    for (pad, atoms) in RUNNERS_UP {
        if let Some(rules) = max_rules(pad, atoms) {
            let (x, y) = (
                padded(pad, rules, atoms, true),
                padded(pad, rules, atoms, false),
            );
            inputs.insert(
                format!("{}/r{rules}_a{atoms}", pad.label()),
                json!(count(&y, &x)),
            );
        }
    }
    json!({
        "label": "atom-level counts of the prototype work budget (D-99); deterministic, not timings",
        "profiles": profiles,
        "inputs": inputs,
    })
}
