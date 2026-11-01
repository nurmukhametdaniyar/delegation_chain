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
