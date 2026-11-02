//! D-97: the memoized containment procedure gives the same answer as the
//! procedure as written, on scopes with many rules. The differential oracle
//! compares the two only on small scopes, where step 3(b)'s skip test has
//! few earlier child rules to look at; these pairs have up to 24 rules a
//! side, most of them sharing one head, and child rules drawn mostly from
//! the parent's, so that the skip test runs often and often succeeds.
//!
//! D-100: on the same pairs, under budgets from 0 to twice each pair's
//! count, a budgeted true implies the reference's true (SPEC §9.6.1).
//!
//! `DC_MEMO_CASES` sets the number of pairs (default 20,000).

use std::cell::Cell;

use dc_policy::{Scope, contains, contains_unmemoized, contains_within};
use proptest::prelude::*;
use proptest::test_runner::{Config, RngAlgorithm, TestRng, TestRunner};

const HEADS: [&str; 2] = [
    "allow at=o:service:s tool=t action=a params { x: int, y: int }",
    "allow at=o:service:u tool=t action=a params { x: int, y: int }",
];

/// One atom on x or y, over a small range, so that clauses often overlap.
fn atom() -> impl Strategy<Value = String> {
    (
        prop::sample::select(vec!["x", "y"]),
        prop::sample::select(vec!["<=", ">=", "=="]),
        -2i64..6,
    )
        .prop_map(|(p, op, c)| format!("{p} {op} {c}"))
}

/// A rule: a head (usually the first), up to three atoms, and an approval
/// requirement drawn from two approvers.
fn rule() -> impl Strategy<Value = (usize, Vec<String>, u8)> {
    (
        prop::sample::select(vec![0usize, 0, 0, 1]),
        prop::collection::vec(atom(), 0..4),
        0u8..4,
    )
}

fn text((head, atoms, approval): &(usize, Vec<String>, u8)) -> String {
    let mut s = HEADS[*head].to_owned();
    if !atoms.is_empty() {
        s.push_str(&format!(" where {}", atoms.join(" and ")));
    }
    let names: Vec<&str> = [(1, "o:approver:p"), (2, "o:approver:q")]
        .iter()
        .filter(|(bit, _)| approval & bit != 0)
        .map(|(_, n)| *n)
        .collect();
    if !names.is_empty() {
        s.push_str(&format!(" approval requires {}", names.join(", ")));
    }
    s
}

/// A parent of 1–24 rules, and a child of 1–24 rules, each either a parent
/// rule with up to two atoms added (and perhaps another approval) or a fresh
/// rule.
fn pair() -> impl Strategy<Value = (Vec<String>, Vec<String>)> {
    prop::collection::vec(rule(), 1..25).prop_flat_map(|parent| {
        let n = parent.len();
        let child = prop::collection::vec(
            (
                0..n,
                prop::collection::vec(atom(), 0..3),
                0u8..4,
                prop::bool::weighted(0.8),
                rule(),
            ),
            1..25,
        );
        (Just(parent), child).prop_map(|(parent, child)| {
            let child = child
                .into_iter()
                .map(|(i, extra, approval, derived, fresh)| {
                    if derived {
                        let (head, mut atoms, a) = parent[i].clone();
                        atoms.extend(extra);
                        text(&(head, atoms, a | approval))
                    } else {
                        text(&fresh)
                    }
                })
                .collect();
            (parent.iter().map(text).collect(), child)
        })
    })
}

#[test]
fn memoized_contains_matches_the_procedure_as_written() {
    let cases: u32 = std::env::var("DC_MEMO_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20_000);
    let config = Config {
        cases,
        failure_persistence: None,
        ..Config::default()
    };
    let mut r = TestRunner::new_with_rng(
        config,
        TestRng::from_seed(RngAlgorithm::ChaCha, &[0xd9; 32]),
    );
    let (both, contained) = (Cell::new(0u32), Cell::new(0u32));
    r.run(&pair(), |(p, c)| {
        let (Ok(s1), Ok(s2)) = (Scope::parse(&p.join("\n")), Scope::parse(&c.join("\n"))) else {
            return Ok(());
        };
        both.set(both.get() + 1);
        let memo = contains(&s1, &s2);
        contained.set(contained.get() + u32::from(memo));
        prop_assert_eq!(
            memo,
            contains_unmemoized(&s1, &s2),
            "S1:\n{}\nS2:\n{}",
            s1,
            s2
        );
        Ok(())
    })
    .unwrap();
    let (both, contained) = (both.get(), contained.get());
    println!("{both} well-formed pairs, {contained} contained");
    // The comparison must cover both answers in quantity.
    assert!(both > cases / 2, "{both} well-formed pairs of {cases}");
    assert!(
        contained > both / 20 && contained < both - both / 20,
        "{contained} contained of {both}"
    );
}

#[test]
fn budgeted_true_implies_the_procedure_as_written() {
    let cases: u32 = std::env::var("DC_MEMO_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20_000);
    let config = Config {
        cases,
        failure_persistence: None,
        ..Config::default()
    };
    let mut r = TestRunner::new_with_rng(
        config,
        TestRng::from_seed(RngAlgorithm::ChaCha, &[0xb0; 32]),
    );
    let (budgeted_true, exhausted) = (Cell::new(0u32), Cell::new(0u32));
    // The budget is a fraction of the pair's count, in thousandths: 0 to 2.
    r.run(&(pair(), 0u64..=2000), |((p, c), frac)| {
        let (Ok(s1), Ok(s2)) = (Scope::parse(&p.join("\n")), Scope::parse(&c.join("\n"))) else {
            return Ok(());
        };
        let reference = contains_unmemoized(&s1, &s2);
        let w = contains_within(&s1, &s2, u64::MAX).work;
        let budget = w * frac / 1000;
        let at = contains_within(&s1, &s2, budget);
        // A budgeted true implies the procedure's true.
        prop_assert!(!at.answer || reference, "S1:\n{}\nS2:\n{}", s1, s2);
        // Within the budget the answers are equal, and past it false.
        prop_assert_eq!(at.answer, reference && w <= budget);
        // The budget runs out exactly when the count passes it.
        prop_assert_eq!(at.exhausted, w > budget);
        prop_assert!(!at.exhausted || at.work > budget);
        // A larger budget never turns true into false.
        let more = contains_within(&s1, &s2, budget.saturating_mul(2).max(budget + 1));
        prop_assert!(!at.answer || more.answer);
        budgeted_true.set(budgeted_true.get() + u32::from(at.answer));
        exhausted.set(exhausted.get() + u32::from(at.exhausted));
        Ok(())
    })
    .unwrap();
    let (t, e) = (budgeted_true.get(), exhausted.get());
    println!("{t} budgeted true, {e} exhausted");
    // Both outcomes, in quantity.
    assert!(t > cases / 20 && e > cases / 20, "{t} true, {e} exhausted");
}
