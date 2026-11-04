//! D-100: `Contains` under a work budget (SPEC §9.6.1).
//!
//! - The unit: counts worked out by hand from SPEC §9.6.1's table equal the
//!   implementation's, for one pair of each path type, one with strings long
//!   enough to cost by length, and one pair that runs step 3(b) and its skip
//!   test (D-101). Replicas agree only if every
//!   implementation counts the same way, so these pin the table to the code.
//! - The boundary: a budget equal to the count answers as the procedure does;
//!   one less answers false, with the budget run out.
//! - Determinism: a pair's count and answer are the same on every run, on
//!   every thread, and whatever ran before on the thread.
//!
//! The property against the procedure as written is in `memo.rs`, beside
//! its generator.

use dc_policy::{DEFAULT_BUDGET, Scope, Within, contains, contains_within};

const HEAD: &str = "allow at=o:service:s tool=t action=a";

fn scope(rules: &[&str]) -> Scope {
    let text: Vec<String> = rules.iter().map(|r| format!("{HEAD} {r}")).collect();
    Scope::parse(&text.join("\n")).unwrap()
}

/// (name, S1, S2, W) with W worked out from SPEC §9.6.1's table (D-101).
/// Every head here is `o:service:s`, `t`, `a` and one declared path, so
/// head(r) = 4 and each test costs 1 + 4.
fn hand_counted() -> Vec<(&'static str, Scope, Scope, u64)> {
    let x20 = "abcdefghijklmnopqrst";
    let x70 = format!("0123456789{x20}{}", "0123456789".repeat(4));
    vec![
        (
            // Test: 5; approvals: 0 + 0. implies(C2 = [x in 1..3], C1 = [x <= 10]).
            // unsat(C2): paths 1; select and look up x (1 + 1)·1 = 2; build
            // w(A) 3; n(F) 3: 9. Atom x <= 10: select 2, build 3, satisfiability
            // 3, n(F) 3 again, n(F′)·w(b) 3·1: 14. W = 5 + 9 + 14.
            "int",
            scope(&["params { x: int } where x <= 10"]),
            scope(&["params { x: int } where x in [1, 2, 3]"]),
            28,
        ),
        (
            // 5; unsat(C2 = [f == true]): 1 + 2 + build 1 + 0 = 4. Atom
            // f in [true, false]: select 2, build 1, 2·w(b) = 4: 7. W = 16.
            "bool",
            scope(&["params { f: bool } where f in [true, false]"]),
            scope(&["params { f: bool } where f == true"]),
            16,
        ),
        (
            // 5; unsat(C2 = [starts_with "/a/b", ends_with ".txt"]): paths 2,
            // select (2 + 1)·1 = 3, build 2, pairs n(P)·z(P) + n(S)·z(S) = 2: 9.
            // Atom starts_with "/a": select 3, build 2, satisfiability 2, the
            // operands' scans 1 + 1 and n·(scan("/a") − 1) = 0: 9. W = 23.
            "string, no finite set",
            scope(&["params { s: string } where s starts_with \"/a\""]),
            scope(&["params { s: string } where s starts_with \"/a/b\" and s ends_with \".txt\""]),
            23,
        ),
        (
            // 5; unsat(C2 = [s in [a, b, c], s starts_with "a"]): 2 + 3 + build
            // w(A) 4 + n(E)·Σ check 3·4 = 21. Atom s in [a, b]: select 3, build
            // 4, satisfiability 12, admissible again 12, n(E′)·check(b) 1·2 =
            // 33. W = 5 + 21 + 33.
            "string, finite set",
            scope(&["params { s: string } where s in [\"a\", \"b\"]"]),
            scope(&[
                "params { s: string } where s in [\"a\", \"b\", \"c\"] and s starts_with \"a\"",
            ]),
            59,
        ),
        (
            // Lengths. 5; unsat(C2 = [contains x70]): 1 + 2 + build w(A) =
            // size(x70) = 1 + 70/64 = 2, no pairs: 5. Atom contains x20: select
            // 2, build 2, satisfiability 0, scan(x70) = 1 + 70/16 = 5 and
            // 1·(scan(x20) − 1) = 1: 10. W = 5 + 5 + 10.
            "string lengths",
            scope(&[&format!(
                "params {{ s: string }} where s contains \"{x20}\""
            )]),
            scope(&[&format!(
                "params {{ s: string }} where s contains \"{x70}\""
            )]),
            20,
        ),
        (
            // Reflexivity of the recommended order: an approval rule before an
            // overlapping permissive one. size(o:approver:p) = 1.
            // r2 = rule 0: test rule 0: 5 + approvals 1 + 1 + implies([x <= 5],
            // [x <= 5]) (unsat 1 + 2 + 1 + 0; atom 2 + 1 + 0 + 0) 7 = 14.
            // r2 = rule 1: test rule 0: 5 + approvals 1 + 0, which fail: 6.
            // Test rule 1: 5 + 0 + 7 = 12. Step 3(b), r′ = rule 0: 5;
            // unsat([x <= 5, x <= 10]): 2 + 3 + 2 + 0 = 7; skip test: head of
            // child rule 0, 4, and implies(rule 0's clause, its clause) 7,
            // which shadows: 23. W = 14 + 6 + 12 + 23.
            "step 3(b) and the skip test",
            scope(&[
                "params { x: int } where x <= 5 approval requires o:approver:p",
                "params { x: int } where x <= 10",
            ]),
            scope(&[
                "params { x: int } where x <= 5 approval requires o:approver:p",
                "params { x: int } where x <= 10",
            ]),
            55,
        ),
    ]
}

#[test]
fn counts_follow_the_spec_table() {
    for (name, s1, s2, w) in hand_counted() {
        assert!(contains(&s1, &s2), "{name}: contained");
        assert_eq!(
            contains_within(&s1, &s2, u64::MAX),
            Within {
                answer: true,
                work: w,
                exhausted: false
            },
            "{name}"
        );
    }
}

#[test]
fn the_budget_is_inclusive() {
    for (name, s1, s2, w) in hand_counted() {
        let at = contains_within(&s1, &s2, w);
        assert!(at.answer && !at.exhausted && at.work == w, "{name}: {at:?}");
        let below = contains_within(&s1, &s2, w - 1);
        assert!(
            !below.answer && below.exhausted && below.work > w - 1,
            "{name}: {below:?}"
        );
        let none = contains_within(&s1, &s2, 0);
        assert!(!none.answer && none.exhausted, "{name}: {none:?}");
    }
}

/// A pair with many rules and long lists, whose count passes the default
/// budget, beside the hand-counted ones.
fn costly() -> (Scope, Scope) {
    let list: Vec<String> = (0..64).map(|v| v.to_string()).collect();
    let rule = format!(
        "params {{ x: int, y: int }} where y in [{}] and x >= 0 and x <= 5",
        list.join(", ")
    );
    let wide = "params { x: int, y: int } where x >= 0 and x <= 6".to_owned();
    let mut parent = vec![rule.as_str(); 40];
    parent.push(&wide);
    let child = vec![rule.as_str(); 40];
    (scope(&parent), scope(&child))
}

#[test]
fn counts_are_deterministic() {
    let (p, c) = costly();
    let mut pairs: Vec<(Scope, Scope)> = hand_counted()
        .into_iter()
        .map(|(_, a, b, _)| (a, b))
        .collect();
    pairs.push((p.clone(), c.clone()));
    pairs.push((c, p));
    let budgets = [0, 100, DEFAULT_BUDGET, u64::MAX];
    let each = |(a, b): &(Scope, Scope)| budgets.map(|budget| contains_within(a, b, budget));
    let first: Vec<[Within; 4]> = pairs.iter().map(each).collect();
    assert!(
        first
            .iter()
            .flatten()
            .any(|w| w.exhausted && w.work > DEFAULT_BUDGET),
        "the costly pair passes the default budget"
    );
    // Repeated.
    for _ in 0..3 {
        assert_eq!(pairs.iter().map(each).collect::<Vec<_>>(), first);
    }
    // In reverse order, so that each call follows different ones.
    let mut back: Vec<[Within; 4]> = pairs.iter().rev().map(each).collect();
    back.reverse();
    assert_eq!(back, first);
    // On other threads.
    std::thread::scope(|t| {
        let handles: Vec<_> = (0..4)
            .map(|_| t.spawn(|| pairs.iter().map(each).collect::<Vec<_>>()))
            .collect();
        for h in handles {
            assert_eq!(h.join().unwrap(), first);
        }
    });
}
