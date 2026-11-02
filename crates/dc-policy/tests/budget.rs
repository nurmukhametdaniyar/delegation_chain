//! D-100: `Contains` under a work budget (SPEC §9.6.1).
//!
//! - The unit: counts worked out by hand from SPEC §9.6.1's table equal the
//!   implementation's, for one pair of each path type and one pair that runs
//!   step 3(b) and its skip test. Replicas agree only if every
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

/// (name, S1, S2, W) with W worked out from SPEC §9.6.1's table.
fn hand_counted() -> Vec<(&'static str, Scope, Scope, u64)> {
    vec![
        (
            // One test r2 ⊆ r1: 1, then implies(C2 = [x in 1..3], C1 = [x <= 10]).
            // unsat(C2): n(C2) 1, select x 1, build w(A) 3, int satisfiability
            // n(F) 3 = 8. Atom x <= 10: select 1, build 3, satisfiability 3,
            // n(F) 3 again, n(F′)·w(b) 3·1 = 13. W = 1 + 8 + 13.
            "int",
            scope(&["params { x: int } where x <= 10"]),
            scope(&["params { x: int } where x in [1, 2, 3]"]),
            22,
        ),
        (
            // 1; unsat(C2 = [f == true]): 1 + 1 + build 1 + 0 = 3. Atom
            // f in [true, false]: select 1, build 1, 2·w(b) = 4. W = 1 + 3 + 6.
            "bool",
            scope(&["params { f: bool } where f in [true, false]"]),
            scope(&["params { f: bool } where f == true"]),
            10,
        ),
        (
            // 1; unsat(C2 = [starts_with "/a/b", ends_with ".txt"]): n(C2) 2,
            // select 2, build 2, n(P)² + n(S)² = 2: 8. Atom starts_with "/a":
            // select 2, build 2, satisfiability 2, n(P) + n(S) = 2: 8. W = 17.
            "string, no finite set",
            scope(&["params { s: string } where s starts_with \"/a\""]),
            scope(&["params { s: string } where s starts_with \"/a/b\" and s ends_with \".txt\""]),
            17,
        ),
        (
            // 1; unsat(C2 = [s in [a, b, c], s starts_with "a"]): 2 + 2 + build
            // w(A) 4 + n(E)·w(A) 3·4 = 20. Atom s in [a, b]: select 2, build 4,
            // satisfiability 12, n(E)·w(A) 12 again, n(E′)·w(b) 1·2 = 32.
            // W = 1 + 20 + 32.
            "string, finite set",
            scope(&["params { s: string } where s in [\"a\", \"b\"]"]),
            scope(&[
                "params { s: string } where s in [\"a\", \"b\", \"c\"] and s starts_with \"a\"",
            ]),
            53,
        ),
        (
            // Reflexivity of the recommended order: an approval rule before an
            // overlapping permissive one.
            // r2 = rule 0: test r2 ⊆ rule 0: 1 + implies([x <= 5], [x <= 5])
            // (unsat 1 + 1 + 1 + 0; atom 1 + 1 + 0 + 0) = 6.
            // r2 = rule 1: test r2 ⊆ rule 0: 1, approvals fail. Test r2 ⊆
            // rule 1: 1 + 5 = 6. Step 3(b), r′ = rule 0: 1; unsat([x <= 5,
            // x <= 10]): 2 + 2 + 2 + 0 = 6; skip test: implies(rule 0's clause,
            // child rule 0's) = 5, which shadows. 19. W = 6 + 19.
            "step 3(b) and the skip test",
            scope(&[
                "params { x: int } where x <= 5 approval requires o:approver:p",
                "params { x: int } where x <= 10",
            ]),
            scope(&[
                "params { x: int } where x <= 5 approval requires o:approver:p",
                "params { x: int } where x <= 10",
            ]),
            25,
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
