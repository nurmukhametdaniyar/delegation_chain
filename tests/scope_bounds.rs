//! A compromised agent can make every link it signs pass while running
//! step 3(b)'s shadow scan in full (D-95): it signs the scopes X and Y of
//! `dc_bench::bounds::alternating` in turn. This checks the construction
//! end to end, at N = 16 and a small size, under the §6.2 policy. The cost
//! at D-21's bounds is `crates/dc-bench/benches/bounds.rs`'s.

mod common;

use common::*;
use dc_bench::bounds::alternating;

const HEAD: &str = "allow at=orgb:service:payments tool=payments action=transfer \
                    params { amount: int, to_account: string }";

#[test]
fn alternating_scopes_pass_every_link() {
    let mut s = Suite::new();
    for i in 7..=16 {
        s.w.enroll(&agent(i), &agent(i)).unwrap();
    }
    let v = s.verifier();
    // The session scope is the policy itself; a1 delegates Y, a2 X, and so
    // on, to a16, who invokes. Distinct agents here; one agent delegating to
    // itself passes line 20 just the same.
    let mut scopes = vec![s.policy.clone()];
    for k in 1..16 {
        scopes.push(alternating(HEAD, "amount", 8, 4, k % 2 == 0));
    }
    let c = s.chain_with(
        &scopes,
        PAYMENTS,
        "payments",
        "transfer",
        transfer(3, "acct_vendor_a"),
    );
    let (r, n) = v.verify_counted(&c.to_bytes());
    assert!(r.is_ok());
    // The ceiling and the 15 links, each passing.
    assert_eq!((n.contains_calls, n.evaluate_calls), (16, 1), "{n:?}");
}

/// D-97: the memoized procedure answers as the procedure as written on the
/// alternating family and the frozen generator's worst case, both
/// directions, and on a variant whose last child rule is widened, which
/// neither may accept. The reference is too slow at the bounds in a debug
/// build, so by default the sizes stop at 32 rules × 16 atoms. With
/// `DC_BOUNDS_FULL=1` (in release), every cell of the bounds bench is also
/// checked to pass, as it did before D-97.
#[test]
fn memoized_contains_agrees_on_the_bounds_constructions() {
    use dc_bench::bounds::{CELLS, SHORT_HEAD, fits, frozen_worst};
    use dc_policy::{Scope, contains, contains_unmemoized};

    for rules in [8, 16, 32] {
        for atoms in [4, 8, 16] {
            let x = alternating(SHORT_HEAD, "x", rules, atoms, true);
            let y = alternating(SHORT_HEAD, "x", rules, atoms, false);
            let wide = Scope::parse(&format!(
                "{x}\n{SHORT_HEAD} where x >= -1 and x <= 9",
                x = alternating(SHORT_HEAD, "x", rules - 1, atoms, true)
            ))
            .unwrap();
            let (p, c) = (
                frozen_worst(rules, atoms, 1000),
                frozen_worst(rules, atoms, 999),
            );
            for (s1, s2, want) in [
                (&y, &x, true),
                (&x, &y, true),
                (&y, &wide, false),
                (&p, &c, true),
            ] {
                assert_eq!(contains(s1, s2), want, "r{rules}_a{atoms}");
                assert_eq!(contains_unmemoized(s1, s2), want, "r{rules}_a{atoms}");
            }
        }
    }
    if std::env::var("DC_BOUNDS_FULL").is_ok_and(|v| v == "1") {
        for (rules, atoms) in CELLS {
            let x = alternating(SHORT_HEAD, "x", rules, atoms, true);
            let y = alternating(SHORT_HEAD, "x", rules, atoms, false);
            assert!(fits(&x) && fits(&y));
            assert!(contains(&y, &x) && contains(&x, &y), "r{rules}_a{atoms}");
            let (p, c) = (
                frozen_worst(rules, atoms, 1000),
                frozen_worst(rules, atoms, 999),
            );
            if fits(&p) && fits(&c) {
                assert!(contains(&p, &c), "frozen r{rules}_a{atoms}");
            }
        }
    }
}
