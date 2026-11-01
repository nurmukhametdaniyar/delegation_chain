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
