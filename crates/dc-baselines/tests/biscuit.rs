//! Arm E (SPEC §12.3, D-68): the Biscuit mapping runs, attenuates, and
//! agrees with DC's `Evaluate` on the paper's §6.2 policy family, where
//! Biscuit allows exactly what DC allows without approval.

use dc_baselines::biscuit::{BiscuitArm, Request};
use dc_cbor::{Key, Value};
use dc_policy::{Decision, Invocation, Scope, evaluate};
use dc_types::{Identifier, Principal};

const T0: u64 = 1_790_000_000;

const POLICY: &str = r#"allow at=orgb:service:payments
  tool=payments action=transfer
  params { amount: int,
           to_account: string }
  where amount <= 1000
allow at=orgb:service:payments
  tool=payments action=transfer
  params { amount: int,
           to_account: string }
  where amount <= 100000
        and to_account in
            ["acct_vendor_a", "acct_vendor_b"]
  approval requires orga:approver:finance
allow at=orgb:service:files
  tool=files action=read
  params { file: string }
  where file under "/home/agent/workspace""#;

fn with_bound(bound: u64) -> Scope {
    Scope::parse(&POLICY.replacen("amount <= 1000\n", &format!("amount <= {bound}\n"), 1)).unwrap()
}

fn map(entries: Vec<(&str, Value)>) -> Value {
    let entries: Vec<(Key, Value)> = entries
        .into_iter()
        .map(|(k, v)| (Key::from(k), v))
        .collect();
    Value::map(entries).unwrap()
}

struct Req {
    aud: Principal,
    tool: Identifier,
    action: Identifier,
    params: Value,
}

fn transfer(amount: u64, to: &str) -> Req {
    Req {
        aud: Principal::parse("orgb:service:payments").unwrap(),
        tool: Identifier::new("payments").unwrap(),
        action: Identifier::new("transfer").unwrap(),
        params: map(vec![
            ("amount", Value::uint(amount)),
            ("to_account", Value::text(to)),
        ]),
    }
}

fn read(file: &str) -> Req {
    Req {
        aud: Principal::parse("orgb:service:files").unwrap(),
        tool: Identifier::new("files").unwrap(),
        action: Identifier::new("read").unwrap(),
        params: map(vec![("file", Value::text(file))]),
    }
}

impl Req {
    fn at(&self, now: u64) -> Request<'_> {
        Request {
            aud: &self.aud,
            tool: &self.tool,
            action: &self.action,
            params: &self.params,
            now,
        }
    }
    fn dc(&self, scope: &Scope) -> Decision {
        evaluate(
            scope,
            &Invocation {
                aud: &self.aud,
                tool: &self.tool,
                action: &self.action,
                params: &self.params,
            },
        )
    }
}

/// The session scope and `depth` attenuations, each tightening rule 1's bound
/// by 100, as the medium profile's delegations do.
fn chain(depth: usize) -> (Scope, Vec<Scope>) {
    (
        Scope::parse(POLICY).unwrap(),
        (1..=depth)
            .map(|i| with_bound(1000 - 100 * i as u64))
            .collect(),
    )
}

fn token(arm: &BiscuitArm, depth: usize, exp: u64) -> (Vec<u8>, Scope) {
    let (session, atts) = chain(depth);
    let refs: Vec<(&Scope, u64)> = atts.iter().map(|s| (s, exp)).collect();
    let t = arm.token(&session, exp, &refs, &[depth as u8]).unwrap();
    (t, atts.last().cloned().unwrap_or(session))
}

#[test]
fn tokens_verify_and_attenuate() {
    let arm = BiscuitArm::new(b"test");
    for depth in 0..=5 {
        let (t, _) = token(&arm, depth, T0 + 3600);
        assert!(
            arm.verify(&t, &transfer(500, "acct_vendor_a").at(T0))
                .is_ok(),
            "depth {depth}"
        );
        // Rule 1's bound after `depth` attenuations is 1000 − 100·depth.
        let over = 1000 - 100 * depth as u64 + 1;
        assert!(
            arm.verify(&t, &transfer(over, "acct_other").at(T0))
                .is_err(),
            "depth {depth}"
        );
    }
}

#[test]
fn deterministic_tokens() {
    let a = BiscuitArm::new(b"seed");
    let b = BiscuitArm::new(b"seed");
    assert_eq!(token(&a, 3, T0).0, token(&b, 3, T0).0);
}

#[test]
fn failures() {
    let arm = BiscuitArm::new(b"test");
    let (t, _) = token(&arm, 2, T0 + 3600);
    let ok = transfer(500, "acct_vendor_a");
    // Expired.
    assert!(arm.verify(&t, &ok.at(T0 + 3601)).is_err());
    assert!(arm.verify(&t, &ok.at(T0 + 3600)).is_ok());
    // Another root, and a tampered token.
    assert!(BiscuitArm::new(b"other").verify(&t, &ok.at(T0)).is_err());
    let mut bad = t.clone();
    let i = bad.len() / 2;
    bad[i] ^= 1;
    assert!(arm.verify(&bad, &ok.at(T0)).is_err());
    // Wrong type, and an undeclared parameter (the closed world).
    let mut typed = transfer(500, "acct_vendor_a");
    typed.params = map(vec![
        ("amount", Value::text("500")),
        ("to_account", Value::text("acct_vendor_a")),
    ]);
    assert!(arm.verify(&t, &typed.at(T0)).is_err());
    let mut extra = transfer(500, "acct_vendor_a");
    extra.params = map(vec![
        ("amount", Value::uint(500)),
        ("memo", Value::text("x")),
        ("to_account", Value::text("acct_vendor_a")),
    ]);
    assert!(arm.verify(&t, &extra.at(T0)).is_err());
}

#[test]
fn agrees_with_evaluate_on_the_policy_family() {
    let arm = BiscuitArm::new(b"test");
    let mut requests = vec![];
    for amount in [
        0, 1, 499, 500, 700, 701, 800, 801, 900, 999, 1000, 1001, 5000, 100_000, 100_001,
    ] {
        for to in ["acct_vendor_a", "acct_vendor_b", "acct_other"] {
            requests.push(transfer(amount, to));
        }
    }
    for file in [
        "/home/agent/workspace",
        "/home/agent/workspace/a.txt",
        "/home/agent/workspace/sub/b",
        "/home/agent/workspacex",
        "/home/agent",
        "home/agent/workspace/a",
    ] {
        requests.push(read(file));
    }
    let mut compared = 0;
    for depth in 0..=3 {
        let (t, last) = token(&arm, depth, T0 + 3600);
        for r in &requests {
            let dc = r.dc(&last);
            let e = arm.verify(&t, &r.at(T0)).is_ok();
            // Biscuit has no receipts: it allows exactly DC's plain Allow.
            // "home/agent/workspace/a" is not absolute, and DC's `under`
            // rejects it; the mapping's `under` does too, since it needs
            // the "/home/…" prefix.
            assert_eq!(
                e,
                dc == Decision::Allow,
                "depth {depth}: {:?} → DC {dc:?}",
                r.params
            );
            compared += 1;
        }
    }
    assert_eq!(compared, 4 * 51);
}
