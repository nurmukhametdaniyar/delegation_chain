//! M5 smoke test: chains built by the §8 services check out end to end.
//! The full verifier arrives in M6; this test does its core work by hand.
//! It decodes, round-trips canonically, recomputes digests, resolves and
//! checks certificates, verifies the aggregate, the containment chain, the
//! evaluation and the receipts.

use dc_cbor::{Key, Value};
use dc_chain::{Chain, ChainBuilder, ChainError, EnforcementPolicy, SigningService, World};
use dc_crypto::{Bls, BlsAggregate, ChainScheme, Dst, SigScheme};
use dc_policy::{Decision, Invocation, Scope, contains, evaluate};
use dc_registry::Resolver;
use dc_types::digest::chain_digests;
use dc_types::{Body, Envelope, Identifier, Params, ParsedCert, Principal, decode_body};

const T0: u64 = 1_790_000_000;

const POLICY: &str = r#"
allow at=orgb:service:payments tool=payments action=transfer
  params { amount: int, to_account: string } where amount <= 1000
allow at=orgb:service:payments tool=payments action=transfer
  params { amount: int, to_account: string }
  where amount <= 100000 and to_account in ["acct_vendor_a", "acct_vendor_b"]
  approval requires orga:approver:finance
allow at=orgb:service:files tool=files action=read
  params { file: string } where file under "/home/agent/workspace""#;

fn p(s: &str) -> Principal {
    Principal::parse(s).unwrap()
}

fn id(s: &str) -> Identifier {
    Identifier::new(s).unwrap()
}

fn transfer(amount: u64) -> Params {
    Params::new(
        Value::map(vec![
            (Key::from("amount"), Value::uint(amount)),
            (Key::from("to_account"), Value::text("acct_vendor_a")),
        ])
        .unwrap(),
    )
    .unwrap()
}

struct Fixture {
    world: World<Bls>,
    policy: Scope,
}

fn fixture() -> Fixture {
    let world = World::new(7, T0);
    Fixture {
        world,
        policy: Scope::parse(POLICY).unwrap(),
    }
}

/// Builds session → a1 → a2 → a3 → invocation, each hop tightening rule 1.
fn build(f: &mut Fixture, amount: u64) -> Result<Chain<BlsAggregate>, ChainError> {
    let w = &mut f.world;
    let issuer = w.issuer("orga:issuer:main");
    let a1 = w.agent("orga:agent:a1");
    let a2 = w.agent("orga:agent:a2");
    let a3 = w.agent("orga:agent:a3");
    let finance = w.approver("orga:approver:finance");
    let hash = w.publish(&f.policy);
    let now = w.now();
    let issued = issuer.issue(a1.agent(), a1.pk(), &f.policy, hash, now, 3600, w.rng())?;
    let mut b = ChainBuilder::<BlsAggregate>::start(issued, f.policy.clone());
    let tighten = |n: u64| {
        Scope::parse(&POLICY.replace("amount <= 1000\n", &format!("amount <= {n}\n"))).unwrap()
    };
    b.delegate(&a1, a2.agent(), a2.pk(), tighten(999), now + 1800, w.rng())?;
    b.delegate(&a2, a3.agent(), a3.pk(), tighten(998), now + 900, w.rng())?;
    b.invoke_approved(
        &a3,
        &p("orgb:service:payments"),
        &id("payments"),
        &id("transfer"),
        transfer(amount),
        now,
        now + 300,
        &[&finance],
        now,
        w.rng(),
    )
}

/// The core of Algorithms 1–2, done by hand for the smoke test.
fn check(f: &Fixture, bytes: &[u8]) -> Decision {
    let env = Envelope::from_bytes(bytes).unwrap();
    let bodies: Vec<Body<Bls>> = env
        .bodies
        .iter()
        .map(|b| {
            let d = decode_body::<Bls>(b).unwrap();
            assert_eq!(d.violation, None);
            assert_eq!(&d.body.canonical_bytes().unwrap(), b);
            d.body
        })
        .collect();
    let refs: Vec<&[u8]> = env.bodies.iter().map(Vec::as_slice).collect();
    let m = chain_digests(&refs);
    let roots = f.world.roots();
    let dir = f.world.directory();
    let t = f.world.now();
    let pks: Vec<_> = bodies
        .iter()
        .map(|b| {
            let cert = dir
                .resolve(b.signer_id(), b.signer_pk(), t)
                .expect("resolvable");
            let c = ParsedCert::<Bls>::decode(&cert).unwrap();
            assert!(Bls::verify(
                &roots[b.signer_id().org()],
                &c.message(),
                Dst::Cert,
                &c.sig
            ));
            Bls::pk_from_bytes(&c.body.pk).unwrap()
        })
        .collect();
    let pk_refs: Vec<_> = pks.iter().collect();
    let sigs = BlsAggregate::from_wire(&env.sigs, bodies.len()).unwrap();
    assert!(BlsAggregate::verify_chain(&pk_refs, &m, &sigs), "aggregate");

    let Body::Session(s0) = &bodies[0] else {
        panic!()
    };
    assert_eq!(s0.policy_hash, f.policy.policy_hash());
    let scopes: Vec<Scope> = bodies[..bodies.len() - 1]
        .iter()
        .map(|b| Scope::from_raw(b.scope().unwrap()).unwrap())
        .collect();
    assert!(contains(&f.policy, &scopes[0]));
    for w in scopes.windows(2) {
        assert!(contains(&w[0], &w[1]));
    }
    let Body::Invocation(inv) = bodies.last().unwrap() else {
        panic!()
    };
    let d = evaluate(
        scopes.last().unwrap(),
        &Invocation {
            aud: &inv.aud,
            tool: &inv.tool,
            action: &inv.action,
            params: inv.params.value(),
        },
    );
    for r in &inv.receipts {
        let cert = dir
            .resolve(&r.approval.approver_id, &r.approval.approver_pk, t)
            .unwrap();
        let c = ParsedCert::<Bls>::decode(&cert).unwrap();
        let pk = Bls::pk_from_bytes(&c.body.pk).unwrap();
        assert_eq!(
            r.approval.invocation_digest,
            inv.invocation_digest().unwrap()
        );
        assert!(Bls::verify(&pk, &r.message(), Dst::Receipt, &r.sig));
    }
    d
}

#[test]
fn chain_without_approval_checks_out() {
    let mut f = fixture();
    let chain = build(&mut f, 500).unwrap();
    assert_eq!(chain.n(), 3);
    assert_eq!(chain.digests, {
        let refs: Vec<&[u8]> = chain.bytes.iter().map(Vec::as_slice).collect();
        chain_digests(&refs)
    });
    assert_eq!(check(&f, &chain.to_bytes()), Decision::Allow);
    let Body::Invocation(inv) = chain.bodies.last().unwrap() else {
        panic!()
    };
    assert!(inv.receipts.is_empty());
}

#[test]
fn chain_with_approval_carries_a_verifying_receipt() {
    let mut f = fixture();
    let chain = build(&mut f, 5000).unwrap();
    assert_eq!(
        check(&f, &chain.to_bytes()),
        Decision::AllowWithApproval(vec![p("orga:approver:finance")])
    );
    let Body::Invocation(inv) = chain.bodies.last().unwrap() else {
        panic!()
    };
    assert_eq!(inv.receipts.len(), 1);
}

#[test]
fn tampering_breaks_the_aggregate() {
    let mut f = fixture();
    let chain = build(&mut f, 500).unwrap();
    let mut env = chain.envelope();
    // Re-sign nothing; change the delegation's expiry by one second.
    let Body::Delegation(mut d) = chain.bodies[1].clone() else {
        panic!()
    };
    d.exp -= 1;
    env.bodies[1] = Body::<Bls>::Delegation(d).canonical_bytes().unwrap();
    let refs: Vec<&[u8]> = env.bodies.iter().map(Vec::as_slice).collect();
    let m = chain_digests(&refs);
    let pks: Vec<_> = chain
        .bodies
        .iter()
        .map(|b| Bls::pk_from_bytes(b.signer_pk()).unwrap())
        .collect();
    let pk_refs: Vec<_> = pks.iter().collect();
    assert!(!BlsAggregate::verify_chain(&pk_refs, &m, &chain.sigs));
}

#[test]
fn builder_refuses_a_denied_invocation() {
    let mut f = fixture();
    let w = &mut f.world;
    let issuer = w.issuer("orga:issuer:main");
    let a1 = w.agent("orga:agent:a1");
    let hash = w.publish(&f.policy);
    let now = w.now();
    let issued = issuer
        .issue(a1.agent(), a1.pk(), &f.policy, hash, now, 3600, w.rng())
        .unwrap();
    let b = ChainBuilder::<BlsAggregate>::start(issued, f.policy.clone());
    let r = b.invoke_approved(
        &a1,
        &p("orgb:service:payments"),
        &id("payments"),
        &id("transfer"),
        transfer(200_000),
        now,
        now + 60,
        &[],
        now,
        w.rng(),
    );
    assert!(matches!(r, Err(ChainError::Denied)));
}

#[test]
fn signing_service_checks_the_body_and_runs_its_policy() {
    let mut f = fixture();
    let chain = build(&mut f, 500).unwrap();
    let m1 = chain.digests[0];
    // Another agent's service refuses a body naming a1 as delegator.
    let a2 = f.world.agent_service("orga:agent:a2", "orga:agent:a2");
    assert!(matches!(
        a2.sign(&chain.bodies[1], &m1),
        Err(ChainError::NotMyBody)
    ));
    // No signing service signs session bodies.
    let a1 = f.world.agent_service("orga:agent:a1", "orga:agent:a1");
    assert!(matches!(
        a1.sign(&chain.bodies[0], &m1),
        Err(ChainError::NotAgentBody)
    ));
    // It computes m_k itself: the same result as the builder's.
    assert_eq!(a1.sign(&chain.bodies[1], &m1).unwrap().m, chain.digests[1]);

    // An enforcement policy (P-12) can refuse.
    struct NoLargeTransfers;
    impl EnforcementPolicy<Bls> for NoLargeTransfers {
        fn check(&self, body: &Body<Bls>) -> Result<(), String> {
            match body {
                Body::Invocation(i)
                    if i.params
                        .value()
                        .get(&Key::from("amount"))
                        .and_then(Value::as_u64)
                        > Some(100) =>
                {
                    Err("amount over 100".into())
                }
                _ => Ok(()),
            }
        }
    }
    let strict = SigningService::<Bls>::with_policy(
        p("orga:agent:a3"),
        f.world.secret("orga:agent:a3"),
        Box::new(NoLargeTransfers),
    );
    let last = chain.bodies.last().unwrap();
    assert!(matches!(
        strict.sign(last, &chain.digests[2]),
        Err(ChainError::Enforcement(_))
    ));
}

#[test]
fn worlds_are_deterministic() {
    let (mut f1, mut f2) = (fixture(), fixture());
    assert_eq!(
        build(&mut f1, 500).unwrap().to_bytes(),
        build(&mut f2, 500).unwrap().to_bytes()
    );
}
