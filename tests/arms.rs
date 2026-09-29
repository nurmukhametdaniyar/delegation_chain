//! The benchmark arms (SPEC §12) on real chains: operation counts per arm,
//! and the prefix caches' hit path and invalidation (SPEC §12.1, D-67).
//! Counts need `count-ops`, which the workspace tests enable.

mod common;

use std::sync::Arc;

use common::*;
use dc_baselines::{BlsIndividual, Ed25519Batch, Ed25519List};
use dc_chain::{Chain, ChainBuilder};
use dc_crypto::{BlsAggregate, ChainScheme, PrefixScheme, WireForm};
use dc_registry::{Directory, MemoryPolicyStore, Resolver};
use dc_types::{ManualClock, ParsedCert};
use dc_verifier::{OpCounts, Path, PrefixVerifier, Reject, VerifierConfig};

type PV<C> = PrefixVerifier<C, Directory, Arc<MemoryPolicyStore>, Arc<ManualClock>>;

/// A three-hop prefix through a1, a2, a3, with every scope the policy.
fn prefix<C: ChainScheme>(s: &mut ArmSuite<C>) -> ChainBuilder<C> {
    let agents: Vec<String> = (1..=3).map(agent).collect();
    let refs: Vec<(&str, &str)> = agents.iter().map(|a| (a.as_str(), a.as_str())).collect();
    let scopes = vec![s.policy.clone(); 3];
    s.prefix((ISSUER, ISSUER), &refs, &scopes)
}

/// A fresh 500-unit transfer by a3 on the prefix.
fn invoke<C: ChainScheme>(s: &mut ArmSuite<C>, b: &ChainBuilder<C>) -> Chain<C> {
    let now = s.now();
    let a3 = agent(3);
    s.invoke_on(
        b.clone(),
        (&a3, &a3),
        PAYMENTS,
        "payments",
        "transfer",
        transfer(500, "acct_vendor_a"),
        (now, b.exp().min(now + 600)),
        &[],
    )
}

fn prefix_verifier<C: PrefixScheme>(s: &ArmSuite<C>, config: VerifierConfig) -> PV<C> {
    PrefixVerifier::new(s.verifier_as(PAYMENTS, config))
}

/// Crypto counts only: (signature verifications, hash to G2, Miller loops,
/// final exponentiations).
fn crypto(n: &OpCounts) -> (u64, u64, u64, u64) {
    (
        n.sig_verifications,
        n.hash_to_curve,
        n.miller_loops,
        n.final_exps,
    )
}

#[test]
fn warm_counts_per_arm_at_n_3() {
    // Arm A: one aggregate over N + 1 = 4 messages.
    let mut a = Suite::new();
    let v = a.verifier();
    assert!(v.verify(&a.chain(3).to_bytes()).is_ok());
    let (r, n) = v.verify_counted(&a.chain(3).to_bytes());
    assert!(r.is_ok());
    assert_eq!(crypto(&n), (1, 4, 5, 1), "A: {n:?}");
    assert_eq!(n.resolver_calls, 0);

    // A-ind: four single verifications.
    let mut s = ArmSuite::<BlsIndividual>::new();
    let v = s.verifier();
    assert!(v.verify(&s.chain(3).to_bytes()).is_ok());
    let (r, n) = v.verify_counted(&s.chain(3).to_bytes());
    assert!(r.is_ok());
    assert_eq!(crypto(&n), (4, 4, 8, 4), "A-ind: {n:?}");

    // C and C-batch: four Ed25519 signatures, checked one by one or batched.
    let mut s = ArmSuite::<Ed25519List>::new();
    let c = s.verifier();
    let cb = s.verifier_for::<Ed25519Batch>(PAYMENTS, VerifierConfig::default());
    assert!(c.verify(&s.chain(3).to_bytes()).is_ok());
    assert!(cb.verify(&s.chain(3).to_bytes()).is_ok());
    let (r, n) = c.verify_counted(&s.chain(3).to_bytes());
    assert!(r.is_ok());
    assert_eq!(crypto(&n), (4, 0, 0, 0), "C: {n:?}");
    let (r, n) = cb.verify_counted(&s.chain(3).to_bytes());
    assert!(r.is_ok());
    assert_eq!(crypto(&n), (4, 0, 0, 0), "C-batch: {n:?}");
}

#[test]
fn arm_b_hit_is_one_pairing_check() {
    let mut s = ArmSuite::<BlsAggregate>::new();
    let pre = prefix(&mut s);
    let v = prefix_verifier(&s, VerifierConfig::default());
    let t = s.now();
    let (r, path) = v.verify_traced(&invoke(&mut s, &pre).to_bytes(), t);
    assert!(r.is_ok());
    assert_eq!((path, v.cached_prefixes()), (Path::Miss, 1));
    let c = invoke(&mut s, &pre).to_bytes();
    assert_eq!(v.verify_traced(&c, t).1, Path::Hit);
    // Counted, on another invocation: one hash to G2, the Miller loops of
    // (H(m_N), pk_N) and (σ_agg, g1), one final exponentiation. No
    // resolution, no containment.
    let (r, n) = v.verify_counted(&invoke(&mut s, &pre).to_bytes());
    assert!(r.is_ok());
    assert_eq!(crypto(&n), (1, 1, 2, 1), "{n:?}");
    assert_eq!(
        (n.resolver_calls, n.contains_calls, n.evaluate_calls),
        (0, 0, 1)
    );
    // A replay of a hit is rejected at line 17, on the hit path.
    assert_eq!(v.verify_traced(&c, t), (Err(Reject::L17Replay), Path::Hit));
}

#[test]
fn arm_d_hit_checks_sigma_n_only() {
    let mut s = ArmSuite::<Ed25519List>::new();
    let pre = prefix(&mut s);
    let v = prefix_verifier(&s, VerifierConfig::default());
    assert!(v.verify(&invoke(&mut s, &pre).to_bytes()).is_ok());
    let (r, n) = v.verify_counted(&invoke(&mut s, &pre).to_bytes());
    assert!(r.is_ok());
    assert_eq!(crypto(&n), (1, 0, 0, 0), "{n:?}");
    assert_eq!((n.resolver_calls, n.contains_calls), (0, 0));
}

#[test]
fn arm_d_needs_byte_identical_prefix_signatures() {
    let mut s = ArmSuite::<Ed25519List>::new();
    let pre = prefix(&mut s);
    let v = prefix_verifier(&s, VerifierConfig::default());
    let uncached = s.verifier_as(PAYMENTS, VerifierConfig::uncached());
    assert!(v.verify(&invoke(&mut s, &pre).to_bytes()).is_ok());
    // Valid prefix bodies with a garbage σ_1: a miss, and line 49 on the
    // full path, as for the uncached verifier (SPEC §12.1).
    let c = invoke(&mut s, &pre);
    let mut env = c.envelope();
    let WireForm::List(sigs) = &mut env.sigs else {
        unreachable!()
    };
    sigs[1][10] ^= 1;
    let bytes = env.to_bytes();
    let t = s.now();
    assert_eq!(
        uncached.verify_at(&bytes, t),
        Err(Reject::L49AggregateInvalid)
    );
    assert_eq!(
        v.verify_traced(&bytes, t),
        (Err(Reject::L49AggregateInvalid), Path::Miss)
    );
}

#[test]
fn revoking_a_prefix_signer_evicts_the_entry() {
    let mut s = ArmSuite::<BlsAggregate>::new();
    let pre = prefix(&mut s);
    let v = prefix_verifier(&s, VerifierConfig::default());
    let t = s.now();
    assert!(v.verify(&invoke(&mut s, &pre).to_bytes()).is_ok());
    assert_eq!(v.cached_prefixes(), 1);
    // Revoke a2, a prefix signer (D-65).
    let reg = s.w.org("orga");
    let cert = reg.resolve(&p(&agent(2)), &s.pk(&agent(2)), t).unwrap();
    let serial = ParsedCert::<S>::decode(&cert).unwrap().body.serial;
    v.ingest_revocation(&reg.revoke(serial).unwrap()).unwrap();
    assert_eq!(v.cached_prefixes(), 0);
    assert_eq!(
        v.verify_traced(&invoke(&mut s, &pre).to_bytes(), t),
        (Err(Reject::L27CertificateNotValid { k: 2 }), Path::Miss)
    );
}

#[test]
fn a_pin_change_clears_the_cache() {
    let mut s = ArmSuite::<Ed25519List>::new();
    let pre = prefix(&mut s);
    let v = prefix_verifier(&s, VerifierConfig::default());
    let t = s.now();
    assert!(v.verify(&invoke(&mut s, &pre).to_bytes()).is_ok());
    v.unpin("orga", &s.hash);
    assert_eq!(v.cached_prefixes(), 0);
    assert_eq!(
        v.verify_traced(&invoke(&mut s, &pre).to_bytes(), t),
        (Err(Reject::L30NotPinned), Path::Miss)
    );
    v.pin("orga", s.hash);
    assert_eq!(
        v.verify_traced(&invoke(&mut s, &pre).to_bytes(), t).1,
        Path::Miss
    );
    assert_eq!(
        v.verify_traced(&invoke(&mut s, &pre).to_bytes(), t).1,
        Path::Hit
    );
}

#[test]
fn an_entry_lives_no_longer_than_the_certificate_cache_ttl() {
    let mut s = ArmSuite::<BlsAggregate>::new();
    let pre = prefix(&mut s);
    let config = VerifierConfig {
        certificate_cache_ttl: 600,
        ..VerifierConfig::default()
    };
    let v = prefix_verifier(&s, config);
    assert!(v.verify(&invoke(&mut s, &pre).to_bytes()).is_ok());
    s.w.clock().advance(600);
    let t = s.now();
    assert_eq!(
        v.verify_traced(&invoke(&mut s, &pre).to_bytes(), t).1,
        Path::Hit
    );
    s.w.clock().advance(1);
    let t = s.now();
    // Past the TTL: a miss, which re-resolves, accepts and refills.
    let (r, path) = v.verify_traced(&invoke(&mut s, &pre).to_bytes(), t);
    assert!(r.is_ok());
    assert_eq!(path, Path::Miss);
    assert_eq!(
        v.verify_traced(&invoke(&mut s, &pre).to_bytes(), t).1,
        Path::Hit
    );
}

#[test]
fn a_rejected_first_invocation_caches_nothing() {
    let mut s = ArmSuite::<BlsAggregate>::new();
    let pre = prefix(&mut s);
    let v = prefix_verifier(&s, VerifierConfig::default());
    let now = s.now();
    let a3 = agent(3);
    // Denied at line 37: the prefix is fine, but nothing is cached (D-67).
    let c = s.invoke_on(
        pre.clone(),
        (&a3, &a3),
        PAYMENTS,
        "payments",
        "transfer",
        transfer(200_000, "acct_other"),
        (now, now + 600),
        &[],
    );
    assert_eq!(v.verify(&c.to_bytes()), Err(Reject::L37Denied));
    assert_eq!(v.cached_prefixes(), 0);
}
