//! The security suite (SPEC §11.2): one test or more per row, each asserting
//! the exact `Reject` variant, meaning the Algorithm line that rejects, or
//! acceptance where the paper says the threat is bounded rather than
//! prevented.
//!
//! Chains are built with the §8 builders, then mutated. Unless a row says
//! otherwise, every body has the same expiry, hop indices and session ids
//! are correct, and every verification uses a fresh nonce, so that an
//! earlier line cannot fire first. Where the attacker is assumed to hold
//! keys, altered bodies are re-signed (`Suite::resign`), so that the line
//! under test, not the aggregate, is what rejects.

mod common;

use common::*;
use dc_cbor::{Key, Value};
use dc_chain::{ApprovalService, combine};
#[cfg(feature = "aggregate-variant")]
use dc_crypto::blst::min_pk::Signature;
use dc_crypto::{ChainScheme, Dst, SigScheme, WireForm};
use dc_policy::{Decision, Scope};
use dc_registry::{RegistryError, Resolver};
use dc_types::digest::m_delegation;
use dc_types::{Body, CertBody, Identifier, Kind, ParsedCert, RawScope};
use dc_verifier::{Reject, VerifierConfig, check_phase8};

/// Removes body `k` from an envelope, and its signature with it when the
/// chain carries one per hop, as an attacker who drops a hop would: per-hop
/// signatures are on the wire. A single aggregate stays as it is (D-84).
fn drop_body(env: &mut dc_types::Envelope, k: usize) {
    env.bodies.remove(k);
    if let WireForm::List(list) = &mut env.sigs {
        list.remove(k);
    }
}

// ============================================================ T1a forgery

#[test]
fn t1a_foreign_signatures() {
    // The chain's signatures replaced by valid signatures from an unrelated
    // key: per hop, N + 1 of them; under the aggregate variant, their sum, an
    // unrelated valid G2 point in place of σ_agg.
    let mut s = Suite::new();
    let v = s.verifier();
    let mut env = s.chain(2).envelope();
    let stranger = S::sign(&S::keygen(&[9; 32]), &[1; 32], Dst::Chain);
    env.sigs = A::to_wire(&combine::<A>(&[stranger; 3]).unwrap());
    assert_eq!(
        v.verify(&env.to_bytes()),
        Err(Reject::L49ChainSignaturesInvalid)
    );
}

#[test]
fn t1a_victim_identity_signed_by_attacker() {
    // Delegation 2 claims the victim a2 as delegator, with a2's key, but is
    // signed with the attacker's key (a5).
    let mut s = Suite::new();
    let v = s.verifier();
    let c = s.chain(3);
    let mut keys = s.keys_for(&c.bodies);
    keys[2] = s.sk(&agent(5));
    let forged = s.resign(c.bodies.clone(), &keys);
    assert_eq!(
        v.verify(&forged.to_bytes()),
        Err(Reject::L49ChainSignaturesInvalid)
    );
}

#[test]
fn t1a_victim_identity_with_attacker_key() {
    // The preceding body names (a2, attacker's key) as delegatee, so line 20
    // passes; no certificate binds a2 to that key.
    let mut s = Suite::new();
    let v = s.verifier();
    let c = s.chain(3);
    let mut bodies = c.bodies.clone();
    let attacker_pk = s.pk(&agent(5));
    let Body::Delegation(d1) = &mut bodies[1] else {
        panic!()
    };
    d1.delegatee_pk = attacker_pk.clone();
    let Body::Delegation(d2) = &mut bodies[2] else {
        panic!()
    };
    d2.delegator_pk = attacker_pk;
    let mut keys = s.keys_for(&bodies);
    keys[2] = s.sk(&agent(5));
    let forged = s.resign(bodies, &keys);
    assert_eq!(
        v.verify(&forged.to_bytes()),
        Err(Reject::L23Unresolvable { k: 2 })
    );
}

// ============================================================ T1b chain forgery

#[test]
fn t1b_reorder() {
    let mut s = Suite::new();
    let v = s.verifier();
    let mut env = s.chain(4).envelope();
    env.bodies.swap(1, 2);
    assert_eq!(
        v.verify(&env.to_bytes()),
        Err(Reject::L11HopOrSession { k: 1 })
    );
}

#[test]
fn t1b_truncation() {
    let mut s = Suite::new();
    let v = s.verifier();
    let mut env = s.chain(4).envelope();
    drop_body(&mut env, 2);
    assert_eq!(
        v.verify(&env.to_bytes()),
        Err(Reject::L11HopOrSession { k: 2 })
    );
}

#[test]
fn t1b_drop_session_or_invocation() {
    let mut s = Suite::new();
    let v = s.verifier();
    let c = s.chain(3);
    let mut env = c.envelope();
    drop_body(&mut env, 0);
    assert_eq!(
        v.verify(&env.to_bytes()),
        Err(Reject::L07KindMismatch { k: 0 })
    );
    let mut env = c.envelope();
    let last = env.bodies.len() - 1;
    drop_body(&mut env, last);
    assert_eq!(
        v.verify(&env.to_bytes()),
        Err(Reject::L07KindMismatch { k: 2 })
    );
}

#[test]
fn t1b_extension() {
    // A delegation appended after the invocation leaves the invocation at a
    // delegation position.
    let mut s = Suite::new();
    let v = s.verifier();
    let c = s.chain(3);
    let mut bodies = c.bodies.clone();
    let Body::Delegation(mut extra) = bodies[2].clone() else {
        panic!()
    };
    extra.hop_index = 4;
    bodies.push(Body::Delegation(extra));
    let forged = s.resign_default(bodies);
    assert_eq!(
        v.verify(&forged.to_bytes()),
        Err(Reject::L07KindMismatch { k: 3 })
    );
}

#[test]
fn t1b_insertion() {
    // An extra hop by a2 inserted mid-chain, correctly signed.
    let mut s = Suite::new();
    let v = s.verifier();
    let c = s.chain(3);
    let mut bodies = c.bodies.clone();
    let Body::Delegation(mut x) = bodies[1].clone() else {
        panic!()
    };
    x.delegator_id = p(&agent(2));
    x.delegator_pk = s.pk(&agent(2));
    x.hop_index = 2;
    bodies.insert(2, Body::Delegation(x));
    let forged = s.resign_default(bodies);
    assert_eq!(
        v.verify(&forged.to_bytes()),
        Err(Reject::L11HopOrSession { k: 3 })
    );
}

#[test]
fn t1b_splice() {
    // A delegation from another session, with the same delegator and
    // delegatee, so every key link is consistent.
    let mut s = Suite::new();
    let v = s.verifier();
    let c1 = s.chain(2);
    let c2 = s.chain(2);
    let mut bodies = c1.bodies.clone();
    bodies[1] = c2.bodies[1].clone();
    let forged = s.resign_default(bodies);
    assert_eq!(
        v.verify(&forged.to_bytes()),
        Err(Reject::L11HopOrSession { k: 1 })
    );
}

#[test]
fn theorem_3_digest_recursion_catches_what_line_11_catches() {
    // Line 11 rejects reordering, truncation and insertion before phase 8,
    // but the paper says those checks are redundant with the digest
    // recursion (Theorem 3). This calls phase 8 (lines 47–49) directly on the
    // mutated bodies, with the signatures moved, dropped or added along with
    // them, as an attacker could: per hop they are on the wire; under the
    // aggregate variant they are recoverable from partial sums (paper §4.8).
    let mut s = Suite::new();
    let c = s.chain(3); // session, d1 (a1→a2), d2 (a2→a3), invocation (a3)
    let pk_of = |b: &Body<S>| S::pk_from_bytes(b.signer_pk()).unwrap();
    let run = |bodies: &[Body<S>], sigs: &<A as ChainScheme>::WireSigs| {
        let bytes: Vec<Vec<u8>> = bodies
            .iter()
            .map(|b| b.canonical_bytes().unwrap())
            .collect();
        let refs: Vec<&[u8]> = bytes.iter().map(Vec::as_slice).collect();
        let pks: Vec<_> = bodies.iter().map(pk_of).collect();
        let pk_refs: Vec<_> = pks.iter().collect();
        check_phase8::<A>(&pk_refs, &refs, sigs)
    };
    // The unmutated chain passes, so the check is not vacuous.
    assert_eq!(run(&c.bodies, &c.sigs), Ok(()));

    // Reorder, with the signatures permuted alike (under the aggregate
    // variant the sum is unchanged); the digests are not.
    let mut reordered = c.bodies.clone();
    reordered.swap(1, 2);
    let sigs = combine::<A>(&[c.parts[0], c.parts[2], c.parts[1], c.parts[3]]).unwrap();
    assert_eq!(
        run(&reordered, &sigs),
        Err(Reject::L49ChainSignaturesInvalid)
    );

    // Truncation: drop d2 and σ_2.
    let truncated = vec![
        c.bodies[0].clone(),
        c.bodies[1].clone(),
        c.bodies[3].clone(),
    ];
    let sigs = combine::<A>(&[c.parts[0], c.parts[1], c.parts[3]]).unwrap();
    assert_eq!(
        run(&truncated, &sigs),
        Err(Reject::L49ChainSignaturesInvalid)
    );

    // Insertion: a hop by a2 signed over the digest of its position; the
    // later digests change.
    let Body::Delegation(mut x) = c.bodies[1].clone() else {
        panic!()
    };
    x.delegator_id = p(&agent(2));
    x.delegator_pk = s.pk(&agent(2));
    let x = Body::Delegation(x);
    let m_x = m_delegation(&c.digests[1], &x.canonical_bytes().unwrap());
    let sig_x = S::sign(&s.sk(&agent(2)), &m_x, Dst::Chain);
    let inserted = vec![
        c.bodies[0].clone(),
        c.bodies[1].clone(),
        x,
        c.bodies[2].clone(),
        c.bodies[3].clone(),
    ];
    let sigs = combine::<A>(&[c.parts[0], c.parts[1], sig_x, c.parts[2], c.parts[3]]).unwrap();
    assert_eq!(
        run(&inserted, &sigs),
        Err(Reject::L49ChainSignaturesInvalid)
    );
}

// ============================================================ T2a / T2b

#[test]
fn t2a_parameter_substitution_keeping_the_hash() {
    let mut s = Suite::new();
    let v = s.verifier();
    let c = s.chain(2);
    let mut inv = invocation(&c);
    inv.params = transfer(400, "acct_vendor_a");
    let mut env = c.envelope();
    env.bodies[2] = Body::Invocation(inv).canonical_bytes().unwrap();
    assert_eq!(v.verify(&env.to_bytes()), Err(Reject::L09ParamsHash));
}

#[test]
fn t2a_parameter_substitution_recomputing_the_hash() {
    let mut s = Suite::new();
    let v = s.verifier();
    let c = s.chain(2);
    let mut inv = invocation(&c);
    inv.params = transfer(400, "acct_vendor_a");
    inv.params_hash = inv.params.hash().unwrap();
    let mut env = c.envelope();
    env.bodies[2] = Body::Invocation(inv).canonical_bytes().unwrap();
    assert_eq!(
        v.verify(&env.to_bytes()),
        Err(Reject::L49ChainSignaturesInvalid)
    );
}

#[test]
fn t2b_delegation_wider_than_parent() {
    let mut s = Suite::new();
    let v = s.verifier();
    let c = s.chain_with(
        &[policy_with_bound(500), s.policy.clone()],
        PAYMENTS,
        "payments",
        "transfer",
        transfer(500, "acct_vendor_a"),
    );
    assert_eq!(
        v.verify(&c.to_bytes()),
        Err(Reject::L34ScopeEscalation { k: 1 })
    );
}

#[test]
fn t2b_session_scope_exceeds_policy() {
    let mut s = Suite::new();
    let v = s.verifier();
    let c = s.chain_with(
        &[policy_with_bound(2000)],
        PAYMENTS,
        "payments",
        "transfer",
        transfer(500, "acct_vendor_a"),
    );
    assert_eq!(
        v.verify(&c.to_bytes()),
        Err(Reject::L32SessionScopeExceedsPolicy)
    );
}

#[test]
fn t2b_policy_not_pinned() {
    let mut s = Suite::new();
    let v = s.verifier();
    v.unpin("orga", &s.hash);
    let c = s.chain(1);
    assert_eq!(v.verify(&c.to_bytes()), Err(Reject::L30NotPinned));
}

#[test]
fn t2b_policy_unavailable_or_malformed() {
    let mut s = Suite::new();
    // Pinned, but absent from the store.
    let absent = policy_with_bound(900);
    s.hash = absent.policy_hash();
    let v = s.verifier();
    let c = s.chain(1);
    assert_eq!(v.verify(&c.to_bytes()), Err(Reject::L31PolicyUnavailable));
    // Pinned, but the store serves bytes that are not a policy (D-12).
    let garbage = b"not a policy".to_vec();
    s.hash = dc_types::digest::policy_hash(&garbage);
    s.w.policies().put_unchecked(s.hash, garbage);
    let v = s.verifier();
    let c = s.chain(1);
    assert_eq!(v.verify(&c.to_bytes()), Err(Reject::L31PolicyUnavailable));
    // Pinned, but the store serves a different document under the hash.
    s.hash = [0x77; 32];
    s.w.policies()
        .put_unchecked(s.hash, s.policy.canonical_bytes());
    let v = s.verifier();
    let c = s.chain(1);
    assert_eq!(v.verify(&c.to_bytes()), Err(Reject::L31PolicyUnavailable));
}

#[test]
fn t2b_allow_all_under_a_rule_list() {
    // The step-2 regression (D-24).
    let mut s = Suite::new();
    let v = s.verifier();
    let c = s.chain_with(
        &[s.policy.clone(), Scope::allow_all()],
        PAYMENTS,
        "payments",
        "transfer",
        transfer(500, "acct_vendor_a"),
    );
    assert_eq!(
        v.verify(&c.to_bytes()),
        Err(Reject::L34ScopeEscalation { k: 1 })
    );
}

// ============================================================ T3 reuse

#[test]
fn t3a_outside_the_validity_window() {
    let mut s = Suite::new();
    let v = s.verifier();
    // t > B_N.exp.
    let c = s.chain(2);
    let exp = invocation(&c).exp;
    s.w.clock().set(exp + 1);
    assert_eq!(v.verify(&c.to_bytes()), Err(Reject::L13TimeWindow));
    s.w.clock().set(T0);
    // t < B_N.nbf.
    let c = s.chain(2);
    let mut bodies = c.bodies.clone();
    let Body::Invocation(inv) = &mut bodies[2] else {
        panic!()
    };
    inv.nbf = T0 + 100;
    let c = s.resign_default(bodies);
    assert_eq!(v.verify(&c.to_bytes()), Err(Reject::L13TimeWindow));
    // A delegation expiring after its parent.
    let c = s.chain(2);
    let mut bodies = c.bodies.clone();
    let Body::Session(sb) = &bodies[0] else {
        panic!()
    };
    let session_exp = sb.exp;
    let Body::Delegation(d) = &mut bodies[1] else {
        panic!()
    };
    d.exp = session_exp + 10;
    let c = s.resign_default(bodies);
    assert_eq!(
        v.verify(&c.to_bytes()),
        Err(Reject::L15ExpiryGrows { k: 1 })
    );
}

#[test]
fn t3b_replay_sequential() {
    let mut s = Suite::new();
    let v = s.verifier();
    let c = s.chain(2).to_bytes();
    assert!(v.verify(&c).is_ok());
    assert_eq!(v.verify(&c), Err(Reject::L17Replay));
}

#[test]
fn t3c_cross_context() {
    let mut s = Suite::new();
    let v = s.verifier();
    let c = s.chain(2); // session, d1, invocation
    let (sess, del, inv) = (
        c.bodies[0].clone(),
        c.bodies[1].clone(),
        c.bodies[2].clone(),
    );
    // An invocation body at a delegation position.
    let x = s.resign_default(vec![sess.clone(), inv.clone(), inv.clone()]);
    assert_eq!(
        v.verify(&x.to_bytes()),
        Err(Reject::L07KindMismatch { k: 1 })
    );
    // A delegation body at the invocation position.
    let x = s.resign_default(vec![sess.clone(), del.clone(), del.clone()]);
    assert_eq!(
        v.verify(&x.to_bytes()),
        Err(Reject::L07KindMismatch { k: 2 })
    );
    // A session body at a delegation position.
    let x = s.resign_default(vec![sess.clone(), sess, inv]);
    assert_eq!(
        v.verify(&x.to_bytes()),
        Err(Reject::L07KindMismatch { k: 1 })
    );
}

#[test]
fn t3d_cross_verifier() {
    let mut s = Suite::new();
    let v = s.verifier();
    let c = s.chain_with(
        &vec![s.policy.clone(); 2],
        FILES,
        "payments",
        "transfer",
        transfer(500, "acct_vendor_a"),
    );
    assert_eq!(v.verify(&c.to_bytes()), Err(Reject::L08WrongAudience));
}

#[test]
fn t3d_audience_clause() {
    // aud is this verifier, but the only transfer rules name another
    // service in `at`.
    let mut s = Suite::new();
    let other = Scope::parse(&POLICY.replace("at=orgb:service:payments", "at=orgb:service:ledger"))
        .unwrap();
    s.hash = s.w.publish(&other);
    let v = s.verifier();
    let c = s.chain_with(
        &[other],
        PAYMENTS,
        "payments",
        "transfer",
        transfer(500, "acct_vendor_a"),
    );
    assert_eq!(v.verify(&c.to_bytes()), Err(Reject::L37Denied));
}

// ============================================================ T4 approvals

#[test]
fn t4a_compromised_approver_is_bounded() {
    // A compromised approval key yields receipts indistinguishable from
    // honest ones, for invocations the policy routes through it: accepted.
    // The bound: it cannot extend to an invocation the scope denies…
    let mut s = Suite::new();
    let v = s.verifier();
    let c = s.approval_chain(2);
    assert_eq!(
        v.verify(&c.to_bytes()).map(|a| a.decision),
        Ok(Decision::AllowWithApproval(vec![p(FINANCE)]))
    );
    let c = s.chain_with(
        &vec![s.policy.clone(); 2],
        PAYMENTS,
        "payments",
        "transfer",
        transfer(200_000, "acct_vendor_a"),
    );
    let mut bodies = c.bodies.clone();
    let Body::Invocation(inv) = &mut bodies[2] else {
        panic!()
    };
    let r = ApprovalService::<S>::new(p(FINANCE), s.sk(FINANCE))
        .approve(inv, s.now())
        .unwrap();
    inv.set_receipts(vec![r]).unwrap();
    let c = s.resign_default(bodies);
    assert_eq!(v.verify(&c.to_bytes()), Err(Reject::L37Denied));
}

#[test]
fn t4a_approver_key_as_delegator() {
    // …and cannot act as a delegator (next row).
    let mut s = Suite::new();
    let v = s.verifier();
    let c = s.chain(3);
    let mut bodies = c.bodies.clone();
    let Body::Delegation(d1) = &mut bodies[1] else {
        panic!()
    };
    d1.delegatee_id = p(FINANCE);
    d1.delegatee_pk = s.pk(FINANCE);
    let Body::Delegation(d2) = &mut bodies[2] else {
        panic!()
    };
    d2.delegator_id = p(FINANCE);
    d2.delegator_pk = s.pk(FINANCE);
    let c = s.resign_default(bodies);
    assert_eq!(v.verify(&c.to_bytes()), Err(Reject::L26WrongKind { k: 2 }));
}

/// An approval chain whose invocation's receipts are replaced by `f`.
fn with_receipts(
    s: &Suite,
    c: &dc_chain::Chain<A>,
    f: impl FnOnce(&mut dc_types::InvocationBody<S>),
) -> Vec<u8> {
    let mut bodies = c.bodies.clone();
    let Body::Invocation(inv) = bodies.last_mut().unwrap() else {
        panic!()
    };
    f(inv);
    s.resign_default(bodies).to_bytes()
}

#[test]
fn t4b_routing_to_a_permissive_approver() {
    let mut s = Suite::new();
    let v = s.verifier();
    let c = s.approval_chain(2);
    let audit = ApprovalService::<S>::new(p(AUDIT), s.sk(AUDIT));
    let now = s.now();
    let x = with_receipts(&s, &c, |inv| {
        let r = audit.approve(inv, now).unwrap();
        inv.set_receipts(vec![r]).unwrap();
    });
    assert_eq!(v.verify(&x), Err(Reject::L40MissingReceipt));
}

#[test]
fn t4c_receipt_reuse() {
    // The receipt for I, attached to I′ ≠ I (a different nonce).
    let mut s = Suite::new();
    let v = s.verifier();
    let c = s.approval_chain(2);
    let mut other = invocation(&c);
    s.fresh(&mut other);
    let mut bodies = c.bodies.clone();
    *bodies.last_mut().unwrap() = Body::Invocation(other);
    let x = s.resign_default(bodies);
    assert_eq!(v.verify(&x.to_bytes()), Err(Reject::L43ReceiptSignature));
}

#[test]
fn t4d_stale_approval() {
    // The invoker changes the parameters after approval, recomputes
    // params_hash and re-signs.
    let mut s = Suite::new();
    let v = s.verifier();
    let c = s.approval_chain(2);
    let x = with_receipts(&s, &c, |inv| {
        inv.params = transfer(6000, "acct_vendor_a");
        inv.params_hash = inv.params.hash().unwrap();
    });
    assert_eq!(v.verify(&x), Err(Reject::L43ReceiptSignature));
}

#[test]
fn receipt_window() {
    let mut s = Suite::new();
    let v = s.verifier();
    let now = s.now();
    // An expired receipt: 10-second window, verified 20 seconds later.
    let c = s.approval_chain(2);
    let short = ApprovalService::<S>::new(p(FINANCE), s.sk(FINANCE)).with_window(10);
    let x = with_receipts(&s, &c, |inv| {
        let r = short.approve(inv, now).unwrap();
        inv.set_receipts(vec![r]).unwrap();
    });
    s.w.clock().set(now + 20);
    assert_eq!(v.verify(&x), Err(Reject::L44ReceiptWindow));
    s.w.clock().set(now);

    // A receipt naming the finance approver, signed with a key no
    // certificate binds to it: unresolvable (line 41, D-27).
    let c = s.approval_chain(2);
    let impostor = ApprovalService::<S>::new(p(FINANCE), s.sk(AUDIT));
    let x = with_receipts(&s, &c, |inv| {
        let r = impostor.approve(inv, now).unwrap();
        inv.set_receipts(vec![r]).unwrap();
    });
    assert_eq!(v.verify(&x), Err(Reject::L41ApproverUnresolvable));

    // An approver certificate not valid yet (D-35).
    s.w.enroll_window(FINANCE, "finance-next", now + 100, now + 1000)
        .unwrap();
    let c = s.approval_chain(2);
    let next = ApprovalService::<S>::new(p(FINANCE), s.sk("finance-next"));
    let x = with_receipts(&s, &c, |inv| {
        let r = next.approve(inv, now).unwrap();
        inv.set_receipts(vec![r]).unwrap();
    });
    assert_eq!(v.verify(&x), Err(Reject::L42ApproverCertificate));

    // A revoked approver.
    let reg = s.w.org("orga");
    let cert = reg.resolve(&p(FINANCE), &s.pk(FINANCE), now).unwrap();
    let serial = ParsedCert::<S>::decode(&cert).unwrap().body.serial;
    v.ingest_revocation(&reg.revoke(serial).unwrap()).unwrap();
    let c = s.approval_chain(2);
    assert_eq!(v.verify(&c.to_bytes()), Err(Reject::L42ApproverCertificate));
}

#[test]
fn receipt_list_rules() {
    // D-34 (paper §4.5, revision 2026-09-29).
    let mut s = Suite::new();
    let v = s.verifier();
    let now = s.now();
    let c = s.approval_chain(2);
    let finance = ApprovalService::<S>::new(p(FINANCE), s.sk(FINANCE));
    let audit = ApprovalService::<S>::new(p(AUDIT), s.sk(AUDIT));
    let inv = invocation(&c);
    let rf = finance.approve(&inv, now).unwrap();
    let rf2 = finance.approve(&inv, now + 1).unwrap();
    let ra = audit.approve(&inv, now).unwrap();
    // Two receipts for one approver.
    let x = with_receipts(&s, &c, |i| i.receipts = vec![rf.clone(), rf2.clone()]);
    assert!(matches!(v.verify(&x), Err(Reject::L02Decode(_))));
    // Out of order (audit sorts before finance).
    let x = with_receipts(&s, &c, |i| i.receipts = vec![rf.clone(), ra.clone()]);
    assert!(matches!(v.verify(&x), Err(Reject::L02Decode(_))));
    // Key 9 present but empty: only expressible as raw bytes.
    let mut bytes: Vec<Vec<u8>> = c.bytes.clone();
    let mut bare = inv.clone();
    bare.receipts.clear();
    bytes[2] = with_field(&bare.to_value().unwrap(), 9, Some(Value::Array(vec![])));
    let keys = s.keys_for(&c.bodies);
    assert!(matches!(
        v.verify(&sign_raw(bytes, &keys)),
        Err(Reject::L02Decode(_))
    ));
    // The required receipt plus one from an approver not required: the
    // extra one is ignored.
    let x = with_receipts(&s, &c, |i| {
        i.set_receipts(vec![rf.clone(), ra.clone()]).unwrap()
    });
    assert!(v.verify(&x).is_ok());
}

// ============================================================ T5 identity infrastructure

#[test]
fn t5a_misattribution_at_registration() {
    let mut s = Suite::new();
    let reg = s.w.org("orga");
    let mallory = p("orga:agent:mallory");
    // Registering a1's public key under Mallory's identifier, without a1's
    // secret key.
    let ch = reg
        .challenge(&mallory, &s.pk(&agent(1)), Kind::Agent)
        .unwrap();
    let pop = S::sign(&s.sk("mallory"), &ch.message().unwrap(), Dst::Pop);
    assert_eq!(reg.register(&ch, &pop).unwrap_err(), RegistryError::BadPop);
    // Replaying a used PoP nonce.
    let ch = reg
        .challenge(&mallory, &s.pk("mallory"), Kind::Agent)
        .unwrap();
    let pop = S::sign(&s.sk("mallory"), &ch.message().unwrap(), Dst::Pop);
    reg.register(&ch, &pop).unwrap();
    assert_eq!(
        reg.register(&ch, &pop).unwrap_err(),
        RegistryError::NonceUsed
    );
}

/// A registration proof is never presentable as a chain signature, or the
/// reverse (paper §5.3). Under BLS a separate DST separates them: a PoP
/// signed under the chain DST.
#[cfg(feature = "aggregate-variant")]
#[test]
fn t5a_pop_under_the_chain_dst() {
    let mut s = Suite::new();
    let reg = s.w.org("orga");
    let ch = reg
        .challenge(&p("orga:agent:m2"), &s.pk("m2"), Kind::Agent)
        .unwrap();
    let pop = S::sign(&s.sk("m2"), &ch.message().unwrap(), Dst::Chain);
    assert_eq!(reg.register(&ch, &pop).unwrap_err(), RegistryError::BadPop);
}

/// Under Ed25519, which has no domain separation tags, the challenge
/// digest's own tag separates them (paper §5.3): the registrant's chain
/// signature, over a hop's digest, presented as the PoP.
#[cfg(not(feature = "aggregate-variant"))]
#[test]
fn t5a_chain_signature_as_pop() {
    let mut s = Suite::new();
    let c = s.chain(1);
    let chain_sig = S::sign(&s.sk("m2"), &c.digests[1], Dst::Chain);
    let reg = s.w.org("orga");
    let ch = reg
        .challenge(&p("orga:agent:m2"), &s.pk("m2"), Kind::Agent)
        .unwrap();
    assert_eq!(
        reg.register(&ch, &chain_sig).unwrap_err(),
        RegistryError::BadPop
    );
}

/// A certificate body for `id` under key `label`, from registry `registry`.
fn cert_body(
    s: &Suite,
    id: &str,
    label: &str,
    kind: Kind,
    registry: &str,
    root_of: &str,
) -> CertBody {
    CertBody {
        identifier: p(id),
        pk: s.pk(label),
        kind,
        registry_id: Identifier::new(registry).unwrap(),
        registry_pk: S::pk_bytes(&s.w.roots()[root_of]),
        iat: T0,
        nbf: T0 - 10,
        exp: T0 + 10_000,
        serial: 999,
    }
}

#[test]
fn t5b_compromised_root_is_bounded() {
    // With orga's root key, the attacker certifies its own issuer.
    let mut s = Suite::new();
    let orga = s.w.org("orga");
    let body = cert_body(
        &s,
        "orga:issuer:rogue",
        "rogue",
        Kind::Issuer,
        "orga",
        "orga",
    );
    orga.publish_arbitrary(&body.identifier, &body.pk, orga.root_sign_arbitrary(&body));
    let v = s.verifier();
    let a1 = (agent(1), agent(1));
    // Within orga's pinned policy: accepted. This is the bound: pinning.
    let c = s.build(
        ("orga:issuer:rogue", "rogue"),
        &[(&a1.0, &a1.1)],
        &[s.policy.clone()],
        PAYMENTS,
        "payments",
        "transfer",
        transfer(500, "acct_vendor_a"),
        &[],
    );
    assert!(v.verify(&c.to_bytes()).is_ok());
    // Beyond the pinned policy: refused at line 32.
    let c = s.build(
        ("orga:issuer:rogue", "rogue"),
        &[(&a1.0, &a1.1)],
        &[policy_with_bound(5000)],
        PAYMENTS,
        "payments",
        "transfer",
        transfer(500, "acct_vendor_a"),
        &[],
    );
    assert_eq!(
        v.verify(&c.to_bytes()),
        Err(Reject::L32SessionScopeExceedsPolicy)
    );
    // Another organization's namespace: a certificate for an orgb issuer
    // signed with orga's root, even if served for orgb, fails line 24.
    let orgb = s.w.org("orgb");
    let body = cert_body(
        &s,
        "orgb:issuer:rogue",
        "rogue",
        Kind::Issuer,
        "orgb",
        "orga",
    );
    orgb.publish_arbitrary(&body.identifier, &body.pk, orga.root_sign_arbitrary(&body));
    let c = s.build(
        ("orgb:issuer:rogue", "rogue"),
        &[(&a1.0, &a1.1)],
        &[s.policy.clone()],
        PAYMENTS,
        "payments",
        "transfer",
        transfer(500, "acct_vendor_a"),
        &[],
    );
    assert_eq!(
        v.verify(&c.to_bytes()),
        Err(Reject::L24CertificateInvalid { k: 0 })
    );
}

#[test]
fn t5c_revocation_propagation() {
    let mut s = Suite::new();
    let v = s.verifier();
    let reg = s.w.org("orga");
    let cert = reg
        .resolve(&p(&agent(2)), &s.pk(&agent(2)), s.now())
        .unwrap();
    let serial = ParsedCert::<S>::decode(&cert).unwrap().body.serial;
    let assertion = reg.revoke(serial).unwrap();
    // Before the verifier ingests the assertion: the propagation window.
    let c = s.chain(3); // a2 is the delegator of body 2
    assert!(v.verify(&c.to_bytes()).is_ok());
    v.ingest_revocation(&assertion).unwrap();
    let c = s.chain(3);
    assert_eq!(
        v.verify(&c.to_bytes()),
        Err(Reject::L27CertificateNotValid { k: 2 })
    );
}

#[test]
fn t5c_expiry_and_not_yet_valid() {
    let mut s = Suite::new();
    let v = s.verifier();
    let now = s.now();
    let a1 = (agent(1), agent(1));
    let chain_via = |s: &mut Suite, x: &str| {
        s.build(
            (ISSUER, ISSUER),
            &[(&a1.0, &a1.1), (x, x)],
            &[s.policy.clone(), s.policy.clone()],
            PAYMENTS,
            "payments",
            "transfer",
            transfer(500, "acct_vendor_a"),
            &[],
        )
    };
    // Expired at t.
    s.w.enroll_window("orga:agent:x1", "orga:agent:x1", now - 100, now + 100)
        .unwrap();
    let c = chain_via(&mut s, "orga:agent:x1");
    s.w.clock().set(now + 150);
    assert_eq!(
        v.verify(&c.to_bytes()),
        Err(Reject::L27CertificateNotValid { k: 2 })
    );
    s.w.clock().set(now);
    // Not yet valid at t (D-35, P-17).
    s.w.enroll_window("orga:agent:x2", "orga:agent:x2", now + 100, now + 200)
        .unwrap();
    let c = chain_via(&mut s, "orga:agent:x2");
    assert_eq!(
        v.verify(&c.to_bytes()),
        Err(Reject::L27CertificateNotValid { k: 2 })
    );
    // The boundaries are inside the window (P-26: closed interval).
    s.w.enroll_window("orga:agent:x3", "orga:agent:x3", now + 50, now + 60)
        .unwrap();
    let at = |s: &mut Suite, t: u64| {
        s.w.clock().set(now);
        let c = chain_via(s, "orga:agent:x3");
        s.w.clock().set(t);
        v.verify(&c.to_bytes())
    };
    // t = nbf and t = exp are accepted; one second after exp is not.
    assert!(at(&mut s, now + 50).is_ok());
    assert!(at(&mut s, now + 60).is_ok());
    assert_eq!(
        at(&mut s, now + 61),
        Err(Reject::L27CertificateNotValid { k: 2 })
    );
}

#[test]
fn t5d_certificate_substitution() {
    let mut s = Suite::new();
    let v = s.verifier();
    let a1 = (agent(1), agent(1));
    let orga = s.w.org("orga");
    let orgb = s.w.org("orgb");
    // A certificate for an orga identifier signed by orgb's root.
    let body = cert_body(&s, "orga:agent:sub", "sub", Kind::Agent, "orga", "orgb");
    orga.publish_arbitrary(&body.identifier, &body.pk, orgb.root_sign_arbitrary(&body));
    let c = s.build(
        (ISSUER, ISSUER),
        &[(&a1.0, &a1.1), ("orga:agent:sub", "sub")],
        &[s.policy.clone(), s.policy.clone()],
        PAYMENTS,
        "payments",
        "transfer",
        transfer(500, "acct_vendor_a"),
        &[],
    );
    assert_eq!(
        v.verify(&c.to_bytes()),
        Err(Reject::L24CertificateInvalid { k: 2 })
    );
    // A certificate orga's root signed, whose registry_id is not orga.
    let body = cert_body(&s, "orga:agent:ns", "ns", Kind::Agent, "orgb", "orga");
    orga.publish_arbitrary(&body.identifier, &body.pk, orga.root_sign_arbitrary(&body));
    let c = s.build(
        (ISSUER, ISSUER),
        &[(&a1.0, &a1.1), ("orga:agent:ns", "ns")],
        &[s.policy.clone(), s.policy.clone()],
        PAYMENTS,
        "payments",
        "transfer",
        transfer(500, "acct_vendor_a"),
        &[],
    );
    assert_eq!(
        v.verify(&c.to_bytes()),
        Err(Reject::L25RegistryNamespace { k: 2 })
    );
}

#[test]
fn t5e_role_confusion() {
    let mut s = Suite::new();
    let v = s.verifier();
    let a = |i: usize| (agent(i), agent(i));
    let (a1, a3, a5) = (a(1), a(3), a(5));
    let args = |s: &Suite| (s.policy.clone(), transfer(500, "acct_vendor_a"));
    // An agent-kind certificate at position 0: an agent issuing a session.
    let (pol, prm) = args(&s);
    let c = s.build(
        (&a5.0, &a5.1),
        &[(&a1.0, &a1.1)],
        &[pol],
        PAYMENTS,
        "payments",
        "transfer",
        prm,
        &[],
    );
    assert_eq!(v.verify(&c.to_bytes()), Err(Reject::L26WrongKind { k: 0 }));
    // An issuer-kind certificate as a delegator.
    let (pol, prm) = args(&s);
    let c = s.build(
        (ISSUER, ISSUER),
        &[(&a1.0, &a1.1), (ISSUER, ISSUER), (&a3.0, &a3.1)],
        &[pol.clone(), pol.clone(), pol],
        PAYMENTS,
        "payments",
        "transfer",
        prm,
        &[],
    );
    assert_eq!(v.verify(&c.to_bytes()), Err(Reject::L26WrongKind { k: 2 }));
    // An approver-kind certificate as the invoker.
    let (pol, prm) = args(&s);
    let c = s.build(
        (ISSUER, ISSUER),
        &[(&a1.0, &a1.1), (FINANCE, FINANCE)],
        &[pol.clone(), pol],
        PAYMENTS,
        "payments",
        "transfer",
        prm,
        &[],
    );
    assert_eq!(v.verify(&c.to_bytes()), Err(Reject::L26WrongKind { k: 2 }));
    // An agent key signing a receipt, naming the required approver: no
    // certificate binds finance to the agent's key (line 41, D-27).
    let c = s.approval_chain(2);
    let now = s.now();
    let rogue = ApprovalService::<S>::new(p(FINANCE), s.sk(&agent(5)));
    let x = with_receipts(&s, &c, |inv| {
        let r = rogue.approve(inv, now).unwrap();
        inv.set_receipts(vec![r]).unwrap();
    });
    assert_eq!(v.verify(&x), Err(Reject::L41ApproverUnresolvable));
}

#[test]
fn scheduled_rotation_with_overlapping_certificates() {
    let mut s = Suite::new();
    let v = s.verifier();
    let now = s.now();
    for (id, old, new) in [
        (ISSUER, "iss-old", "iss-new"),
        (&agent(1) as &str, "a1-old", "a1-new"),
        (FINANCE, "fin-old", "fin-new"),
    ] {
        s.w.enroll_window(id, old, now - 1000, now + 100).unwrap();
        s.w.enroll_window(id, new, now - 10, now + 1000).unwrap();
    }
    let a1 = agent(1);
    let a2 = agent(2);
    let chain = |s: &mut Suite, iss: &str, a1key: &str, fin: &str| {
        s.build(
            (ISSUER, iss),
            &[(&a1, a1key), (&a2, &a2)],
            &[s.policy.clone(), s.policy.clone()],
            PAYMENTS,
            "payments",
            "transfer",
            transfer(5000, "acct_vendor_a"),
            &[(FINANCE, fin)],
        )
    };
    // During the overlap, chains under either key verify.
    let c = chain(&mut s, "iss-old", "a1-old", "fin-old");
    assert!(v.verify(&c.to_bytes()).is_ok());
    let c = chain(&mut s, "iss-new", "a1-new", "fin-new");
    assert!(v.verify(&c.to_bytes()).is_ok());
    // After the old certificates expire, a chain naming an old key fails.
    s.w.clock().set(now + 150);
    let c = chain(&mut s, "iss-old", "a1-new", "fin-new");
    assert_eq!(
        v.verify(&c.to_bytes()),
        Err(Reject::L27CertificateNotValid { k: 0 })
    );
    let c = chain(&mut s, "iss-new", "a1-old", "fin-new");
    assert_eq!(
        v.verify(&c.to_bytes()),
        Err(Reject::L27CertificateNotValid { k: 1 })
    );
    let c = chain(&mut s, "iss-new", "a1-new", "fin-old");
    assert_eq!(v.verify(&c.to_bytes()), Err(Reject::L42ApproverCertificate));
    // Before the new certificates' nbf, a chain naming a new key fails.
    s.w.clock().set(now - 20);
    let c = chain(&mut s, "iss-new", "a1-old", "fin-old");
    assert_eq!(
        v.verify(&c.to_bytes()),
        Err(Reject::L27CertificateNotValid { k: 0 })
    );
}

// ============================================================ T6 bounded misuse

#[test]
fn t6a_prompt_injection_is_bounded() {
    let mut s = Suite::new();
    let v = s.verifier();
    // A "compromised" agent's within-policy invocation is accepted…
    assert!(v.verify(&s.chain(2).to_bytes()).is_ok());
    // …but it cannot step outside the policy.
    let c = s.chain_with(
        &vec![s.policy.clone(); 2],
        PAYMENTS,
        "payments",
        "transfer",
        transfer(200_000, "acct_other"),
    );
    assert_eq!(v.verify(&c.to_bytes()), Err(Reject::L37Denied));
}

#[test]
fn t6b_confused_deputy_is_bounded() {
    let mut s = Suite::new();
    s.w.enroll("orga:agent:mallory", "orga:agent:mallory")
        .unwrap();
    let v = s.verifier();
    let a1 = (agent(1), agent(1));
    let m = ("orga:agent:mallory", "orga:agent:mallory");
    // A delegation to an adversary within the delegator's scope: accepted.
    let c = s.build(
        (ISSUER, ISSUER),
        &[(&a1.0, &a1.1), m],
        &[s.policy.clone(), policy_with_bound(500)],
        PAYMENTS,
        "payments",
        "transfer",
        transfer(400, "acct_vendor_a"),
        &[],
    );
    assert!(v.verify(&c.to_bytes()).is_ok());
    // Wider than the delegator's scope: refused.
    let c = s.build(
        (ISSUER, ISSUER),
        &[(&a1.0, &a1.1), m],
        &[policy_with_bound(500), s.policy.clone()],
        PAYMENTS,
        "payments",
        "transfer",
        transfer(400, "acct_vendor_a"),
        &[],
    );
    assert_eq!(
        v.verify(&c.to_bytes()),
        Err(Reject::L34ScopeEscalation { k: 1 })
    );
}

// ============================================================ closed world

#[test]
fn closed_world() {
    let mut s = Suite::new();
    let v = s.verifier();
    let pol = || Scope::parse(POLICY).unwrap();
    let with_params =
        |entries: Vec<(Key, Value)>| dc_types::Params::new(Value::map(entries).unwrap()).unwrap();
    // An undeclared parameter.
    let prm = with_params(vec![
        (Key::from("amount"), Value::uint(500)),
        (Key::from("to_account"), Value::text("acct_vendor_a")),
        (Key::from("override_limits"), Value::Bool(true)),
    ]);
    let c = s.chain_with(&[pol(), pol()], PAYMENTS, "payments", "transfer", prm);
    assert_eq!(v.verify(&c.to_bytes()), Err(Reject::L37Denied));
    // An array-valued parameter.
    let prm = with_params(vec![
        (Key::from("amount"), Value::Array(vec![Value::uint(500)])),
        (Key::from("to_account"), Value::text("acct_vendor_a")),
    ]);
    let c = s.chain_with(&[pol(), pol()], PAYMENTS, "payments", "transfer", prm);
    assert_eq!(v.verify(&c.to_bytes()), Err(Reject::L37Denied));
    // A path escaping the workspace through /../, at the files service.
    let files = s.verifier_as(FILES, VerifierConfig::default());
    let prm = with_params(vec![(
        Key::from("file"),
        Value::text("/home/agent/workspace/../../etc/passwd"),
    )]);
    let c = s.chain_with(&[pol(), pol()], FILES, "files", "read", prm);
    assert_eq!(files.verify(&c.to_bytes()), Err(Reject::L37Denied));
    let prm = with_params(vec![(
        Key::from("file"),
        Value::text("/home/agent/workspace/notes"),
    )]);
    let c = s.chain_with(&[pol(), pol()], FILES, "files", "read", prm);
    assert!(files.verify(&c.to_bytes()).is_ok());
}

// ============================================================ structure

/// The canonical bytes of body `k` with `from` replaced by `to` once.
fn splice(bytes: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    let i = bytes
        .windows(from.len())
        .position(|w| w == from)
        .expect("pattern present");
    let mut out = bytes[..i].to_vec();
    out.extend_from_slice(to);
    out.extend_from_slice(&bytes[i + from.len()..]);
    out
}

#[test]
fn structure() {
    let mut s = Suite::new();
    let v = s.verifier();
    // Garbage bytes.
    assert!(matches!(
        v.verify(b"\x00garbage"),
        Err(Reject::L02Decode(_))
    ));
    // A single body (N = 0).
    let c = s.chain(1);
    let mut env = c.envelope();
    drop_body(&mut env, 1);
    assert_eq!(v.verify(&env.to_bytes()), Err(Reject::L03TooShort));
    // A non-canonical body encoding: hop_index 1 written as 0x18 0x01.
    let c = s.chain(2);
    let mut env = c.envelope();
    env.bodies[1] = splice(&env.bodies[1], &[0x07, 0x01], &[0x07, 0x18, 0x01]);
    assert_eq!(
        v.verify(&env.to_bytes()),
        Err(Reject::L05NonCanonical { k: 1 })
    );
}

#[test]
fn structure_limits_and_classes() {
    // D-16, D-31, D-32.
    let mut s = Suite::new();
    let v = s.verifier();
    let c = s.chain(2);
    // N = 17.
    let mut env = c.envelope();
    while env.bodies.len() < 18 {
        env.bodies.insert(1, c.bytes[1].clone());
    }
    assert!(matches!(
        v.verify(&env.to_bytes()),
        Err(Reject::L02Decode(_))
    ));
    // A non-canonical envelope: the outer array head in two bytes.
    let mut bytes = c.to_bytes();
    bytes.splice(0..1, [0x98, 0x02]);
    assert!(matches!(v.verify(&bytes), Err(Reject::L02Decode(_))));
    // A float, and a tag, inside a body: the session's iat.
    let Body::Session(sb) = &c.bodies[0] else {
        panic!()
    };
    let iat = [&[0x09u8, 0x1a][..], &(sb.iat as u32).to_be_bytes()].concat();
    let keys = s.keys_for(&c.bodies);
    for bad in [
        [&[0x09u8, 0xfb][..], &(sb.iat as f64).to_be_bytes()].concat(),
        [&[0x09u8, 0xc1][..], &iat[1..]].concat(),
    ] {
        let mut bytes = c.bytes.clone();
        bytes[0] = splice(&bytes[0], &iat, &bad);
        assert!(matches!(
            v.verify(&sign_raw(bytes, &keys)),
            Err(Reject::L02Decode(_))
        ));
    }
    // An unknown kind value.
    let mut bytes = c.bytes.clone();
    bytes[1] = with_field(&c.bodies[1].to_value().unwrap(), 1, Some(Value::uint(3)));
    assert!(matches!(
        v.verify(&sign_raw(bytes, &keys)),
        Err(Reject::L02Decode(_))
    ));
    // The same body with a non-shortest integer, correctly signed: only a
    // canonical-form violation, so line 5.
    let mut bytes = c.bytes.clone();
    bytes[1] = splice(&bytes[1], &[0x07, 0x01], &[0x07, 0x18, 0x01]);
    assert_eq!(
        v.verify(&sign_raw(bytes, &keys)),
        Err(Reject::L05NonCanonical { k: 1 })
    );
}

#[test]
fn reencoding_alone_catches_non_canonical_bodies() {
    // D-31: with the recorded violations ignored (test hook), line 5's
    // re-encoding comparison still rejects, for a non-shortest integer and
    // for non-NFC parameters.
    let mut s = Suite::new();
    let mut config = VerifierConfig::default();
    config.hooks.ignore_recorded_violations = true;
    let v = s.verifier_as(PAYMENTS, config);
    let c = s.chain(2);
    let keys = s.keys_for(&c.bodies);
    let mut bytes = c.bytes.clone();
    bytes[1] = splice(&bytes[1], &[0x07, 0x01], &[0x07, 0x18, 0x01]);
    assert_eq!(
        v.verify(&sign_raw(bytes, &keys)),
        Err(Reject::L05NonCanonical { k: 1 })
    );
    // Non-NFC text in the parameters.
    let inv = invocation(&c);
    let decomposed = Value::map(vec![
        (Key::from("amount"), Value::uint(500)),
        (Key::from("to_account"), Value::text("acct_vendore\u{301}")),
    ])
    .unwrap();
    let mut bytes = c.bytes.clone();
    bytes[2] = with_field(&inv.to_value().unwrap(), 7, Some(decomposed));
    assert_eq!(
        v.verify(&sign_raw(bytes, &keys)),
        Err(Reject::L05NonCanonical { k: 2 })
    );
}

/// An off-subgroup G2 point in compressed form.
#[cfg(feature = "aggregate-variant")]
fn off_subgroup_g2() -> Vec<u8> {
    (1u8..=255)
        .map(|x| {
            let mut b = vec![0u8; 96];
            b[0] = 0x80;
            b[95] = x;
            b
        })
        .find(|b| Signature::uncompress(b).is_ok())
        .unwrap()
}

#[cfg(feature = "aggregate-variant")]
#[test]
fn point_validation_bls() {
    // The aggregate variant (paper §4.8; D-30): every signature point is
    // validated at decode.
    let mut s = Suite::new();
    let v = s.verifier();
    let c = s.chain(2);
    let mut identity = vec![0u8; 96];
    identity[0] = 0xc0;
    let sig = combine::<A>(&c.parts).unwrap();
    for bad in [
        identity.clone(),
        off_subgroup_g2(),
        sig.serialize().to_vec(),
    ] {
        let mut env = c.envelope();
        env.sigs = WireForm::Single(bad);
        assert!(matches!(
            v.verify(&env.to_bytes()),
            Err(Reject::L02Decode(_))
        ));
    }
    // A receipt signature that is the identity.
    let c = s.approval_chain(2);
    let inv = invocation(&c);
    let receipt = Value::Array(vec![
        Value::bytes(inv.receipts[0].approval_bytes.clone()),
        Value::bytes(identity),
    ]);
    let mut bytes = c.bytes.clone();
    bytes[2] = with_field(
        &inv.to_value().unwrap(),
        9,
        Some(Value::Array(vec![receipt])),
    );
    let keys = s.keys_for(&c.bodies);
    assert!(matches!(
        v.verify(&sign_raw(bytes, &keys)),
        Err(Reject::L02Decode(_))
    ));
}

/// p = 2^255 − 19 and ℓ, the Ed25519 group order, little-endian.
#[cfg(not(feature = "aggregate-variant"))]
const P_LE: [u8; 32] = [
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];
#[cfg(not(feature = "aggregate-variant"))]
const L_LE: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

#[cfg(not(feature = "aggregate-variant"))]
#[test]
fn point_validation_ed25519() {
    // The default instantiation (paper §4.7; D-30, D-81): a signature needs
    // a canonically encoded R and a canonical s at decode, and strict
    // verification rejects a small-order R. Registries reject small-order and
    // non-canonically encoded keys (paper §5.3).
    let mut s = Suite::new();
    let v = s.verifier();
    let c = s.chain(2);
    let honest: Vec<Vec<u8>> = c.parts.iter().map(S::sig_bytes).collect();
    let with_sig1 = |r: Option<[u8; 32]>, sv: Option<[u8; 32]>| {
        let mut list = honest.clone();
        if let Some(r) = r {
            list[1][..32].copy_from_slice(&r);
        }
        if let Some(sv) = sv {
            list[1][32..].copy_from_slice(&sv);
        }
        let mut env = c.envelope();
        env.sigs = WireForm::List(list);
        env.to_bytes()
    };
    // R = p + 1, a non-canonical encoding of y = 1.
    let mut r_alias = P_LE;
    r_alias[0] += 1;
    assert!(matches!(
        v.verify(&with_sig1(Some(r_alias), None)),
        Err(Reject::L02Decode(_))
    ));
    // s = ℓ, not below the group order.
    assert!(matches!(
        v.verify(&with_sig1(None, Some(L_LE))),
        Err(Reject::L02Decode(_))
    ));
    // R the identity, canonically encoded: it decodes, and strict
    // verification rejects it, being of small order.
    let mut identity = [0u8; 32];
    identity[0] = 1;
    assert_eq!(
        v.verify(&with_sig1(Some(identity), None)),
        Err(Reject::L49ChainSignaturesInvalid)
    );
    // A receipt signature with s = ℓ.
    let c = s.approval_chain(2);
    let inv = invocation(&c);
    let mut bad = S::sig_bytes(&inv.receipts[0].sig);
    bad[32..].copy_from_slice(&L_LE);
    let receipt = Value::Array(vec![
        Value::bytes(inv.receipts[0].approval_bytes.clone()),
        Value::bytes(bad),
    ]);
    let mut bytes = c.bytes.clone();
    bytes[2] = with_field(
        &inv.to_value().unwrap(),
        9,
        Some(Value::Array(vec![receipt])),
    );
    let keys = s.keys_for(&c.bodies);
    assert!(matches!(
        v.verify(&sign_raw(bytes, &keys)),
        Err(Reject::L02Decode(_))
    ));
    // Registration: a small-order key (the identity), and y + p for a valid
    // key's small y, a non-canonical encoding of that key.
    let valid_y = (2u8..19)
        .find(|&y| {
            let mut b = [0u8; 32];
            b[0] = y;
            S::pk_from_bytes(&b).is_ok()
        })
        .expect("a valid key with y below 19");
    let mut alias = P_LE;
    alias[0] += valid_y;
    let reg = s.w.org("orga");
    for key in [identity, alias] {
        let ch = reg
            .challenge(&p("orga:agent:z"), &key, Kind::Agent)
            .unwrap();
        let pop = S::sign(&s.sk("z"), &ch.message().unwrap(), Dst::Pop);
        assert!(matches!(
            reg.register(&ch, &pop),
            Err(RegistryError::InvalidKey(_))
        ));
    }
}

const P15_CHILD: &str = r#"
allow at=orgb:service:payments tool=payments action=transfer
  params { amount: int, to_account: string }
  where amount <= 100000 and to_account in ["acct_vendor_a", "acct_vendor_b"]
        and z >= -18446744073709551616
  approval requires orga:approver:finance
allow at=orgb:service:payments tool=payments action=transfer
  params { amount: int, to_account: string }
  where amount <= 1000"#;

#[test]
fn malformed_scopes_p15() {
    let mut s = Suite::new();
    let v = s.verifier();
    let bad = RawScope(Scope::parse_unchecked(P15_CHILD).unwrap().to_value());
    // As a delegation scope.
    let c = s.chain(2);
    let mut bodies = c.bodies.clone();
    let Body::Delegation(d) = &mut bodies[1] else {
        panic!()
    };
    d.scope = bad.clone();
    let x = s.resign_default(bodies);
    assert!(matches!(v.verify(&x.to_bytes()), Err(Reject::L02Decode(_))));
    // As the session scope.
    let mut bodies = c.bodies.clone();
    let Body::Session(sb) = &mut bodies[0] else {
        panic!()
    };
    sb.scope = bad.clone();
    let x = s.resign_default(bodies);
    assert!(matches!(v.verify(&x.to_bytes()), Err(Reject::L02Decode(_))));
    // As the pinned policy document.
    let doc = dc_cbor::encode(&bad.0).unwrap();
    s.hash = dc_types::digest::policy_hash(&doc);
    s.w.policies().put_unchecked(s.hash, doc);
    let v = s.verifier();
    let c = s.chain(1);
    assert_eq!(v.verify(&c.to_bytes()), Err(Reject::L31PolicyUnavailable));
}

// ============================================================ key chain, resolution

#[test]
fn key_chain_keys() {
    let mut s = Suite::new();
    let v = s.verifier();
    // subject_pk ≠ spk(B_1).
    let c = s.chain(2);
    let mut bodies = c.bodies.clone();
    let Body::Session(sb) = &mut bodies[0] else {
        panic!()
    };
    sb.subject_pk = s.pk(&agent(5));
    let x = s.resign_default(bodies);
    assert_eq!(v.verify(&x.to_bytes()), Err(Reject::L18SubjectMismatch));
    // delegatee_pk ≠ the next signer's key.
    let c = s.chain(3);
    let mut bodies = c.bodies.clone();
    let Body::Delegation(d) = &mut bodies[1] else {
        panic!()
    };
    d.delegatee_pk = s.pk(&agent(5));
    let x = s.resign_default(bodies);
    assert_eq!(
        v.verify(&x.to_bytes()),
        Err(Reject::L20DelegateeMismatch { k: 1 })
    );
}

#[test]
fn key_chain_identifiers_p16() {
    // One key under two identifiers: PoP passes for both, since the
    // registrant holds the key.
    let mut s = Suite::new();
    s.w.enroll("orga:agent:alice", "shared").unwrap();
    s.w.enroll("orga:agent:mallory", "shared").unwrap();
    let v = s.verifier();
    let shared = s.pk("shared");
    // The session names alice; mallory signs body 1 under the same key.
    let c = s.chain(2);
    let mut bodies = c.bodies.clone();
    let Body::Session(sb) = &mut bodies[0] else {
        panic!()
    };
    sb.subject_id = p("orga:agent:alice");
    sb.subject_pk = shared.clone();
    let Body::Delegation(d) = &mut bodies[1] else {
        panic!()
    };
    d.delegator_id = p("orga:agent:mallory");
    d.delegator_pk = shared.clone();
    let mut keys = s.keys_for(&bodies);
    keys[1] = s.sk("shared");
    let x = s.resign(bodies, &keys);
    assert_eq!(v.verify(&x.to_bytes()), Err(Reject::L18SubjectMismatch));
    // A delegation names alice; mallory signs the next hop.
    let c = s.chain(3);
    let mut bodies = c.bodies.clone();
    let Body::Delegation(d1) = &mut bodies[1] else {
        panic!()
    };
    d1.delegatee_id = p("orga:agent:alice");
    d1.delegatee_pk = shared.clone();
    let Body::Delegation(d2) = &mut bodies[2] else {
        panic!()
    };
    d2.delegator_id = p("orga:agent:mallory");
    d2.delegator_pk = shared;
    let mut keys = s.keys_for(&bodies);
    keys[2] = s.sk("shared");
    let x = s.resign(bodies, &keys);
    assert_eq!(
        v.verify(&x.to_bytes()),
        Err(Reject::L20DelegateeMismatch { k: 1 })
    );
}

#[test]
fn resolution_unknown_signer() {
    let mut s = Suite::new();
    let v = s.verifier();
    let c = s.chain(3);
    let mut bodies = c.bodies.clone();
    let ghost = p("orga:agent:ghost");
    let Body::Delegation(d1) = &mut bodies[1] else {
        panic!()
    };
    d1.delegatee_id = ghost.clone();
    d1.delegatee_pk = s.pk("ghost");
    let Body::Delegation(d2) = &mut bodies[2] else {
        panic!()
    };
    d2.delegator_id = ghost;
    d2.delegator_pk = s.pk("ghost");
    let mut keys = s.keys_for(&bodies);
    keys[2] = s.sk("ghost");
    let x = s.resign(bodies, &keys);
    assert_eq!(
        v.verify(&x.to_bytes()),
        Err(Reject::L23Unresolvable { k: 2 })
    );
}

#[test]
fn distinct_messages() {
    // A real duplicate digest needs a SHA-256 collision, so a test hook
    // copies m_0 over m_1 before line 48.
    let mut s = Suite::new();
    let mut config = VerifierConfig::default();
    config.hooks.duplicate_digest = Some((0, 1));
    let v = s.verifier_as(PAYMENTS, config);
    assert_eq!(
        v.verify(&s.chain(2).to_bytes()),
        Err(Reject::L48DuplicateDigest)
    );
}

// ============================================================ phase ordering, offline

#[test]
fn phase_ordering_count_ops() {
    // Paper §4.6, Figure 2: once certificates are cached, a chain that cannot
    // succeed is discarded before any signature is verified; a cold verifier
    // verifies the N + 1 certificates first (phase 5). A fresh (cold)
    // verifier for each case, so that resolver counts mean something.
    let mut s = Suite::new();
    // An expired chain.
    let c = s.chain(2);
    s.w.clock().set(invocation(&c).exp + 1);
    let (r, n) = s.verifier().verify_counted(&c.to_bytes());
    assert_eq!(r, Err(Reject::L13TimeWindow));
    assert_eq!(
        (n.sig_verifications, n.pairings(), n.resolver_calls),
        (0, 0, 0),
        "{n:?}"
    );
    s.w.clock().set(T0);
    // A wrong audience.
    let c = s.chain_with(
        &vec![s.policy.clone(); 2],
        FILES,
        "payments",
        "transfer",
        transfer(500, "acct_vendor_a"),
    );
    let (r, n) = s.verifier().verify_counted(&c.to_bytes());
    assert_eq!(r, Err(Reject::L08WrongAudience));
    assert_eq!(
        (n.sig_verifications, n.pairings(), n.resolver_calls),
        (0, 0, 0),
        "{n:?}"
    );
    // A line-34 rejection. Warm, nothing is verified. Cold, phase 5 has
    // already checked the N + 1 = 3 certificates (issuer, a1, a2) at line 24,
    // and under BLS registry roots each is a pairing check (D-61, P-28).
    let c = s.chain_with(
        &[policy_with_bound(500), s.policy.clone()],
        PAYMENTS,
        "payments",
        "transfer",
        transfer(500, "acct_vendor_a"),
    );
    let warm = s.verifier();
    assert!(warm.verify(&s.chain(2).to_bytes()).is_ok()); // caches a1, a2, the issuer, the policy
    let (r, n) = warm.verify_counted(&c.to_bytes());
    assert_eq!(r, Err(Reject::L34ScopeEscalation { k: 1 }));
    assert_eq!(
        (n.sig_verifications, n.pairings(), n.resolver_calls),
        (0, 0, 0),
        "warm: {n:?}"
    );
    let (r, n) = s.verifier().verify_counted(&c.to_bytes());
    assert_eq!(r, Err(Reject::L34ScopeEscalation { k: 1 }));
    assert_eq!(
        (n.sig_verifications, n.resolver_calls),
        (3, 3),
        "cold: {n:?}"
    );
    // Each certificate check is one hash-to-G2, two Miller loops and one
    // final exponentiation; there is no aggregate or receipt check.
    #[cfg(feature = "aggregate-variant")]
    assert_eq!(
        (n.hash_to_curve, n.miller_loops, n.final_exps),
        (3, 6, 3),
        "cold: {n:?}"
    );
    // Sanity check of the counters on an accepted chain, warm: N + 1 = 3
    // chain signatures per hop; under the aggregate variant, one aggregate
    // over 3 messages, which is 3 hash-to-G2, 4 Miller loops and 1 final
    // exponentiation.
    let v = s.verifier();
    assert!(v.verify(&s.chain(2).to_bytes()).is_ok());
    let (r, n) = v.verify_counted(&s.chain(2).to_bytes());
    assert!(r.is_ok());
    #[cfg(not(feature = "aggregate-variant"))]
    assert_eq!((n.sig_verifications, n.pairings()), (3, 0), "{n:?}");
    #[cfg(feature = "aggregate-variant")]
    assert_eq!(
        (
            n.hash_to_curve,
            n.miller_loops,
            n.final_exps,
            n.sig_verifications
        ),
        (3, 4, 1, 1),
        "{n:?}"
    );
}

#[test]
fn steady_state_is_offline() {
    // Paper §8.2: a warm verifier accepts chains from known partners
    // without touching the registry or the policy store.
    let mut s = Suite::new();
    let v = s.verifier();
    assert!(v.verify(&s.approval_chain(3).to_bytes()).is_ok());
    let (r, n) = v.verify_counted(&s.approval_chain(3).to_bytes());
    assert!(r.is_ok());
    assert_eq!((n.resolver_calls, n.policy_store_calls), (0, 0), "{n:?}");
    // And a cold one does touch them.
    let (_, n) = s.verifier().verify_counted(&s.approval_chain(3).to_bytes());
    assert!(n.resolver_calls > 0 && n.policy_store_calls > 0);
}

#[test]
fn theorem_5_part_2_cross_verifier() {
    let mut s = Suite::new();
    let v1 = s.verifier();
    let v2 = s.verifier_as("orgb:service:ledger", VerifierConfig::default());
    let c = s.chain(2).to_bytes();
    assert!(v1.verify(&c).is_ok());
    assert_eq!(v2.verify(&c), Err(Reject::L08WrongAudience));
}
