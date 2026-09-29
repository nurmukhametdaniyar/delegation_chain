//! Fixed test fixtures: deterministic keys and one chain's bodies.
#![allow(dead_code)]

use dc_cbor::{Key, Value};
use dc_crypto::{Dst, SigScheme};
use dc_types::digest::sha256;
use dc_types::{
    ApprovalBody, Body, DelegationBody, Identifier, InvocationBody, Params, Principal, RawScope,
    Receipt, SessionBody,
};

pub fn sk<S: SigScheme>(label: &str) -> S::SecretKey {
    S::keygen(&sha256(&[b"dc-test-key", label.as_bytes()]))
}

pub fn pk_bytes<S: SigScheme>(label: &str) -> Vec<u8> {
    S::pk_bytes(&S::public_key(&sk::<S>(label)))
}

pub fn p(s: &str) -> Principal {
    Principal::parse(s).unwrap()
}

pub fn id(s: &str) -> Identifier {
    Identifier::new(s).unwrap()
}

/// `allow all` as a raw scope AST (SPEC §9.2).
pub fn allow_all() -> RawScope {
    RawScope(Value::Map(vec![(Key::Uint(1), Value::uint(0))]))
}

pub fn params() -> Params {
    Params::new(
        Value::map(vec![
            (Key::from("amount"), Value::uint(500)),
            (Key::from("to_account"), Value::text("acct_vendor_a")),
        ])
        .unwrap(),
    )
    .unwrap()
}

pub const T0: u64 = 1_790_000_000;

pub fn session<S: SigScheme>() -> SessionBody {
    SessionBody {
        issuer_id: p("orga:issuer:main"),
        issuer_pk: pk_bytes::<S>("issuer"),
        subject_id: p("orga:agent:orchestrator"),
        subject_pk: pk_bytes::<S>("orchestrator"),
        session_id: [0x11; 16],
        policy_hash: sha256(&[b"policy"]),
        scope: allow_all(),
        iat: T0,
        exp: T0 + 3600,
        nonce: [0x01; 16],
    }
}

pub fn delegation<S: SigScheme>() -> DelegationBody {
    DelegationBody {
        delegator_id: p("orga:agent:orchestrator"),
        delegator_pk: pk_bytes::<S>("orchestrator"),
        delegatee_id: p("orga:agent:payer"),
        delegatee_pk: pk_bytes::<S>("payer"),
        scope: allow_all(),
        hop_index: 1,
        session_id: [0x11; 16],
        exp: T0 + 1800,
        nonce: [0x02; 16],
    }
}

pub fn invocation<S: SigScheme>() -> InvocationBody<S> {
    let params = params();
    InvocationBody {
        invoker_id: p("orga:agent:payer"),
        invoker_pk: pk_bytes::<S>("payer"),
        aud: p("orgb:service:payments"),
        tool: id("payments"),
        action: id("transfer"),
        params_hash: params.hash().unwrap(),
        params,
        receipts: vec![],
        nbf: T0,
        exp: T0 + 600,
        nonce: [0x03; 16],
    }
}

pub fn receipt_for<S: SigScheme>(inv: &InvocationBody<S>, approver: &str) -> Receipt<S> {
    let approval = ApprovalBody {
        approver_id: p(&format!("orga:approver:{approver}")),
        approver_pk: pk_bytes::<S>(approver),
        invocation_digest: inv.invocation_digest().unwrap(),
        attestation: b"human:alice".to_vec(),
        iat: T0,
        exp: T0 + 300,
    };
    let msg = dc_types::digest::approval_message(&approval.canonical_bytes().unwrap());
    let sig = S::sign(&sk::<S>(approver), &msg, Dst::Receipt);
    Receipt::new(approval, sig).unwrap()
}

/// An invocation carrying one receipt from `orga:approver:finance`.
pub fn invocation_with_receipt<S: SigScheme>() -> InvocationBody<S> {
    let mut inv = invocation::<S>();
    let r = receipt_for(&inv, "finance");
    inv.set_receipts(vec![r]).unwrap();
    inv
}

pub fn chain_bodies<S: SigScheme>() -> Vec<Body<S>> {
    vec![
        Body::Session(session::<S>()),
        Body::Delegation(delegation::<S>()),
        Body::Invocation(invocation_with_receipt::<S>()),
    ]
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
