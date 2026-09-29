//! Bodies, parameters, receipts, digests, envelope and certificate
//! structures (SPEC §5.4, §6, §7; D-14, D-15, D-16, D-31, D-32, D-34, D-51).

mod common;

use common::*;
use dc_cbor::schema::SchemaError;
use dc_cbor::{CanonViolation, Key, Value, encode};
use dc_crypto::{Bls, BlsAggregate, ChainScheme, CryptoError, Dst, SigScheme, WireForm};
use dc_types::digest::{self, TAG_DEL, TAG_INV, TAG_SES, sha256};
use dc_types::{
    Body, BodyKind, BuildError, CertBody, Certificate, Envelope, Identifier, Kind,
    MAX_CHAIN_BODIES, Malformed, ManualClock, Params, ParsedCert, ParsedRevocation, PopChallenge,
    Principal, RevocationAssertion, RevocationBody, decode_body,
};

type B = Bls;

/// Re-encodes `v` (a body map) with field `key` replaced, removed (`None`),
/// or added.
fn with_field(v: &Value, key: u64, new: Option<Value>) -> Vec<u8> {
    let mut m: Vec<(Key, Value)> = v
        .as_map()
        .unwrap()
        .iter()
        .filter(|(k, _)| *k != Key::Uint(key))
        .cloned()
        .collect();
    if let Some(x) = new {
        m.push((Key::Uint(key), x));
    }
    encode(&Value::map(m).unwrap()).unwrap()
}

fn malformed(bytes: &[u8]) -> Malformed {
    decode_body::<B>(bytes).unwrap_err()
}

// ---- identifiers (D-08, D-51) ----

#[test]
fn principal_grammar() {
    let x = p("orga:agent:payer-1_b");
    assert_eq!(
        (x.org(), x.kind(), x.local()),
        ("orga", Kind::Agent, "payer-1_b")
    );
    for bad in [
        "orga:agent",
        "orga:agent:x:y",
        "1org:agent:x",
        "orga:agent:",
        "orga:robot:x",
        "orgä:agent:x",
        "org a:agent:x",
        "orga:agent:x.y",
        "",
    ] {
        assert!(Principal::parse(bad).is_err(), "{bad:?}");
    }
    assert!(Identifier::new("payments").is_ok());
    assert!(Identifier::new("_x").is_err());
    assert!(Identifier::new("a.b").is_err());
    assert_eq!(Kind::Service.cert_code(), None);
    for k in [Kind::Agent, Kind::Signer, Kind::Approver, Kind::Issuer] {
        assert_eq!(Kind::from_cert_code(k.cert_code().unwrap()), Some(k));
    }
}

// ---- round trips ----

#[test]
fn every_body_round_trips_canonically() {
    for body in chain_bodies::<B>() {
        let bytes = body.canonical_bytes().unwrap();
        let d = decode_body::<B>(&bytes).unwrap();
        assert_eq!(d.violation, None);
        assert_eq!(d.body, body);
        assert_eq!(d.body.canonical_bytes().unwrap(), bytes);
    }
}

#[test]
fn signer_accessors_follow_paper_4_6() {
    let bodies = chain_bodies::<B>();
    assert_eq!(bodies[0].signer_id().as_str(), "orga:issuer:main");
    assert_eq!(bodies[1].signer_id().as_str(), "orga:agent:orchestrator");
    assert_eq!(bodies[2].signer_id().as_str(), "orga:agent:payer");
    assert_eq!(bodies[1].signer_pk(), pk_bytes::<B>("orchestrator"));
    assert!(
        bodies[0].scope().is_some() && bodies[1].scope().is_some() && bodies[2].scope().is_none()
    );
    assert_eq!(
        bodies.iter().map(Body::kind).collect::<Vec<_>>(),
        [
            BodyKind::Session,
            BodyKind::Delegation,
            BodyKind::Invocation
        ]
    );
}

// ---- decoding by own kind (D-32) and malformed input (L02) ----

#[test]
fn decodes_by_the_bodys_own_kind_field() {
    // dc-types does not know positions; the kind field alone selects the
    // schema, so a misplaced body decodes and line 7 can reject it.
    let inv = Body::Invocation(invocation::<B>())
        .canonical_bytes()
        .unwrap();
    assert_eq!(
        decode_body::<B>(&inv).unwrap().body.kind(),
        BodyKind::Invocation
    );
    let del = Body::<B>::Delegation(delegation::<B>())
        .canonical_bytes()
        .unwrap();
    assert_eq!(
        decode_body::<B>(&del).unwrap().body.kind(),
        BodyKind::Delegation
    );
}

#[test]
fn rejects_unknown_or_missing_kind() {
    let v = delegation::<B>().to_value().unwrap();
    assert_eq!(
        malformed(&with_field(&v, 1, Some(Value::uint(3)))),
        Malformed::UnknownKind(3)
    );
    assert_eq!(malformed(&with_field(&v, 1, None)), Malformed::NoKind);
    assert_eq!(
        malformed(&with_field(&v, 1, Some(Value::text("1")))),
        Malformed::NoKind
    );
    // A delegation's fields under the session kind do not fit that schema.
    assert!(matches!(
        malformed(&with_field(&v, 1, Some(Value::uint(0)))),
        Malformed::Schema(_)
    ));
}

#[test]
fn rejects_unknown_missing_and_mistyped_fields() {
    let v = session::<B>().to_value().unwrap();
    assert_eq!(
        malformed(&with_field(&v, 12, Some(Value::uint(0)))),
        Malformed::Schema(SchemaError::Unknown("SessionBody", 12))
    );
    assert_eq!(
        malformed(&with_field(&v, 11, None)),
        Malformed::Schema(SchemaError::Missing("SessionBody", 11))
    );
    // Wrong byte-string lengths: public key, nonce, session id, policy hash.
    for (key, len) in [(3u64, 47usize), (11, 15), (6, 17), (7, 31)] {
        assert_eq!(
            malformed(&with_field(&v, key, Some(Value::bytes(vec![0; len])))),
            Malformed::Schema(SchemaError::Invalid("SessionBody", key)),
            "key {key}"
        );
    }
    // Negative time, malformed principal, unknown kind component.
    assert_eq!(
        malformed(&with_field(&v, 10, Some(Value::Int(-1)))),
        Malformed::Schema(SchemaError::Invalid("SessionBody", 10))
    );
    assert_eq!(
        malformed(&with_field(&v, 2, Some(Value::text("orga:issuer")))),
        Malformed::Schema(SchemaError::Invalid("SessionBody", 2))
    );
    assert_eq!(
        malformed(&with_field(&v, 4, Some(Value::text("orga:robot:x")))),
        Malformed::Schema(SchemaError::Invalid("SessionBody", 4))
    );
    // A text key in a protocol structure.
    let mut m = v.as_map().unwrap().to_vec();
    m.push((Key::from("x"), Value::Null));
    assert!(matches!(
        malformed(&encode(&Value::Map(m)).unwrap()),
        Malformed::Schema(SchemaError::NonUintKey("SessionBody"))
    ));
    // Not a map at all, and trailing garbage.
    assert_eq!(malformed(&[0x80]), Malformed::NoKind);
    let mut trailing = Body::<B>::Session(session::<B>())
        .canonical_bytes()
        .unwrap();
    trailing.push(0);
    assert!(matches!(malformed(&trailing), Malformed::Cbor(_)));
}

#[test]
fn kind_component_is_not_checked_at_decode() {
    // D-51: the certificate checks (lines 26, 42) and line 8 decide whether
    // a principal's kind suits its position, so decoding accepts any of the
    // five kinds anywhere.
    let mut d = delegation::<B>();
    d.delegator_id = p("orga:issuer:main");
    let bytes = Body::<B>::Delegation(d.clone()).canonical_bytes().unwrap();
    assert_eq!(decode_body::<B>(&bytes).unwrap().body, Body::Delegation(d));
    let mut inv = invocation::<B>();
    inv.aud = p("orgb:agent:not-a-service");
    let bytes = Body::Invocation(inv).canonical_bytes().unwrap();
    assert!(decode_body::<B>(&bytes).is_ok());
}

// ---- canonical-form violations are recorded, not rejected (D-31) ----

#[test]
fn records_non_canonical_body_encodings() {
    let canonical = Body::<B>::Delegation(delegation::<B>())
        .canonical_bytes()
        .unwrap();
    // hop_index = 1 is key 7; rewrite its value 0x01 as 0x18 0x01.
    let pos = canonical
        .windows(2)
        .position(|w| w == [0x07, 0x01])
        .unwrap();
    let mut b = canonical.clone();
    b.splice(pos + 1..pos + 2, [0x18, 0x01]);
    let d = decode_body::<B>(&b).unwrap();
    assert_eq!(d.violation, Some(CanonViolation::NonShortest(pos + 1)));
    assert_eq!(d.body.canonical_bytes().unwrap(), canonical);
    assert_ne!(d.body.canonical_bytes().unwrap(), b);
}

// ---- parameters (paper §4.4) ----

#[test]
fn params_must_have_text_keys_at_every_level() {
    let v = invocation::<B>().to_value().unwrap();
    let uint_key = Value::Map(vec![(Key::Uint(1), Value::Null)]);
    assert!(matches!(
        malformed(&with_field(&v, 7, Some(uint_key))),
        Malformed::Params(_)
    ));
    let nested = Value::Map(vec![(
        Key::from("a"),
        Value::Array(vec![Value::Map(vec![(Key::Uint(1), Value::Null)])]),
    )]);
    assert!(matches!(
        malformed(&with_field(&v, 7, Some(nested))),
        Malformed::Params(_)
    ));
    assert!(matches!(
        malformed(&with_field(&v, 7, Some(Value::Array(vec![])))),
        Malformed::Params(_)
    ));
    // Every value type of §4.4 is allowed.
    let rich = Params::new(
        Value::map(vec![
            (Key::from("b"), Value::bytes(vec![1])),
            (Key::from("n"), Value::Null),
            (
                Key::from("a"),
                Value::Array(vec![Value::Int(-3), Value::Bool(true)]),
            ),
            (
                Key::from("m"),
                Value::map(vec![(Key::from("x"), Value::uint(1))]).unwrap(),
            ),
        ])
        .unwrap(),
    );
    assert!(rich.is_ok());
    assert!(Params::new(Value::Null).is_err());
}

#[test]
fn non_nfc_params_are_a_canonical_form_violation() {
    let mut inv = invocation::<B>();
    let decomposed = Value::map(vec![(Key::from("to"), Value::text("caf\u{65}\u{301}"))]).unwrap();
    // Build the canonical body, then splice in decomposed text by hand, as a
    // non-conforming sender would.
    inv.params = Params::new(decomposed.clone()).unwrap();
    inv.params_hash = inv.params.hash().unwrap();
    let v = inv.to_value().unwrap();
    let bytes = with_field(&v, 7, Some(decomposed));
    let d = decode_body::<B>(&bytes).unwrap();
    assert_eq!(d.violation, Some(CanonViolation::NonNfc));
    // Canon normalizes, so the re-encoding differs (caught at line 5), and
    // the parameter hash is that of the normalized form.
    assert_eq!(
        d.body.canonical_bytes().unwrap(),
        Body::Invocation(inv.clone()).canonical_bytes().unwrap()
    );
    assert_ne!(d.body.canonical_bytes().unwrap(), bytes);
    let Body::Invocation(decoded) = d.body else {
        unreachable!()
    };
    assert_eq!(decoded.params.hash().unwrap(), inv.params_hash);
}

#[test]
fn params_hash_is_sha256_of_canonical_params() {
    let prm = params();
    assert_eq!(
        prm.hash().unwrap(),
        sha256(&[&prm.canonical_bytes().unwrap()])
    );
    assert_eq!(Params::empty().canonical_bytes().unwrap(), vec![0xa0]);
}

// ---- receipts (D-14, D-15, D-34) ----

#[test]
fn receipts_round_trip_sorted() {
    let mut inv = invocation::<B>();
    let (a, z) = (receipt_for(&inv, "zeta"), receipt_for(&inv, "alpha"));
    inv.set_receipts(vec![a, z]).unwrap();
    assert_eq!(
        inv.receipts[0].approval.approver_id.as_str(),
        "orga:approver:alpha"
    );
    let bytes = Body::Invocation(inv.clone()).canonical_bytes().unwrap();
    assert_eq!(
        decode_body::<B>(&bytes).unwrap().body,
        Body::Invocation(inv.clone())
    );
    let dup = receipt_for(&inv, "alpha");
    assert_eq!(
        inv.set_receipts(vec![dup.clone(), dup]).unwrap_err(),
        BuildError::Receipts("two receipts for one approver")
    );
}

#[test]
fn rejects_bad_receipt_lists() {
    let inv = invocation::<B>();
    let v = inv.to_value().unwrap();
    let a = receipt_for(&inv, "alpha").to_value();
    let z = receipt_for(&inv, "zeta").to_value();
    let cases = [
        (Value::Array(vec![]), "present but empty (D-14)"),
        (
            Value::Array(vec![z.clone(), a.clone()]),
            "not sorted by approver_id",
        ),
        (
            Value::Array(vec![a.clone(), a.clone()]),
            "two receipts for one approver",
        ),
        (Value::uint(1), "not an array"),
    ];
    for (receipts, why) in cases {
        assert_eq!(
            malformed(&with_field(&v, 9, Some(receipts))),
            Malformed::Receipts(why)
        );
    }
}

#[test]
fn receipt_parts_are_validated() {
    let inv = invocation::<B>();
    let v = inv.to_value().unwrap();
    let good = receipt_for(&inv, "alpha");
    // The identity as a receipt signature (D-30).
    let mut identity = vec![0u8; 96];
    identity[0] = 0xc0;
    let r = Value::Array(vec![
        Value::bytes(good.approval_bytes.clone()),
        Value::bytes(identity),
    ]);
    assert_eq!(
        malformed(&with_field(&v, 9, Some(Value::Array(vec![r])))),
        Malformed::Crypto(CryptoError::Identity)
    );
    // A non-canonical approval body is malformed, not an L05 (D-50).
    let mut approval = good.approval_bytes.clone();
    let pos = approval.iter().position(|&b| b == 0x05).unwrap(); // key 5, iat
    approval.splice(pos..pos + 1, [0x18, 0x05]);
    let r = Value::Array(vec![
        Value::bytes(approval),
        Value::bytes(Bls::sig_bytes(&good.sig)),
    ]);
    assert!(matches!(
        malformed(&with_field(&v, 9, Some(Value::Array(vec![r])))),
        Malformed::Strict(_)
    ));
    // Attestation over 256 bytes.
    let mut long = good.approval.clone();
    long.attestation = vec![0; 257];
    assert!(long.canonical_bytes().is_err());
}

#[test]
fn invocation_digest_excludes_receipts_and_binds_everything_else() {
    let bare = invocation::<B>();
    let with = invocation_with_receipt::<B>();
    assert_eq!(
        bare.invocation_digest().unwrap(),
        with.invocation_digest().unwrap()
    );
    let no_receipts = Body::Invocation(bare.clone()).canonical_bytes().unwrap();
    assert_eq!(
        bare.invocation_digest().unwrap(),
        sha256(&[digest::TAG_IVD, &no_receipts])
    );
    let mut changed = bare.clone();
    changed.nonce[0] ^= 1;
    assert_ne!(
        changed.invocation_digest().unwrap(),
        bare.invocation_digest().unwrap()
    );
}

// ---- chain digests (paper §4.3) ----

#[test]
fn chain_digests_use_position_tags_and_recurse() {
    let bodies: Vec<Vec<u8>> = chain_bodies::<B>()
        .iter()
        .map(|b| b.canonical_bytes().unwrap())
        .collect();
    let refs: Vec<&[u8]> = bodies.iter().map(Vec::as_slice).collect();
    let m = digest::chain_digests(&refs);
    assert_eq!(m[0], sha256(&[TAG_SES, &bodies[0]]));
    assert_eq!(m[1], sha256(&[TAG_DEL, &m[0], &bodies[1]]));
    assert_eq!(m[2], sha256(&[TAG_INV, &m[1], &bodies[2]]));
    // N = 1: the second body is the invocation.
    let short = digest::chain_digests(&[&bodies[0], &bodies[2]]);
    assert_eq!(short[1], sha256(&[TAG_INV, &m[0], &bodies[2]]));
    // Changing an early body changes every later digest.
    let mut altered = bodies[0].clone();
    *altered.last_mut().unwrap() ^= 1;
    let m2 = digest::chain_digests(&[&altered, &bodies[1], &bodies[2]]);
    assert!(m.iter().zip(&m2).all(|(a, b)| a != b));
    assert_eq!(TAG_SES.len(), 8);
}

// ---- envelope (SPEC §7.5, D-16) ----

fn aggregate_envelope() -> Envelope {
    let bodies = chain_bodies::<B>();
    let bytes: Vec<Vec<u8>> = bodies
        .iter()
        .map(|b| b.canonical_bytes().unwrap())
        .collect();
    let refs: Vec<&[u8]> = bytes.iter().map(Vec::as_slice).collect();
    let m = digest::chain_digests(&refs);
    let signers = ["issuer", "orchestrator", "payer"];
    let mut agg = BlsAggregate::start(Bls::sign(&sk::<B>(signers[0]), &m[0], Dst::Chain));
    for k in 1..3 {
        BlsAggregate::accumulate(&mut agg, Bls::sign(&sk::<B>(signers[k]), &m[k], Dst::Chain));
    }
    Envelope {
        bodies: bytes,
        sigs: BlsAggregate::to_wire(&agg),
    }
}

#[test]
fn envelope_round_trips() {
    let e = aggregate_envelope();
    let bytes = e.to_bytes();
    assert_eq!(Envelope::from_bytes(&bytes).unwrap(), e);
    let list = Envelope {
        bodies: e.bodies.clone(),
        sigs: WireForm::List(vec![vec![1; 64], vec![2; 64], vec![3; 64]]),
    };
    assert_eq!(Envelope::from_bytes(&list.to_bytes()).unwrap(), list);
}

#[test]
fn envelope_rejects_too_many_bodies_and_bad_shapes() {
    let e = aggregate_envelope();
    let mut many = e.clone();
    many.bodies = vec![e.bodies[1].clone(); MAX_CHAIN_BODIES];
    assert!(Envelope::from_bytes(&many.to_bytes()).is_ok());
    many.bodies.push(e.bodies[1].clone());
    assert_eq!(
        Envelope::from_bytes(&many.to_bytes()).unwrap_err(),
        Malformed::Envelope("more than 17 bodies (D-16)")
    );
    // Non-canonical envelope: array head written in two bytes.
    let mut nc = e.to_bytes();
    nc.splice(0..1, [0x98, 0x02]);
    assert!(matches!(
        Envelope::from_bytes(&nc).unwrap_err(),
        Malformed::Strict(_)
    ));
    for bad in [
        encode(&Value::uint(1)).unwrap(),
        encode(&Value::Array(vec![Value::Array(vec![]), Value::uint(1)])).unwrap(),
        encode(&Value::Array(vec![
            Value::Array(vec![Value::uint(1)]),
            Value::bytes(vec![]),
        ]))
        .unwrap(),
        encode(&Value::Array(vec![Value::Array(vec![])])).unwrap(),
    ] {
        assert!(Envelope::from_bytes(&bad).is_err());
    }
    // Zero and one body decode; line 3 rejects them.
    let one = Envelope {
        bodies: vec![e.bodies[0].clone()],
        sigs: e.sigs.clone(),
    };
    assert!(Envelope::from_bytes(&one.to_bytes()).is_ok());
}

#[test]
fn envelope_aggregate_verifies() {
    let e = aggregate_envelope();
    let refs: Vec<&[u8]> = e.bodies.iter().map(Vec::as_slice).collect();
    let m = digest::chain_digests(&refs);
    let pks: Vec<_> = ["issuer", "orchestrator", "payer"]
        .iter()
        .map(|s| Bls::public_key(&sk::<B>(s)))
        .collect();
    let pk_refs: Vec<_> = pks.iter().collect();
    let sigs = BlsAggregate::from_wire(&e.sigs, 3).unwrap();
    assert!(BlsAggregate::verify_chain(&pk_refs, &m, &sigs));
}

// ---- certificates, revocations, PoP (SPEC §6.3–§6.5) ----

fn cert_body() -> CertBody {
    CertBody {
        identifier: p("orga:agent:payer"),
        pk: pk_bytes::<B>("payer"),
        kind: Kind::Agent,
        registry_id: id("orga"),
        registry_pk: pk_bytes::<B>("root-orga"),
        iat: T0,
        nbf: T0,
        exp: T0 + 86_400,
        serial: 7,
    }
}

#[test]
fn certificates_round_trip_and_verify() {
    let body = cert_body();
    let body_bytes = body.canonical_bytes().unwrap();
    let msg = digest::cert_message(&body_bytes);
    let sig = Bls::sign(&sk::<B>("root-orga"), &msg, Dst::Cert);
    let cert = Certificate::assemble::<B>(&body_bytes, &sig);
    let parsed = ParsedCert::<B>::decode(&cert).unwrap();
    assert_eq!(parsed.body, body);
    assert_eq!(parsed.message(), msg);
    let root = Bls::public_key(&sk::<B>("root-orga"));
    assert!(Bls::verify(
        &root,
        &parsed.message(),
        Dst::Cert,
        &parsed.sig
    ));
    assert!(!Bls::verify(
        &root,
        &parsed.message(),
        Dst::Chain,
        &parsed.sig
    ));
}

#[test]
fn certificate_kind_must_match_the_identifier() {
    let mut body = cert_body();
    body.kind = Kind::Issuer;
    let body_bytes = body.canonical_bytes().unwrap();
    let sig = Bls::sign(
        &sk::<B>("root-orga"),
        &digest::cert_message(&body_bytes),
        Dst::Cert,
    );
    assert_eq!(
        ParsedCert::<B>::decode(&Certificate::assemble::<B>(&body_bytes, &sig)).unwrap_err(),
        Malformed::Certificate("kind does not match the identifier's kind component")
    );
    let mut service = cert_body();
    service.identifier = p("orgb:service:payments");
    service.kind = Kind::Service;
    assert!(service.canonical_bytes().is_err());
    // Version other than 1.
    let v = cert_body().to_value().unwrap();
    let bad = with_field(&v, 1, Some(Value::uint(2)));
    let cert = Certificate::assemble::<B>(&bad, &sig);
    assert!(matches!(
        ParsedCert::<B>::decode(&cert).unwrap_err(),
        Malformed::Schema(SchemaError::Invalid("CertBody", 1))
    ));
}

#[test]
fn revocations_and_pop_challenges_round_trip() {
    let rb = RevocationBody {
        registry_id: id("orga"),
        serial: 7,
        revoked_at: T0 + 10,
        identifier: p("orga:agent:payer"),
        pk: pk_bytes::<B>("payer"),
    };
    let bytes = rb.canonical_bytes();
    let sig = Bls::sign(
        &sk::<B>("root-orga"),
        &digest::revocation_message(&bytes),
        Dst::Revoke,
    );
    let parsed =
        ParsedRevocation::<B>::decode(&RevocationAssertion::assemble::<B>(&bytes, &sig)).unwrap();
    assert_eq!(parsed.body, rb);

    let ch = PopChallenge {
        identifier: p("orga:agent:payer"),
        pk: pk_bytes::<B>("payer"),
        kind: Kind::Agent,
        registry_id: id("orga"),
        nonce: [9; 16],
        timestamp: T0,
    };
    let bytes = ch.canonical_bytes().unwrap();
    assert_eq!(PopChallenge::decode(&bytes, Bls::PK_LEN).unwrap(), ch);
    assert_eq!(ch.message().unwrap(), sha256(&[digest::TAG_POP, &bytes]));
}

#[test]
fn manual_clock() {
    use dc_types::Clock;
    let c = ManualClock::new(5);
    c.advance(10);
    assert_eq!(c.now(), 15);
    c.set(3);
    assert_eq!(c.now(), 3);
}

// ---- NFC in scopes (paper §6.1; D-55) ----

#[test]
fn non_nfc_scope_text_is_a_canonical_form_violation() {
    let decomposed = "caf\u{65}\u{301}";
    let composed = "caf\u{e9}";
    // A scope-shaped value holding one text operand; dc-types does not
    // validate the AST, only its NFC form.
    let scope = |t: &str| {
        dc_types::RawScope(
            Value::map(vec![
                (Key::Uint(1), Value::uint(2)),
                (Key::Uint(9), Value::text(t)),
            ])
            .unwrap(),
        )
    };
    let mut good = delegation::<B>();
    good.scope = scope(composed);
    let canonical = Body::<B>::Delegation(good.clone())
        .canonical_bytes()
        .unwrap();
    assert_eq!(decode_body::<B>(&canonical).unwrap().violation, None);

    let v = good.to_value().unwrap();
    let bytes = with_field(&v, 6, Some(scope(decomposed).0));
    let d = decode_body::<B>(&bytes).unwrap();
    assert_eq!(d.violation, Some(CanonViolation::NonNfc));
    // Canon normalizes, so line 5's re-encoding differs from the input and
    // equals the composed form.
    assert_ne!(d.body.canonical_bytes().unwrap(), bytes);
    assert_eq!(d.body.canonical_bytes().unwrap(), canonical);

    // The same for a session scope.
    let v = session::<B>().to_value().unwrap();
    let bytes = with_field(&v, 8, Some(scope(decomposed).0));
    assert_eq!(
        decode_body::<B>(&bytes).unwrap().violation,
        Some(CanonViolation::NonNfc)
    );
}
