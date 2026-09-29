//! Regression vectors (SPEC §11.1): fixed inputs, with their expected bytes
//! and digests committed in `tests/vectors/*.json` at the repository root.
//! They are *regression* vectors, not normative: they pin this
//! implementation's encodings so that a change shows up. Regenerate with
//! `DC_REGEN_VECTORS=1 cargo test -p dc-types --test vectors`, and review the
//! diff.

mod common;

use std::collections::BTreeMap;
use std::path::PathBuf;

use common::*;
use dc_crypto::{Bls, BlsAggregate, ChainScheme, Dst, Ed25519, SigScheme, WireForm};
use dc_types::digest;
use dc_types::{
    Body, CertBody, Certificate, Envelope, Kind, ParsedCert, PopChallenge, RevocationAssertion,
    RevocationBody, decode_body,
};

const LABEL: &str = "regression, not normative (SPEC §11.1)";

fn build<S: SigScheme>(sigs: impl Fn(&[S::Signature]) -> WireForm) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut put = |k: &str, v: &[u8]| {
        out.insert(k.to_owned(), hex(v));
    };

    let bodies = chain_bodies::<S>();
    let bytes: Vec<Vec<u8>> = bodies
        .iter()
        .map(|b| b.canonical_bytes().unwrap())
        .collect();
    for (name, b) in ["body.0.session", "body.1.delegation", "body.2.invocation"]
        .iter()
        .zip(&bytes)
    {
        put(name, b);
    }
    let Body::Invocation(inv) = &bodies[2] else {
        unreachable!()
    };
    put("params.canonical", &inv.params.canonical_bytes().unwrap());
    put("params.hash", &inv.params_hash);
    put("invocation_digest", &inv.invocation_digest().unwrap());
    put("receipt.approval_body", &inv.receipts[0].approval_bytes);
    put("receipt.message", &inv.receipts[0].message());
    put("receipt.sig", &S::sig_bytes(&inv.receipts[0].sig));

    let refs: Vec<&[u8]> = bytes.iter().map(Vec::as_slice).collect();
    let m = digest::chain_digests(&refs);
    let signers = ["issuer", "orchestrator", "payer"];
    let mut chain_sigs = vec![];
    for k in 0..3 {
        put(&format!("m.{k}"), &m[k]);
        let s = S::sign(&sk::<S>(signers[k]), &m[k], Dst::Chain);
        put(&format!("sig.{k}"), &S::sig_bytes(&s));
        chain_sigs.push(s);
    }
    let envelope = Envelope {
        bodies: bytes.clone(),
        sigs: sigs(&chain_sigs),
    };
    put("envelope", &envelope.to_bytes());

    let cert = CertBody {
        identifier: p("orga:agent:payer"),
        pk: pk_bytes::<S>("payer"),
        kind: Kind::Agent,
        registry_id: id("orga"),
        registry_pk: pk_bytes::<S>("root-orga"),
        iat: T0,
        nbf: T0,
        exp: T0 + 86_400,
        serial: 1,
    };
    let cert_bytes = cert.canonical_bytes().unwrap();
    let cert_msg = digest::cert_message(&cert_bytes);
    let cert_sig = S::sign(&sk::<S>("root-orga"), &cert_msg, Dst::Cert);
    put("cert.message", &cert_msg);
    put(
        "cert",
        &Certificate::assemble::<S>(&cert_bytes, &cert_sig).0,
    );

    let rev = RevocationBody {
        registry_id: id("orga"),
        serial: 1,
        revoked_at: T0 + 60,
        identifier: p("orga:agent:payer"),
        pk: pk_bytes::<S>("payer"),
    }
    .canonical_bytes();
    let rev_msg = digest::revocation_message(&rev);
    let rev_sig = S::sign(&sk::<S>("root-orga"), &rev_msg, Dst::Revoke);
    put("revocation.message", &rev_msg);
    put(
        "revocation",
        &RevocationAssertion::assemble::<S>(&rev, &rev_sig).0,
    );

    let pop = PopChallenge {
        identifier: p("orga:agent:payer"),
        pk: pk_bytes::<S>("payer"),
        kind: Kind::Agent,
        registry_id: id("orga"),
        nonce: [0x5a; 16],
        timestamp: T0,
    };
    put("pop.challenge", &pop.canonical_bytes().unwrap());
    put("pop.message", &pop.message().unwrap());
    put(
        "pop.sig",
        &S::sig_bytes(&S::sign(
            &sk::<S>("payer"),
            &pop.message().unwrap(),
            Dst::Pop,
        )),
    );
    out
}

fn check(name: &str, scheme: &str, items: BTreeMap<String, String>) {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("../../tests/vectors/{name}.json"));
    let doc = serde_json::json!({ "label": LABEL, "scheme": scheme, "items": items });
    if std::env::var_os("DC_REGEN_VECTORS").is_some() {
        std::fs::write(&path, serde_json::to_string_pretty(&doc).unwrap() + "\n").unwrap();
        return;
    }
    let committed: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap_or_else(|_| {
            panic!(
                "{} missing; generate with DC_REGEN_VECTORS=1",
                path.display()
            )
        }))
        .unwrap();
    assert_eq!(committed["label"], LABEL);
    assert_eq!(committed["scheme"], scheme);
    let committed: BTreeMap<String, String> =
        serde_json::from_value(committed["items"].clone()).unwrap();
    assert_eq!(
        committed.keys().collect::<Vec<_>>(),
        items.keys().collect::<Vec<_>>()
    );
    for (k, v) in &items {
        assert_eq!(&committed[k], v, "vector {name}/{k} changed");
    }
}

#[test]
fn bls_vectors() {
    let items = build::<Bls>(|sigs| {
        let mut agg = BlsAggregate::start(sigs[0]);
        for s in &sigs[1..] {
            BlsAggregate::accumulate(&mut agg, *s);
        }
        BlsAggregate::to_wire(&agg)
    });
    check("bls", Bls::NAME, items.clone());

    // The committed bytes decode back to the fixtures, and the aggregate in
    // the committed envelope verifies.
    let env = Envelope::from_bytes(&unhex(&items["envelope"])).unwrap();
    for (b, expect) in env.bodies.iter().zip(chain_bodies::<Bls>()) {
        let d = decode_body::<Bls>(b).unwrap();
        assert_eq!((d.body, d.violation), (expect, None));
    }
    let refs: Vec<&[u8]> = env.bodies.iter().map(Vec::as_slice).collect();
    let m = digest::chain_digests(&refs);
    let pks: Vec<_> = ["issuer", "orchestrator", "payer"]
        .iter()
        .map(|s| Bls::public_key(&sk::<Bls>(s)))
        .collect();
    let pk_refs: Vec<_> = pks.iter().collect();
    assert!(BlsAggregate::verify_chain(
        &pk_refs,
        &m,
        &BlsAggregate::from_wire(&env.sigs, 3).unwrap()
    ));
    assert!(ParsedCert::<Bls>::decode(&Certificate(unhex(&items["cert"]))).is_ok());
}

#[test]
fn ed25519_vectors() {
    let items =
        build::<Ed25519>(|sigs| WireForm::List(sigs.iter().map(Ed25519::sig_bytes).collect()));
    check("ed25519", Ed25519::NAME, items);
}
