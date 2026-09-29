//! Property tests over invocation bodies with arbitrary parameters.

mod common;

use common::*;
use dc_cbor::{Key, Value};
use dc_crypto::Bls;
use dc_types::{Body, Params, decode_body};
use proptest::collection::{btree_map, vec};
use proptest::prelude::*;

fn arb_param_value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        any::<i64>().prop_map(|n| Value::Int(n.into())),
        vec(any::<u8>(), 0..8).prop_map(Value::Bytes),
        prop_oneof![".{0,6}", Just("e\u{301}".to_owned())].prop_map(Value::Text),
        any::<bool>().prop_map(Value::Bool),
        Just(Value::Null),
    ];
    leaf.prop_recursive(3, 24, 4, |inner| {
        prop_oneof![
            vec(inner.clone(), 0..4).prop_map(Value::Array),
            btree_map("[a-z]{1,4}", inner, 0..4)
                .prop_map(|m| Value::Map(m.into_iter().map(|(k, v)| (Key::Text(k), v)).collect())),
        ]
    })
}

fn arb_params() -> impl Strategy<Value = Params> {
    btree_map("[a-z]{1,6}", arb_param_value(), 0..5).prop_filter_map("NFC key collision", |m| {
        Params::new(Value::Map(
            m.into_iter().map(|(k, v)| (Key::Text(k), v)).collect(),
        ))
        .ok()
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    /// Built bodies are canonical: they decode to themselves with no
    /// violation, and re-encode to the same bytes.
    #[test]
    fn invocation_round_trips(prm in arb_params(), with_receipt in any::<bool>()) {
        let mut inv = if with_receipt { invocation_with_receipt::<Bls>() } else { invocation::<Bls>() };
        inv.params_hash = prm.hash().unwrap();
        inv.params = prm;
        let body = Body::Invocation(inv);
        let bytes = body.canonical_bytes().unwrap();
        let d = decode_body::<Bls>(&bytes).unwrap();
        prop_assert_eq!(d.violation, None);
        prop_assert_eq!(d.body.canonical_bytes().unwrap(), bytes);
        prop_assert_eq!(d.body, body);
    }

    /// D-31 at body level: whenever a mutated body still decodes, "violation
    /// recorded" and "re-encoding differs" agree.
    #[test]
    fn mutated_bodies_classify_consistently(
        which in 0usize..3,
        edits in vec((any::<prop::sample::Index>(), any::<u8>()), 1..3),
    ) {
        let mut b = chain_bodies::<Bls>()[which].canonical_bytes().unwrap();
        for (at, byte) in edits {
            let i = at.index(b.len());
            b[i] = byte;
        }
        if let Ok(d) = decode_body::<Bls>(&b) {
            if let Ok(again) = d.body.canonical_bytes() {
                prop_assert_eq!(d.violation.is_none(), again == b);
            } else {
                prop_assert!(d.violation.is_some());
            }
        }
    }
}
