//! Hand-written vectors for every rule of SPEC §4.4, plus accepted boundary
//! values. Each malformed vector asserts the exact error; each non-canonical
//! vector asserts that `decode` records the violation, that `decode_strict`
//! rejects it, and that re-encoding differs from the input (D-31).

use dc_cbor::{
    CanonViolation, DecodeError, EncodeError, INT_MAX, INT_MIN, Key, Limits, StrictError, Value,
    decode, decode_strict, encode, nfc, schema,
};

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn malformed(input: &str, expected: DecodeError) {
    let b = hex(input);
    assert_eq!(
        decode(&b, Limits::BODY).unwrap_err(),
        expected,
        "input {input}"
    );
    assert_eq!(
        decode_strict(&b, Limits::BODY).unwrap_err(),
        StrictError::Malformed(expected),
        "input {input}"
    );
}

fn non_canonical(input: &str, expected: CanonViolation, value: Value) {
    let b = hex(input);
    let (v, violation) = decode(&b, Limits::BODY).unwrap_or_else(|e| panic!("input {input}: {e}"));
    assert_eq!(violation, Some(expected), "input {input}");
    assert_eq!(v, value, "input {input}");
    assert_eq!(
        decode_strict(&b, Limits::BODY).unwrap_err(),
        StrictError::NonCanonical(expected),
        "input {input}"
    );
    assert_ne!(
        encode(&v).unwrap(),
        b,
        "re-encoding must differ for {input}"
    );
}

fn canonical(input: &str, value: Value) {
    let b = hex(input);
    assert_eq!(
        decode_strict(&b, Limits::BODY).unwrap(),
        value,
        "input {input}"
    );
    assert_eq!(encode(&value).unwrap(), b, "input {input}");
}

fn map(entries: Vec<(Key, Value)>) -> Value {
    Value::map(entries).unwrap()
}

// ---- accepted: boundaries of every argument width ----

#[test]
fn accepts_integer_boundaries() {
    for (h, n) in [
        ("00", 0i128),
        ("17", 23),
        ("1818", 24),
        ("18ff", 255),
        ("190100", 256),
        ("19ffff", 65535),
        ("1a00010000", 65536),
        ("1affffffff", 4294967295),
        ("1b0000000100000000", 4294967296),
        ("1bffffffffffffffff", INT_MAX),
        ("20", -1),
        ("37", -24),
        ("3818", -25),
        ("3bffffffffffffffff", INT_MIN),
    ] {
        canonical(h, Value::Int(n));
    }
}

#[test]
fn accepts_simple_and_empty_items() {
    canonical("f4", Value::Bool(false));
    canonical("f5", Value::Bool(true));
    canonical("f6", Value::Null);
    canonical("40", Value::Bytes(vec![]));
    canonical("60", Value::text(""));
    canonical("80", Value::Array(vec![]));
    canonical("a0", Value::Map(vec![]));
    canonical("6449455446", Value::text("IETF"));
    canonical("62c3bc", Value::text("\u{fc}"));
}

#[test]
fn accepts_canonical_key_order() {
    // uint keys before text keys; text keys shorter first (RFC 8949 §4.2.1).
    canonical(
        "a4 01 f6 18 18 f6 61 62 f6 62 61 61 f6",
        map(vec![
            (Key::Uint(1), Value::Null),
            (Key::Uint(24), Value::Null),
            (Key::from("b"), Value::Null),
            (Key::from("aa"), Value::Null),
        ]),
    );
}

#[test]
fn nesting_limit_is_exactly_sixteen() {
    // 16 nested arrays decode; 17 do not (D-02).
    let ok = format!("{}80", "81".repeat(15));
    assert!(decode_strict(&hex(&ok), Limits::BODY).is_ok());
    let too_deep = format!("{}80", "81".repeat(16));
    malformed(
        &too_deep,
        DecodeError::TooDeep {
            limit: 16,
            offset: 16,
        },
    );
}

// ---- malformed (Algorithm 1 line 2) ----

#[test]
fn rejects_truncation() {
    malformed("", DecodeError::Truncated(0));
    malformed("18", DecodeError::Truncated(1));
    malformed("1900", DecodeError::Truncated(2));
    malformed("4201", DecodeError::Truncated(2));
    malformed("8201", DecodeError::Truncated(2));
    malformed("a101", DecodeError::Truncated(2));
    malformed("9f01", DecodeError::Truncated(2));
    // A forged huge length is truncation, found before allocating.
    malformed("9bffffffffffffffff", DecodeError::Truncated(9));
    malformed("5bffffffffffffffff", DecodeError::Truncated(9));
}

#[test]
fn rejects_trailing_bytes() {
    malformed("0102", DecodeError::TrailingBytes(1));
    malformed("80 00", DecodeError::TrailingBytes(1));
}

#[test]
fn rejects_oversized_input() {
    let limits = Limits {
        max_depth: 16,
        max_size: 4,
    };
    assert_eq!(
        decode(&hex("4401020304"), limits).unwrap_err(),
        DecodeError::TooLarge { len: 5, limit: 4 }
    );
    let at_limit = hex("43010203");
    assert!(decode(&at_limit, limits).is_ok());
}

#[test]
fn rejects_body_larger_than_64_kib() {
    // D-03: a 65,537-byte body is rejected under the body limits.
    let mut b = hex("5a00010000");
    b.resize(5 + 65_536, 0);
    assert_eq!(
        decode(&b, Limits::BODY).unwrap_err(),
        DecodeError::TooLarge {
            len: 65_541,
            limit: 65_536
        }
    );
}

#[test]
fn rejects_tags() {
    malformed("c060", DecodeError::Tag(0));
    malformed("d82060", DecodeError::Tag(0));
    malformed("81c100", DecodeError::Tag(1));
}

#[test]
fn rejects_floats() {
    malformed("f93c00", DecodeError::Float(0));
    malformed("fa3f800000", DecodeError::Float(0));
    malformed("fb3ff0000000000000", DecodeError::Float(0));
}

#[test]
fn rejects_disallowed_simple_values() {
    malformed("f7", DecodeError::Simple(0)); // undefined
    malformed("e0", DecodeError::Simple(0)); // simple(0)
    malformed("f3", DecodeError::Simple(0)); // simple(19)
    malformed("f820", DecodeError::Simple(0)); // simple(32), two-byte form
}

#[test]
fn rejects_reserved_additional_information() {
    malformed("1c", DecodeError::Reserved(0));
    malformed("3d", DecodeError::Reserved(0));
    malformed("5e", DecodeError::Reserved(0));
    malformed("fc", DecodeError::Reserved(0));
}

#[test]
fn rejects_indefinite_integers_and_stray_breaks() {
    malformed("1f", DecodeError::IndefiniteInteger(0));
    malformed("3f", DecodeError::IndefiniteInteger(0));
    malformed("ff", DecodeError::UnexpectedBreak(0));
    malformed("bf01ff", DecodeError::UnexpectedBreak(2));
}

#[test]
fn rejects_bad_chunks() {
    malformed("5f01ff", DecodeError::BadChunk(1)); // integer chunk in a byte string
    malformed("5f5fffff", DecodeError::BadChunk(1)); // nested indefinite chunk
    malformed("7f4100ff", DecodeError::BadChunk(1)); // byte chunk in a text string
}

#[test]
fn rejects_invalid_utf8() {
    malformed("61ff", DecodeError::InvalidUtf8(0));
    malformed("62c328", DecodeError::InvalidUtf8(0));
    // Each chunk must be valid on its own (RFC 8949 §3.2.3).
    malformed("7f61c361a9ff", DecodeError::InvalidUtf8(1));
    malformed("a161ff00", DecodeError::InvalidUtf8(1));
}

#[test]
fn rejects_duplicate_keys() {
    malformed("a2 01 00 01 00", DecodeError::DuplicateKey(3));
    malformed("a2 6161 00 6161 00", DecodeError::DuplicateKey(4));
    // Unsorted input needs the full check.
    malformed("a3 02 00 01 00 02 00", DecodeError::DuplicateKey(0));
}

#[test]
fn rejects_disallowed_key_types() {
    malformed("a1 20 00", DecodeError::KeyType(1)); // negative integer
    malformed("a1 40 00", DecodeError::KeyType(1)); // byte string
    malformed("a1 80 00", DecodeError::KeyType(1)); // array
    malformed("a1 f4 00", DecodeError::KeyType(1)); // bool
    malformed("a1 c0 00 00", DecodeError::KeyType(1)); // tag
}

// ---- non-canonical (Algorithm 1 line 5) ----

#[test]
fn records_non_shortest_arguments() {
    non_canonical("1817", CanonViolation::NonShortest(0), Value::Int(23));
    non_canonical("1900ff", CanonViolation::NonShortest(0), Value::Int(255));
    non_canonical(
        "1a0000ffff",
        CanonViolation::NonShortest(0),
        Value::Int(65535),
    );
    non_canonical(
        "1b00000000ffffffff",
        CanonViolation::NonShortest(0),
        Value::Int(4294967295),
    );
    non_canonical("3800", CanonViolation::NonShortest(0), Value::Int(-1));
    non_canonical(
        "5801aa",
        CanonViolation::NonShortest(0),
        Value::Bytes(vec![0xaa]),
    );
    non_canonical("7800", CanonViolation::NonShortest(0), Value::text(""));
    non_canonical("9800", CanonViolation::NonShortest(0), Value::Array(vec![]));
    non_canonical("b800", CanonViolation::NonShortest(0), Value::Map(vec![]));
    non_canonical(
        "a1 1801 00",
        CanonViolation::NonShortest(1),
        map(vec![(Key::Uint(1), Value::Int(0))]),
    );
    non_canonical(
        "82 00 1801",
        CanonViolation::NonShortest(2),
        Value::Array(vec![Value::Int(0), Value::Int(1)]),
    );
}

#[test]
fn records_indefinite_lengths() {
    non_canonical("9fff", CanonViolation::Indefinite(0), Value::Array(vec![]));
    non_canonical("bfff", CanonViolation::Indefinite(0), Value::Map(vec![]));
    non_canonical(
        "5f4101ff",
        CanonViolation::Indefinite(0),
        Value::Bytes(vec![1]),
    );
    non_canonical("7f6161ff", CanonViolation::Indefinite(0), Value::text("a"));
    non_canonical(
        "9f 01 02 ff",
        CanonViolation::Indefinite(0),
        Value::Array(vec![Value::Int(1), Value::Int(2)]),
    );
    non_canonical(
        "bf 01 02 ff",
        CanonViolation::Indefinite(0),
        map(vec![(Key::Uint(1), Value::Int(2))]),
    );
}

#[test]
fn records_unsorted_keys() {
    let v = map(vec![
        (Key::Uint(1), Value::Int(0)),
        (Key::Uint(2), Value::Int(0)),
    ]);
    let (d, violation) = decode(&hex("a2 02 00 01 00"), Limits::BODY).unwrap();
    assert_eq!(violation, Some(CanonViolation::UnsortedKeys(3)));
    assert_eq!(encode(&d).unwrap(), hex("a2 01 00 02 00"));
    assert_eq!(Value::map(d.as_map().unwrap().to_vec()).unwrap(), v);
    // "aa" before "b": equal first byte order but longer, so unsorted.
    let (_, violation) = decode(&hex("a2 626161 00 6162 00"), Limits::BODY).unwrap();
    assert_eq!(violation, Some(CanonViolation::UnsortedKeys(5)));
    // A uint key after a text key.
    let (_, violation) = decode(&hex("a2 6161 00 01 00"), Limits::BODY).unwrap();
    assert_eq!(violation, Some(CanonViolation::UnsortedKeys(4)));
}

#[test]
fn malformed_input_wins_over_an_earlier_violation() {
    // A non-shortest integer followed by a float: the float is malformed, so
    // the whole item is L02 regardless of order (D-31).
    malformed("82 1801 f93c00", DecodeError::Float(3));
}

// ---- encoder ----

#[test]
fn encoder_refuses_what_the_decoder_would_reject() {
    assert_eq!(
        encode(&Value::Int(INT_MAX + 1)).unwrap_err(),
        EncodeError::IntOutOfRange(INT_MAX + 1)
    );
    assert_eq!(
        encode(&Value::Int(INT_MIN - 1)).unwrap_err(),
        EncodeError::IntOutOfRange(INT_MIN - 1)
    );
    let dup = Value::Map(vec![
        (Key::Uint(1), Value::Null),
        (Key::Uint(1), Value::Null),
    ]);
    assert_eq!(encode(&dup).unwrap_err(), EncodeError::DuplicateKey);
    let mut deep = Value::Array(vec![]);
    for _ in 0..16 {
        deep = Value::Array(vec![deep]);
    }
    assert_eq!(encode(&deep).unwrap_err(), EncodeError::TooDeep);
    assert_eq!(
        Value::map(vec![
            (Key::Uint(1), Value::Null),
            (Key::Uint(1), Value::Null)
        ])
        .unwrap_err(),
        EncodeError::DuplicateKey
    );
}

#[test]
fn encoder_sorts_unsorted_maps() {
    let v = Value::Map(vec![
        (Key::from("b"), Value::Null),
        (Key::Uint(7), Value::Null),
    ]);
    assert_eq!(encode(&v).unwrap(), hex("a2 07 f6 6162 f6"));
}

// ---- NFC helpers (paper §4.4) ----

#[test]
fn nfc_detection_and_normalization() {
    let decomposed = "e\u{301}"; // e + combining acute
    let composed = "\u{e9}";
    let params = Value::Map(vec![(Key::from("to"), Value::text(decomposed))]);
    assert!(!nfc::is_nfc_deep(&params));
    let n = nfc::to_nfc_deep(&params).unwrap();
    assert!(nfc::is_nfc_deep(&n));
    assert_eq!(n, map(vec![(Key::from("to"), Value::text(composed))]));
    // Keys are normalized too, and a collision is refused.
    let colliding = Value::Map(vec![
        (Key::from(composed), Value::Null),
        (Key::from(decomposed), Value::Null),
    ]);
    assert!(!nfc::is_nfc_deep(&colliding));
    assert_eq!(
        nfc::to_nfc_deep(&colliding).unwrap_err(),
        EncodeError::DuplicateKey
    );
    // Nested arrays and maps are covered.
    let nested = Value::Array(vec![map(vec![(Key::Uint(1), Value::text(decomposed))])]);
    assert!(!nfc::is_nfc_deep(&nested));
}

// ---- protocol-structure reader (D-01) ----

#[test]
fn fields_reader_rejects_unknown_missing_and_non_uint_keys() {
    let v = map(vec![
        (Key::Uint(1), Value::uint(5)),
        (Key::Uint(2), Value::text("x")),
    ]);
    let mut f = schema::Fields::new("T", &v).unwrap();
    assert_eq!(f.get(1, Value::as_u64).unwrap(), 5);
    assert_eq!(
        f.finish().unwrap_err(),
        schema::SchemaError::Unknown("T", 2)
    );

    let mut f = schema::Fields::new("T", &v).unwrap();
    assert_eq!(f.req(3).unwrap_err(), schema::SchemaError::Missing("T", 3));
    assert_eq!(
        f.get(2, Value::as_u64).unwrap_err(),
        schema::SchemaError::Invalid("T", 2)
    );

    let text_keyed = map(vec![(Key::from("a"), Value::Null)]);
    assert!(matches!(
        schema::Fields::new("T", &text_keyed),
        Err(schema::SchemaError::NonUintKey("T"))
    ));
    assert!(matches!(
        schema::Fields::new("T", &Value::Null),
        Err(schema::SchemaError::NotAMap("T"))
    ));
}
