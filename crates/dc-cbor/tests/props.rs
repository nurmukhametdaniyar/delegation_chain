//! Property tests of SPEC §4.5, plus the D-31 redundancy property: for any
//! input the decoder accepts, "a canonical-form violation was recorded" and
//! "re-encoding differs from the input" are the same thing.

use dc_cbor::{INT_MAX, INT_MIN, Key, Limits, Value, decode, decode_strict, encode};
use proptest::collection::{btree_map, vec};
use proptest::prelude::*;

const LIMITS: Limits = Limits {
    max_depth: 16,
    max_size: 1 << 20,
};

fn arb_int() -> impl Strategy<Value = i128> {
    prop_oneof![
        prop::sample::select(vec![
            INT_MIN,
            INT_MIN + 1,
            -65537,
            -65536,
            -257,
            -256,
            -25,
            -24,
            -1,
            0,
            23,
            24,
            255,
            256,
            65535,
            65536,
            (1 << 32) - 1,
            1 << 32,
            INT_MAX - 1,
            INT_MAX,
        ]),
        any::<u64>().prop_map(i128::from),
        any::<u64>().prop_map(|n| -1 - i128::from(n)),
        (-30i128..30),
    ]
}

fn arb_text() -> impl Strategy<Value = String> {
    prop_oneof![".{0,8}", "[a-z]{0,30}", Just("e\u{301}".to_owned())]
}

fn arb_key() -> impl Strategy<Value = Key> {
    prop_oneof![
        (0u64..40).prop_map(Key::Uint),
        any::<u64>().prop_map(Key::Uint),
        arb_text().prop_map(Key::Text),
    ]
}

/// Canonical values: maps come from a `BTreeMap<Key, _>`, which orders keys
/// by `Key`'s canonical order and keeps them unique.
fn arb_value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        arb_int().prop_map(Value::Int),
        vec(any::<u8>(), 0..40).prop_map(Value::Bytes),
        arb_text().prop_map(Value::Text),
        any::<bool>().prop_map(Value::Bool),
        Just(Value::Null),
    ];
    leaf.prop_recursive(6, 96, 8, |inner| {
        prop_oneof![
            vec(inner.clone(), 0..8).prop_map(Value::Array),
            btree_map(arb_key(), inner, 0..8).prop_map(|m| Value::Map(m.into_iter().collect())),
        ]
    })
}

fn encode_key(k: &Key) -> Vec<u8> {
    let v = Value::Map(vec![(k.clone(), Value::Null)]);
    let b = encode(&v).unwrap();
    b[1..b.len() - 1].to_vec()
}

/// Recursively sorts map entries, so values decoded from shuffled input can
/// be compared with the canonical original.
fn sorted(v: Value) -> Value {
    match v {
        Value::Array(a) => Value::Array(a.into_iter().map(sorted).collect()),
        Value::Map(m) => Value::map(m.into_iter().map(|(k, x)| (k, sorted(x)))).unwrap(),
        other => other,
    }
}

/// A deliberately non-canonical encoder: random wider heads, indefinite
/// lengths, chunked strings and shuffled map entries. Decoding its output
/// must give back the same value.
struct Variant(u64);

impl Variant {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn one_in(&mut self, n: u64) -> bool {
        self.next().is_multiple_of(n)
    }

    fn head(&mut self, out: &mut Vec<u8>, major: u8, arg: u64) {
        let min_width = match arg {
            0..=23 => 0,
            24..=0xff => 1,
            0x100..=0xffff => 2,
            0x1_0000..=0xffff_ffff => 3,
            _ => 4,
        };
        let width = if self.one_in(4) {
            min_width + (self.next() % (5 - min_width))
        } else {
            min_width
        };
        let m = major << 5;
        match width {
            0 => out.push(m | arg as u8),
            1 => out.extend([m | 24, arg as u8]),
            2 => {
                out.push(m | 25);
                out.extend((arg as u16).to_be_bytes());
            }
            3 => {
                out.push(m | 26);
                out.extend((arg as u32).to_be_bytes());
            }
            _ => {
                out.push(m | 27);
                out.extend(arg.to_be_bytes());
            }
        }
    }

    fn string(&mut self, out: &mut Vec<u8>, major: u8, s: &[u8], cuts: &[usize]) {
        if !self.one_in(4) {
            self.head(out, major, s.len() as u64);
            out.extend_from_slice(s);
            return;
        }
        out.push((major << 5) | 31);
        let mut prev = 0;
        for &c in cuts.iter().chain(std::iter::once(&s.len())) {
            if c < prev || (c != s.len() && !self.one_in(2)) {
                continue;
            }
            self.head(out, major, (c - prev) as u64);
            out.extend_from_slice(&s[prev..c]);
            prev = c;
        }
        out.push(0xff);
    }

    fn text(&mut self, out: &mut Vec<u8>, s: &str) {
        let cuts: Vec<usize> = s
            .char_indices()
            .map(|(i, _)| i)
            .filter(|&i| i > 0)
            .collect();
        self.string(out, 3, s.as_bytes(), &cuts);
    }

    fn key(&mut self, out: &mut Vec<u8>, k: &Key) {
        match k {
            Key::Uint(n) => self.head(out, 0, *n),
            Key::Text(s) => self.text(out, s),
        }
    }

    fn value(&mut self, out: &mut Vec<u8>, v: &Value) {
        match v {
            Value::Int(n) if *n >= 0 => self.head(out, 0, *n as u64),
            Value::Int(n) => self.head(out, 1, (-1 - *n) as u64),
            Value::Bytes(b) => {
                let cuts: Vec<usize> = (1..b.len()).collect();
                self.string(out, 2, b, &cuts);
            }
            Value::Text(s) => self.text(out, s),
            Value::Array(a) => {
                let indefinite = self.one_in(4);
                if indefinite {
                    out.push(0x9f);
                } else {
                    self.head(out, 4, a.len() as u64);
                }
                for x in a {
                    self.value(out, x);
                }
                if indefinite {
                    out.push(0xff);
                }
            }
            Value::Map(m) => {
                let mut entries: Vec<&(Key, Value)> = m.iter().collect();
                if self.one_in(4) {
                    for i in (1..entries.len()).rev() {
                        let j = (self.next() % (i as u64 + 1)) as usize;
                        entries.swap(i, j);
                    }
                }
                let indefinite = self.one_in(4);
                if indefinite {
                    out.push(0xbf);
                } else {
                    self.head(out, 5, entries.len() as u64);
                }
                for (k, x) in entries {
                    self.key(out, k);
                    self.value(out, x);
                }
                if indefinite {
                    out.push(0xff);
                }
            }
            Value::Bool(false) => out.push(0xf4),
            Value::Bool(true) => out.push(0xf5),
            Value::Null => out.push(0xf6),
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    /// SPEC §4.5: decode(encode(x)) == x.
    #[test]
    fn roundtrip_value(x in arb_value()) {
        let b = encode(&x).unwrap();
        prop_assert_eq!(decode(&b, LIMITS).unwrap(), (x, None));
    }

    /// `Key`'s order is the bytewise order of the encoded keys.
    #[test]
    fn key_order_matches_encoded_order(a in arb_key(), b in arb_key()) {
        prop_assert_eq!(a.cmp(&b), encode_key(&a).cmp(&encode_key(&b)));
    }

    /// D-31: for non-canonical encodings of a value, decoding recovers the
    /// value, and a violation is recorded exactly when the bytes differ from
    /// the canonical encoding.
    #[test]
    fn violation_recorded_iff_reencoding_differs(x in arb_value(), seed in 1u64..) {
        let mut out = Vec::new();
        Variant(seed).value(&mut out, &x);
        let (y, violation) = decode(&out, LIMITS).unwrap();
        let canonical = encode(&x).unwrap();
        prop_assert_eq!(violation.is_none(), out == canonical);
        prop_assert_eq!(encode(&y).unwrap(), canonical);
        prop_assert_eq!(sorted(y), x);
    }

    /// SPEC §4.5: for any bytes that `decode_strict` accepts,
    /// encode(decode(b)) == b; and the D-31 equivalence holds for every
    /// input `decode` accepts. Inputs are mutations of valid encodings, so
    /// that many of them decode.
    #[test]
    fn accepted_mutations_reencode_consistently(
        x in arb_value(),
        edits in vec((any::<prop::sample::Index>(), any::<u8>(), 0u8..4), 1..4),
    ) {
        let mut b = encode(&x).unwrap();
        for (at, byte, kind) in edits {
            if b.is_empty() { break; }
            let i = at.index(b.len());
            match kind {
                0 => b[i] = byte,
                1 => b[i] ^= 1 << (byte % 8),
                2 => b.insert(i, byte),
                _ => { b.remove(i); }
            }
        }
        if let Ok((y, violation)) = decode(&b, LIMITS) {
            let again = encode(&y).unwrap();
            prop_assert_eq!(violation.is_none(), again == b);
            if let Ok(z) = decode_strict(&b, LIMITS) {
                prop_assert_eq!(encode(&z).unwrap(), b);
            }
        }
    }

    /// Arbitrary bytes never panic the decoder.
    #[test]
    fn arbitrary_bytes_never_panic(b in vec(any::<u8>(), 0..64)) {
        let _ = decode(&b, LIMITS);
    }
}
