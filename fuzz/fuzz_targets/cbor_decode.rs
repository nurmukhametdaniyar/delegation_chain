//! The dc-cbor decoder on arbitrary bytes (SPEC §11.4).
//!
//! Properties:
//! - no input panics the decoder or the encoder;
//! - input decoded with no canonical-form violation re-encodes to exactly
//!   itself. Algorithm 1 line 5 relies on this: the verifier rejects both a
//!   recorded violation and a re-encoding that differs (D-31), and a
//!   failure here would mean the recorder misses a violation;
//! - re-encoding is a fixed point: whatever decodes and re-encodes,
//!   re-decodes with no violation and re-encodes to the same bytes. (Not the
//!   same `Value`: for non-canonical input the decoder keeps the input's map
//!   order and records the violation, while the encoder writes canonical
//!   order. The first formulation compared values and failed on exactly
//!   that; D-74.)
#![no_main]

use dc_cbor::{decode, encode, Limits};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok((value, violation)) = decode(data, Limits::BODY) else {
        return;
    };
    let again = encode(&value);
    if violation.is_none() {
        assert_eq!(
            again.as_deref().ok(),
            Some(data),
            "canonical input must re-encode to itself"
        );
    }
    if let Ok(bytes) = again {
        let (v2, violation2) = decode(&bytes, Limits::BODY).expect("a re-encoding decodes");
        assert!(violation2.is_none(), "a re-encoding is canonical");
        assert_eq!(
            encode(&v2).ok(),
            Some(bytes),
            "re-encoding is a fixed point"
        );
    }
});
