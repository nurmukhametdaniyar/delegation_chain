//! The chain envelope, `[bodies: [bstr; N+1], sigs]` (SPEC §7.5).

use dc_cbor::{Limits, MAX_BODY_SIZE, MAX_DEPTH, Value, decode_strict, encode};
use dc_crypto::WireForm;

use crate::error::Malformed;

/// N ≤ 16, so at most 17 bodies (D-16).
pub const MAX_CHAIN_BODIES: usize = 17;

/// Room for the maximum number of maximum-size bodies, plus signatures. Each
/// body is checked against its own 64 KiB limit when decoded (D-03).
pub const ENVELOPE_LIMITS: Limits = Limits {
    max_depth: MAX_DEPTH,
    max_size: MAX_CHAIN_BODIES * (MAX_BODY_SIZE + 16) + MAX_CHAIN_BODIES * 128 + 64,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    /// Each body's canonical encoding, as received.
    pub bodies: Vec<Vec<u8>>,
    pub sigs: WireForm,
}

impl Envelope {
    pub fn to_bytes(&self) -> Vec<u8> {
        let sigs = match &self.sigs {
            WireForm::Single(b) => Value::bytes(b.clone()),
            WireForm::List(l) => Value::Array(l.iter().map(|b| Value::bytes(b.clone())).collect()),
        };
        encode(&Value::Array(vec![
            Value::Array(
                self.bodies
                    .iter()
                    .map(|b| Value::bytes(b.clone()))
                    .collect(),
            ),
            sigs,
        ]))
        .expect("an envelope of byte strings always encodes")
    }

    /// Algorithm 1 line 2, outer layer. The envelope must be canonical (a
    /// violation here is malformed, D-31), and may hold at most 17 bodies
    /// (D-16). Fewer than two bodies decode, and line 3 rejects them.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Malformed> {
        let v = decode_strict(bytes, ENVELOPE_LIMITS)?;
        let [bodies, sigs] = v.as_array().ok_or(Malformed::Envelope("not an array"))? else {
            return Err(Malformed::Envelope("not a two-element array"));
        };
        let bodies = bodies
            .as_array()
            .ok_or(Malformed::Envelope("bodies is not an array"))?;
        if bodies.len() > MAX_CHAIN_BODIES {
            return Err(Malformed::Envelope("more than 17 bodies (D-16)"));
        }
        let bodies = bodies
            .iter()
            .map(|b| b.as_bytes().map(<[u8]>::to_vec))
            .collect::<Option<Vec<_>>>()
            .ok_or(Malformed::Envelope("a body is not a byte string"))?;
        let sigs = match sigs {
            Value::Bytes(b) => WireForm::Single(b.clone()),
            Value::Array(a) => WireForm::List(
                a.iter()
                    .map(|s| s.as_bytes().map(<[u8]>::to_vec))
                    .collect::<Option<Vec<_>>>()
                    .ok_or(Malformed::Envelope("a signature is not a byte string"))?,
            ),
            _ => {
                return Err(Malformed::Envelope(
                    "sigs is neither a byte string nor an array",
                ));
            }
        };
        Ok(Envelope { bodies, sigs })
    }
}
