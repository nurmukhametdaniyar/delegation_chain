//! Field converters for `dc_cbor::schema::Fields`. Each returns `None` when
//! the value has the wrong type or shape, which the reader reports as a
//! malformed field.

use dc_cbor::Value;

use crate::ident::{Identifier, Principal};

pub(crate) fn u64_of(v: &Value) -> Option<u64> {
    v.as_u64()
}

pub(crate) fn bytes_n(v: &Value, n: usize) -> Option<Vec<u8>> {
    v.as_bytes().filter(|b| b.len() == n).map(<[u8]>::to_vec)
}

pub(crate) fn arr16(v: &Value) -> Option<[u8; 16]> {
    v.as_bytes()?.try_into().ok()
}

pub(crate) fn arr32(v: &Value) -> Option<[u8; 32]> {
    v.as_bytes()?.try_into().ok()
}

/// Principal grammar only. Whether the kind component suits the position is
/// decided by the certificate checks of lines 26 and 42, and by line 8 for
/// `aud` (D-51).
pub(crate) fn principal(v: &Value) -> Option<Principal> {
    Principal::parse(v.as_text()?).ok()
}

pub(crate) fn identifier(v: &Value) -> Option<Identifier> {
    Identifier::new(v.as_text()?).ok()
}
