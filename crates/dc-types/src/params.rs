//! Invocation parameters (paper §4.4; SPEC §4.3).
//!
//! A nested map with text keys at every level. Values may be integers,
//! byte strings, text, booleans, null, arrays and maps. Text keys and text
//! values are NFC-normalized, and `Canon(params)` normalizes, so that a
//! non-NFC encoding re-encodes differently and is caught at line 5 (D-31).

use dc_cbor::nfc::{is_nfc_deep, to_nfc_deep};
use dc_cbor::{Key, Value, encode};

use crate::digest::{Digest32, params_hash};
use crate::error::{BuildError, Malformed};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Params {
    value: Value,
    /// Every text key and value is NFC. Always true for built params; for
    /// decoded params it records what the input carried.
    nfc: bool,
}

/// True if `v` is a map whose keys, at every depth (including maps inside
/// arrays), are text.
fn well_shaped(v: &Value) -> bool {
    fn inner(v: &Value) -> bool {
        match v {
            Value::Map(m) => m.iter().all(|(k, x)| matches!(k, Key::Text(_)) && inner(x)),
            Value::Array(a) => a.iter().all(inner),
            _ => true,
        }
    }
    matches!(v, Value::Map(_)) && inner(v)
}

impl Params {
    /// Builds parameters, normalizing all text to NFC. Fails if `v` is not a
    /// text-keyed map, or if normalization makes two keys of one map equal.
    pub fn new(v: Value) -> Result<Self, BuildError> {
        if !well_shaped(&v) {
            return Err(BuildError::Params(
                "not a map with text keys at every level",
            ));
        }
        Ok(Params {
            value: to_nfc_deep(&v)?,
            nfc: true,
        })
    }

    pub fn empty() -> Self {
        Params {
            value: Value::Map(vec![]),
            nfc: true,
        }
    }

    /// From a decoded body: the shape is checked (malformed otherwise); NFC
    /// is reported through [`Params::is_nfc`].
    pub(crate) fn from_decoded(v: &Value) -> Result<Self, Malformed> {
        if !well_shaped(v) {
            return Err(Malformed::Params("not a map with text keys at every level"));
        }
        Ok(Params {
            value: v.clone(),
            nfc: is_nfc_deep(v),
        })
    }

    pub fn value(&self) -> &Value {
        &self.value
    }

    pub fn is_nfc(&self) -> bool {
        self.nfc
    }

    /// The canonical form used inside the body and by `params_hash`.
    pub(crate) fn canonical_value(&self) -> Result<Value, BuildError> {
        if self.nfc {
            Ok(self.value.clone())
        } else {
            Ok(to_nfc_deep(&self.value)?)
        }
    }

    /// `Canon(params)`.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, BuildError> {
        if self.nfc {
            Ok(encode(&self.value)?)
        } else {
            Ok(encode(&to_nfc_deep(&self.value)?)?)
        }
    }

    /// `H(Canon(params))`, Algorithm 1 line 9.
    pub fn hash(&self) -> Result<Digest32, BuildError> {
        Ok(params_hash(&self.canonical_bytes()?))
    }
}
