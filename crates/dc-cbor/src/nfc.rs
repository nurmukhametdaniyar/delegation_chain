//! NFC rules for parameter maps (paper §4.4, SPEC §4.3). The generic decoder
//! does not know which maps are parameter maps; the caller applies these.

use unicode_normalization::{UnicodeNormalization, is_nfc};

use crate::error::EncodeError;
use crate::value::{Key, Value};

/// True if every text key and text value inside `v`, at any depth, is NFC.
pub fn is_nfc_deep(v: &Value) -> bool {
    match v {
        Value::Text(s) => is_nfc(s),
        Value::Array(a) => a.iter().all(is_nfc_deep),
        Value::Map(m) => m.iter().all(|(k, x)| {
            let key_ok = match k {
                Key::Text(s) => is_nfc(s),
                Key::Uint(_) => true,
            };
            key_ok && is_nfc_deep(x)
        }),
        Value::Int(_) | Value::Bytes(_) | Value::Bool(_) | Value::Null => true,
    }
}

fn nfc(s: &str) -> String {
    if is_nfc(s) {
        s.to_owned()
    } else {
        s.nfc().collect()
    }
}

/// Returns `v` with every text key and value NFC-normalized and every map in
/// canonical order. Fails if normalization makes two keys of one map equal.
pub fn to_nfc_deep(v: &Value) -> Result<Value, EncodeError> {
    Ok(match v {
        Value::Text(s) => Value::Text(nfc(s)),
        Value::Array(a) => Value::Array(a.iter().map(to_nfc_deep).collect::<Result<_, _>>()?),
        Value::Map(m) => Value::map(
            m.iter()
                .map(|(k, x)| {
                    let k = match k {
                        Key::Text(s) => Key::Text(nfc(s)),
                        Key::Uint(n) => Key::Uint(*n),
                    };
                    Ok((k, to_nfc_deep(x)?))
                })
                .collect::<Result<Vec<_>, EncodeError>>()?,
        )?,
        other => other.clone(),
    })
}
