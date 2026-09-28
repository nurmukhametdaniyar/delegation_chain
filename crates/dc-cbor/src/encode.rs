//! Canonical encoder (SPEC §4.2): shortest arguments, definite lengths, map
//! keys in canonical order, no duplicates.

use crate::MAX_DEPTH;
use crate::error::EncodeError;
use crate::value::{INT_MAX, INT_MIN, Key, Value};

/// Encodes `v` canonically.
pub fn encode(v: &Value) -> Result<Vec<u8>, EncodeError> {
    let mut out = Vec::new();
    encode_into(v, &mut out)?;
    Ok(out)
}

/// Appends the canonical encoding of `v` to `out`. On error, `out` may hold a
/// partial encoding.
pub fn encode_into(v: &Value, out: &mut Vec<u8>) -> Result<(), EncodeError> {
    item(v, out, 1)
}

pub(crate) fn head(out: &mut Vec<u8>, major: u8, arg: u64) {
    let m = major << 5;
    if arg < 24 {
        out.push(m | arg as u8);
    } else if arg <= 0xff {
        out.push(m | 24);
        out.push(arg as u8);
    } else if arg <= 0xffff {
        out.push(m | 25);
        out.extend_from_slice(&(arg as u16).to_be_bytes());
    } else if arg <= 0xffff_ffff {
        out.push(m | 26);
        out.extend_from_slice(&(arg as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&arg.to_be_bytes());
    }
}

fn key(k: &Key, out: &mut Vec<u8>) {
    match k {
        Key::Uint(n) => head(out, 0, *n),
        Key::Text(s) => {
            head(out, 3, s.len() as u64);
            out.extend_from_slice(s.as_bytes());
        }
    }
}

/// `depth` counts enclosing containers, the item itself included when it is
/// one; containers deeper than [`MAX_DEPTH`] are refused.
fn item(v: &Value, out: &mut Vec<u8>, depth: usize) -> Result<(), EncodeError> {
    match v {
        Value::Int(n) => {
            if *n >= 0 {
                if *n > INT_MAX {
                    return Err(EncodeError::IntOutOfRange(*n));
                }
                head(out, 0, *n as u64);
            } else {
                if *n < INT_MIN {
                    return Err(EncodeError::IntOutOfRange(*n));
                }
                head(out, 1, (-1 - *n) as u64);
            }
        }
        Value::Bytes(b) => {
            head(out, 2, b.len() as u64);
            out.extend_from_slice(b);
        }
        Value::Text(s) => {
            head(out, 3, s.len() as u64);
            out.extend_from_slice(s.as_bytes());
        }
        Value::Array(a) => {
            if depth > MAX_DEPTH {
                return Err(EncodeError::TooDeep);
            }
            head(out, 4, a.len() as u64);
            for x in a {
                item(x, out, depth + 1)?;
            }
        }
        Value::Map(m) => {
            if depth > MAX_DEPTH {
                return Err(EncodeError::TooDeep);
            }
            head(out, 5, m.len() as u64);
            if m.windows(2).all(|w| w[0].0 < w[1].0) {
                for (k, x) in m {
                    key(k, out);
                    item(x, out, depth + 1)?;
                }
            } else {
                let mut sorted: Vec<&(Key, Value)> = m.iter().collect();
                sorted.sort_by(|a, b| a.0.cmp(&b.0));
                if sorted.windows(2).any(|w| w[0].0 == w[1].0) {
                    return Err(EncodeError::DuplicateKey);
                }
                for (k, x) in sorted {
                    key(k, out);
                    item(x, out, depth + 1)?;
                }
            }
        }
        Value::Bool(false) => out.push(0xf4),
        Value::Bool(true) => out.push(0xf5),
        Value::Null => out.push(0xf6),
    }
    Ok(())
}
