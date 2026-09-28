//! The data model of SPEC §4.1.

use std::cmp::Ordering;

use crate::error::EncodeError;

/// Smallest integer CBOR can carry (major type 1 with argument 2⁶⁴ − 1).
pub const INT_MIN: i128 = -(1i128 << 64);
/// Largest integer CBOR can carry (major type 0 with argument 2⁶⁴ − 1).
pub const INT_MAX: i128 = (1i128 << 64) - 1;

/// A map key. The protocol uses unsigned-integer keys in protocol structures
/// and text keys in parameter and declaration maps (SPEC §4.3); no other key
/// type is accepted (D-49).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Key {
    Uint(u64),
    Text(String),
}

impl Key {
    pub fn as_uint(&self) -> Option<u64> {
        match self {
            Key::Uint(n) => Some(*n),
            Key::Text(_) => None,
        }
    }

    pub fn as_text(&self) -> Option<&str> {
        match self {
            Key::Text(s) => Some(s),
            Key::Uint(_) => None,
        }
    }
}

/// Canonical key order: the bytewise order of the keys' shortest encodings
/// (RFC 8949 §4.2.1). Unsigned integers (major type 0) sort before text
/// (major type 3). Integers sort numerically, because shortest-form heads grow
/// with the value. Text sorts by length and then by bytes, because the head
/// encodes the length. `tests/props.rs` checks this against the encoder.
impl Ord for Key {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Key::Uint(a), Key::Uint(b)) => a.cmp(b),
            (Key::Uint(_), Key::Text(_)) => Ordering::Less,
            (Key::Text(_), Key::Uint(_)) => Ordering::Greater,
            (Key::Text(a), Key::Text(b)) => a
                .len()
                .cmp(&b.len())
                .then_with(|| a.as_bytes().cmp(b.as_bytes())),
        }
    }
}

impl PartialOrd for Key {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl From<u64> for Key {
    fn from(n: u64) -> Self {
        Key::Uint(n)
    }
}

impl From<&str> for Key {
    fn from(s: &str) -> Self {
        Key::Text(s.to_owned())
    }
}

impl From<String> for Key {
    fn from(s: String) -> Self {
        Key::Text(s)
    }
}

/// A CBOR value in the subset of SPEC §4.1.
///
/// Map entries keep the order they were decoded in. A decoded canonical map
/// is therefore sorted; one built through [`Value::map`] is sorted too. The
/// encoder always writes canonical order, whatever the entry order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// Integers in `[INT_MIN, INT_MAX]`.
    Int(i128),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    Map(Vec<(Key, Value)>),
    Bool(bool),
    Null,
}

impl Value {
    pub fn uint(n: u64) -> Self {
        Value::Int(i128::from(n))
    }

    pub fn text(s: impl Into<String>) -> Self {
        Value::Text(s.into())
    }

    pub fn bytes(b: impl Into<Vec<u8>>) -> Self {
        Value::Bytes(b.into())
    }

    /// Builds a map in canonical key order, rejecting duplicate keys.
    pub fn map(entries: impl IntoIterator<Item = (Key, Value)>) -> Result<Self, EncodeError> {
        let mut entries: Vec<(Key, Value)> = entries.into_iter().collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        if entries.windows(2).any(|w| w[0].0 == w[1].0) {
            return Err(EncodeError::DuplicateKey);
        }
        Ok(Value::Map(entries))
    }

    pub fn as_int(&self) -> Option<i128> {
        match self {
            Value::Int(n) => Some(*n),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::Int(n) => u64::try_from(*n).ok(),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }

    pub fn as_text(&self) -> Option<&str> {
        match self {
            Value::Text(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }

    pub fn as_map(&self) -> Option<&[(Key, Value)]> {
        match self {
            Value::Map(m) => Some(m),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Looks up a map entry. Linear, because protocol maps are small and a
    /// map decoded from non-canonical input may be unsorted.
    pub fn get(&self, key: &Key) -> Option<&Value> {
        self.as_map()?
            .iter()
            .find_map(|(k, v)| (k == key).then_some(v))
    }
}
