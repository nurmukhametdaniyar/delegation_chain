//! Error types. Decoding failures fall into the two classes of SPEC §4.4 and
//! D-31: [`DecodeError`] is malformed input (Algorithm 1 line 2), and
//! [`CanonViolation`] is a valid value encoded non-canonically (line 5).

use thiserror::Error;

/// Malformed input. Offsets are byte positions in the decoded buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum DecodeError {
    #[error("input truncated at byte {0}")]
    Truncated(usize),
    #[error("trailing bytes after the top-level item, from byte {0}")]
    TrailingBytes(usize),
    #[error("input of {len} bytes exceeds the limit of {limit} (D-03)")]
    TooLarge { len: usize, limit: usize },
    #[error("nesting deeper than {limit} at byte {offset} (D-02)")]
    TooDeep { limit: usize, offset: usize },
    #[error("tag at byte {0} (tags are not allowed, paper §4.4, §4.7)")]
    Tag(usize),
    #[error("floating-point value at byte {0}")]
    Float(usize),
    #[error("disallowed simple value at byte {0}")]
    Simple(usize),
    #[error("reserved additional-information value at byte {0}")]
    Reserved(usize),
    #[error("indefinite length on an integer at byte {0}")]
    IndefiniteInteger(usize),
    #[error("break code outside an indefinite-length item at byte {0}")]
    UnexpectedBreak(usize),
    #[error("invalid chunk inside an indefinite-length string at byte {0}")]
    BadChunk(usize),
    #[error("invalid UTF-8 in a text string at byte {0}")]
    InvalidUtf8(usize),
    #[error("duplicate map key at byte {0}")]
    DuplicateKey(usize),
    #[error("map key of a disallowed type at byte {0} (D-49)")]
    KeyType(usize),
}

/// A canonical-form violation (RFC 8949 §4.2.1 and paper §4.4).
/// Offsets are byte positions of the offending head; `NonNfc` is reported by
/// the caller that knows which maps are parameter maps.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum CanonViolation {
    #[error("argument not in shortest form at byte {0}")]
    NonShortest(usize),
    #[error("indefinite length at byte {0}")]
    Indefinite(usize),
    #[error("map keys not in canonical order at byte {0}")]
    UnsortedKeys(usize),
    #[error("text in a parameter map is not NFC-normalized")]
    NonNfc,
}

/// Failure of [`crate::decode_strict`], which rejects both classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum StrictError {
    #[error("malformed: {0}")]
    Malformed(#[from] DecodeError),
    #[error("non-canonical: {0}")]
    NonCanonical(#[from] CanonViolation),
}

/// A value the encoder refuses to write, because the decoder would reject
/// the result or no canonical form exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum EncodeError {
    #[error("integer {0} is outside the CBOR range")]
    IntOutOfRange(i128),
    #[error("duplicate map key")]
    DuplicateKey,
    #[error("nesting deeper than the limit (D-02)")]
    TooDeep,
}
