//! Strict deterministic CBOR subset (SPEC §4).
//!
//! The data model is SPEC §4.1. Only unsigned-integer and text map keys are
//! accepted (D-49). Encoding follows RFC 8949 §4.2.1 core deterministic
//! encoding (SPEC §4.2).
//!
//! The decoder separates malformed input from canonical-form violations
//! (D-31):
//! - [`decode`] fails on the first malformed item, and returns the first
//!   canonical-form violation next to the value;
//! - [`decode_strict`] rejects both.
//!
//! Serde-based CBOR crates are deliberately not used: their decoders do not
//! enforce canonical form (SPEC §3.2).

mod decode;
mod encode;
mod error;
pub mod nfc;
pub mod schema;
mod value;

pub use decode::{Limits, decode, decode_strict};
pub use encode::{encode, encode_into};
pub use error::{CanonViolation, DecodeError, EncodeError, StrictError};
pub use value::{INT_MAX, INT_MIN, Key, Value};

/// Maximum container nesting (D-02).
pub const MAX_DEPTH: usize = 16;
/// Maximum encoded size of a single body or other protocol structure (D-03).
pub const MAX_BODY_SIZE: usize = 64 * 1024;
