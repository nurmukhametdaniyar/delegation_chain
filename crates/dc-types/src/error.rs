use dc_cbor::schema::SchemaError;
use dc_cbor::{DecodeError, EncodeError, StrictError};
use dc_crypto::CryptoError;
use thiserror::Error;

use crate::ident::IdentError;

/// Malformed protocol input. Inside a chain every variant is Algorithm 1
/// line 2 (`L02`); canonical-form violations are reported separately
/// (D-31).
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum Malformed {
    #[error("CBOR: {0}")]
    Cbor(#[from] DecodeError),
    #[error("non-canonical nested structure: {0}")]
    Strict(StrictError),
    #[error("schema: {0}")]
    Schema(#[from] SchemaError),
    #[error("identifier: {0}")]
    Ident(#[from] IdentError),
    #[error("key or signature: {0}")]
    Crypto(#[from] CryptoError),
    #[error("unknown body kind {0} (D-32)")]
    UnknownKind(u64),
    #[error("body kind field missing or not an unsigned integer")]
    NoKind,
    #[error("parameters: {0}")]
    Params(&'static str),
    #[error("receipts: {0} (D-34)")]
    Receipts(&'static str),
    #[error("certificate: {0}")]
    Certificate(&'static str),
    #[error("envelope: {0}")]
    Envelope(&'static str),
}

impl From<StrictError> for Malformed {
    fn from(e: StrictError) -> Self {
        match e {
            StrictError::Malformed(d) => Malformed::Cbor(d),
            nc @ StrictError::NonCanonical(_) => Malformed::Strict(nc),
        }
    }
}

/// A value that cannot be encoded canonically.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum BuildError {
    #[error("encoding: {0}")]
    Encode(#[from] EncodeError),
    #[error("parameters: {0}")]
    Params(&'static str),
    #[error("receipts: {0}")]
    Receipts(&'static str),
    #[error("identifier: {0}")]
    Ident(#[from] IdentError),
}
