use thiserror::Error;

/// Why a key, signature or wire form was rejected. When a chain or receipt
/// is decoded, every variant means malformed input, Algorithm 1 line 2 (D-30).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum CryptoError {
    #[error("expected {expected} bytes, got {got}")]
    BadLength { expected: usize, got: usize },
    #[error("invalid point encoding")]
    BadEncoding,
    #[error("point is the identity element")]
    Identity,
    #[error("point is not in the prime-order subgroup")]
    NotInSubgroup,
    #[error("weak (small-order) public key")]
    WeakKey,
    #[error("signature container has the wrong shape for this arm")]
    WireShape,
    #[error("expected {expected} signatures, got {got}")]
    SignatureCount { expected: usize, got: usize },
}
