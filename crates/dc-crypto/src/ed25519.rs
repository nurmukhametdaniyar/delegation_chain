//! Ed25519 via `ed25519-dalek` (SPEC §5.8). VARIANT: arms C, C-batch, D.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::{CryptoError, Dst, SigScheme};

/// Ed25519 single signatures: 32-byte keys, 64-byte signatures.
///
/// Ed25519 has no domain-separation tags. The `dst` argument is ignored, and
/// the per-structure digest tags of D-07 separate purposes instead. Strict
/// verification (`verify_strict`) rejects weak keys and non-canonical
/// signatures itself; decoding a signature checks only its length, so each
/// point is still examined exactly once (D-30).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ed25519;

impl SigScheme for Ed25519 {
    const NAME: &'static str = "Ed25519";
    const PK_LEN: usize = 32;
    const SIG_LEN: usize = 64;

    type SecretKey = SigningKey;
    type PublicKey = VerifyingKey;
    type Signature = Signature;

    fn keygen(ikm: &[u8; 32]) -> SigningKey {
        SigningKey::from_bytes(ikm)
    }

    fn public_key(sk: &SigningKey) -> VerifyingKey {
        sk.verifying_key()
    }

    fn sign(sk: &SigningKey, msg: &[u8; 32], _dst: Dst) -> Signature {
        sk.sign(msg)
    }

    fn verify(pk: &VerifyingKey, msg: &[u8; 32], _dst: Dst, sig: &Signature) -> bool {
        crate::ops::add(|c| c.sig_verifications += 1);
        pk.verify_strict(msg, sig).is_ok()
    }

    fn pk_bytes(pk: &VerifyingKey) -> Vec<u8> {
        pk.to_bytes().to_vec()
    }

    fn pk_from_bytes(bytes: &[u8]) -> Result<VerifyingKey, CryptoError> {
        let arr: &[u8; 32] = bytes.try_into().map_err(|_| CryptoError::BadLength {
            expected: 32,
            got: bytes.len(),
        })?;
        let pk = VerifyingKey::from_bytes(arr).map_err(|_| CryptoError::BadEncoding)?;
        // The Ed25519 counterpart of rejecting the identity (SPEC §5.3).
        if pk.is_weak() {
            return Err(CryptoError::WeakKey);
        }
        Ok(pk)
    }

    fn sig_bytes(sig: &Signature) -> Vec<u8> {
        sig.to_bytes().to_vec()
    }

    fn sig_from_bytes(bytes: &[u8]) -> Result<Signature, CryptoError> {
        let arr: &[u8; 64] = bytes.try_into().map_err(|_| CryptoError::BadLength {
            expected: 64,
            got: bytes.len(),
        })?;
        Ok(Signature::from_bytes(arr))
    }
}
