//! Ed25519 via `ed25519-dalek`: the protocol's default instantiation (paper
//! §4.2, §4.7; SPEC §5.8). Every hop signs its own message, and the chain
//! carries the N+1 signatures ([`Ed25519List`]).

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::phases::{Phase, within};
use crate::{ChainScheme, CryptoError, Dst, SigScheme, WireForm, list};

/// Ed25519 single signatures: 32-byte keys, 64-byte signatures, in their
/// RFC 8032 encodings.
///
/// - **No domain-separation tags.** Ed25519 has none. The `dst` argument is
///   ignored, and the per-structure digest tags of D-07 separate purposes
///   instead (paper §5.3).
/// - **Decoding** (paper §4.7; D-81):
///   - a public key must be canonically encoded (its y below p), decompress,
///     and not be of small order;
///   - a signature must have a canonically encoded R (y below p) and a
///     canonical s (below the group order ℓ).
///
///   These are byte checks except the key's decompression, so each point is
///   still decompressed once.
/// - **Verification** is strict (`verify_strict`). It also rejects a
///   signature whose R is of small order, and a small-order key (D-30).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ed25519;

/// p = 2^255 − 19, little-endian.
const P: [u8; 32] = [
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];

/// ℓ = 2^252 + 27742317777372353535851937790883648493, little-endian.
const L: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// Whether the little-endian 256-bit `x` is below the little-endian `bound`.
fn below(x: &[u8; 32], bound: &[u8; 32]) -> bool {
    for i in (0..32).rev() {
        if x[i] != bound[i] {
            return x[i] < bound[i];
        }
    }
    false
}

/// Whether a compressed Edwards point's y coordinate (the low 255 bits) is
/// canonical, i.e. below p (RFC 8032 §5.1.3).
pub(crate) fn y_canonical(point: &[u8; 32]) -> bool {
    let mut y = *point;
    y[31] &= 0x7f;
    below(&y, &P)
}

impl Ed25519 {
    /// `ed25519_dalek::verify_batch` over the triples (SPEC §5.8; arm C-batch
    /// only). Its semantics differ from [`SigScheme::verify`]'s
    /// `verify_strict` at the edges (D-66). The keys are copied, because the
    /// library takes them by value.
    pub fn verify_batch(pks: &[&VerifyingKey], msgs: &[[u8; 32]], sigs: &[Signature]) -> bool {
        crate::ops::add(|c| c.sig_verifications += msgs.len() as u64);
        within(Phase::Signatures, || {
            let keys: Vec<VerifyingKey> = pks.iter().map(|k| **k).collect();
            let msgs: Vec<&[u8]> = msgs.iter().map(|m| &m[..]).collect();
            ed25519_dalek::verify_batch(&msgs, sigs, &keys).is_ok()
        })
    }
}

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
        within(Phase::Signatures, || pk.verify_strict(msg, sig).is_ok())
    }

    fn pk_bytes(pk: &VerifyingKey) -> Vec<u8> {
        pk.to_bytes().to_vec()
    }

    fn pk_from_bytes(bytes: &[u8]) -> Result<VerifyingKey, CryptoError> {
        let arr: &[u8; 32] = bytes.try_into().map_err(|_| CryptoError::BadLength {
            expected: 32,
            got: bytes.len(),
        })?;
        within(Phase::PointValidation, || {
            // Non-canonical encodings are rejected (paper §4.7; D-81). The
            // other non-canonical form, x = 0 with the sign bit set, is a
            // small-order point, which `is_weak` rejects below.
            if !y_canonical(arr) {
                return Err(CryptoError::BadEncoding);
            }
            let pk = VerifyingKey::from_bytes(arr).map_err(|_| CryptoError::BadEncoding)?;
            // Small-order keys, the Ed25519 counterpart of rejecting the
            // identity (paper §4.7, §5.3; SPEC §5.3).
            if pk.is_weak() {
                return Err(CryptoError::WeakKey);
            }
            Ok(pk)
        })
    }

    fn sig_bytes(sig: &Signature) -> Vec<u8> {
        sig.to_bytes().to_vec()
    }

    fn sig_from_bytes(bytes: &[u8]) -> Result<Signature, CryptoError> {
        let arr: &[u8; 64] = bytes.try_into().map_err(|_| CryptoError::BadLength {
            expected: 64,
            got: bytes.len(),
        })?;
        // Canonical R and s (paper §4.7; D-81). R's order is left to strict
        // verification, which decompresses it.
        let (r, s) = arr.split_at(32);
        let r: &[u8; 32] = r.try_into().expect("32 bytes");
        let s: &[u8; 32] = s.try_into().expect("32 bytes");
        if !y_canonical(r) || !below(s, &L) {
            return Err(CryptoError::BadEncoding);
        }
        Ok(Signature::from_bytes(arr))
    }
}

/// The default instantiation's chain scheme (paper §4.3, §4.6): N+1 Ed25519
/// signatures, one per hop, each checked with strict verification at line
/// 49. Arm C of the benchmark; arm D is this scheme behind a prefix cache.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ed25519List;

impl ChainScheme for Ed25519List {
    type Base = Ed25519;
    type WireSigs = Vec<Signature>;

    fn start(sig0: Signature) -> Self::WireSigs {
        vec![sig0]
    }

    fn accumulate(acc: &mut Self::WireSigs, sig: Signature) {
        acc.push(sig);
    }

    fn verify_chain(pks: &[&VerifyingKey], msgs: &[[u8; 32]], sigs: &Self::WireSigs) -> bool {
        list::verify_each::<Ed25519>(pks, msgs, sigs)
    }

    fn to_wire(sigs: &Self::WireSigs) -> WireForm {
        list::to_wire::<Ed25519>(sigs)
    }

    fn from_wire(form: &WireForm, n_bodies: usize) -> Result<Self::WireSigs, CryptoError> {
        list::from_wire::<Ed25519>(form, n_bodies)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_are_exact() {
        // p − 1 is canonical, p and p + 1 are not; the sign bit is ignored.
        let mut x = P;
        x[0] -= 1;
        assert!(y_canonical(&x));
        x[31] |= 0x80;
        assert!(y_canonical(&x));
        assert!(!y_canonical(&P));
        let mut x = P;
        x[0] += 1;
        assert!(!y_canonical(&x));
        // ℓ − 1 is a canonical s, ℓ is not.
        let mut s = L;
        s[0] -= 1;
        assert!(below(&s, &L));
        assert!(!below(&L, &L));
    }

    #[test]
    fn non_canonical_keys_are_ours_to_reject() {
        // A valid key whose y is small has a second encoding, y + p.
        // ed25519-dalek decompresses it to the same point, so the canonical
        // check of paper §4.7 is not redundant (D-81).
        let y = (2u8..19)
            .find(|&y| {
                let mut b = [0u8; 32];
                b[0] = y;
                Ed25519::pk_from_bytes(&b).is_ok()
            })
            .expect("a valid key with y below 19");
        let mut alias = P;
        alias[0] += y;
        assert!(VerifyingKey::from_bytes(&alias).is_ok());
        assert_eq!(
            Ed25519::pk_from_bytes(&alias),
            Err(CryptoError::BadEncoding)
        );
    }

    #[test]
    fn honest_signatures_decode() {
        let sk = Ed25519::keygen(&[7; 32]);
        for i in 0..64u8 {
            let sig = Ed25519::sign(&sk, &[i; 32], Dst::Chain);
            let back = Ed25519::sig_from_bytes(&Ed25519::sig_bytes(&sig)).unwrap();
            assert_eq!(back, sig);
        }
        let pk = Ed25519::public_key(&sk);
        assert_eq!(Ed25519::pk_from_bytes(&Ed25519::pk_bytes(&pk)).unwrap(), pk);
    }
}
