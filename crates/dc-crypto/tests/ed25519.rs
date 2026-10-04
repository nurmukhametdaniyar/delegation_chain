//! SPEC §11.1, `dc-crypto`, Ed25519 (VARIANT, SPEC §5.8). Built only with
//! `variant-ed25519`.

use dc_crypto::{CryptoError, Dst, Ed25519, SigScheme};

fn msg(i: u8) -> [u8; 32] {
    [i; 32]
}

#[test]
fn sign_verify_round_trip() {
    let sk = Ed25519::keygen(&[1; 32]);
    let pk = Ed25519::public_key(&sk);
    let sig = Ed25519::sign(&sk, &msg(1), Dst::Chain);
    assert!(Ed25519::verify(&pk, &msg(1), Dst::Chain, &sig));
    assert!(!Ed25519::verify(&pk, &msg(2), Dst::Chain, &sig));
    let other = Ed25519::public_key(&Ed25519::keygen(&[2; 32]));
    assert!(!Ed25519::verify(&other, &msg(1), Dst::Chain, &sig));
}

#[test]
fn dst_is_ignored() {
    // Ed25519 has no DSTs; purposes are separated by digest tags (D-07).
    let sk = Ed25519::keygen(&[3; 32]);
    let pk = Ed25519::public_key(&sk);
    let sig = Ed25519::sign(&sk, &msg(1), Dst::Cert);
    for dst in Dst::ALL {
        assert!(Ed25519::verify(&pk, &msg(1), dst, &sig));
    }
}

#[test]
fn bytes_round_trip() {
    let sk = Ed25519::keygen(&[4; 32]);
    let pk = Ed25519::public_key(&sk);
    assert_eq!(Ed25519::pk_from_bytes(&Ed25519::pk_bytes(&pk)).unwrap(), pk);
    let sig = Ed25519::sign(&sk, &msg(1), Dst::Chain);
    assert_eq!(
        Ed25519::sig_from_bytes(&Ed25519::sig_bytes(&sig)).unwrap(),
        sig
    );
    assert_eq!(
        Ed25519::pk_from_bytes(&[0; 31]).unwrap_err(),
        CryptoError::BadLength {
            expected: 32,
            got: 31
        }
    );
    assert_eq!(
        Ed25519::sig_from_bytes(&[0; 65]).unwrap_err(),
        CryptoError::BadLength {
            expected: 64,
            got: 65
        }
    );
}

#[test]
fn rejects_weak_keys() {
    // The identity (y = 1) and the order-4 point y = 0 are small-order.
    let mut identity = [0u8; 32];
    identity[0] = 1;
    assert_eq!(
        Ed25519::pk_from_bytes(&identity).unwrap_err(),
        CryptoError::WeakKey
    );
    assert_eq!(
        Ed25519::pk_from_bytes(&[0u8; 32]).unwrap_err(),
        CryptoError::WeakKey
    );
}

#[test]
fn rejects_non_decompressible_keys() {
    let mut rejected = 0;
    for y in 2u8..=40 {
        let mut b = [0u8; 32];
        b[0] = y;
        if ed25519_dalek::VerifyingKey::from_bytes(&b).is_err() {
            assert_eq!(
                Ed25519::pk_from_bytes(&b).unwrap_err(),
                CryptoError::BadEncoding
            );
            rejected += 1;
        }
    }
    assert!(rejected > 0);
}

/// Paper §4.7 (D-81): s + ℓ is rejected at decode. Before the 2026-10-04
/// reconciliation this test decoded it and expected strict verification to
/// reject it; it now checks both, the second through dalek's unchecked
/// constructor.
#[test]
fn non_canonical_s_is_rejected_at_decode_and_by_strict_verification() {
    let sk = Ed25519::keygen(&[5; 32]);
    let pk = Ed25519::public_key(&sk);
    let sig = Ed25519::sign(&sk, &msg(1), Dst::Chain);
    let mut b = Ed25519::sig_bytes(&sig);
    // s + ℓ, where ℓ = 2^252 + 27742317777372353535851937790883648493
    // (little-endian). Same value mod ℓ, non-canonical encoding.
    const L: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];
    let mut carry = 0u16;
    for i in 0..32 {
        let t = u16::from(b[32 + i]) + u16::from(L[i]) + carry;
        b[32 + i] = t as u8;
        carry = t >> 8;
    }
    assert_eq!(carry, 0, "s + ℓ fits in 32 bytes for a reduced s");
    assert!(matches!(
        Ed25519::sig_from_bytes(&b),
        Err(dc_crypto::CryptoError::BadEncoding)
    ));
    let unchecked = ed25519_dalek::Signature::from_bytes(&b.try_into().unwrap());
    assert!(!Ed25519::verify(&pk, &msg(1), Dst::Chain, &unchecked));
}
