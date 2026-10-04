//! D-66: arm C checks each chain signature with `verify_strict`; arm C-batch
//! checks them all with `verify_batch`. The two differ at the edges.
//! `verify_batch` is cofactorless, takes its random coefficients from a
//! transcript of the inputs, and does not reject a small-order R. It
//! compares points rather than R's encoding.
//!
//! Every signature below needs the signer's secret key: none is a forgery
//! by a third party. But a signer can present a chain that arm C rejects and
//! arm C-batch accepts. With a mixed-order R, whether C-batch accepts
//! depends on the other signatures in the batch.

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use dc_baselines::Ed25519Batch;
use dc_crypto::{ChainScheme, Dst, Ed25519, Ed25519List, SigScheme};
use dc_types::digest::sha256;
use ed25519_dalek::{Signature, SigningKey};
use sha2::{Digest, Sha512};

fn key(label: &str) -> SigningKey {
    Ed25519::keygen(&sha256(&[b"dc-batch", label.as_bytes()]))
}

/// The point of order 2, (0, −1): y = p − 1, sign bit 0.
fn order_two() -> EdwardsPoint {
    let mut y = [0xff; 32];
    y[0] = 0xec;
    y[31] = 0x7f;
    let t = CompressedEdwardsY(y).decompress().unwrap();
    assert!(t.is_small_order() && t != EdwardsPoint::identity());
    t
}

/// A signature by `sk` on `m` whose R is `rB + t`: s = r + H(R ‖ A ‖ m)·a.
fn crafted(sk: &SigningKey, r: Scalar, t: EdwardsPoint, m: &[u8; 32]) -> Signature {
    let big_r = (EdwardsPoint::mul_base(&r) + t).compress();
    let mut h = Sha512::new();
    h.update(big_r.as_bytes());
    h.update(sk.verifying_key().as_bytes());
    h.update(m);
    let h = Scalar::from_bytes_mod_order_wide(&h.finalize().into());
    let s = r + h * sk.to_scalar();
    Signature::from_components(big_r.to_bytes(), s.to_bytes())
}

#[test]
fn a_small_order_r_is_rejected_by_c_and_accepted_by_c_batch() {
    let (issuer, agent) = (key("issuer"), key("agent"));
    let m = [sha256(&[b"m0"]), sha256(&[b"m1"])];
    let pks = [issuer.verifying_key(), agent.verifying_key()];
    let pk_refs: Vec<_> = pks.iter().collect();
    // σ_0 is honest; σ_1 has R = the identity, so s = H(R ‖ A ‖ m)·a.
    let sigs = vec![
        Ed25519::sign(&issuer, &m[0], Dst::Chain),
        crafted(&agent, Scalar::ZERO, EdwardsPoint::identity(), &m[1]),
    ];
    assert!(!Ed25519::verify(&pks[1], &m[1], Dst::Chain, &sigs[1]));
    assert!(!Ed25519List::verify_chain(&pk_refs, &m, &sigs));
    assert!(Ed25519Batch::verify_chain(&pk_refs, &m, &sigs));
}

#[test]
fn a_mixed_order_r_makes_c_batch_depend_on_the_rest_of_the_batch() {
    let (issuer, agent) = (key("issuer"), key("agent"));
    let pks = [issuer.verifying_key(), agent.verifying_key()];
    let pk_refs: Vec<_> = pks.iter().collect();
    let t = order_two();
    let m1 = sha256(&[b"m1"]);
    let sig1 = crafted(&agent, Scalar::from(7u64), t, &m1);
    assert!(!Ed25519::verify(&pks[1], &m1, Dst::Chain, &sig1));
    // The same σ_1 beside 64 different honest σ_0: C rejects every chain;
    // C-batch accepts about half, as its coefficient for σ_1 is even or odd.
    let mut accepted = 0;
    for i in 0..64u8 {
        let m = [sha256(&[b"m0", &[i]]), m1];
        let sigs = vec![Ed25519::sign(&issuer, &m[0], Dst::Chain), sig1];
        assert!(!Ed25519List::verify_chain(&pk_refs, &m, &sigs));
        if Ed25519Batch::verify_chain(&pk_refs, &m, &sigs) {
            accepted += 1;
        }
    }
    println!("C-batch accepted {accepted} of 64");
    assert!(0 < accepted && accepted < 64, "{accepted}");
}

#[test]
fn honest_and_bit_flipped_chains_agree() {
    let keys: Vec<SigningKey> = (0..6).map(|i| key(&format!("k{i}"))).collect();
    let pks: Vec<_> = keys.iter().map(SigningKey::verifying_key).collect();
    for n in 1..=6 {
        let m: Vec<[u8; 32]> = (0..n).map(|i| sha256(&[&[n as u8, i as u8]])).collect();
        let sigs: Vec<Signature> = m
            .iter()
            .zip(&keys)
            .map(|(m, k)| Ed25519::sign(k, m, Dst::Chain))
            .collect();
        let pk_refs: Vec<_> = pks[..n].iter().collect();
        assert!(Ed25519List::verify_chain(&pk_refs, &m, &sigs));
        assert!(Ed25519Batch::verify_chain(&pk_refs, &m, &sigs));
        for k in 0..n {
            for bit in [0usize, 100, 300, 511] {
                let mut bytes = sigs[k].to_bytes();
                bytes[bit / 8] ^= 1 << (bit % 8);
                let mut bad = sigs.clone();
                bad[k] = Signature::from_bytes(&bytes);
                assert_eq!(
                    Ed25519List::verify_chain(&pk_refs, &m, &bad),
                    Ed25519Batch::verify_chain(&pk_refs, &m, &bad),
                    "n {n}, signature {k}, bit {bit}"
                );
            }
        }
    }
}
