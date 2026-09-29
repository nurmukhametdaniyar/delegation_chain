//! SPEC §11.1, `dc-crypto`, BLS: round trips, point validation (§5.3),
//! DST separation (D-04), aggregate negatives, and the recorded behaviour
//! of `blst` (D-29, D-30).

use dc_crypto::blst::min_pk::{PublicKey, Signature};
use dc_crypto::{
    BLST_THREADED, Bls, BlsAggregate, ChainScheme, CryptoError, Dst, SigScheme, WireForm,
};

fn key(i: u8) -> (<Bls as SigScheme>::SecretKey, PublicKey) {
    let sk = Bls::keygen(&[i; 32]);
    let pk = Bls::public_key(&sk);
    (sk, pk)
}

fn msg(i: u8) -> [u8; 32] {
    let mut m = [0u8; 32];
    m[0] = i;
    m[31] = 0xa5;
    m
}

#[test]
// The constant is fixed per build; checking it in the default build is the
// point of the test.
#[allow(clippy::assertions_on_constants)]
fn default_build_is_single_threaded() {
    // D-29: this crate's default features include `blst-no-threads`.
    assert!(!BLST_THREADED);
}

#[test]
fn sign_verify_round_trip_under_every_dst() {
    let (sk, pk) = key(1);
    for dst in Dst::ALL {
        let sig = Bls::sign(&sk, &msg(7), dst);
        assert!(Bls::verify(&pk, &msg(7), dst, &sig), "{dst:?}");
        assert!(!Bls::verify(&pk, &msg(8), dst, &sig), "{dst:?}");
        let (_, other) = key(2);
        assert!(!Bls::verify(&other, &msg(7), dst, &sig), "{dst:?}");
    }
}

#[test]
fn dst_separation() {
    // A signature under one DST fails under every other (SPEC §11.1).
    let (sk, pk) = key(3);
    for a in Dst::ALL {
        let sig = Bls::sign(&sk, &msg(1), a);
        for b in Dst::ALL {
            assert_eq!(
                Bls::verify(&pk, &msg(1), b, &sig),
                a == b,
                "signed {a:?}, checked {b:?}"
            );
        }
    }
    let mut strings: Vec<&[u8]> = Dst::ALL.iter().map(|d| d.bls()).collect();
    strings.dedup();
    assert_eq!(strings.len(), 5);
    assert_eq!(
        Dst::Chain.bls(),
        b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"
    );
}

#[test]
fn keys_and_signatures_round_trip_through_bytes() {
    let (sk, pk) = key(4);
    let pk_bytes = Bls::pk_bytes(&pk);
    assert_eq!(pk_bytes.len(), Bls::PK_LEN);
    assert_eq!(Bls::pk_from_bytes(&pk_bytes).unwrap(), pk);
    let sig = Bls::sign(&sk, &msg(1), Dst::Chain);
    let sig_bytes = Bls::sig_bytes(&sig);
    assert_eq!(sig_bytes.len(), Bls::SIG_LEN);
    assert_eq!(Bls::sig_from_bytes(&sig_bytes).unwrap(), sig);
}

#[test]
fn rejects_wrong_lengths_and_uncompressed_forms() {
    let (sk, pk) = key(5);
    let uncompressed_pk = pk.serialize(); // 96 bytes
    assert_eq!(
        Bls::pk_from_bytes(&uncompressed_pk).unwrap_err(),
        CryptoError::BadLength {
            expected: 48,
            got: 96
        }
    );
    assert_eq!(
        Bls::pk_from_bytes(&[0u8; 47]).unwrap_err(),
        CryptoError::BadLength {
            expected: 48,
            got: 47
        }
    );
    let sig = Bls::sign(&sk, &msg(1), Dst::Chain);
    let uncompressed_sig = sig.serialize(); // 192 bytes
    assert_eq!(
        Bls::sig_from_bytes(&uncompressed_sig).unwrap_err(),
        CryptoError::BadLength {
            expected: 96,
            got: 192
        }
    );
    // The first 96 bytes of the uncompressed form lack the compression flag.
    assert_eq!(
        Bls::sig_from_bytes(&uncompressed_sig[..96]).unwrap_err(),
        CryptoError::BadEncoding
    );
    // Clearing the compression flag of a valid compressed key.
    let mut b = Bls::pk_bytes(&pk);
    b[0] &= 0x7f;
    assert!(Bls::pk_from_bytes(&b).is_err());
}

#[test]
fn rejects_the_identity() {
    // Compressed identity: compression and infinity flags set, all else zero.
    let mut pk = [0u8; 48];
    pk[0] = 0xc0;
    assert_eq!(Bls::pk_from_bytes(&pk).unwrap_err(), CryptoError::Identity);
    let mut sig = [0u8; 96];
    sig[0] = 0xc0;
    assert_eq!(
        Bls::sig_from_bytes(&sig).unwrap_err(),
        CryptoError::Identity
    );
    assert_eq!(
        BlsAggregate::from_wire(&WireForm::Single(sig.to_vec()), 2).unwrap_err(),
        CryptoError::Identity
    );
}

/// Finds a compressed encoding of a curve point outside the prime-order
/// subgroup. The cofactors are huge, so small x-coordinates that lie on the
/// curve essentially never land in the subgroup.
fn off_subgroup(len: usize, on_curve: impl Fn(&[u8]) -> bool) -> Vec<u8> {
    for x in 1u8..=255 {
        let mut b = vec![0u8; len];
        b[0] = 0x80;
        b[len - 1] = x;
        if on_curve(&b) {
            return b;
        }
    }
    panic!("no on-curve x found");
}

#[test]
fn rejects_points_outside_the_subgroup() {
    let pk = off_subgroup(48, |b| PublicKey::uncompress(b).is_ok());
    assert_eq!(
        Bls::pk_from_bytes(&pk).unwrap_err(),
        CryptoError::NotInSubgroup
    );
    let sig = off_subgroup(96, |b| Signature::uncompress(b).is_ok());
    assert_eq!(
        Bls::sig_from_bytes(&sig).unwrap_err(),
        CryptoError::NotInSubgroup
    );
}

#[test]
fn rejects_x_coordinates_not_on_the_curve() {
    let mut rejected = 0;
    for x in 1u8..=16 {
        let mut b = vec![0u8; 48];
        b[0] = 0x80;
        b[47] = x;
        if PublicKey::uncompress(&b).is_err() {
            assert_eq!(
                Bls::pk_from_bytes(&b).unwrap_err(),
                CryptoError::BadEncoding
            );
            rejected += 1;
        }
    }
    assert!(rejected > 0);
}

fn chain(n: u8) -> (Vec<PublicKey>, Vec<[u8; 32]>, Signature) {
    let mut pks = vec![];
    let mut msgs = vec![];
    let mut acc: Option<Signature> = None;
    for i in 0..n {
        let (sk, pk) = key(10 + i);
        let s = Bls::sign(&sk, &msg(i), Dst::Chain);
        match acc.as_mut() {
            None => acc = Some(BlsAggregate::start(s)),
            Some(a) => BlsAggregate::accumulate(a, s),
        }
        pks.push(pk);
        msgs.push(msg(i));
    }
    (pks, msgs, acc.unwrap())
}

#[test]
fn aggregate_verifies_and_rejects_every_mismatch() {
    let (pks, msgs, agg) = chain(4);
    let refs: Vec<&PublicKey> = pks.iter().collect();
    assert!(BlsAggregate::verify_chain(&refs, &msgs, &agg));

    let mut wrong_msg = msgs.clone();
    wrong_msg[2][5] ^= 1;
    assert!(!BlsAggregate::verify_chain(&refs, &wrong_msg, &agg));

    let (_, stranger) = key(99);
    let mut wrong_key = refs.clone();
    wrong_key[1] = &stranger;
    assert!(!BlsAggregate::verify_chain(&wrong_key, &msgs, &agg));

    // One signature missing from the aggregate.
    let (short_pks, short_msgs, short_agg) = chain(3);
    let short: Vec<&PublicKey> = short_pks.iter().collect();
    assert!(BlsAggregate::verify_chain(&short, &short_msgs, &short_agg));
    assert!(!BlsAggregate::verify_chain(&refs, &msgs, &short_agg));
    // An extra pair the aggregate does not cover.
    assert!(!BlsAggregate::verify_chain(&refs[..3], &msgs[..3], &agg));

    // Messages permuted against keys fail; permuting the pairs jointly does
    // not change the product, so it still verifies.
    let mut swapped = msgs.clone();
    swapped.swap(0, 1);
    assert!(!BlsAggregate::verify_chain(&refs, &swapped, &agg));
    let mut joint_pks = refs.clone();
    joint_pks.swap(0, 1);
    assert!(BlsAggregate::verify_chain(&joint_pks, &swapped, &agg));

    assert!(!BlsAggregate::verify_chain(&[], &[], &agg));
    assert!(!BlsAggregate::verify_chain(&refs, &msgs[..3], &agg));
}

#[test]
fn blst_does_not_check_message_distinctness() {
    // Recorded behaviour (SPEC §5.6, D-30): two keys sign the same message,
    // and blst's aggregate_verify accepts. Algorithm 2 line 48 is therefore
    // the only distinctness check in this implementation.
    let (sk_a, pk_a) = key(20);
    let (sk_b, pk_b) = key(21);
    let mut agg = BlsAggregate::start(Bls::sign(&sk_a, &msg(1), Dst::Chain));
    BlsAggregate::accumulate(&mut agg, Bls::sign(&sk_b, &msg(1), Dst::Chain));
    assert!(BlsAggregate::verify_chain(
        &[&pk_a, &pk_b],
        &[msg(1), msg(1)],
        &agg
    ));
}

#[test]
fn aggregate_wire_form() {
    let (pks, msgs, agg) = chain(3);
    let wire = BlsAggregate::to_wire(&agg);
    let WireForm::Single(ref b) = wire else {
        panic!("arm A carries one byte string");
    };
    assert_eq!(b.len(), 96);
    let back = BlsAggregate::from_wire(&wire, 3).unwrap();
    let refs: Vec<&PublicKey> = pks.iter().collect();
    assert!(BlsAggregate::verify_chain(&refs, &msgs, &back));
    assert_eq!(
        BlsAggregate::from_wire(&WireForm::List(vec![b.clone()]), 1).unwrap_err(),
        CryptoError::WireShape
    );
}
