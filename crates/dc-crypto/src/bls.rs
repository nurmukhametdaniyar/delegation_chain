//! BLS12-381, minimal-pubkey-size variant, via `blst::min_pk` (SPEC §5.2).

use blst::BLST_ERROR;
use blst::min_pk::{AggregateSignature, PublicKey, SecretKey, Signature};

use crate::{ChainScheme, CryptoError, Dst, SigScheme, WireForm};

/// BLS single signatures: G1 public keys (48 bytes), G2 signatures (96 bytes).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Bls;

fn from_blst(e: BLST_ERROR) -> CryptoError {
    match e {
        // blst uses the PK variant for both keys and signatures.
        BLST_ERROR::BLST_PK_IS_INFINITY => CryptoError::Identity,
        BLST_ERROR::BLST_POINT_NOT_IN_GROUP => CryptoError::NotInSubgroup,
        _ => CryptoError::BadEncoding,
    }
}

fn check_len(bytes: &[u8], expected: usize) -> Result<(), CryptoError> {
    if bytes.len() == expected {
        Ok(())
    } else {
        Err(CryptoError::BadLength {
            expected,
            got: bytes.len(),
        })
    }
}

impl SigScheme for Bls {
    const NAME: &'static str = "BLS12-381 min-pk";
    const PK_LEN: usize = 48;
    const SIG_LEN: usize = 96;

    type SecretKey = SecretKey;
    type PublicKey = PublicKey;
    type Signature = Signature;

    fn keygen(ikm: &[u8; 32]) -> SecretKey {
        // Fails only for fewer than 32 bytes of input keying material.
        SecretKey::key_gen(ikm, &[]).expect("32 bytes of IKM")
    }

    fn public_key(sk: &SecretKey) -> PublicKey {
        sk.sk_to_pk()
    }

    fn sign(sk: &SecretKey, msg: &[u8; 32], dst: Dst) -> Signature {
        sk.sign(msg, dst.bls(), &[])
    }

    fn verify(pk: &PublicKey, msg: &[u8; 32], dst: Dst, sig: &Signature) -> bool {
        // Both points were validated when they were parsed (D-05, D-30).
        sig.verify(false, msg, dst.bls(), &[], pk, false) == BLST_ERROR::BLST_SUCCESS
    }

    fn pk_bytes(pk: &PublicKey) -> Vec<u8> {
        pk.compress().to_vec()
    }

    fn pk_from_bytes(bytes: &[u8]) -> Result<PublicKey, CryptoError> {
        // blst's from_bytes also takes the 96-byte uncompressed form; only the
        // compressed form is allowed (paper §4.7), hence the length check.
        check_len(bytes, 48)?;
        PublicKey::key_validate(bytes).map_err(from_blst)
    }

    fn sig_bytes(sig: &Signature) -> Vec<u8> {
        sig.compress().to_vec()
    }

    fn sig_from_bytes(bytes: &[u8]) -> Result<Signature, CryptoError> {
        check_len(bytes, 96)?;
        Signature::sig_validate(bytes, true).map_err(from_blst)
    }
}

/// Arm A, the paper's protocol: one 96-byte aggregate, checked with a single
/// multi-pairing (SPEC §5.5, §5.6).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BlsAggregate;

impl ChainScheme for BlsAggregate {
    type Base = Bls;
    type WireSigs = Signature;

    fn start(sig0: Signature) -> Signature {
        sig0
    }

    fn accumulate(acc: &mut Signature, sig: Signature) {
        let mut agg = AggregateSignature::from_signature(acc);
        // SPEC §5.5 asks for the group check; `sig` is a validated value, so
        // it cannot fail.
        agg.add_signature(&sig, true)
            .expect("Signature values are validated on construction");
        *acc = agg.to_signature();
    }

    fn verify_chain(pks: &[&PublicKey], msgs: &[[u8; 32]], sigs: &Signature) -> bool {
        if pks.is_empty() || pks.len() != msgs.len() {
            return false;
        }
        let msgs: Vec<&[u8]> = msgs.iter().map(|m| &m[..]).collect();
        // σ_agg was validated at decode and the keys when their certificates
        // were cached, so neither is re-checked here (D-05, D-30). blst does
        // not check message distinctness; line 48 does (SPEC §5.6).
        sigs.aggregate_verify(false, &msgs, Dst::Chain.bls(), pks, false)
            == BLST_ERROR::BLST_SUCCESS
    }

    fn to_wire(sigs: &Signature) -> WireForm {
        WireForm::Single(sigs.compress().to_vec())
    }

    fn from_wire(form: &WireForm, _n_bodies: usize) -> Result<Signature, CryptoError> {
        match form {
            WireForm::Single(b) => Bls::sig_from_bytes(b),
            WireForm::List(_) => Err(CryptoError::WireShape),
        }
    }
}
