use std::fmt::Debug;

use crate::{CryptoError, Dst};

/// A single-signature scheme over 32-byte digests (SPEC §5.4). Values of
/// `PublicKey` and `Signature` are always validated: they come from
/// [`SigScheme::public_key`], [`SigScheme::sign`], or the `*_from_bytes`
/// functions, which perform every check SPEC §5.3 requires (D-05, D-30).
/// Implementors are zero-sized markers; the supertraits let generic types
/// over a scheme derive the usual traits.
pub trait SigScheme:
    'static + Send + Sync + Sized + Clone + Copy + Debug + Default + PartialEq + Eq
{
    const NAME: &'static str;
    const PK_LEN: usize;
    const SIG_LEN: usize;

    type SecretKey: Send + Sync;
    type PublicKey: Clone + Debug + PartialEq + Send + Sync;
    type Signature: Clone + Debug + PartialEq + Send + Sync;

    /// Deterministic key generation from 32 bytes of seed material.
    fn keygen(ikm: &[u8; 32]) -> Self::SecretKey;
    fn public_key(sk: &Self::SecretKey) -> Self::PublicKey;
    fn sign(sk: &Self::SecretKey, msg: &[u8; 32], dst: Dst) -> Self::Signature;
    /// Verifies with already-validated inputs; no point is re-checked.
    fn verify(pk: &Self::PublicKey, msg: &[u8; 32], dst: Dst, sig: &Self::Signature) -> bool;

    fn pk_bytes(pk: &Self::PublicKey) -> Vec<u8>;
    /// Parses and fully validates a public key: exact length, compressed
    /// form, on the curve, in the subgroup, not the identity or weak.
    fn pk_from_bytes(bytes: &[u8]) -> Result<Self::PublicKey, CryptoError>;
    fn sig_bytes(sig: &Self::Signature) -> Vec<u8>;
    /// Parses and fully validates a signature (D-30).
    fn sig_from_bytes(bytes: &[u8]) -> Result<Self::Signature, CryptoError>;
}

/// The `sigs` element of the chain envelope (SPEC §7.5), before the arm
/// interprets it: one byte string (arms A, B) or a list (the others).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WireForm {
    Single(Vec<u8>),
    List(Vec<Vec<u8>>),
}

/// How the N+1 chain signatures are carried and checked (SPEC §5.1, §12).
pub trait ChainScheme:
    'static + Send + Sync + Sized + Clone + Copy + Debug + Default + PartialEq + Eq
{
    type Base: SigScheme;
    /// What the envelope carries, validated.
    type WireSigs: Clone + Debug + Send + Sync;

    /// The wire signatures after σ_0 alone.
    fn start(sig0: <Self::Base as SigScheme>::Signature) -> Self::WireSigs;
    /// Adds σ_k to the running aggregate, or appends it to the list.
    fn accumulate(acc: &mut Self::WireSigs, sig: <Self::Base as SigScheme>::Signature);
    /// Algorithm 2 line 49, over the pairs `(pks[k], msgs[k])`. Does **not**
    /// check that the messages are distinct; that is line 48 (SPEC §5.6).
    fn verify_chain(
        pks: &[&<Self::Base as SigScheme>::PublicKey],
        msgs: &[[u8; 32]],
        sigs: &Self::WireSigs,
    ) -> bool;
    fn to_wire(sigs: &Self::WireSigs) -> WireForm;
    /// Parses and validates the wire form for a chain of `n_bodies` bodies.
    fn from_wire(form: &WireForm, n_bodies: usize) -> Result<Self::WireSigs, CryptoError>;
}
