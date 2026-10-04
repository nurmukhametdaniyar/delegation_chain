//! Chain schemes of the benchmark's ablation arms (SPEC §12): N+1 BLS
//! signatures (A-ind), and arm C's wire format verified in one batch
//! (C-batch). Both carry a list, through `dc_crypto::list`. Arm C itself,
//! `dc_crypto::Ed25519List`, is the protocol's default instantiation (D-80).

use dc_crypto::list::{from_wire as list_from_wire, to_wire as list_to_wire, verify_each};
use dc_crypto::{Bls, ChainScheme, CryptoError, Ed25519, SigScheme, WireForm};

/// Arm A-ind: N+1 BLS signatures, each checked with its own pairing
/// equation. Isolates what the multi-pairing saves (SPEC §12.2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BlsIndividual;

impl ChainScheme for BlsIndividual {
    type Base = Bls;
    type WireSigs = Vec<<Bls as SigScheme>::Signature>;

    fn start(sig0: <Bls as SigScheme>::Signature) -> Self::WireSigs {
        vec![sig0]
    }

    fn accumulate(acc: &mut Self::WireSigs, sig: <Bls as SigScheme>::Signature) {
        acc.push(sig);
    }

    fn verify_chain(
        pks: &[&<Bls as SigScheme>::PublicKey],
        msgs: &[[u8; 32]],
        sigs: &Self::WireSigs,
    ) -> bool {
        verify_each::<Bls>(pks, msgs, sigs)
    }

    fn to_wire(sigs: &Self::WireSigs) -> WireForm {
        list_to_wire::<Bls>(sigs)
    }

    fn from_wire(form: &WireForm, n_bodies: usize) -> Result<Self::WireSigs, CryptoError> {
        list_from_wire::<Bls>(form, n_bodies)
    }
}

/// Arm C-batch: arm C's wire format, with one `verify_batch` at line 49.
/// Batch and strict verification differ at the edges (D-66).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ed25519Batch;

impl ChainScheme for Ed25519Batch {
    type Base = Ed25519;
    type WireSigs = Vec<<Ed25519 as SigScheme>::Signature>;

    fn start(sig0: <Ed25519 as SigScheme>::Signature) -> Self::WireSigs {
        vec![sig0]
    }

    fn accumulate(acc: &mut Self::WireSigs, sig: <Ed25519 as SigScheme>::Signature) {
        acc.push(sig);
    }

    fn verify_chain(
        pks: &[&<Ed25519 as SigScheme>::PublicKey],
        msgs: &[[u8; 32]],
        sigs: &Self::WireSigs,
    ) -> bool {
        !pks.is_empty()
            && pks.len() == msgs.len()
            && sigs.len() == msgs.len()
            && Ed25519::verify_batch(pks, msgs, sigs)
    }

    fn to_wire(sigs: &Self::WireSigs) -> WireForm {
        list_to_wire::<Ed25519>(sigs)
    }

    fn from_wire(form: &WireForm, n_bodies: usize) -> Result<Self::WireSigs, CryptoError> {
        list_from_wire::<Ed25519>(form, n_bodies)
    }
}
