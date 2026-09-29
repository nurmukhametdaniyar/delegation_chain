//! Chain schemes that carry N+1 separate signatures (SPEC §5.1, §12).

use dc_crypto::{Bls, ChainScheme, CryptoError, Dst, Ed25519, PrefixScheme, SigScheme, WireForm};

/// Parses a list of exactly `n` signatures of scheme `S`.
fn list_from_wire<S: SigScheme>(
    form: &WireForm,
    n: usize,
) -> Result<Vec<S::Signature>, CryptoError> {
    let WireForm::List(list) = form else {
        return Err(CryptoError::WireShape);
    };
    if list.len() != n {
        return Err(CryptoError::SignatureCount {
            expected: n,
            got: list.len(),
        });
    }
    list.iter().map(|b| S::sig_from_bytes(b)).collect()
}

fn list_to_wire<S: SigScheme>(sigs: &[S::Signature]) -> WireForm {
    WireForm::List(sigs.iter().map(S::sig_bytes).collect())
}

/// Checks each (key, digest, signature) triple with the base scheme's
/// single verification, stopping at the first failure, as arm C does.
fn verify_each<S: SigScheme>(
    pks: &[&S::PublicKey],
    msgs: &[[u8; 32]],
    sigs: &[S::Signature],
) -> bool {
    !pks.is_empty()
        && pks.len() == msgs.len()
        && sigs.len() == msgs.len()
        && pks
            .iter()
            .zip(msgs)
            .zip(sigs)
            .all(|((pk, m), s)| S::verify(pk, m, Dst::Chain, s))
}

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

/// Arm C: N+1 Ed25519 signatures, each checked with `verify_strict`. The
/// non-aggregating, AIP-style design (SPEC §12). Arm D is this scheme
/// behind a prefix cache.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ed25519List;

impl ChainScheme for Ed25519List {
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
        verify_each::<Ed25519>(pks, msgs, sigs)
    }

    fn to_wire(sigs: &Self::WireSigs) -> WireForm {
        list_to_wire::<Ed25519>(sigs)
    }

    fn from_wire(form: &WireForm, n_bodies: usize) -> Result<Self::WireSigs, CryptoError> {
        list_from_wire::<Ed25519>(form, n_bodies)
    }
}

/// Arm D (SPEC §12.1): an entry keeps the prefix's verified signature
/// bytes. A hit requires the received prefix signatures to be
/// byte-identical to them, and then checks σ_N alone.
impl PrefixScheme for Ed25519List {
    type PrefixState = Vec<Vec<u8>>;

    fn prefix_state(
        _pks: &[&<Ed25519 as SigScheme>::PublicKey],
        msgs: &[[u8; 32]],
        wire: &WireForm,
    ) -> Vec<Vec<u8>> {
        match wire {
            WireForm::List(list) if list.len() > msgs.len() => list[..msgs.len()].to_vec(),
            // Unreachable for an accepted chain; an empty state never matches.
            _ => vec![],
        }
    }

    fn prefix_matches(state: &Vec<Vec<u8>>, wire: &WireForm) -> bool {
        matches!(wire, WireForm::List(list)
            if !state.is_empty() && list.len() > state.len() && list[..state.len()] == state[..])
    }

    fn verify_last(
        state: &Vec<Vec<u8>>,
        pk_n: &<Ed25519 as SigScheme>::PublicKey,
        m_n: &[u8; 32],
        sigs: &Self::WireSigs,
    ) -> bool {
        sigs.len() == state.len() + 1
            && Ed25519::verify(pk_n, m_n, Dst::Chain, sigs.last().expect("N + 1 ≥ 2"))
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
