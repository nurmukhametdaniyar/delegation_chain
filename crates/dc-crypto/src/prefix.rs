//! Prefix caching at line 49 (SPEC §12.1; VARIANT, arms B and D).
//!
//! A prefix-cache entry stands for the first N bodies of an accepted chain.
//! On a hit, only the last body's signature work remains; what the entry
//! keeps for that is the scheme's business. Arm B keeps the Miller-loop
//! product of the prefix pairs (SPEC §5.7). Arm D keeps the prefix's
//! verified signature bytes.

use crate::{ChainScheme, Dst, Ed25519, Ed25519List, SigScheme, WireForm};

type Pk<C> = <<C as ChainScheme>::Base as SigScheme>::PublicKey;

pub trait PrefixScheme: ChainScheme {
    /// What an entry keeps to decide line 49 on a hit.
    type PrefixState: Send + Sync;

    /// Computed once, when a chain is accepted on the full path. `pks` and
    /// `msgs` are the prefix's keys and digests (positions 0 … N−1); `wire`
    /// is the accepted chain's signature container.
    fn prefix_state(pks: &[&Pk<Self>], msgs: &[[u8; 32]], wire: &WireForm) -> Self::PrefixState;

    /// Whether a received chain's signature container may use this entry.
    /// A mismatch is a cache miss, never a rejection.
    fn prefix_matches(state: &Self::PrefixState, wire: &WireForm) -> bool;

    /// Algorithm 2 line 49 on a hit, given the last body's key and digest.
    fn verify_last(
        state: &Self::PrefixState,
        pk_n: &Pk<Self>,
        m_n: &[u8; 32],
        sigs: &Self::WireSigs,
    ) -> bool;
}

/// Arm D (SPEC §12.1): an entry keeps the prefix's verified signature
/// bytes. A hit requires the received prefix signatures to be byte-identical
/// to them, and then checks σ_N alone (paper §4.3: each σ_k authenticates
/// the prefix up to hop k).
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
