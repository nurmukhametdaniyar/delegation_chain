//! Prefix caching at line 49 (SPEC §12.1; VARIANT, arms B and D).
//!
//! A prefix-cache entry stands for the first N bodies of an accepted chain.
//! On a hit, only the last body's signature work remains; what the entry
//! keeps for that is the scheme's business. Arm B keeps the Miller-loop
//! product of the prefix pairs (SPEC §5.7). Arm D keeps the prefix's
//! verified signature bytes.

use crate::{ChainScheme, SigScheme, WireForm};

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
