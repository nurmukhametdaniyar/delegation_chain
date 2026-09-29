//! VARIANT benchmark arms (SPEC §12). Nothing here is on the protocol path.
//!
//! | Arm     | Chain scheme                    | Verifier                          |
//! | ------- | ------------------------------- | --------------------------------- |
//! | A       | `dc_crypto::BlsAggregate`       | `dc_verifier::Verifier`           |
//! | A-ind   | [`BlsIndividual`]               | `Verifier`                        |
//! | B       | `BlsAggregate`                  | `dc_verifier::PrefixVerifier`     |
//! | C       | [`Ed25519List`]                 | `Verifier`                        |
//! | C-batch | [`Ed25519Batch`]                | `Verifier`                        |
//! | D       | [`Ed25519List`]                 | `PrefixVerifier`                  |
//! | E       | Biscuit (biscuit-auth 6.0)      | [`biscuit::BiscuitArm`]           |
//!
//! A, A-ind, C and C-batch run the same generic verifier; only line 49 and
//! the base scheme's signatures differ (SPEC §12). B and D wrap that verifier
//! in a prefix cache (SPEC §12.1), with arm B's pairing cache (SPEC §5.7) in
//! `dc_crypto::pairing_cache`.

pub mod biscuit;
mod schemes;

pub use schemes::{BlsIndividual, Ed25519Batch, Ed25519List};

/// The verifier types of the arms, over any resolver, policy store and
/// clock.
pub mod arms {
    use dc_crypto::BlsAggregate;
    use dc_verifier::{PrefixVerifier, Verifier};

    use crate::{BlsIndividual, Ed25519Batch, Ed25519List};

    pub type A<R, P, K> = Verifier<BlsAggregate, R, P, K>;
    pub type AInd<R, P, K> = Verifier<BlsIndividual, R, P, K>;
    pub type B<R, P, K> = PrefixVerifier<BlsAggregate, R, P, K>;
    pub type C<R, P, K> = Verifier<Ed25519List, R, P, K>;
    pub type CBatch<R, P, K> = Verifier<Ed25519Batch, R, P, K>;
    pub type D<R, P, K> = PrefixVerifier<Ed25519List, R, P, K>;
}
