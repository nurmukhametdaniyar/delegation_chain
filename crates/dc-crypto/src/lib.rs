//! Signature schemes (SPEC §5).
//!
//! [`SigScheme`] is a single-signature scheme: sign, verify, and validated
//! encodings of keys and signatures. [`ChainScheme`] says how a chain's N+1
//! signatures travel and are checked at Algorithm 2 line 49. SPEC §5.1
//! sketches one trait; splitting it lets certificates, receipts, PoP and
//! revocations use the arm's base scheme directly (D-52).
//!
//! The protocol is [`Bls`] with [`BlsAggregate`]. Ed25519 is a VARIANT,
//! compiled only with the `variant-ed25519` feature (SPEC §0 rule 3). The
//! other chain schemes (A-ind, C, C-batch) live in `dc-baselines`. The
//! prefix-cache trait and arm B's pairing cache (SPEC §5.7, §12.1) are
//! VARIANTs too, behind `variant-prefix`.

mod bls;
mod dst;
#[cfg(feature = "variant-ed25519")]
mod ed25519;
mod error;
pub mod ops;
#[cfg(feature = "variant-prefix")]
pub mod pairing_cache;
#[cfg(feature = "variant-prefix")]
mod prefix;
mod scheme;

pub use bls::{Bls, BlsAggregate};
pub use dst::Dst;
#[cfg(feature = "variant-ed25519")]
pub use ed25519::Ed25519;
pub use error::CryptoError;
#[cfg(feature = "variant-prefix")]
pub use prefix::PrefixScheme;
pub use scheme::{ChainScheme, SigScheme, WireForm};

/// Re-export for the pairing cache of arm B (SPEC §5.7), so that no other
/// crate depends on `blst` directly and the threading mode stays under this
/// crate's control (D-29).
pub use blst;

/// True when this build of `blst` runs `aggregate_verify` on its thread pool,
/// i.e. without the `blst-no-threads` feature. Only the supplementary arm A-mt
/// may be measured with a build where this is true (D-29).
pub const BLST_THREADED: bool = !cfg!(feature = "blst-no-threads");
