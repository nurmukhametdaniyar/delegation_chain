//! Signature schemes (SPEC §5).
//!
//! [`SigScheme`] is a single-signature scheme: sign, verify, and validated
//! encodings of keys and signatures. [`ChainScheme`] says how a chain's N+1
//! signatures travel and are checked at Algorithm 2 line 49. SPEC §5.1
//! sketches one trait; splitting it lets certificates, receipts, PoP and
//! revocations use the instantiation's base scheme directly (D-52).
//!
//! The protocol's default instantiation is [`Ed25519`] with [`Ed25519List`]:
//! one strict Ed25519 signature per hop (paper §4.2, §4.6; D-80). The BLS
//! aggregate variant (paper §4.8), `Bls` with `BlsAggregate`, is a VARIANT,
//! compiled only with the `variant-bls` feature (SPEC §0 rule 3), as is
//! `blst` itself. The other chain schemes (A-ind, C-batch) live in
//! `dc-baselines`. The prefix-cache trait and arm B's pairing cache (SPEC
//! §5.7, §12.1) are VARIANTs too, behind `variant-prefix`.

#[cfg(feature = "variant-bls")]
mod bls;
mod dst;
mod ed25519;
mod error;
pub mod list;
pub mod ops;
#[cfg(all(feature = "variant-prefix", feature = "variant-bls"))]
pub mod pairing_cache;
pub mod phases;
#[cfg(feature = "variant-prefix")]
mod prefix;
mod scheme;

#[cfg(feature = "variant-bls")]
pub use bls::{Bls, BlsAggregate};
pub use dst::Dst;
pub use ed25519::{Ed25519, Ed25519List};
pub use error::CryptoError;
#[cfg(feature = "variant-prefix")]
pub use prefix::PrefixScheme;
pub use scheme::{ChainScheme, SigScheme, WireForm};

/// Re-export for the pairing cache of arm B (SPEC §5.7), so that no other
/// crate depends on `blst` directly and the threading mode stays under this
/// crate's control (D-29).
#[cfg(feature = "variant-bls")]
pub use blst;

/// True when this build of `blst` runs `aggregate_verify` on its thread pool,
/// i.e. without the `blst-no-threads` feature. Only the supplementary arm A-mt
/// may be measured with a build where this is true (D-29).
#[cfg(feature = "variant-bls")]
pub const BLST_THREADED: bool = !cfg!(feature = "blst-no-threads");
