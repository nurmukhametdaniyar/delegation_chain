//! In-memory registry, proof of possession, certificates, revocation,
//! resolution and the policy store (paper §5; SPEC §6).
//!
//! Only direct peering is modelled (SPEC §6.2): the verifier's trust
//! configuration maps each organization to its registry's root key.

mod registry;
mod resolve;
mod revocation;

pub use registry::{
    MAX_CERT_LIFETIME, POP_NONCE_TTL, Registry, RegistryError, default_lifetime, enroll,
    enroll_with_validity,
};
pub use resolve::{Directory, MemoryPolicyStore, PolicyStore, Resolver, WithLatency};
pub use revocation::{RevocationError, RevocationSet, RevokedBinding, verify_revocation};
