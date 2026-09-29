//! Issuer, signing service, approval service and chain builder (paper §3.1,
//! §4.1–§4.5; SPEC §8), plus a deterministic `World` of organizations for
//! tests and workloads.

mod builder;
mod services;
pub mod world;

use dc_types::{BuildError, Principal};
use thiserror::Error;

pub use builder::{Chain, ChainBuilder, assemble, combine};
pub use services::{
    APPROVAL_WINDOW, AcceptAll, ApprovalService, EnforcementPolicy, IssuanceService, Issued,
    Signed, SigningService, raw,
};
pub use world::World;

#[derive(Debug, Error)]
pub enum ChainError {
    #[error("a signing service signs delegation and invocation bodies only")]
    NotAgentBody,
    #[error("the body does not name this signing service's agent and key as signer")]
    NotMyBody,
    #[error("the signing service's enforcement policy refused: {0}")]
    Enforcement(String),
    #[error("the holder's scope denies this invocation")]
    Denied,
    #[error("no approval service available for {0}")]
    NoApprover(Principal),
    #[error("bodies and keys differ in number, or there are none")]
    CountMismatch,
    #[error("encoding: {0}")]
    Build(#[from] BuildError),
    #[error("registry: {0}")]
    Registry(#[from] dc_registry::RegistryError),
}
