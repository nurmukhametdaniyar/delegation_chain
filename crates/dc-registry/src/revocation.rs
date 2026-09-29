//! Checking revocation assertions on the verifier side (paper §5.6; SPEC
//! §6.5). The verifier's `ingest_revocation` (M6) uses this, then evicts the
//! cache entries that depend on the serial.

use std::collections::HashSet;

use dc_crypto::{Dst, SigScheme};
use dc_types::{Malformed, ParsedRevocation, RevocationAssertion};
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum RevocationError {
    #[error("malformed assertion: {0}")]
    Malformed(#[from] Malformed),
    #[error("no root key configured for organization {0}")]
    UnknownOrg(String),
    #[error("assertion signature does not verify under the organization's root")]
    BadSignature,
}

/// Verifies `assertion` under the root the verifier holds for the
/// organization it names. Returns `(org, serial)` on success.
pub fn verify_revocation<'a, S: SigScheme>(
    assertion: &RevocationAssertion,
    root_of: impl Fn(&str) -> Option<&'a S::PublicKey>,
) -> Result<(String, u64), RevocationError> {
    let parsed = ParsedRevocation::<S>::decode(assertion)?;
    let org = parsed.body.registry_id.as_str();
    let root = root_of(org).ok_or_else(|| RevocationError::UnknownOrg(org.to_owned()))?;
    if !S::verify(root, &parsed.message(), Dst::Revoke, &parsed.sig) {
        return Err(RevocationError::BadSignature);
    }
    Ok((org.to_owned(), parsed.body.serial))
}

/// The set of revoked `(organization, serial)` pairs a verifier has learned.
#[derive(Clone, Debug, Default)]
pub struct RevocationSet {
    revoked: HashSet<(String, u64)>,
}

impl RevocationSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Verifies and records an assertion; returns the pair it revoked.
    pub fn ingest<'a, S: SigScheme>(
        &mut self,
        assertion: &RevocationAssertion,
        root_of: impl Fn(&str) -> Option<&'a S::PublicKey>,
    ) -> Result<(String, u64), RevocationError> {
        let pair = verify_revocation::<S>(assertion, root_of)?;
        self.revoked.insert(pair.clone());
        Ok(pair)
    }

    pub fn is_revoked(&self, org: &str, serial: u64) -> bool {
        self.revoked.contains(&(org.to_owned(), serial))
    }
}
