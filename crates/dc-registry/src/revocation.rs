//! Checking revocation assertions on the verifier side (paper §5.6; SPEC
//! §6.5). An assertion revokes a binding, meaning an identifier and a key in
//! the registry's namespace (D-65, P-29). The verifier's `ingest_revocation`
//! uses this, then evicts the cache entries for that binding.

use std::collections::HashMap;

use dc_crypto::{Dst, SigScheme};
use dc_types::{Malformed, ParsedRevocation, Principal, RevocationAssertion};
use thiserror::Error;

use crate::MAX_CERT_LIFETIME;

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum RevocationError {
    #[error("malformed assertion: {0}")]
    Malformed(#[from] Malformed),
    #[error("no root key configured for organization {0}")]
    UnknownOrg(String),
    #[error("assertion signature does not verify under the organization's root")]
    BadSignature,
    #[error("the revoked identifier is outside the registry's namespace")]
    Namespace,
}

/// A verified revocation: the binding it revokes, and the audit fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevokedBinding {
    pub registry: String,
    pub identifier: Principal,
    pub pk: Vec<u8>,
    pub serial: u64,
    pub revoked_at: u64,
}

/// Verifies `assertion` under the root the verifier holds for the
/// organization it names. The revoked identifier must be in that
/// organization's namespace.
pub fn verify_revocation<'a, S: SigScheme>(
    assertion: &RevocationAssertion,
    root_of: impl Fn(&str) -> Option<&'a S::PublicKey>,
) -> Result<RevokedBinding, RevocationError> {
    let parsed = ParsedRevocation::<S>::decode(assertion)?;
    let org = parsed.body.registry_id.as_str();
    let root = root_of(org).ok_or_else(|| RevocationError::UnknownOrg(org.to_owned()))?;
    if !S::verify(root, &parsed.message(), Dst::Revoke, &parsed.sig) {
        return Err(RevocationError::BadSignature);
    }
    if parsed.body.identifier.org() != org {
        return Err(RevocationError::Namespace);
    }
    Ok(RevokedBinding {
        registry: org.to_owned(),
        identifier: parsed.body.identifier,
        pk: parsed.body.pk,
        serial: parsed.body.serial,
        revoked_at: parsed.body.revoked_at,
    })
}

/// The revoked bindings a verifier has learned, keyed by identifier, then
/// key and registry, with the revocation time.
#[derive(Clone, Debug, Default)]
pub struct RevocationSet {
    revoked: HashMap<String, Vec<(Vec<u8>, String, u64)>>,
}

impl RevocationSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Verifies and records an assertion.
    pub fn ingest<'a, S: SigScheme>(
        &mut self,
        assertion: &RevocationAssertion,
        root_of: impl Fn(&str) -> Option<&'a S::PublicKey>,
    ) -> Result<RevokedBinding, RevocationError> {
        let b = verify_revocation::<S>(assertion, root_of)?;
        self.insert(&b);
        Ok(b)
    }

    pub fn insert(&mut self, b: &RevokedBinding) {
        let entries = self
            .revoked
            .entry(b.identifier.as_str().to_owned())
            .or_default();
        if !entries
            .iter()
            .any(|(pk, reg, _)| *pk == b.pk && *reg == b.registry)
        {
            entries.push((b.pk.clone(), b.registry.clone(), b.revoked_at));
        }
    }

    /// Is the binding (registry, identifier, key) revoked?
    pub fn is_revoked(&self, registry: &str, identifier: &Principal, pk: &[u8]) -> bool {
        self.revoked.get(identifier.as_str()).is_some_and(|v| {
            v.iter()
                .any(|(k, reg, _)| k.as_slice() == pk && reg == registry)
        })
    }

    /// Forgets revocations older than the maximum certificate lifetime. A
    /// certificate issued no later than the revocation expires no later than
    /// `revoked_at + MAX_CERT_LIFETIME`, and is valid through that instant
    /// (closed interval, D-35), so a record is kept through it. After that,
    /// every certificate for the binding has expired, and the registry
    /// certifies it no more (D-65).
    pub fn forget_before(&mut self, t: u64) {
        for v in self.revoked.values_mut() {
            v.retain(|(_, _, at)| at.saturating_add(MAX_CERT_LIFETIME) >= t);
        }
        self.revoked.retain(|_, v| !v.is_empty());
    }

    pub fn len(&self) -> usize {
        self.revoked.values().map(Vec::len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.revoked.is_empty()
    }
}
