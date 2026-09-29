//! A deterministic set of organizations, registries, keys and policies,
//! for tests and benchmark workloads. Every key is derived from the world
//! seed and a label, so the same seed always gives the same world.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use dc_crypto::SigScheme;
use dc_policy::Scope;
use dc_registry::{Directory, MemoryPolicyStore, Registry, enroll, enroll_with_validity};
use dc_types::digest::{Digest32, sha256};
use dc_types::{Certificate, Clock, Identifier, ManualClock, Principal};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use crate::ChainError;
use crate::services::{ApprovalService, IssuanceService, SigningService};

pub type WorldRegistry<S> = Registry<S, Arc<ManualClock>>;

pub struct World<S: SigScheme> {
    seed: u64,
    clock: Arc<ManualClock>,
    policies: Arc<MemoryPolicyStore>,
    registries: BTreeMap<String, Arc<WorldRegistry<S>>>,
    rng: ChaCha20Rng,
}

impl<S: SigScheme> World<S> {
    pub fn new(seed: u64, t0: u64) -> Self {
        World {
            seed,
            clock: Arc::new(ManualClock::new(t0)),
            policies: Arc::new(MemoryPolicyStore::new()),
            registries: BTreeMap::new(),
            rng: ChaCha20Rng::seed_from_u64(seed),
        }
    }

    pub fn clock(&self) -> Arc<ManualClock> {
        self.clock.clone()
    }

    pub fn now(&self) -> u64 {
        self.clock.now()
    }

    /// The seeded generator for nonces and session ids.
    pub fn rng(&mut self) -> &mut ChaCha20Rng {
        &mut self.rng
    }

    pub fn policies(&self) -> Arc<MemoryPolicyStore> {
        self.policies.clone()
    }

    /// The secret key for `label`, derived from the world seed.
    pub fn secret(&self, label: &str) -> S::SecretKey {
        S::keygen(&sha256(&[
            b"dc-world-key",
            &self.seed.to_le_bytes(),
            label.as_bytes(),
        ]))
    }

    pub fn pk(&self, label: &str) -> Vec<u8> {
        S::pk_bytes(&S::public_key(&self.secret(label)))
    }

    /// The registry of organization `org`, created on first use.
    pub fn org(&mut self, org: &str) -> Arc<WorldRegistry<S>> {
        if let Some(r) = self.registries.get(org) {
            return r.clone();
        }
        let root = sha256(&[b"dc-world-root", &self.seed.to_le_bytes(), org.as_bytes()]);
        let nonce_seed = u64::from_le_bytes(
            sha256(&[b"dc-world-nonce", org.as_bytes()])[..8]
                .try_into()
                .unwrap(),
        );
        let reg = Arc::new(Registry::new(
            Identifier::new(org).expect("organization identifier"),
            &root,
            self.clock.clone(),
            self.seed ^ nonce_seed,
        ));
        self.registries.insert(org.to_owned(), reg.clone());
        reg
    }

    /// Every registry's root key: the verifier's `Root[o]` (paper §5.1).
    pub fn roots(&self) -> HashMap<String, S::PublicKey> {
        self.registries
            .iter()
            .map(|(o, r)| (o.clone(), r.root_pk().clone()))
            .collect()
    }

    /// A resolver that routes to each organization's registry.
    pub fn directory(&self) -> Directory {
        let mut d = Directory::new();
        for (o, r) in &self.registries {
            d.add(o, r.clone());
        }
        d
    }

    /// Enrolls `id` under the key derived from `key_label`, with the default
    /// lifetime (D-10).
    pub fn enroll(&mut self, id: &str, key_label: &str) -> Result<Certificate, ChainError> {
        let p = Principal::parse(id).expect("principal");
        let reg = self.org(p.org());
        Ok(enroll(&*reg, &p, &self.secret(key_label))?)
    }

    /// Enrolls with an explicit validity window, for rotation and expiry
    /// tests.
    pub fn enroll_window(
        &mut self,
        id: &str,
        key_label: &str,
        nbf: u64,
        exp: u64,
    ) -> Result<Certificate, ChainError> {
        let p = Principal::parse(id).expect("principal");
        let reg = self.org(p.org());
        Ok(enroll_with_validity(
            &*reg,
            &p,
            &self.secret(key_label),
            nbf,
            exp,
        )?)
    }

    /// An enrolled agent's signing service; the key label is the identifier.
    pub fn agent(&mut self, id: &str) -> SigningService<S> {
        self.enroll(id, id).expect("enroll agent");
        self.agent_service(id, id)
    }

    /// A signing service for `id` holding the key of `key_label`, without
    /// enrolling anything.
    pub fn agent_service(&self, id: &str, key_label: &str) -> SigningService<S> {
        SigningService::new(
            Principal::parse(id).expect("principal"),
            self.secret(key_label),
        )
    }

    /// An enrolled issuance service.
    pub fn issuer(&mut self, id: &str) -> IssuanceService<S> {
        self.enroll(id, id).expect("enroll issuer");
        IssuanceService::new(Principal::parse(id).expect("principal"), self.secret(id))
    }

    /// An enrolled approval service.
    pub fn approver(&mut self, id: &str) -> ApprovalService<S> {
        self.enroll(id, id).expect("enroll approver");
        ApprovalService::new(Principal::parse(id).expect("principal"), self.secret(id))
    }

    /// Stores a policy document and returns its hash.
    pub fn publish(&self, policy: &Scope) -> Digest32 {
        self.policies.put(policy.canonical_bytes())
    }
}
