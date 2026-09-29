//! Resolution and policy storage (paper §5.4; SPEC §6.6). Both are
//! in-process, behind traits, with optional injected latency for the cold-path
//! experiments of SPEC §13.4 (no network code, SPEC §0 rule 12).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use dc_types::digest::{Digest32, policy_hash};
use dc_types::{Certificate, Principal};

/// Certificate resolution by identifier **and** key (Algorithm 1 line 23).
pub trait Resolver: Send + Sync {
    /// The most recently issued certificate binding `id` to `pk`, valid or
    /// not (D-26); `None` if there is none.
    fn resolve(&self, id: &Principal, pk: &[u8], t: u64) -> Option<Certificate>;
}

/// Content-addressed policy retrieval (paper §5.4). The store is not trusted
/// for integrity: the verifier checks the hash and well-formedness (D-12).
pub trait PolicyStore: Send + Sync {
    fn load(&self, policy_hash: &Digest32) -> Option<Vec<u8>>;
}

impl<R: Resolver + ?Sized> Resolver for Arc<R> {
    fn resolve(&self, id: &Principal, pk: &[u8], t: u64) -> Option<Certificate> {
        (**self).resolve(id, pk, t)
    }
}

impl<R: Resolver + ?Sized> Resolver for &R {
    fn resolve(&self, id: &Principal, pk: &[u8], t: u64) -> Option<Certificate> {
        (**self).resolve(id, pk, t)
    }
}

impl<P: PolicyStore + ?Sized> PolicyStore for Arc<P> {
    fn load(&self, h: &Digest32) -> Option<Vec<u8>> {
        (**self).load(h)
    }
}

impl<P: PolicyStore + ?Sized> PolicyStore for &P {
    fn load(&self, h: &Digest32) -> Option<Vec<u8>> {
        (**self).load(h)
    }
}

/// Routes each lookup to the registry of the identifier's organization, as a
/// verifier queries "the issuing registry's resolution endpoint" (paper §5.4).
#[derive(Default)]
pub struct Directory {
    by_org: HashMap<String, Arc<dyn Resolver>>,
}

impl Directory {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, org: &str, resolver: Arc<dyn Resolver>) {
        self.by_org.insert(org.to_owned(), resolver);
    }
}

impl Resolver for Directory {
    fn resolve(&self, id: &Principal, pk: &[u8], t: u64) -> Option<Certificate> {
        self.by_org.get(id.org())?.resolve(id, pk, t)
    }
}

/// An in-memory policy store, keyed by SHA-256 of the stored bytes.
#[derive(Default)]
pub struct MemoryPolicyStore {
    docs: RwLock<HashMap<Digest32, Vec<u8>>>,
}

impl MemoryPolicyStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Stores a canonically encoded policy and returns its hash.
    pub fn put(&self, canonical_policy: Vec<u8>) -> Digest32 {
        let h = policy_hash(&canonical_policy);
        self.docs.write().unwrap().insert(h, canonical_policy);
        h
    }

    /// Stores arbitrary bytes under an arbitrary hash: a store that serves
    /// the wrong document or a malformed one (SPEC §11.2, T2b line 31).
    pub fn put_unchecked(&self, hash: Digest32, bytes: Vec<u8>) {
        self.docs.write().unwrap().insert(hash, bytes);
    }
}

impl PolicyStore for MemoryPolicyStore {
    fn load(&self, h: &Digest32) -> Option<Vec<u8>> {
        self.docs.read().unwrap().get(h).cloned()
    }
}

/// Wraps a resolver or policy store with a fixed delay per call, and counts
/// calls (SPEC §6.6, §13.4).
pub struct WithLatency<T> {
    inner: T,
    delay: Duration,
    calls: AtomicU64,
}

impl<T> WithLatency<T> {
    pub fn new(inner: T, delay: Duration) -> Self {
        WithLatency {
            inner,
            delay,
            calls: AtomicU64::new(0),
        }
    }

    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::Relaxed)
    }

    fn enter(&self) {
        self.calls.fetch_add(1, Ordering::Relaxed);
        if !self.delay.is_zero() {
            std::thread::sleep(self.delay);
        }
    }
}

impl<R: Resolver> Resolver for WithLatency<R> {
    fn resolve(&self, id: &Principal, pk: &[u8], t: u64) -> Option<Certificate> {
        self.enter();
        self.inner.resolve(id, pk, t)
    }
}

impl<P: PolicyStore> PolicyStore for WithLatency<P> {
    fn load(&self, h: &Digest32) -> Option<Vec<u8>> {
        self.enter();
        self.inner.load(h)
    }
}
