//! The nonce cache (paper §4.6, Theorem 5; SPEC §10.4, D-25).

use dashmap::DashMap;
use dashmap::mapref::entry::Entry;

/// Keyed by invoker public key and nonce; the value is the absolute time at
/// which the entry expires. One logical cache per verifier (Theorem 5).
#[derive(Default)]
pub struct NonceCache {
    map: DashMap<Vec<u8>, u64>,
}

/// The cache key: the invoker's key bytes followed by the nonce.
pub fn nonce_key(invoker_pk: &[u8], nonce: &[u8; 16]) -> Vec<u8> {
    let mut k = Vec::with_capacity(invoker_pk.len() + 16);
    k.extend_from_slice(invoker_pk);
    k.extend_from_slice(nonce);
    k
}

impl NonceCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Line 17, a lookup only. An expired entry counts as absent, and is
    /// evicted lazily, but only if it is still expired when the shard is
    /// locked.
    pub fn contains(&self, key: &[u8], t: u64) -> bool {
        let expired = match self.map.get(key) {
            None => return false,
            Some(e) if *e > t => return true,
            Some(_) => true,
        };
        if expired {
            self.map.remove_if(key, |_, e| *e <= t);
        }
        false
    }

    /// Line 50: atomic insert-if-absent, under the entry's shard lock. An
    /// expired entry counts as absent and is replaced. Returns false if an
    /// unexpired entry is already present.
    pub fn insert_if_absent(&self, key: Vec<u8>, expires_at: u64, t: u64) -> bool {
        match self.map.entry(key) {
            Entry::Occupied(mut o) => {
                if *o.get() > t {
                    false
                } else {
                    o.insert(expires_at);
                    true
                }
            }
            Entry::Vacant(v) => {
                v.insert(expires_at);
                true
            }
        }
    }

    /// The periodic sweep: removes expired entries only.
    pub fn sweep(&self, t: u64) {
        self.map.retain(|_, e| *e > t);
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}
