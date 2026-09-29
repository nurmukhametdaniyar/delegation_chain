//! Nonce-cache semantics (SPEC §10.4, D-25) and certificate-cache
//! behaviour (paper §5.4, D-37).

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use dc_verifier::{NonceCache, nonce_key};

#[test]
fn lookup_is_only_a_filter_and_expired_entries_are_evicted_lazily() {
    let c = NonceCache::new();
    let k = nonce_key(&[1; 48], &[2; 16]);
    assert!(!c.contains(&k, 100));
    assert!(c.insert_if_absent(k.clone(), 200, 100));
    assert!(c.contains(&k, 199));
    // Expired at 200: absent, and removed by the lookup.
    assert!(!c.contains(&k, 200));
    assert_eq!(c.len(), 0);
}

#[test]
fn insert_if_absent_refuses_a_live_entry_and_replaces_an_expired_one() {
    let c = NonceCache::new();
    let k = nonce_key(&[1; 48], &[2; 16]);
    assert!(c.insert_if_absent(k.clone(), 200, 100));
    assert!(!c.insert_if_absent(k.clone(), 300, 150));
    // Expired entries count as absent.
    assert!(c.insert_if_absent(k.clone(), 400, 250));
    assert!(c.contains(&k, 399));
    // Keys differ by invoker key as well as nonce.
    assert!(c.insert_if_absent(nonce_key(&[9; 48], &[2; 16]), 400, 250));
    assert_eq!(c.len(), 2);
}

#[test]
fn sweep_never_evicts_a_live_entry() {
    let c = NonceCache::new();
    for i in 0..100u8 {
        c.insert_if_absent(nonce_key(&[i; 48], &[i; 16]), 100 + u64::from(i), 0);
    }
    c.sweep(150);
    assert_eq!(c.len(), 49); // expiries 151..=199 remain
    for i in 51..100u8 {
        assert!(c.contains(&nonce_key(&[i; 48], &[i; 16]), 150));
    }
}

#[test]
fn concurrent_inserts_admit_exactly_one() {
    let c = Arc::new(NonceCache::new());
    let wins = AtomicU64::new(0);
    let k = nonce_key(&[3; 48], &[4; 16]);
    std::thread::scope(|s| {
        for _ in 0..32 {
            s.spawn(|| {
                if c.insert_if_absent(k.clone(), 1000, 0) {
                    wins.fetch_add(1, Ordering::Relaxed);
                }
            });
        }
    });
    assert_eq!(wins.load(Ordering::Relaxed), 1);
}
