//! Time, in Unix seconds, behind a trait so tests and the cache-equivalence
//! suite can move it (SPEC §10.1, §11.3).

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub trait Clock: Send + Sync {
    fn now(&self) -> u64;
}

/// Wall-clock time.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

/// A clock that only moves when told to.
#[derive(Debug, Default)]
pub struct ManualClock(AtomicU64);

impl ManualClock {
    pub fn new(t: u64) -> Self {
        ManualClock(AtomicU64::new(t))
    }

    pub fn set(&self, t: u64) {
        self.0.store(t, Ordering::SeqCst);
    }

    pub fn advance(&self, secs: u64) {
        self.0.fetch_add(secs, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

impl<C: Clock + ?Sized> Clock for std::sync::Arc<C> {
    fn now(&self) -> u64 {
        (**self).now()
    }
}

impl<C: Clock + ?Sized> Clock for &C {
    fn now(&self) -> u64 {
        (**self).now()
    }
}
