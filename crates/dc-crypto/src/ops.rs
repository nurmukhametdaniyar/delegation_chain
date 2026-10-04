//! Operation counts per verification (SPEC §10.3), behind the `count-ops`
//! feature. Counters are thread-local; one verification runs on one thread
//! (D-29). Without the feature every function here is a no-op, and
//! [`snapshot`] returns zeros.
//!
//! Crypto counts are taken where this crate asks `blst` for the work, with
//! the multiplicities `blst` performs: a single BLS verification is one
//! hash-to-G2, two Miller loops and one final exponentiation; an aggregate
//! over n messages is n hash-to-G2, n + 1 Miller loops and one final
//! exponentiation. "Pairings" in SPEC §11.2 means Miller loops plus final
//! exponentiations.

/// Counts of the operations SPEC §10.3 lists.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OpCounts {
    pub hash_to_curve: u64,
    pub miller_loops: u64,
    pub final_exps: u64,
    pub sig_verifications: u64,
    pub resolver_calls: u64,
    pub policy_store_calls: u64,
    pub contains_calls: u64,
    pub evaluate_calls: u64,
    /// Ed25519 keys and signatures put through D-81's canonical-encoding
    /// checks at decode: what D-87's cost model multiplies.
    pub key_encoding_checks: u64,
    pub sig_encoding_checks: u64,
}

impl OpCounts {
    /// Any pairing work at all.
    pub fn pairings(&self) -> u64 {
        self.miller_loops + self.final_exps
    }
}

/// True when this build counts operations. Headline benchmark runs must
/// not use such a build (SPEC §10.3).
pub const ENABLED: bool = cfg!(feature = "count-ops");

#[cfg(feature = "count-ops")]
thread_local! {
    static COUNTS: std::cell::Cell<OpCounts> = const {
        std::cell::Cell::new(OpCounts {
            hash_to_curve: 0,
            miller_loops: 0,
            final_exps: 0,
            sig_verifications: 0,
            resolver_calls: 0,
            policy_store_calls: 0,
            contains_calls: 0,
            evaluate_calls: 0,
            key_encoding_checks: 0,
            sig_encoding_checks: 0,
        })
    };
}

/// Adds to this thread's counters.
#[inline]
pub fn add(_f: impl FnOnce(&mut OpCounts)) {
    #[cfg(feature = "count-ops")]
    COUNTS.with(|c| {
        let mut v = c.get();
        _f(&mut v);
        c.set(v);
    });
}

/// Resets this thread's counters.
#[inline]
pub fn reset() {
    #[cfg(feature = "count-ops")]
    COUNTS.with(|c| c.set(OpCounts::default()));
}

/// This thread's counters.
#[inline]
pub fn snapshot() -> OpCounts {
    #[cfg(feature = "count-ops")]
    return COUNTS.with(|c| c.get());
    #[cfg(not(feature = "count-ops"))]
    OpCounts::default()
}
