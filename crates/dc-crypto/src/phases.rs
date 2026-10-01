//! Per-phase time of one verification (SPEC §10.3), behind the
//! `phase-timing` feature, for the exploratory phase breakdown (D-77). Like
//! [`crate::ops`], the state is thread-local: one verification runs on one
//! thread (D-29). Without the feature every function here is a no-op, the
//! closure passed to [`within`] is simply called, and [`snapshot`] returns
//! zeros. Headline benchmark runs must not use such a build.
//!
//! The verifier marks where each of its phases begins ([`enter`]). This
//! crate wraps its own primitives in [`within`], so that their time is
//! charged to cryptography whichever phase calls them: a signature's point
//! validation while decoding, a certificate's signature while resolving
//! identity. Between [`begin`] and [`end`], every nanosecond is charged to
//! exactly one phase. Outside them, nothing is recorded.

/// The phases of one verification, in Algorithm order (D-77).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// Line 2: the envelope.
    Envelope,
    /// Line 2: the bodies and the signature container.
    Bodies,
    /// Line 2: scopes, decoded and validated (D-28).
    Scopes,
    /// Lines 4–6: the canonical-form check, by re-encoding (D-31).
    Canonical,
    /// Lines 3 and 7–12.
    Structure,
    /// Lines 13–16.
    Temporal,
    /// Lines 17 and 50: the nonce cache.
    Replay,
    /// Lines 18–21.
    KeyChain,
    /// Lines 23–28, cryptography excluded.
    Identity,
    /// Lines 30–31: pinning and `LoadPolicy`.
    PolicyLoad,
    /// Lines 32–35.
    Contains,
    /// Lines 36–37.
    Evaluate,
    /// Lines 38–46, cryptography excluded.
    Approvals,
    /// Lines 47–48: the SHA-256 chain digests and their distinctness.
    Digests,
    /// Point decompression and validation, wherever it happens (D-30).
    PointValidation,
    /// Signature verification, wherever it happens (lines 24, 43, 49).
    Signatures,
    /// After line 50: the accept hook and the result.
    Commit,
}

/// The number of phases.
pub const COUNT: usize = 17;

/// Every phase, in Algorithm order.
pub const ALL: [Phase; COUNT] = [
    Phase::Envelope,
    Phase::Bodies,
    Phase::Scopes,
    Phase::Canonical,
    Phase::Structure,
    Phase::Temporal,
    Phase::Replay,
    Phase::KeyChain,
    Phase::Identity,
    Phase::PolicyLoad,
    Phase::Contains,
    Phase::Evaluate,
    Phase::Approvals,
    Phase::Digests,
    Phase::PointValidation,
    Phase::Signatures,
    Phase::Commit,
];

impl Phase {
    /// The column name in the phase CSVs.
    pub fn label(self) -> &'static str {
        match self {
            Phase::Envelope => "envelope",
            Phase::Bodies => "bodies",
            Phase::Scopes => "scopes",
            Phase::Canonical => "canonical",
            Phase::Structure => "structure",
            Phase::Temporal => "temporal",
            Phase::Replay => "replay",
            Phase::KeyChain => "key_chain",
            Phase::Identity => "identity",
            Phase::PolicyLoad => "policy_load",
            Phase::Contains => "contains",
            Phase::Evaluate => "evaluate",
            Phase::Approvals => "approvals",
            Phase::Digests => "digests",
            Phase::PointValidation => "point_validation",
            Phase::Signatures => "signatures",
            Phase::Commit => "commit",
        }
    }
}

/// True when this build times phases. Headline benchmark runs must not use
/// such a build (SPEC §10.3).
pub const ENABLED: bool = cfg!(feature = "phase-timing");

#[cfg(feature = "phase-timing")]
mod imp {
    use std::cell::RefCell;
    use std::time::Instant;

    use super::{COUNT, Phase};

    pub(super) struct State {
        pub current: Phase,
        /// When the current phase was entered; `None` outside a verification.
        pub since: Option<Instant>,
        pub ns: [u64; COUNT],
    }

    thread_local! {
        pub(super) static STATE: RefCell<State> = const {
            RefCell::new(State {
                current: Phase::Envelope,
                since: None,
                ns: [0; COUNT],
            })
        };
    }

    /// Charges the time since the last switch to the current phase, then
    /// makes `to` current. Returns the phase that was current. Outside a
    /// verification it changes nothing.
    pub(super) fn switch(to: Phase) -> Phase {
        STATE.with(|s| {
            let mut s = s.borrow_mut();
            let prev = s.current;
            if let Some(t0) = s.since {
                let now = Instant::now();
                s.ns[prev as usize] += now.duration_since(t0).as_nanos() as u64;
                s.since = Some(now);
                s.current = to;
            }
            prev
        })
    }
}

/// Starts timing a verification on this thread, in phase `p`.
#[inline]
pub fn begin(_p: Phase) {
    #[cfg(feature = "phase-timing")]
    imp::STATE.with(|s| {
        let mut s = s.borrow_mut();
        s.ns = [0; COUNT];
        s.current = _p;
        s.since = Some(std::time::Instant::now());
    });
}

/// From now on, time is charged to `p`.
#[inline]
pub fn enter(_p: Phase) {
    #[cfg(feature = "phase-timing")]
    imp::switch(_p);
}

/// Stops timing; [`snapshot`] then holds the verification's phases.
#[inline]
pub fn end() {
    #[cfg(feature = "phase-timing")]
    imp::STATE.with(|s| {
        let mut s = s.borrow_mut();
        if let Some(t0) = s.since.take() {
            let current = s.current as usize;
            s.ns[current] += t0.elapsed().as_nanos() as u64;
        }
    });
}

/// Puts the previous phase back when dropped.
struct Within {
    #[cfg(feature = "phase-timing")]
    prev: Phase,
}

impl Within {
    #[inline]
    fn enter(_p: Phase) -> Self {
        Within {
            #[cfg(feature = "phase-timing")]
            prev: imp::switch(_p),
        }
    }
}

#[cfg(feature = "phase-timing")]
impl Drop for Within {
    fn drop(&mut self) {
        imp::switch(self.prev);
    }
}

/// Runs `f`, charging its time to `p`, then returns to the phase that was
/// current.
#[inline]
pub fn within<T>(p: Phase, f: impl FnOnce() -> T) -> T {
    let _g = Within::enter(p);
    f()
}

/// This thread's per-phase nanoseconds for the last verification, indexed
/// like [`ALL`].
#[inline]
pub fn snapshot() -> [u64; COUNT] {
    #[cfg(feature = "phase-timing")]
    return imp::STATE.with(|s| s.borrow().ns);
    #[cfg(not(feature = "phase-timing"))]
    [0; COUNT]
}

#[cfg(all(test, feature = "phase-timing"))]
mod tests {
    use super::*;

    fn spin(us: u64) {
        let t = std::time::Instant::now();
        while t.elapsed().as_micros() < u128::from(us) {
            std::hint::spin_loop();
        }
    }

    #[test]
    fn phases_partition_the_call() {
        let t = std::time::Instant::now();
        begin(Phase::Envelope);
        spin(200);
        enter(Phase::Bodies);
        within(Phase::PointValidation, || spin(300));
        spin(100);
        enter(Phase::Digests);
        within(Phase::Signatures, || {
            within(Phase::PointValidation, || spin(100));
            spin(100)
        });
        end();
        let total = t.elapsed().as_nanos() as u64;
        let ns = snapshot();
        let at = |p: Phase| ns[p as usize];
        assert!(at(Phase::Envelope) >= 200_000);
        assert!(at(Phase::Bodies) >= 100_000 && at(Phase::Bodies) < 300_000);
        assert!(at(Phase::PointValidation) >= 400_000);
        assert!(at(Phase::Signatures) >= 100_000 && at(Phase::Signatures) < 200_000);
        assert!(ns.iter().sum::<u64>() <= total);
        // Outside a verification nothing is recorded.
        within(Phase::Signatures, || spin(50));
        enter(Phase::Contains);
        assert_eq!(snapshot(), ns);
    }
}
