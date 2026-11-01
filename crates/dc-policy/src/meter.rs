//! PROTOTYPE (D-99): a count of the containment procedure's atom-level
//! checks, for a deterministic work budget on `Contains`. Only the
//! `work-budget` feature counts. Without it, [`charge`] never calls its
//! argument and compiles to nothing, so the protocol path is unchanged; no
//! headline build enables it.
//!
//! The unit is one atom examined, weighted by its operand's literals: an
//! atom with a 64-element `in` list counts 64. The count depends only on the
//! two scopes, so every replica of a verifier reaches the same total on the
//! same input. String lengths are not counted.

use crate::ast::{Atom, Operand};

#[cfg(feature = "work-budget")]
thread_local! {
    static WORK: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// True when this build counts.
pub const ENABLED: bool = cfg!(feature = "work-budget");

/// Adds `n()` checks to this thread's count, in a counting build.
#[inline(always)]
pub(crate) fn charge(n: impl FnOnce() -> usize) {
    #[cfg(feature = "work-budget")]
    WORK.with(|w| w.set(w.get() + n() as u64));
    #[cfg(not(feature = "work-budget"))]
    let _ = n;
}

/// An atom's weight: the literals of its operand.
pub(crate) fn weight(a: &Atom) -> usize {
    match &a.operand {
        Operand::One(_) => 1,
        Operand::List(l) => l.len().max(1),
    }
}

/// The total weight of `atoms`.
pub(crate) fn weights(atoms: &[&Atom]) -> usize {
    atoms.iter().map(|a| weight(a)).sum()
}

/// Sets this thread's count to zero.
#[cfg(feature = "work-budget")]
pub fn reset() {
    WORK.with(|w| w.set(0));
}

/// This thread's count.
#[cfg(feature = "work-budget")]
pub fn spent() -> u64 {
    WORK.with(std::cell::Cell::get)
}
