//! The work count of `Contains` under a budget (SPEC §9.6.1; D-100, from
//! D-99's prototype).
//!
//! The unit is one atom literal examined: an atom with a 64-element `in`
//! list counts 64. SPEC §9.6.1's table says where each check is charged.
//! The count depends only on the two scopes, so every replica of a verifier
//! reaches the same total on the same input. String lengths are not
//! counted.
//!
//! Every charge comes before the work it pays for, and a check whose charge
//! passes the budget skips that work and answers in the sound direction
//! (`implies` and `unsat` false). Once the budget has run out the answer is
//! false whatever the skipped checks would have said, so skipping them
//! changes no decision; it only stops the procedure promptly.

use std::cell::Cell;

use crate::ast::{Atom, Operand};

/// A running count of atom-level checks, against a budget.
#[derive(Debug)]
pub struct Meter {
    spent: Cell<u64>,
    budget: u64,
}

impl Meter {
    pub fn new(budget: u64) -> Self {
        Meter {
            spent: Cell::new(0),
            budget,
        }
    }

    /// A meter that never runs out: the procedure without a budget.
    pub fn unlimited() -> Self {
        Meter::new(u64::MAX)
    }

    /// Adds `n` checks. False once the count has passed the budget, in which
    /// case the caller skips the work it charged for.
    pub(crate) fn charge(&self, n: usize) -> bool {
        let spent = self.spent.get().saturating_add(n as u64);
        self.spent.set(spent);
        spent <= self.budget
    }

    /// The count so far.
    pub fn spent(&self) -> u64 {
        self.spent.get()
    }

    /// Has the count passed the budget?
    pub fn exhausted(&self) -> bool {
        self.spent.get() > self.budget
    }
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
