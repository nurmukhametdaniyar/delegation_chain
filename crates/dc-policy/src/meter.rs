//! The work count of `Contains` under a budget (SPEC §9.6.1; D-100, D-101).
//!
//! The unit is one integer literal examined, as in D-99. Every other
//! operation of the procedure is charged so as to bound its work from
//! above (D-101): a string by its length, per 64 bytes where it is compared
//! ([`size`]) and per 16 bytes where it is scanned ([`scan`]); head and
//! approval comparisons by the strings they compare. SPEC §9.6.1's table
//! says where each charge is made. The count depends only on the two
//! scopes, so every replica of a verifier reaches the same total on the
//! same input.
//!
//! Every charge comes before the work it pays for, and a check whose charge
//! passes the budget skips that work and answers in the sound direction
//! (`implies` and `unsat` false). Once the budget has run out the answer is
//! false whatever the skipped checks would have said, so skipping them
//! changes no decision; it only stops the procedure promptly.

use std::cell::Cell;

use crate::ast::{Atom, Literal, Operand};

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

/// A compared string's size: 1, and 1 more for every 64 bytes. Equality,
/// ordering, prefix and suffix tests read each byte at most once, and
/// cheaply.
pub fn size(s: &str) -> usize {
    1 + s.len() / 64
}

/// A scanned string's size: 1, and 1 more for every 16 bytes. Substring
/// search and the canonical-path check do several steps per byte.
pub fn scan(s: &str) -> usize {
    1 + s.len() / 16
}

/// A literal's size: 1 for an integer or a boolean, a string's [`size`].
pub fn literal(l: &Literal) -> usize {
    match l {
        Literal::Str(s) => size(s),
        Literal::Int(_) | Literal::Bool(_) => 1,
    }
}

/// An atom's weight: the sizes of its operand's literals. For integers and
/// booleans, the number of literals (D-99).
pub(crate) fn weight(a: &Atom) -> usize {
    match &a.operand {
        Operand::One(l) => literal(l),
        Operand::List(l) => l.iter().map(literal).sum::<usize>().max(1),
    }
}

/// The total weight of `atoms`.
pub(crate) fn weights(atoms: &[&Atom]) -> usize {
    atoms.iter().map(|a| weight(a)).sum()
}
