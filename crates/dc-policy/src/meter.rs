//! The work count of `Contains` under a budget (SPEC §9.6.1; D-100, D-101).
//!
//! The unit is one integer literal examined, as in D-99. Every other
//! operation of the procedure is charged so as to bound its work from
//! above (D-101, D-102): a string by its length, per 64 bytes where it is
//! compared ([`size`]), per 8 bytes where it is searched ([`search`]) and
//! per 4 bytes where it is walked as a path ([`walk`]); head and approval
//! comparisons by the strings they compare; and each set an `==` or `in`
//! atom forms ([`SET`]). Each class costs at most about what an integer
//! literal check costs per unit, so that the integer and set-building
//! classes, whose probes are purer than any use in the procedure, bound the
//! time per unit. SPEC §9.6.1's table
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

/// A searched string's size: 1, and 1 more for every 8 bytes. Substring
/// search does several steps per byte (D-102: per 16 before).
pub fn search(s: &str) -> usize {
    1 + s.len() / 8
}

/// A walked path's size: 1, and 1 more for every 4 bytes. The canonical-path
/// check splits a value into segments and tests each, the costliest step
/// per byte of any (D-102: per 16 before).
pub fn walk(s: &str) -> usize {
    1 + s.len() / 4
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

/// What forming one `==` or `in` atom's set costs beyond its literals: the
/// operand's vector, the set, and its intersection with the sets before it,
/// each allocated (D-102).
pub const SET: usize = 4;

/// What building a path's constraint from `atoms` costs: their weights, and
/// [`SET`] for each `==` or `in` atom (SPEC §9.6.1).
pub(crate) fn build(atoms: &[&Atom]) -> usize {
    let sets = atoms
        .iter()
        .filter(|a| matches!(a.op, crate::ast::Op::Eq | crate::ast::Op::In))
        .count();
    weights(atoms) + SET * sets
}
