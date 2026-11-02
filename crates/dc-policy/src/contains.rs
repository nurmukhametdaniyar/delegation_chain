//! `Contains(S1, S2)`: is S2 ⊆ S1 (paper §6.4; SPEC §9.6)? Sound, not
//! complete (Proposition 2, Remark 1). The verifier runs it under a work
//! budget (SPEC §9.6.1; D-100): [`contains_within`].

use crate::ast::{Atom, Rule, Scope, ScopeForm};
#[cfg(feature = "test-hooks")]
use crate::logic::{implies, unsat};
use crate::logic::{implies_counted, unsat_counted};
use crate::meter::Meter;

/// The verifier's default work budget for one `Contains` call, in atom
/// literals examined (SPEC §9.6.1; D-100).
pub const DEFAULT_BUDGET: u64 = 65_536;

fn atoms(r: &Rule) -> Vec<&Atom> {
    r.atoms.iter().collect()
}

/// Rule subsumption `r2 ⊆ r1`: same audience, tool and action; identical
/// declarations; r1's approval requirement no stronger than r2's; and r2's
/// clause implies r1's.
pub fn subsumes(r1: &Rule, r2: &Rule) -> bool {
    subsumes_counted(r1, r2, &Meter::unlimited())
}

/// [`subsumes`], charging `m` one, then the `implies` call.
fn subsumes_counted(r1: &Rule, r2: &Rule, m: &Meter) -> bool {
    m.charge(1)
        && r2.same_head(r1)
        && r1.approval.is_subset(&r2.approval)
        && implies_counted(&r2.params, &atoms(r2), &atoms(r1), m)
}

/// Step 3(b)'s skip test for one rule r′ of S1: does a child rule before
/// r2 shadow it? The set of earlier child rules only grows as r2 moves along
/// S2, so the first child rule that shadows r′ is searched for once, from
/// where the previous search stopped, and reused for every later r2. The
/// answer is the procedure's; only repeated `implies` calls are saved
/// (D-97). Since D-100 this order is part of the procedure's definition,
/// because the work count depends on it (SPEC §9.6.1).
#[derive(Clone, Copy, Default)]
struct Shadow {
    /// Child rules 0 .. `scanned` have been tested.
    scanned: usize,
    /// The first of them that shadows r′, if any.
    first: Option<usize>,
}

impl Shadow {
    /// Does one of child rules 0 .. j shadow r′? `shadows(k)` tests child
    /// rule k. The search also stops when the budget has run out.
    fn before(&mut self, j: usize, shadows: impl Fn(usize) -> bool, m: &Meter) -> bool {
        while self.first.is_none() && self.scanned < j && !m.exhausted() {
            if shadows(self.scanned) {
                self.first = Some(self.scanned);
            }
            self.scanned += 1;
        }
        self.first.is_some_and(|k| k < j)
    }
}

/// Steps 1–4 of the procedure, charging `m` (SPEC §9.6.1). It gives up,
/// returning false, once the budget has run out.
fn core(s1: &Scope, s2: &Scope, m: &Meter) -> bool {
    let (r1s, r2s) = match (s1.form(), s2.form()) {
        // Step 1.
        (ScopeForm::AllowAll, _) => return true,
        // Step 2.
        (_, ScopeForm::DenyAll) => return true,
        (_, ScopeForm::AllowAll) => return false,
        // S1 = deny all against a rule list: step 3(a) finds no r1 (D-24).
        (ScopeForm::DenyAll, ScopeForm::Rules(_)) => return false,
        (ScopeForm::Rules(a), ScopeForm::Rules(b)) => (a, b),
    };
    let mut shadow = vec![Shadow::default(); r1s.len()];
    // Step 3.
    for (j, r2) in r2s.iter().enumerate() {
        // (a) the first rule of S1 that subsumes r2.
        let mut found = None;
        for (i, r1) in r1s.iter().enumerate() {
            if m.exhausted() {
                return false;
            }
            if subsumes_counted(r1, r2, m) {
                found = Some(i);
                break;
            }
        }
        let Some(i1) = found else {
            return false;
        };
        // (b) earlier rules of S1 that could decide an invocation r2 decides.
        for (i, rp) in r1s[..i1].iter().enumerate() {
            if !m.charge(1) {
                return false;
            }
            if !rp.same_head(r2) {
                continue;
            }
            let mut joint = atoms(rp);
            joint.extend(atoms(r2));
            if unsat_counted(&r2.params, &joint, m) {
                continue;
            }
            // Skip r′ if an earlier rule of S2 already catches everything r′
            // matches.
            let shadowed = shadow[i].before(
                j,
                |k| {
                    r2s[k].same_head(rp)
                        && implies_counted(&rp.params, &atoms(rp), &atoms(&r2s[k]), m)
                },
                m,
            );
            if m.exhausted() {
                return false;
            }
            if shadowed {
                continue;
            }
            if !rp.approval.is_subset(&r2.approval) {
                return false;
            }
        }
    }
    // Step 4.
    !m.exhausted()
}

/// Steps 1–4 as written, with step 3(b)'s skip test re-run over every
/// earlier child rule each time: the procedure before D-97, kept as the
/// reference the memoized one is compared with.
#[cfg(feature = "test-hooks")]
fn core_unmemoized(s1: &Scope, s2: &Scope) -> bool {
    let (r1s, r2s) = match (s1.form(), s2.form()) {
        (ScopeForm::AllowAll, _) => return true,
        (_, ScopeForm::DenyAll) => return true,
        (_, ScopeForm::AllowAll) => return false,
        (ScopeForm::DenyAll, ScopeForm::Rules(_)) => return false,
        (ScopeForm::Rules(a), ScopeForm::Rules(b)) => (a, b),
    };
    for (j, r2) in r2s.iter().enumerate() {
        let Some(i1) = r1s.iter().position(|r1| subsumes(r1, r2)) else {
            return false;
        };
        for rp in &r1s[..i1] {
            if !rp.same_head(r2) {
                continue;
            }
            let mut joint = atoms(rp);
            joint.extend(atoms(r2));
            if unsat(&r2.params, &joint) {
                continue;
            }
            let shadowed = r2s[..j]
                .iter()
                .any(|r2p| r2p.same_head(rp) && implies(&rp.params, &atoms(rp), &atoms(r2p)));
            if shadowed {
                continue;
            }
            if !rp.approval.is_subset(&r2.approval) {
                return false;
            }
        }
    }
    true
}

/// `Contains(S1, S2)`, the procedure without a budget. Returns false if
/// either scope is malformed, a defensive check that a decoded chain never
/// reaches, since every constructor but the test hook validates (paper
/// §6.4; D-28).
pub fn contains(s1: &Scope, s2: &Scope) -> bool {
    s1.is_well_formed() && s2.is_well_formed() && core(s1, s2, &Meter::unlimited())
}

/// `Contains_B`'s answer and the work it counted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Within {
    /// The answer: `Contains`'s, or false if the budget ran out.
    pub answer: bool,
    /// Atom literals examined (SPEC §9.6.1): W if the procedure finished
    /// within the budget, otherwise the count at which it stopped, past the
    /// budget.
    pub work: u64,
    /// The count passed the budget, and the answer is false for that reason.
    pub exhausted: bool,
}

/// `Contains_B(S1, S2)` (SPEC §9.6.1; D-100): the procedure's answer if its
/// work count W is at most `budget`, and false otherwise. It stops as soon
/// as the count passes `budget`. Sound: the budget only turns answers to
/// false. `u64::MAX` is no budget.
pub fn contains_within(s1: &Scope, s2: &Scope, budget: u64) -> Within {
    let m = Meter::new(budget);
    let answer = s1.is_well_formed() && s2.is_well_formed() && core(s1, s2, &m);
    Within {
        answer: answer && !m.exhausted(),
        work: m.spent(),
        exhausted: m.exhausted(),
    }
}

/// The procedure as it stood before the P-15 fix: no well-formedness check,
/// and atoms on undeclared paths judged against their unconstrained domain.
/// For the P-15 regression test only (SPEC §9.7).
#[cfg(feature = "test-hooks")]
pub fn contains_pre_review(s1: &Scope, s2: &Scope) -> bool {
    core(s1, s2, &Meter::unlimited())
}

/// `Contains` as it stood before D-97's memoization, for comparison only.
#[cfg(feature = "test-hooks")]
pub fn contains_unmemoized(s1: &Scope, s2: &Scope) -> bool {
    s1.is_well_formed() && s2.is_well_formed() && core_unmemoized(s1, s2)
}
