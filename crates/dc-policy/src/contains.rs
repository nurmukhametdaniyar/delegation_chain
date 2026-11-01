//! `Contains(S1, S2)`: is S2 ⊆ S1 (paper §6.4; SPEC §9.6)? Sound, not
//! complete (Proposition 2, Remark 1).

use crate::ast::{Atom, Rule, Scope, ScopeForm};
use crate::logic::{implies, unsat};
use crate::meter::charge;

fn atoms(r: &Rule) -> Vec<&Atom> {
    r.atoms.iter().collect()
}

/// Rule subsumption `r2 ⊆ r1`: same audience, tool and action; identical
/// declarations; r1's approval requirement no stronger than r2's; and r2's
/// clause implies r1's.
pub fn subsumes(r1: &Rule, r2: &Rule) -> bool {
    charge(|| 1);
    r2.same_head(r1)
        && r1.approval.is_subset(&r2.approval)
        && implies(&r2.params, &atoms(r2), &atoms(r1))
}

/// Step 3(b)'s skip test for one rule r′ of S1: does a child rule before
/// r2 shadow it? The set of earlier child rules only grows as r2 moves along
/// S2, so the first child rule that shadows r′ is searched for once, from
/// where the previous search stopped, and reused for every later r2. The
/// answer is the procedure's; only repeated `implies` calls are saved
/// (D-97).
#[derive(Clone, Copy, Default)]
struct Shadow {
    /// Child rules 0 .. `scanned` have been tested.
    scanned: usize,
    /// The first of them that shadows r′, if any.
    first: Option<usize>,
}

impl Shadow {
    /// Does one of child rules 0 .. j shadow r′? `shadows(k)` tests child
    /// rule k. The search also stops when `stop()` says so (D-99).
    fn before(
        &mut self,
        j: usize,
        shadows: impl Fn(usize) -> bool,
        stop: &impl Fn() -> bool,
    ) -> bool {
        while self.first.is_none() && self.scanned < j && !stop() {
            if shadows(self.scanned) {
                self.first = Some(self.scanned);
            }
            self.scanned += 1;
        }
        self.first.is_some_and(|k| k < j)
    }
}

/// Steps 1–4 of the procedure. It gives up, returning false, as soon as
/// `stop()` is true between two of its checks: the work budget of D-99's
/// prototype. `contains` passes a `stop` that is always false.
fn core(s1: &Scope, s2: &Scope, stop: &impl Fn() -> bool) -> bool {
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
            if stop() {
                return false;
            }
            if subsumes(r1, r2) {
                found = Some(i);
                break;
            }
        }
        let Some(i1) = found else {
            return false;
        };
        // (b) earlier rules of S1 that could decide an invocation r2 decides.
        for (i, rp) in r1s[..i1].iter().enumerate() {
            charge(|| 1);
            if stop() {
                return false;
            }
            if !rp.same_head(r2) {
                continue;
            }
            let mut joint = atoms(rp);
            joint.extend(atoms(r2));
            if unsat(&r2.params, &joint) {
                continue;
            }
            // Skip r′ if an earlier rule of S2 already catches everything r′
            // matches.
            let shadowed = shadow[i].before(
                j,
                |k| r2s[k].same_head(rp) && implies(&rp.params, &atoms(rp), &atoms(&r2s[k])),
                stop,
            );
            if stop() {
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
    true
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

/// `Contains(S1, S2)`. Returns false if either scope is malformed, a
/// defensive check that a decoded chain never reaches, since every
/// constructor but the test hook validates (paper §6.4; D-28).
pub fn contains(s1: &Scope, s2: &Scope) -> bool {
    s1.is_well_formed() && s2.is_well_formed() && core(s1, s2, &|| false)
}

/// PROTOTYPE (D-99): `Contains` under a work budget, and what it spent.
#[cfg(feature = "work-budget")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Within {
    /// The answer: `Contains`'s, or false if the budget ran out.
    pub answer: bool,
    /// Atom-level checks counted (`crate::meter`).
    pub work: u64,
    /// The count passed `budget` and the procedure gave up.
    pub exhausted: bool,
}

/// PROTOTYPE (D-99): `Contains`, giving up with false once more than
/// `budget` atom-level checks have been counted. The count is checked
/// between the procedure's checks, so it can pass `budget` by one check's
/// worth before the procedure stops. Sound: it only turns answers to false.
#[cfg(feature = "work-budget")]
pub fn contains_within(s1: &Scope, s2: &Scope, budget: u64) -> Within {
    crate::meter::reset();
    let stop = || crate::meter::spent() > budget;
    let answer = s1.is_well_formed() && s2.is_well_formed() && core(s1, s2, &stop);
    let work = crate::meter::spent();
    let exhausted = work > budget;
    Within {
        answer: answer && !exhausted,
        work,
        exhausted,
    }
}

/// The procedure as it stood before the P-15 fix: no well-formedness check,
/// and atoms on undeclared paths judged against their unconstrained domain.
/// For the P-15 regression test only (SPEC §9.7).
#[cfg(feature = "test-hooks")]
pub fn contains_pre_review(s1: &Scope, s2: &Scope) -> bool {
    core(s1, s2, &|| false)
}

/// `Contains` as it stood before D-97's memoization, for comparison only.
#[cfg(feature = "test-hooks")]
pub fn contains_unmemoized(s1: &Scope, s2: &Scope) -> bool {
    s1.is_well_formed() && s2.is_well_formed() && core_unmemoized(s1, s2)
}
