//! `Contains(S1, S2)`: is S2 ⊆ S1 (paper §6.4; SPEC §9.6)? Sound, not
//! complete (Proposition 2, Remark 1).

use crate::ast::{Atom, Rule, Scope, ScopeForm};
use crate::logic::{implies, unsat};

fn atoms(r: &Rule) -> Vec<&Atom> {
    r.atoms.iter().collect()
}

/// Rule subsumption `r2 ⊆ r1`: same audience, tool and action; identical
/// declarations; r1's approval requirement no stronger than r2's; and r2's
/// clause implies r1's.
pub fn subsumes(r1: &Rule, r2: &Rule) -> bool {
    r2.same_head(r1)
        && r1.approval.is_subset(&r2.approval)
        && implies(&r2.params, &atoms(r2), &atoms(r1))
}

/// Steps 1–4 of the procedure.
fn core(s1: &Scope, s2: &Scope) -> bool {
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
    // Step 3.
    for (j, r2) in r2s.iter().enumerate() {
        // (a) the first rule of S1 that subsumes r2.
        let Some(i1) = r1s.iter().position(|r1| subsumes(r1, r2)) else {
            return false;
        };
        // (b) earlier rules of S1 that could decide an invocation r2 decides.
        for rp in &r1s[..i1] {
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
    // Step 4.
    true
}

/// `Contains(S1, S2)`. Returns false if either scope is malformed, a
/// defensive check that a decoded chain never reaches, since every
/// constructor but the test hook validates (paper §6.4; D-28).
pub fn contains(s1: &Scope, s2: &Scope) -> bool {
    s1.is_well_formed() && s2.is_well_formed() && core(s1, s2)
}

/// The procedure as it stood before the P-15 fix: no well-formedness check,
/// and atoms on undeclared paths judged against their unconstrained domain.
/// For the P-15 regression test only (SPEC §9.7).
#[cfg(feature = "test-hooks")]
pub fn contains_pre_review(s1: &Scope, s2: &Scope) -> bool {
    core(s1, s2)
}
