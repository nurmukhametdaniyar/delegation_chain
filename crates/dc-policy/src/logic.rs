//! `implies` and `unsat` over conjunctions of atoms (SPEC §9.5).
//!
//! Soundness contract: `implies` may wrongly say `false`, never `true`;
//! `unsat` may wrongly say `false` (satisfiable), never `true`. Atoms are
//! grouped by path, and paths are independent (paper §6.4). Each path's
//! domain is its declared type. For well-formed rules every where-path is
//! declared (D-28). Only the `test-hooks` pre-review procedure reaches an
//! undeclared path; there the type is read off the operand and the domain
//! taken as unconstrained, which is exactly the P-15 bug.
//!
//! Exact cases: int, bool, and string when an `==`/`in` atom gives a finite
//! set. Strings without a finite set use the sound rules of SPEC §9.5, plus
//! the tautologies `starts_with ""`, `ends_with ""` and `contains ""`
//! (P-08).

use std::collections::BTreeSet;

use dc_cbor::{INT_MAX, INT_MIN};

use crate::ast::{Atom, Declaration, Literal, Op, Operand, Type};
use crate::eval::{Leaf, atom_holds};
use crate::validate::seg_prefix;

fn ints(o: &Operand) -> Vec<i128> {
    match o {
        Operand::One(Literal::Int(n)) => vec![*n],
        Operand::List(l) => l
            .iter()
            .filter_map(|x| match x {
                Literal::Int(n) => Some(*n),
                _ => None,
            })
            .collect(),
        _ => vec![],
    }
}

fn bools(o: &Operand) -> Vec<bool> {
    match o {
        Operand::One(Literal::Bool(b)) => vec![*b],
        Operand::List(l) => l
            .iter()
            .filter_map(|x| match x {
                Literal::Bool(b) => Some(*b),
                _ => None,
            })
            .collect(),
        _ => vec![],
    }
}

fn strs(o: &Operand) -> Vec<&str> {
    match o {
        Operand::One(Literal::Str(s)) => vec![s.as_str()],
        Operand::List(l) => l
            .iter()
            .filter_map(|x| match x {
                Literal::Str(s) => Some(s.as_str()),
                _ => None,
            })
            .collect(),
        _ => vec![],
    }
}

fn str_of(o: &Operand) -> Option<&str> {
    match o {
        Operand::One(Literal::Str(s)) => Some(s),
        _ => None,
    }
}

/// Int path: an interval `[lo, hi]`, and optionally a finite set F from
/// `==` and `in` (exact).
struct IntC {
    lo: i128,
    hi: i128,
    set: Option<BTreeSet<i128>>,
}

impl IntC {
    fn new(atoms: &[&Atom]) -> Self {
        let mut c = IntC {
            lo: INT_MIN,
            hi: INT_MAX,
            set: None,
        };
        for a in atoms {
            let v = ints(&a.operand);
            match a.op {
                Op::Lt => v.first().into_iter().for_each(|&n| c.hi = c.hi.min(n - 1)),
                Op::Le => v.first().into_iter().for_each(|&n| c.hi = c.hi.min(n)),
                Op::Gt => v.first().into_iter().for_each(|&n| c.lo = c.lo.max(n + 1)),
                Op::Ge => v.first().into_iter().for_each(|&n| c.lo = c.lo.max(n)),
                Op::Eq | Op::In => {
                    let s: BTreeSet<i128> = v.into_iter().collect();
                    c.set = Some(match c.set.take() {
                        None => s,
                        Some(prev) => prev.intersection(&s).copied().collect(),
                    });
                }
                _ => {}
            }
        }
        c
    }

    /// The admissible set, when it is finite.
    fn finite(&self) -> Option<Vec<i128>> {
        self.set.as_ref().map(|s| {
            s.iter()
                .copied()
                .filter(|v| (self.lo..=self.hi).contains(v))
                .collect()
        })
    }

    fn unsat(&self) -> bool {
        match self.finite() {
            Some(a) => a.is_empty(),
            None => self.lo > self.hi,
        }
    }

    fn implies(&self, b: &Atom) -> bool {
        if self.unsat() {
            return true;
        }
        if let Some(a) = self.finite() {
            return a.iter().all(|v| atom_holds(b, &Leaf::Int(*v)));
        }
        let (lo, hi) = (self.lo, self.hi);
        let n = ints(&b.operand);
        match (b.op, n.as_slice()) {
            (Op::Lt, [c]) => hi < *c,
            (Op::Le, [c]) => hi <= *c,
            (Op::Gt, [c]) => lo > *c,
            (Op::Ge, [c]) => lo >= *c,
            (Op::Eq, [c]) => lo == hi && lo == *c,
            (Op::In, list) => {
                // Every integer of [lo, hi] must be listed; |L| ≤ 64 bounds the loop.
                let set: BTreeSet<i128> = list.iter().copied().collect();
                hi - lo < set.len() as i128 && (lo..=hi).all(|v| set.contains(&v))
            }
            _ => false,
        }
    }
}

/// Bool path: the admissible subset of {false, true} (exact).
struct BoolC {
    allowed: [bool; 2],
}

impl BoolC {
    fn new(atoms: &[&Atom]) -> Self {
        let mut allowed = [true, true];
        for a in atoms {
            if matches!(a.op, Op::Eq | Op::In) {
                let v = bools(&a.operand);
                for (i, b) in [false, true].into_iter().enumerate() {
                    allowed[i] &= v.contains(&b);
                }
            }
        }
        BoolC { allowed }
    }

    fn values(&self) -> impl Iterator<Item = bool> + '_ {
        [false, true]
            .into_iter()
            .filter(|b| self.allowed[*b as usize])
    }

    fn unsat(&self) -> bool {
        self.values().next().is_none()
    }

    fn implies(&self, b: &Atom) -> bool {
        self.values().all(|v| atom_holds(b, &Leaf::Bool(v)))
    }
}

/// String path. With a finite set E from `==`/`in`, exact; otherwise the
/// sound rules of SPEC §9.5.
struct StrC<'a> {
    atoms: Vec<&'a Atom>,
    e: Option<BTreeSet<&'a str>>,
    p: Vec<&'a str>,
    s: Vec<&'a str>,
    k: Vec<&'a str>,
    u: Vec<&'a str>,
}

impl<'a> StrC<'a> {
    fn new(atoms: &[&'a Atom]) -> Self {
        let mut c = StrC {
            atoms: atoms.to_vec(),
            e: None,
            p: vec![],
            s: vec![],
            k: vec![],
            u: vec![],
        };
        for a in atoms {
            match a.op {
                Op::Eq | Op::In => {
                    let set: BTreeSet<&str> = strs(&a.operand).into_iter().collect();
                    c.e = Some(match c.e.take() {
                        None => set,
                        Some(prev) => prev.intersection(&set).copied().collect(),
                    });
                }
                Op::StartsWith => c.p.extend(str_of(&a.operand)),
                Op::EndsWith => c.s.extend(str_of(&a.operand)),
                Op::Contains => c.k.extend(str_of(&a.operand)),
                Op::Under => c.u.extend(str_of(&a.operand)),
                _ => {}
            }
        }
        c
    }

    /// With a finite set: the members that satisfy every atom.
    fn admissible(&self) -> Option<Vec<&'a str>> {
        let e = self.e.as_ref()?;
        Some(
            e.iter()
                .copied()
                .filter(|v| self.atoms.iter().all(|a| atom_holds(a, &Leaf::Str(v))))
                .collect(),
        )
    }

    fn unsat(&self) -> bool {
        if let Some(a) = self.admissible() {
            return a.is_empty();
        }
        let pairs = |v: &[&str], ok: &dyn Fn(&str, &str) -> bool| {
            v.iter()
                .enumerate()
                .any(|(i, x)| v[i + 1..].iter().any(|y| !ok(x, y)))
        };
        let prefix_compatible = |x: &str, y: &str| x.starts_with(y) || y.starts_with(x);
        pairs(&self.p, &prefix_compatible)
            || pairs(&self.s, &|x, y| x.ends_with(y) || y.ends_with(x))
            || pairs(&self.u, &|x, y| seg_prefix(x, y) || seg_prefix(y, x))
            || self
                .p
                .iter()
                .any(|p| self.u.iter().any(|q| !prefix_compatible(p, q)))
    }

    fn implies(&self, b: &Atom) -> bool {
        if self.unsat() {
            return true;
        }
        if let Some(a) = self.admissible() {
            return a.iter().all(|v| atom_holds(b, &Leaf::Str(v)));
        }
        let Some(x) = str_of(&b.operand) else {
            return false; // `in`: never, without a finite set
        };
        match b.op {
            Op::StartsWith => {
                x.is_empty()
                    || self.p.iter().any(|p| p.starts_with(x))
                    || self.u.iter().any(|q| q.starts_with(x))
            }
            Op::EndsWith => x.is_empty() || self.s.iter().any(|s| s.ends_with(x)),
            Op::Contains => {
                x.is_empty()
                    || self
                        .p
                        .iter()
                        .chain(&self.s)
                        .chain(&self.k)
                        .chain(&self.u)
                        .any(|y| y.contains(x))
            }
            Op::Under => self.u.iter().any(|q| seg_prefix(x, q)),
            _ => false, // `==`: never, without a finite set
        }
    }
}

/// The type of `path`: its declaration, or (only for unvalidated scopes, via
/// the test hook) the type of the first atom's operand on it.
fn path_type(decl: &Declaration, path: &str, atoms: &[&Atom]) -> Option<Type> {
    decl.get(path).copied().or_else(|| {
        atoms
            .iter()
            .find(|a| a.path == path)
            .and_then(|a| match &a.operand {
                Operand::One(l) => Some(l.ty()),
                Operand::List(l) => l.first().map(Literal::ty),
            })
    })
}

fn on_path<'a>(atoms: &[&'a Atom], path: &str) -> Vec<&'a Atom> {
    atoms.iter().copied().filter(|a| a.path == path).collect()
}

/// Is the conjunction of atoms on one path, of type `ty`, unsatisfiable?
pub fn unsat_path(ty: Type, atoms: &[&Atom]) -> bool {
    match ty {
        Type::Int => IntC::new(atoms).unsat(),
        Type::Bool => BoolC::new(atoms).unsat(),
        Type::String => StrC::new(atoms).unsat(),
    }
}

/// Do the atoms on one path, of type `ty`, force `b`?
pub fn implies_path(ty: Type, atoms: &[&Atom], b: &Atom) -> bool {
    match ty {
        Type::Int => IntC::new(atoms).implies(b),
        Type::Bool => BoolC::new(atoms).implies(b),
        Type::String => StrC::new(atoms).implies(b),
    }
}

/// `unsat(C)` for a conjunction over the paths of `decl`: some path's
/// constraint is inconsistent.
pub fn unsat(decl: &Declaration, atoms: &[&Atom]) -> bool {
    let mut paths: Vec<&str> = atoms.iter().map(|a| a.path.as_str()).collect();
    paths.sort_unstable();
    paths.dedup();
    paths.into_iter().any(|p| {
        let here = on_path(atoms, p);
        path_type(decl, p, &here).is_some_and(|t| unsat_path(t, &here))
    })
}

/// `implies(C2, C1)`: every atom of C1 is forced by C2's atoms on its path.
/// Vacuously true when C2 is unsatisfiable.
pub fn implies(decl: &Declaration, c2: &[&Atom], c1: &[&Atom]) -> bool {
    if unsat(decl, c2) {
        return true;
    }
    c1.iter().all(|b| {
        let here = on_path(c2, &b.path);
        match path_type(decl, &b.path, &[b]) {
            Some(t) => implies_path(t, &here, b),
            None => false,
        }
    })
}
