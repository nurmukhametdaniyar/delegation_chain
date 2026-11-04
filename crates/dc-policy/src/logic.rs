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
//!
//! The `*_counted` forms charge a [`Meter`] as SPEC §9.6.1's table says
//! (D-100). A check whose charge passes the budget skips its work and
//! weakens the constraint or answers false, both sound; `Contains` answers
//! false once the budget has run out in any case. The plain forms never
//! run out.

use std::collections::BTreeSet;

use dc_cbor::{INT_MAX, INT_MIN};

use crate::ast::{Atom, Declaration, Literal, Op, Operand, Type};
use crate::eval::{Leaf, atom_holds};
use crate::meter::{Meter, scan, size, weight, weights};
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
    fn new(atoms: &[&Atom], m: &Meter) -> Self {
        let mut c = IntC {
            lo: INT_MIN,
            hi: INT_MAX,
            set: None,
        };
        // Past the budget: the unconstrained path.
        if !m.charge(weights(atoms)) {
            return c;
        }
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
    fn finite(&self, m: &Meter) -> Option<Vec<i128>> {
        let s = self.set.as_ref()?;
        // Past the budget: the set is ignored, which only weakens the
        // constraint.
        if !m.charge(s.len()) {
            return None;
        }
        Some(
            s.iter()
                .copied()
                .filter(|v| (self.lo..=self.hi).contains(v))
                .collect(),
        )
    }

    fn unsat(&self, m: &Meter) -> bool {
        match self.finite(m) {
            Some(a) => a.is_empty(),
            None => self.lo > self.hi,
        }
    }

    fn implies(&self, b: &Atom, m: &Meter) -> bool {
        if self.unsat(m) {
            return true;
        }
        if let Some(a) = self.finite(m) {
            return m.charge(a.len() * weight(b))
                && a.iter().all(|v| atom_holds(b, &Leaf::Int(*v)));
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
                if !m.charge(list.len()) {
                    return false;
                }
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
    fn new(atoms: &[&Atom], m: &Meter) -> Self {
        let mut allowed = [true, true];
        // Past the budget: the unconstrained path.
        if !m.charge(weights(atoms)) {
            return BoolC { allowed };
        }
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

    fn implies(&self, b: &Atom, m: &Meter) -> bool {
        m.charge(2 * weight(b)) && self.values().all(|v| atom_holds(b, &Leaf::Bool(v)))
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
    fn new(atoms: &[&'a Atom], m: &Meter) -> Self {
        let mut c = StrC {
            atoms: vec![],
            e: None,
            p: vec![],
            s: vec![],
            k: vec![],
            u: vec![],
        };
        // Past the budget: the unconstrained path.
        if !m.charge(weights(atoms)) {
            return c;
        }
        c.atoms = atoms.to_vec();
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
    ///
    /// Exact. An `==` or `in` atom holds only for members of its set, so
    /// every satisfying value lies in the intersection E; filtering E by
    /// every atom yields precisely the satisfying values.
    fn admissible(&self, m: &Meter) -> Option<Vec<&'a str>> {
        let e = self.e.as_ref()?;
        // Each member against each atom: the atom's check, and for a
        // `contains` or `under` atom a scan of the member. Past the budget:
        // the set is ignored, which only weakens the constraint.
        let checks: usize = self.atoms.iter().map(|a| check(a)).sum();
        let scanning = self.k.len() + self.u.len();
        let extra: usize = e.iter().map(|v| scan(v) - 1).sum();
        if !m.charge(e.len() * checks + scanning * extra) {
            return None;
        }
        Some(
            e.iter()
                .copied()
                .filter(|v| self.atoms.iter().all(|a| atom_holds(a, &Leaf::Str(v))))
                .collect(),
        )
    }

    /// Returns true only when no string satisfies every atom. Each rule below
    /// states why it can never say `true` for a satisfiable conjunction.
    ///
    /// A fact used twice: if `v under q` holds, then `v` starts with `q` as a
    /// string. `v` is canonical, and `segments(q)` is a prefix of
    /// `segments(v)`, so `v` is `q`, or `q/…`, or (for `q = "/"`) some path
    /// beginning with `/`.
    fn unsat(&self, m: &Meter) -> bool {
        // Finite set: exact (see `admissible`).
        if let Some(a) = self.admissible(m) {
            return a.is_empty();
        }
        // Each pair compares two operands, at most the shorter's size.
        let sizes = |v: &[&str]| v.iter().map(|x| size(x)).sum::<usize>();
        let (p, s, u) = (self.p.len(), self.s.len(), self.u.len());
        if !m.charge(
            p * sizes(&self.p) + s * sizes(&self.s) + u * sizes(&self.u) + p * sizes(&self.u),
        ) {
            return false;
        }
        let prefix_compatible = |x: &str, y: &str| x.starts_with(y) || y.starts_with(x);
        let incompatible_pair = |v: &[&str], ok: &dyn Fn(&str, &str) -> bool| {
            v.iter()
                .enumerate()
                .any(|(i, x)| v[i + 1..].iter().any(|y| !ok(x, y)))
        };
        // Two `starts_with` operands, neither a prefix of the other: a string
        // starting with both has each as a prefix, and two prefixes of one
        // string are always nested.
        incompatible_pair(&self.p, &prefix_compatible)
            // Two `ends_with` operands, neither a suffix of the other: two
            // suffixes of one string are always nested.
            || incompatible_pair(&self.s, &|x, y| x.ends_with(y) || y.ends_with(x))
            // Two `under` operands, neither a segment prefix of the other: two
            // segment prefixes of one path's segment list are always nested.
            || incompatible_pair(&self.u, &|x, y| seg_prefix(x, y) || seg_prefix(y, x))
            // `starts_with p` and `under q` with p and q not nested as strings:
            // the value would start with both p and q (fact above), so p and q
            // would be nested.
            || self
                .p
                .iter()
                .any(|p| self.u.iter().any(|q| !prefix_compatible(p, q)))
    }

    /// Returns true only when every string satisfying the atoms satisfies
    /// `b`. Each rule below states why.
    fn implies(&self, b: &Atom, m: &Meter) -> bool {
        // Vacuous: nothing satisfies the atoms (sound because `unsat` is).
        if self.unsat(m) {
            return true;
        }
        // Finite set: exact (see `admissible`).
        if let Some(a) = self.admissible(m) {
            let extra: usize = if matches!(b.op, Op::Contains | Op::Under) {
                a.iter().map(|v| scan(v) - 1).sum()
            } else {
                0
            };
            return m.charge(a.len() * check(b) + extra)
                && a.iter().all(|v| atom_holds(b, &Leaf::Str(v)));
        }
        // Without a finite set, `in` and `==` are never implied: the answer
        // `false` is always sound.
        let Some(x) = str_of(&b.operand) else {
            return false;
        };
        // At most one test of `x` against every operand: a substring search
        // reads both, every other test less.
        let all = [&self.p, &self.s, &self.k, &self.u];
        let n: usize = all.iter().map(|v| v.len()).sum();
        let scanned: usize = all.iter().flat_map(|v| v.iter()).map(|y| scan(y)).sum();
        if !m.charge(scanned + n * (scan(x) - 1)) {
            return false;
        }
        match b.op {
            Op::StartsWith => {
                // Every string starts with "" (D-57).
                x.is_empty()
                    // v starts with p, and p starts with x, so v starts with x.
                    || self.p.iter().any(|p| p.starts_with(x))
                    // v under q means v starts with q (fact above); q starts with x.
                    || self.u.iter().any(|q| q.starts_with(x))
            }
            Op::EndsWith => {
                // Every string ends with "" (D-57); v ends with s, and s ends
                // with x, so v ends with x.
                x.is_empty() || self.s.iter().any(|s| s.ends_with(x))
            }
            Op::Contains => {
                // Every string contains "" (D-57). Otherwise v contains the
                // operand y of some `starts_with`, `ends_with`, `contains` or
                // `under` atom (for `under`, v starts with y by the fact
                // above), and y contains x, so v contains x.
                x.is_empty()
                    || self
                        .p
                        .iter()
                        .chain(&self.s)
                        .chain(&self.k)
                        .chain(&self.u)
                        .any(|y| y.contains(x))
            }
            // v is canonical, and segments(q) is a prefix of segments(v).
            // segments(x) is a prefix of segments(q), and prefixes compose, so
            // v is under x.
            Op::Under => self.u.iter().any(|q| seg_prefix(x, q)),
            // `==` without a finite set: never implied, so `false` is sound.
            _ => false,
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

/// What testing one string atom against one value costs, apart from
/// scanning the value: a `contains` operand is scanned, every other
/// operand compared.
fn check(a: &Atom) -> usize {
    match (&a.op, &a.operand) {
        (Op::Contains, Operand::One(Literal::Str(x))) => scan(x),
        _ => weight(a),
    }
}

/// The atoms on `path`, charging their selection and the lookup of the
/// path's declared type that follows. Past the budget, none: the
/// unconstrained path.
fn on_path<'a>(atoms: &[&'a Atom], path: &str, m: &Meter) -> Vec<&'a Atom> {
    if !m.charge((atoms.len() + 1) * size(path)) {
        return vec![];
    }
    atoms.iter().copied().filter(|a| a.path == path).collect()
}

/// Is the conjunction of atoms on one path, of type `ty`, unsatisfiable?
pub fn unsat_path(ty: Type, atoms: &[&Atom]) -> bool {
    unsat_path_counted(ty, atoms, &Meter::unlimited())
}

/// [`unsat_path`], charging `m`.
pub fn unsat_path_counted(ty: Type, atoms: &[&Atom], m: &Meter) -> bool {
    match ty {
        Type::Int => IntC::new(atoms, m).unsat(m),
        Type::Bool => BoolC::new(atoms, m).unsat(),
        Type::String => StrC::new(atoms, m).unsat(m),
    }
}

/// Do the atoms on one path, of type `ty`, force `b`?
pub fn implies_path(ty: Type, atoms: &[&Atom], b: &Atom) -> bool {
    implies_path_counted(ty, atoms, b, &Meter::unlimited())
}

/// [`implies_path`], charging `m`.
pub fn implies_path_counted(ty: Type, atoms: &[&Atom], b: &Atom, m: &Meter) -> bool {
    match ty {
        Type::Int => IntC::new(atoms, m).implies(b, m),
        Type::Bool => BoolC::new(atoms, m).implies(b, m),
        Type::String => StrC::new(atoms, m).implies(b, m),
    }
}

/// `unsat(C)` for a conjunction over the paths of `decl`: some path's
/// constraint is inconsistent.
pub fn unsat(decl: &Declaration, atoms: &[&Atom]) -> bool {
    unsat_counted(decl, atoms, &Meter::unlimited())
}

/// [`unsat`], charging `m`. Paths are checked in byte order.
pub fn unsat_counted(decl: &Declaration, atoms: &[&Atom], m: &Meter) -> bool {
    // Collecting, sorting and deduplicating the paths.
    if !m.charge(atoms.iter().map(|a| size(&a.path)).sum()) {
        return false;
    }
    let mut paths: Vec<&str> = atoms.iter().map(|a| a.path.as_str()).collect();
    paths.sort_unstable();
    paths.dedup();
    paths.into_iter().any(|p| {
        let here = on_path(atoms, p, m);
        !m.exhausted() && path_type(decl, p, &here).is_some_and(|t| unsat_path_counted(t, &here, m))
    })
}

/// `implies(C2, C1)`: every atom of C1 is forced by C2's atoms on its path.
/// Vacuously true when C2 is unsatisfiable.
pub fn implies(decl: &Declaration, c2: &[&Atom], c1: &[&Atom]) -> bool {
    implies_counted(decl, c2, c1, &Meter::unlimited())
}

/// [`implies`], charging `m`.
pub fn implies_counted(decl: &Declaration, c2: &[&Atom], c1: &[&Atom], m: &Meter) -> bool {
    if unsat_counted(decl, c2, m) {
        return true;
    }
    c1.iter().all(|b| {
        let here = on_path(c2, &b.path, m);
        !m.exhausted()
            && match path_type(decl, &b.path, &[b]) {
                Some(t) => implies_path_counted(t, &here, b, m),
                None => false,
            }
    })
}
