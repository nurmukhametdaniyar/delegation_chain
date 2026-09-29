//! The differential oracle (SPEC §9.7), the most important test in the
//! repository.
//!
//! Universe: 2 audiences, 2 tools, 1 action; declarations drawn from subsets
//! of {x: int, s: string, f: bool}; int constants in [−2, 6] plus −2⁶⁴ and
//! 2⁶⁴ − 1; a string set with canonical paths, non-canonical paths, a
//! near-miss prefix, short words and the empty string; 2 approvers. The
//! generator also puts atoms on undeclared paths and `under` on
//! non-canonical literals, and the test asserts that the validator rejects
//! exactly those scopes (D-28, paper §6.1).
//!
//! Oracle: Definition 1, checked exhaustively over the enumerated
//! invocations: ints in [−4, 8] plus −2⁶⁴, −2⁶⁴ + 1, 2⁶⁴ − 2 and 2⁶⁴ − 1; the
//! string set plus every concatenation of two members; both booleans; every
//! declaration shape; and two shapes no rule can declare.
//!
//! Assertions: (i) `Contains` true ⇒ no counterexample; (ii) reflexivity;
//! (iii) the same soundness property for `implies` and `unsat`, per type.
//! Completeness (the share of oracle-contained pairs that `Contains`
//! accepts) is reported, not asserted. Completeness is relative to the
//! bounded oracle, so for strings without a finite set it is a lower bound.
//!
//! Scale: `DC_ORACLE_CASES` sets the number of generated pairs (default
//! 4,096; the M4 record used 150,000 in release mode, see
//! `docs/test-reports/policy-oracle-m4.json`). `DC_ORACLE_REPORT`
//! names a JSON file to write the statistics to. Runs are deterministic for
//! a given `DC_ORACLE_SEED`.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

use dc_cbor::{INT_MAX, INT_MIN, Key, Value};
use dc_policy::logic::{implies as logic_implies, implies_path, unsat as logic_unsat, unsat_path};
use dc_policy::validate::is_canonical_abs;
use dc_policy::{
    Atom, Decision, Declaration, Invocation, Leaf, Literal, Op, Operand, Rule, Scope, ScopeForm,
    Type, atom_holds, contains, evaluate, subsumes,
};
use dc_types::{Identifier, Principal};
use proptest::collection::vec;
use proptest::prelude::*;
use proptest::test_runner::{Config, RngAlgorithm, TestRng, TestRunner};

// ---------------------------------------------------------------- universe

const AUDS: [&str; 2] = ["orgb:service:v1", "orgb:service:v2"];
const TOOLS: [&str; 2] = ["t1", "t2"];
const APPROVERS: [&str; 2] = ["orga:approver:p", "orga:approver:q"];
const PATHS: [(&str, Type); 3] = [("x", Type::Int), ("s", Type::String), ("f", Type::Bool)];

const CANONICAL: [&str; 6] = [
    "/",
    "/a",
    "/a/b",
    "/b",
    "/home/agent/workspace",
    "/home/agent/workspace/x",
];
const NON_CANONICAL: [&str; 3] = ["/a/../b", "//a", "/a/"];
const WORDS: [&str; 7] = [
    "",
    "a",
    "b",
    "ab",
    "ba",
    "abc",
    "/home/agent/workspace-evil",
];

fn int_constants() -> Vec<i128> {
    let mut v: Vec<i128> = (-2..=6).collect();
    v.push(INT_MIN);
    v.push(INT_MAX);
    v
}

fn str_constants() -> Vec<&'static str> {
    CANONICAL
        .iter()
        .chain(&NON_CANONICAL)
        .chain(&WORDS)
        .copied()
        .collect()
}

struct Universe {
    auds: Vec<Principal>,
    tools: Vec<Identifier>,
    action: Identifier,
    ints: Vec<i128>,
    strs: Vec<String>,
    /// A richer string domain (concatenations of up to three constants),
    /// used only to show how much of the bounded oracle's string
    /// incompleteness is an artifact of `strs` being small.
    strs3: Vec<String>,
    /// Parameter maps for each declaration mask (bit 0 x, bit 1 s, bit 2 f).
    by_mask: Vec<Vec<Value>>,
    /// Shapes no rule of the universe can declare.
    extra: Vec<Value>,
}

fn universe() -> &'static Universe {
    static U: OnceLock<Universe> = OnceLock::new();
    U.get_or_init(|| {
        let mut ints: Vec<i128> = (-4..=8).collect();
        ints.extend([INT_MIN, INT_MIN + 1, INT_MAX - 1, INT_MAX]);
        let base = str_constants();
        let mut strs: BTreeSet<String> = base.iter().map(|s| s.to_string()).collect();
        for a in &base {
            for b in &base {
                strs.insert(format!("{a}{b}"));
            }
        }
        let strs: Vec<String> = strs.into_iter().collect();
        let mut strs3: BTreeSet<String> = strs.iter().cloned().collect();
        for a in &base {
            for b in &base {
                for c in &base {
                    strs3.insert(format!("{a}{b}{c}"));
                }
            }
        }
        let strs3: Vec<String> = strs3.into_iter().collect();
        let mut by_mask = vec![];
        for mask in 0u8..8 {
            let mut maps: Vec<Vec<(Key, Value)>> = vec![vec![]];
            for (bit, (name, ty)) in PATHS.iter().enumerate() {
                if mask & (1 << bit) == 0 {
                    continue;
                }
                let values: Vec<Value> = match ty {
                    Type::Int => ints.iter().map(|n| Value::Int(*n)).collect(),
                    Type::String => strs.iter().map(|s| Value::text(s.clone())).collect(),
                    Type::Bool => vec![Value::Bool(false), Value::Bool(true)],
                };
                maps = maps
                    .into_iter()
                    .flat_map(|m| {
                        values.iter().map(move |v| {
                            let mut m = m.clone();
                            m.push((Key::from(*name), v.clone()));
                            m
                        })
                    })
                    .collect();
            }
            by_mask.push(maps.into_iter().map(|m| Value::map(m).unwrap()).collect());
        }
        let extra = vec![
            Value::map(vec![(Key::from("y"), Value::uint(0))]).unwrap(),
            Value::map(vec![(Key::from("x"), Value::Null)]).unwrap(),
        ];
        Universe {
            auds: AUDS.iter().map(|a| Principal::parse(a).unwrap()).collect(),
            tools: TOOLS.iter().map(|t| Identifier::new(*t).unwrap()).collect(),
            action: Identifier::new("a").unwrap(),
            ints,
            strs,
            strs3,
            by_mask,
            extra,
        }
    })
}

fn mask_of(d: &Declaration) -> u8 {
    PATHS
        .iter()
        .enumerate()
        .filter(|(_, (n, _))| d.contains_key(*n))
        .fold(0, |m, (i, _)| m | (1 << i))
}

// ---------------------------------------------------------------- generator

fn atom_for(path: usize) -> BoxedStrategy<Atom> {
    let name = PATHS[path].0.to_owned();
    let int = prop::sample::select(int_constants());
    let s = prop::sample::select(str_constants());
    let mk = move |op: Op, operand: Operand| Atom {
        op,
        path: name.clone(),
        operand,
    };
    match PATHS[path].1 {
        Type::Int => {
            let mk2 = mk.clone();
            prop_oneof![
                5 => (prop::sample::select(vec![Op::Lt, Op::Le, Op::Eq, Op::Ge, Op::Gt]), int.clone())
                    .prop_map(move |(op, n)| mk(op, Operand::One(Literal::Int(n)))),
                1 => vec(int, 1..=3).prop_map(move |l| mk2(Op::In, Operand::List(l.into_iter().map(Literal::Int).collect()))),
            ]
            .boxed()
        }
        Type::String => {
            let (mk2, mk3) = (mk.clone(), mk.clone());
            let under = prop_oneof![
                5 => prop::sample::select(CANONICAL.to_vec()),
                1 => prop::sample::select(NON_CANONICAL.to_vec()),
            ];
            prop_oneof![
                4 => (prop::sample::select(vec![Op::Eq, Op::StartsWith, Op::EndsWith, Op::Contains]), s.clone())
                    .prop_map(move |(op, x)| mk(op, Operand::One(Literal::Str(x.to_owned())))),
                1 => vec(s, 1..=3).prop_map(move |l| mk2(Op::In, Operand::List(l.into_iter().map(|x| Literal::Str(x.to_owned())).collect()))),
                1 => under.prop_map(move |q| mk3(Op::Under, Operand::One(Literal::Str(q.to_owned())))),
            ]
            .boxed()
        }
        Type::Bool => {
            let mk2 = mk.clone();
            prop_oneof![
                any::<bool>().prop_map(move |b| mk(Op::Eq, Operand::One(Literal::Bool(b)))),
                vec(any::<bool>(), 1..=2).prop_map(move |l| mk2(
                    Op::In,
                    Operand::List(l.into_iter().map(Literal::Bool).collect())
                )),
            ]
            .boxed()
        }
    }
}

fn any_atom() -> BoxedStrategy<Atom> {
    prop_oneof![atom_for(0), atom_for(1), atom_for(2)].boxed()
}

fn rule() -> BoxedStrategy<Rule> {
    (0..2usize, 0..2usize, 0u8..8, 0u8..4)
        .prop_flat_map(|(aud, tool, mask, appr)| {
            let declared: Vec<usize> = (0..3).filter(|i| mask & (1 << i) != 0).collect();
            let atoms = if declared.is_empty() {
                // Rarely give an undeclared-path atom to a rule with no params.
                prop_oneof![9 => Just(vec![]).boxed(), 1 => vec(any_atom(), 1..=1).boxed()].boxed()
            } else {
                let on_declared = prop::sample::select(declared).prop_flat_map(atom_for);
                // 1 in 20 atoms names any path, possibly undeclared (D-28).
                vec(prop_oneof![19 => on_declared, 1 => any_atom()], 0..=3).boxed()
            };
            atoms.prop_map(move |atoms| {
                let u = universe();
                Rule {
                    at: u.auds[aud].clone(),
                    tool: u.tools[tool].clone(),
                    action: u.action.clone(),
                    params: PATHS
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| mask & (1 << i) != 0)
                        .map(|(_, (n, t))| (n.to_string(), *t))
                        .collect(),
                    atoms,
                    approval: APPROVERS
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| appr & (1 << i) != 0)
                        .map(|(_, a)| Principal::parse(a).unwrap())
                        .collect(),
                }
            })
        })
        .boxed()
}

fn scope() -> BoxedStrategy<ScopeForm> {
    prop_oneof![
        1 => Just(ScopeForm::AllowAll),
        1 => Just(ScopeForm::DenyAll),
        14 => vec(rule(), 1..=4).prop_map(ScopeForm::Rules),
    ]
    .boxed()
}

#[derive(Clone, Debug)]
enum Mutation {
    Keep,
    Drop,
    AddAtom(Atom),
    ReplaceAtom(prop::sample::Index, Atom),
    ToggleApproval(u8),
    SwapWithNext,
    Duplicate(Atom),
}

fn mutation() -> BoxedStrategy<Mutation> {
    prop_oneof![
        4 => Just(Mutation::Keep),
        2 => Just(Mutation::Drop),
        3 => any_atom().prop_map(Mutation::AddAtom),
        2 => (any::<prop::sample::Index>(), any_atom()).prop_map(|(i, a)| Mutation::ReplaceAtom(i, a)),
        2 => (1u8..4).prop_map(Mutation::ToggleApproval),
        1 => Just(Mutation::SwapWithNext),
        1 => any_atom().prop_map(Mutation::Duplicate),
    ]
    .boxed()
}

/// Makes an atom land on a declared path of `r` when it has one (so that
/// mutations mostly keep rules well-formed), keeping the atom otherwise.
fn retarget(r: &Rule, a: Atom) -> Atom {
    if r.params.contains_key(&a.path) || r.params.is_empty() {
        return a;
    }
    a
}

fn mutate(parent: &ScopeForm, muts: &[Mutation]) -> ScopeForm {
    let ScopeForm::Rules(rules) = parent else {
        return parent.clone();
    };
    let mut out: Vec<Rule> = vec![];
    for (r, m) in rules.iter().zip(muts.iter().cycle()) {
        let mut r = r.clone();
        match m {
            Mutation::Keep => {}
            Mutation::Drop => continue,
            Mutation::AddAtom(a) => r.atoms.push(retarget(&r, a.clone())),
            Mutation::ReplaceAtom(i, a) => {
                if !r.atoms.is_empty() {
                    let k = i.index(r.atoms.len());
                    r.atoms[k] = retarget(&r, a.clone());
                }
            }
            Mutation::ToggleApproval(bits) => {
                for (i, name) in APPROVERS.iter().enumerate() {
                    if bits & (1 << i) != 0 {
                        let p = Principal::parse(name).unwrap();
                        if !r.approval.remove(&p) {
                            r.approval.insert(p);
                        }
                    }
                }
            }
            Mutation::SwapWithNext => {
                out.push(r);
                let n = out.len();
                if n >= 2 {
                    out.swap(n - 1, n - 2);
                }
                continue;
            }
            Mutation::Duplicate(a) => {
                let mut copy = r.clone();
                copy.atoms.push(retarget(&copy, a.clone()));
                out.push(copy);
            }
        }
        out.push(r);
    }
    if out.is_empty() {
        ScopeForm::DenyAll
    } else {
        out.truncate(6);
        ScopeForm::Rules(out)
    }
}

/// A pair (S1, S2): half the time S2 is derived from S1 by mutation, so that
/// containment is often true or nearly so; otherwise independent.
fn pair() -> BoxedStrategy<(ScopeForm, ScopeForm)> {
    prop_oneof![
        1 => (scope(), scope()),
        1 => (scope(), vec(mutation(), 1..=4)).prop_map(|(s1, muts)| {
            let s2 = mutate(&s1, &muts);
            (s1, s2)
        }),
    ]
    .boxed()
}

/// What the validator must say: malformed exactly when some atom names an
/// undeclared path or `under` has a non-canonical literal.
fn expected_malformed(form: &ScopeForm) -> (bool, u64, u64) {
    let ScopeForm::Rules(rules) = form else {
        return (false, 0, 0);
    };
    let (mut undeclared, mut noncanon) = (0, 0);
    for r in rules {
        for a in &r.atoms {
            if !r.params.contains_key(&a.path) {
                undeclared += 1;
            }
            if let (Op::Under, Operand::One(Literal::Str(q))) = (a.op, &a.operand)
                && !is_canonical_abs(q)
            {
                noncanon += 1;
            }
        }
    }
    (undeclared + noncanon > 0, undeclared, noncanon)
}

// ---------------------------------------------------------------- oracle

fn accepts_with(d: &Decision) -> Option<BTreeSet<&Principal>> {
    d.approvals().map(|a| a.iter().collect())
}

fn eval(s: &Scope, aud: &Principal, tool: &Identifier, params: &Value) -> Decision {
    evaluate(
        s,
        &Invocation {
            aud,
            tool,
            action: &universe().action,
            params,
        },
    )
}

/// Definition 1 over the enumeration: a counterexample is an invocation S2
/// accepts that S1 denies, or accepts with an approval requirement S2 does
/// not impose.
fn counterexample(s1: &Scope, s2: &Scope) -> Option<String> {
    let u = universe();
    let check = |aud: &Principal, tool: &Identifier, params: &Value| -> Option<String> {
        let d2 = eval(s2, aud, tool, params);
        let a2 = accepts_with(&d2)?;
        let d1 = eval(s1, aud, tool, params);
        match accepts_with(&d1) {
            Some(a1) if a1.is_subset(&a2) => None,
            _ => Some(format!("{aud} {tool} {params:?}: S2 {d2:?}, S1 {d1:?}")),
        }
    };
    match s2.form() {
        ScopeForm::DenyAll => None,
        ScopeForm::AllowAll => {
            for aud in &u.auds {
                for tool in &u.tools {
                    for p in u.extra.iter().chain(u.by_mask.iter().flatten()) {
                        if let Some(c) = check(aud, tool, p) {
                            return Some(c);
                        }
                    }
                }
            }
            None
        }
        ScopeForm::Rules(rules) => {
            // Only invocations matching some rule head of S2 can be accepted
            // by S2, so enumerating those heads is complete.
            let heads: BTreeSet<(usize, usize, u8)> = rules
                .iter()
                .map(|r| {
                    let aud = u.auds.iter().position(|a| *a == r.at).unwrap();
                    let tool = u.tools.iter().position(|t| *t == r.tool).unwrap();
                    (aud, tool, mask_of(&r.params))
                })
                .collect();
            for (aud, tool, mask) in heads {
                for p in &u.by_mask[mask as usize] {
                    if let Some(c) = check(&u.auds[aud], &u.tools[tool], p) {
                        return Some(c);
                    }
                }
            }
            None
        }
    }
}

// ---------------------------------------------------------------- miss causes

/// Where `Contains` first returns false, replayed step by step through the
/// public API (`subsumes`, `logic::unsat`, `logic::implies`), mirroring the
/// procedure of paper §6.4. The test asserts that the replay agrees with
/// `contains` on every pair.
#[derive(Clone, Copy, Debug)]
enum Failure {
    /// S2 is `allow all`, or S1 is `deny all` against rules.
    SpecialForm,
    /// Step 3(a): no rule of S1 subsumes S2's rule `j`.
    NoSubsumer { j: usize },
    /// Step 3(b): S1's rule `ip`, before the subsuming rule, blocks S2's rule `j`.
    Blocked { j: usize, ip: usize },
}

fn rules_of(s: &Scope) -> &[Rule] {
    match s.form() {
        ScopeForm::Rules(r) => r,
        _ => &[],
    }
}

fn atoms_of(r: &Rule) -> Vec<&Atom> {
    r.atoms.iter().collect()
}

fn trace(s1: &Scope, s2: &Scope) -> Option<Failure> {
    match (s1.form(), s2.form()) {
        (ScopeForm::AllowAll, _) | (_, ScopeForm::DenyAll) => return None,
        (_, ScopeForm::AllowAll) | (ScopeForm::DenyAll, _) => return Some(Failure::SpecialForm),
        _ => {}
    }
    let (r1s, r2s) = (rules_of(s1), rules_of(s2));
    for (j, r2) in r2s.iter().enumerate() {
        let Some(i1) = r1s.iter().position(|r1| subsumes(r1, r2)) else {
            return Some(Failure::NoSubsumer { j });
        };
        for (ip, rp) in r1s[..i1].iter().enumerate() {
            if !rp.same_head(r2) {
                continue;
            }
            let joint: Vec<&Atom> = rp.atoms.iter().chain(&r2.atoms).collect();
            if logic_unsat(&r2.params, &joint) {
                continue;
            }
            let shadowed = r2s[..j].iter().any(|r2p| {
                r2p.same_head(rp) && logic_implies(&rp.params, &atoms_of(rp), &atoms_of(r2p))
            });
            if !shadowed && !rp.approval.is_subset(&r2.approval) {
                return Some(Failure::Blocked { j, ip });
            }
        }
    }
    None
}

/// Values of a path type: the SPEC enumeration, or (strings only) the richer
/// one.
fn leaves(ty: Type, extended: bool) -> Vec<Leaf<'static>> {
    let u = universe();
    match ty {
        Type::Int => u.ints.iter().map(|n| Leaf::Int(*n)).collect(),
        Type::Bool => vec![Leaf::Bool(false), Leaf::Bool(true)],
        Type::String if extended => u.strs3.iter().map(|s| Leaf::Str(s)).collect(),
        Type::String => u.strs.iter().map(|s| Leaf::Str(s)).collect(),
    }
}

fn sat_on_path(ty: Type, atoms: &[&Atom], extended: bool) -> Vec<Leaf<'static>> {
    leaves(ty, extended)
        .into_iter()
        .filter(|v| atoms.iter().all(|a| atom_holds(a, v)))
        .collect()
}

/// Semantic `unsat` and `implies` over the enumerated domain. A head's
/// invocations are the product of its paths' domains, so both factor per
/// path.
fn sem_unsat(decl: &Declaration, atoms: &[&Atom], extended: bool) -> bool {
    decl.iter().any(|(p, ty)| {
        let here: Vec<&Atom> = atoms.iter().copied().filter(|a| a.path == *p).collect();
        !here.is_empty() && sat_on_path(*ty, &here, extended).is_empty()
    })
}

fn sem_implies(decl: &Declaration, c2: &[&Atom], c1: &[&Atom], extended: bool) -> bool {
    if sem_unsat(decl, c2, extended) {
        return true;
    }
    c1.iter().all(|b| {
        let here: Vec<&Atom> = c2.iter().copied().filter(|a| a.path == b.path).collect();
        sat_on_path(decl[&b.path], &here, extended)
            .iter()
            .all(|v| atom_holds(b, v))
    })
}

/// Does any of these rules constrain a string path without an `==`/`in`?
fn has_open_string(rules: &[&Rule]) -> bool {
    rules.iter().any(|r| {
        r.atoms.iter().any(|a| {
            r.params.get(&a.path) == Some(&Type::String)
                && !r
                    .atoms
                    .iter()
                    .any(|b| b.path == a.path && matches!(b.op, Op::Eq | Op::In))
        })
    })
}

fn matches(r: &Rule, params: &Value) -> bool {
    let single = Scope::new(ScopeForm::Rules(vec![r.clone()])).expect("well-formed rule");
    eval(&single, &r.at, &r.tool, params) != Decision::Deny
}

/// The enumerated invocations of `r`'s head.
fn head_domain(r: &Rule) -> &'static [Value] {
    &universe().by_mask[mask_of(&r.params) as usize]
}

/// Do earlier rules with the same head match? Only those can match the same
/// invocations, since the declaration fixes the shape.
fn earlier_matches(rules: &[Rule], k: usize, params: &Value) -> bool {
    rules[..k]
        .iter()
        .any(|e| e.same_head(&rules[k]) && matches(e, params))
}

#[derive(Default)]
struct Misses {
    total: AtomicU64,
    union: AtomicU64,
    step_3b_child_cover: AtomicU64,
    step_3b_parent_shadow: AtomicU64,
    step_3b_both: AtomicU64,
    string_confirmed: AtomicU64,
    string_artifact: AtomicU64,
    unsat_child: AtomicU64,
    shadowed_child: AtomicU64,
    partly_shadowed_child: AtomicU64,
    exact_type_anomaly: AtomicU64,
}

enum Cause {
    Union,
    Step3b {
        child_cover: bool,
        parent_shadow: bool,
    },
    StringImplication {
        confirmed: bool,
    },
    /// The child rule can never match: its clause is unsatisfiable, or S2 is
    /// a rule list under a `deny all` parent that accepts nothing.
    UnsatChild,
    /// The child rule is satisfiable but every invocation it matches is
    /// decided by an earlier child rule.
    ShadowedChild,
    PartlyShadowedChild,
    ExactTypeAnomaly,
}

impl Misses {
    fn record(&self, c: Cause) {
        self.total.fetch_add(1, Relaxed);
        let slot = match c {
            Cause::Union => &self.union,
            Cause::Step3b {
                child_cover: true,
                parent_shadow: false,
            } => &self.step_3b_child_cover,
            Cause::Step3b {
                child_cover: false,
                parent_shadow: true,
            } => &self.step_3b_parent_shadow,
            Cause::Step3b { .. } => &self.step_3b_both,
            Cause::StringImplication { confirmed: true } => &self.string_confirmed,
            Cause::StringImplication { confirmed: false } => &self.string_artifact,
            Cause::UnsatChild => &self.unsat_child,
            Cause::ShadowedChild => &self.shadowed_child,
            Cause::PartlyShadowedChild => &self.partly_shadowed_child,
            Cause::ExactTypeAnomaly => &self.exact_type_anomaly,
        };
        slot.fetch_add(1, Relaxed);
    }

    fn json(&self) -> serde_json::Value {
        let g = |a: &AtomicU64| a.load(Relaxed);
        let step3b =
            g(&self.step_3b_child_cover) + g(&self.step_3b_parent_shadow) + g(&self.step_3b_both);
        serde_json::json!({
            "total": g(&self.total),
            "union of rules (Remark 1)": g(&self.union),
            "step 3(b) conservatism": {
                "total": step3b,
                "joint region decided by earlier child rules": g(&self.step_3b_child_cover),
                "joint region decided by earlier parent rules": g(&self.step_3b_parent_shadow),
                "both": g(&self.step_3b_both),
            },
            "string implication": {
                "total": g(&self.string_confirmed) + g(&self.string_artifact),
                "still holds on the richer string set": g(&self.string_confirmed),
                "artifact of the SPEC string set": g(&self.string_artifact),
            },
            "other": {
                "child rule unsatisfiable": g(&self.unsat_child),
                "child rule fully shadowed by earlier child rules": g(&self.shadowed_child),
                "child rule partly shadowed by earlier child rules": g(&self.partly_shadowed_child),
                "int/bool implication anomaly (expected 0)": g(&self.exact_type_anomaly),
            },
        })
    }
}

/// Assigns a miss (the oracle says contained, `Contains` says no) to a cause.
fn classify(s1: &Scope, s2: &Scope, failure: Failure) -> Cause {
    let (r1s, r2s) = (rules_of(s1), rules_of(s2));
    match failure {
        // S1 = deny all against rules is contained only if S2 accepts nothing.
        Failure::SpecialForm => Cause::UnsatChild,
        Failure::NoSubsumer { j } => {
            let r2 = &r2s[j];
            let live: Vec<&Value> = head_domain(r2)
                .iter()
                .filter(|p| matches(r2, p) && !earlier_matches(r2s, j, p))
                .collect();
            if live.is_empty() {
                return if sem_unsat(&r2.params, &atoms_of(r2), false) {
                    Cause::UnsatChild
                } else {
                    Cause::ShadowedChild
                };
            }
            let candidates: Vec<&Rule> = r1s
                .iter()
                .filter(|r1| r1.same_head(r2) && r1.approval.is_subset(&r2.approval))
                .collect();
            // A single parent rule semantically subsumes the whole child rule,
            // but `implies` said no.
            if let Some(r1) = candidates
                .iter()
                .find(|r1| sem_implies(&r2.params, &atoms_of(r2), &atoms_of(r1), false))
            {
                if !has_open_string(&[r1, r2]) {
                    return Cause::ExactTypeAnomaly;
                }
                let confirmed = sem_implies(&r2.params, &atoms_of(r2), &atoms_of(r1), true);
                return Cause::StringImplication { confirmed };
            }
            // A single parent rule covers the part of the child rule that is
            // not shadowed, but not the whole rule.
            if candidates
                .iter()
                .any(|r1| live.iter().all(|p| matches(r1, p)))
            {
                return Cause::PartlyShadowedChild;
            }
            Cause::Union
        }
        Failure::Blocked { j, ip } => {
            let (r2, rp) = (&r2s[j], &r1s[ip]);
            // The skip test (r′ implies some earlier r2′) holds semantically,
            // but `implies` missed it.
            let skip = r2s[..j].iter().find(|r2p| {
                r2p.same_head(rp) && sem_implies(&rp.params, &atoms_of(rp), &atoms_of(r2p), false)
            });
            let joint: Vec<&Atom> = rp.atoms.iter().chain(&r2.atoms).collect();
            if skip.is_some() || sem_unsat(&r2.params, &joint, false) {
                let mut involved: Vec<&Rule> = vec![rp, r2];
                involved.extend(skip);
                if !has_open_string(&involved) {
                    return Cause::ExactTypeAnomaly;
                }
                let confirmed = match skip {
                    Some(r2p) => sem_implies(&rp.params, &atoms_of(rp), &atoms_of(r2p), true),
                    None => sem_unsat(&r2.params, &joint, true),
                };
                return Cause::StringImplication { confirmed };
            }
            // The joint region is non-empty, yet (the pair being contained) no
            // invocation in it is decided by both r′ and r2. Record who decides
            // it instead.
            let (mut child_cover, mut parent_shadow) = (false, false);
            for p in head_domain(r2)
                .iter()
                .filter(|p| matches(rp, p) && matches(r2, p))
            {
                if earlier_matches(r2s, j, p) {
                    child_cover = true;
                } else if earlier_matches(r1s, ip, p) {
                    parent_shadow = true;
                }
            }
            Cause::Step3b {
                child_cover,
                parent_shadow,
            }
        }
    }
}

// ---------------------------------------------------------------- statistics

#[derive(Default)]
struct Counter {
    oracle_contained: AtomicU64,
    accepted: AtomicU64,
}

impl Counter {
    fn record(&self, contained: bool, accepted: bool) {
        if contained {
            self.oracle_contained.fetch_add(1, Relaxed);
            if accepted {
                self.accepted.fetch_add(1, Relaxed);
            }
        }
    }

    fn json(&self) -> serde_json::Value {
        let (c, a) = (
            self.oracle_contained.load(Relaxed),
            self.accepted.load(Relaxed),
        );
        serde_json::json!({
            "oracle_true": c,
            "procedure_true": a,
            "completeness": if c == 0 { serde_json::Value::Null } else { serde_json::json!(a as f64 / c as f64) },
        })
    }
}

#[derive(Default)]
struct Stats {
    cases: AtomicU64,
    wellformed_pairs: AtomicU64,
    malformed_scopes: AtomicU64,
    undeclared_atoms: AtomicU64,
    noncanonical_under: AtomicU64,
    reflexivity_checks: AtomicU64,
    contains_true: AtomicU64,
    soundness_violations: AtomicU64,
    reflexivity_failures: AtomicU64,
    overall: Counter,
    /// Pairs whose S2 has no unsatisfiable rule: closer to real policies,
    /// which do not contain contradictions.
    overall_satisfiable_children: Counter,
    by_category: [Counter; 6],
    misses: Misses,
}

const CATEGORIES: [&str; 6] = [
    "no atoms",
    "int",
    "bool",
    "string, finite set",
    "string, no finite set",
    "mixed",
];

/// The atom types a pair involves: int, bool, string with a finite set on
/// that path in that rule (an `==` or `in`), or string without.
fn category(forms: [&ScopeForm; 2]) -> usize {
    let mut kinds = BTreeSet::new();
    for f in forms {
        let ScopeForm::Rules(rules) = f else { continue };
        for r in rules {
            for a in &r.atoms {
                let k = match r.params.get(&a.path) {
                    Some(Type::Int) => 1,
                    Some(Type::Bool) => 2,
                    Some(Type::String) => {
                        let finite = r
                            .atoms
                            .iter()
                            .any(|b| b.path == a.path && matches!(b.op, Op::Eq | Op::In));
                        if finite { 3 } else { 4 }
                    }
                    None => 5,
                };
                kinds.insert(k);
            }
        }
    }
    match kinds.len() {
        0 => 0,
        1 => *kinds.iter().next().unwrap(),
        _ => 5,
    }
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn runner(seed: u64, shard: u64, cases: u32) -> TestRunner {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&seed.to_le_bytes());
    bytes[8..16].copy_from_slice(&shard.to_le_bytes());
    let config = Config {
        cases,
        failure_persistence: None,
        ..Config::default()
    };
    TestRunner::new_with_rng(config, TestRng::from_seed(RngAlgorithm::ChaCha, &bytes))
}

/// Work is split into a fixed number of shards, each with its own seed, and
/// the shards are scheduled on a pool of `DC_ORACLE_THREADS` threads (default:
/// all cores). Statistics are sums, so a run reproduces for a given seed
/// whatever the thread count or machine (D-58).
const SHARDS: u64 = 64;

fn run_sharded(total: u64, work: impl Fn(u64, u32) + Sync) {
    let threads = env_u64(
        "DC_ORACLE_THREADS",
        std::thread::available_parallelism()
            .map(|n| n.get() as u64)
            .unwrap_or(4),
    )
    .max(1);
    let next = AtomicU64::new(0);
    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| {
                loop {
                    let shard = next.fetch_add(1, Relaxed);
                    if shard >= SHARDS {
                        break;
                    }
                    let cases = total / SHARDS + u64::from(shard < total % SHARDS);
                    if cases > 0 {
                        work(shard, cases as u32);
                    }
                }
            });
        }
    });
}

// ---------------------------------------------------------------- the tests

#[derive(Default)]
struct LogicStats {
    cases: AtomicU64,
    soundness_violations: AtomicU64,
    implies: Counter,
    unsat: Counter,
    /// Strings only: the same, against the richer domain.
    implies_extended: Counter,
    unsat_extended: Counter,
}

/// (iii): `implies` and `unsat` per type, against the enumerated domain.
fn logic_check(ty_index: usize, stats: &[LogicStats; 4], seed: u64, total: u64) {
    let (name, ty) = PATHS[ty_index];
    let u = universe();
    let domain: Vec<Leaf<'_>> = match ty {
        Type::Int => u.ints.iter().map(|n| Leaf::Int(*n)).collect(),
        Type::String => u.strs.iter().map(|s| Leaf::Str(s)).collect(),
        Type::Bool => vec![Leaf::Bool(false), Leaf::Bool(true)],
    };
    let extended: Vec<Leaf<'_>> = match ty {
        Type::String => u.strs3.iter().map(|s| Leaf::Str(s)).collect(),
        _ => vec![],
    };
    let (domain, extended) = (&domain, &extended);
    run_sharded(total, |shard, cases| {
        {
            {
                let mut r = runner(seed ^ 0x1061c, shard + 64 * ty_index as u64, cases);
                let strategy = (vec(atom_for(ty_index), 0..=4), atom_for(ty_index));
                r.run(&strategy, |(c, b)| {
                    // `under` with a non-canonical literal is malformed and never
                    // reaches the procedures; leave it out of the statistics.
                    let malformed = |a: &Atom| {
                        matches!((a.op, &a.operand), (Op::Under, Operand::One(Literal::Str(q))) if !is_canonical_abs(q))
                    };
                    if c.iter().any(malformed) || malformed(&b) {
                        return Ok(());
                    }
                    let refs: Vec<&Atom> = c.iter().collect();
                    let sat: Vec<&Leaf<'_>> = domain.iter().filter(|v| refs.iter().all(|a| atom_holds(a, v))).collect();
                    let truth_unsat = sat.is_empty();
                    let truth_implies = sat.iter().all(|v| atom_holds(&b, v));
                    let (got_unsat, got_implies) = (unsat_path(ty, &refs), implies_path(ty, &refs, &b));
                    // Strings with an `==`/`in` atom are the finite-set case.
                    let slot = match ty {
                        Type::Int => 0,
                        Type::Bool => 1,
                        Type::String if c.iter().any(|a| matches!(a.op, Op::Eq | Op::In)) => 2,
                        Type::String => 3,
                    };
                    let st = &stats[slot];
                    st.cases.fetch_add(1, Relaxed);
                    st.implies.record(truth_implies, got_implies);
                    st.unsat.record(truth_unsat, got_unsat);
                    let mut sound = !(got_unsat && !truth_unsat) && !(got_implies && !truth_implies);
                    if !extended.is_empty() {
                        let sat: Vec<&Leaf<'_>> =
                            extended.iter().filter(|v| refs.iter().all(|a| atom_holds(a, v))).collect();
                        let (x_unsat, x_implies) = (sat.is_empty(), sat.iter().all(|v| atom_holds(&b, v)));
                        st.implies_extended.record(x_implies, got_implies);
                        st.unsat_extended.record(x_unsat, got_unsat);
                        sound &= !(got_unsat && !x_unsat) && !(got_implies && !x_implies);
                    }
                    if !sound {
                        st.soundness_violations.fetch_add(1, Relaxed);
                    }
                    prop_assert!(sound, "implies/unsat unsound on {name}: {c:?} ⇒ {b:?}");
                    Ok(())
                })
                .unwrap();
            }
        }
    });
}

#[test]
fn differential_oracle() {
    let total = env_u64("DC_ORACLE_CASES", 4096);
    let seed = env_u64("DC_ORACLE_SEED", 0xDC04);
    let stats = Stats::default();
    let start = std::time::Instant::now();

    let stats = &stats;
    run_sharded(total, |shard, cases| {
        {
            {
                let mut r = runner(seed, shard, cases);
                r.run(&pair(), |(f1, f2)| {
                    stats.cases.fetch_add(1, Relaxed);
                    let mut scopes = vec![];
                    for f in [&f1, &f2] {
                        let (expect_bad, undeclared, noncanon) = expected_malformed(f);
                        stats.undeclared_atoms.fetch_add(undeclared, Relaxed);
                        stats.noncanonical_under.fetch_add(noncanon, Relaxed);
                        let s = Scope::new(f.clone());
                        prop_assert_eq!(
                            s.is_err(),
                            expect_bad,
                            "validator disagrees on {:?}: {:?}",
                            f,
                            s
                        );
                        if let Ok(s) = s {
                            scopes.push(s);
                        } else {
                            stats.malformed_scopes.fetch_add(1, Relaxed);
                        }
                    }
                    for s in &scopes {
                        stats.reflexivity_checks.fetch_add(1, Relaxed);
                        if !contains(s, s) {
                            stats.reflexivity_failures.fetch_add(1, Relaxed);
                        }
                        prop_assert!(contains(s, s), "reflexivity fails for {}", s);
                    }
                    let [s1, s2] = scopes.as_slice() else {
                        return Ok(());
                    };
                    stats.wellformed_pairs.fetch_add(1, Relaxed);
                    let claimed = contains(s1, s2);
                    let ce = counterexample(s1, s2);
                    if claimed {
                        stats.contains_true.fetch_add(1, Relaxed);
                        if ce.is_some() {
                            stats.soundness_violations.fetch_add(1, Relaxed);
                        }
                    }
                    prop_assert!(
                        !claimed || ce.is_none(),
                        "UNSOUND: Contains true but {:?}\nS1:\n{}\nS2:\n{}",
                        ce,
                        s1,
                        s2
                    );
                    // The instrumented replay must agree with the procedure.
                    let failure = trace(s1, s2);
                    prop_assert_eq!(failure.is_none(), claimed, "trace disagrees with contains");
                    let contained = ce.is_none();
                    stats.overall.record(contained, claimed);
                    if !rules_of(s2)
                        .iter()
                        .any(|r| sem_unsat(&r.params, &atoms_of(r), false))
                    {
                        stats
                            .overall_satisfiable_children
                            .record(contained, claimed);
                    }
                    stats.by_category[category([s1.form(), s2.form()])].record(contained, claimed);
                    if contained && !claimed {
                        stats.misses.record(classify(s1, s2, failure.unwrap()));
                    }
                    Ok(())
                })
                .unwrap();
            }
        }
    });

    let logic: [LogicStats; 4] = Default::default();
    let per_type = env_u64("DC_ORACLE_LOGIC_CASES", total);
    for t in 0..3 {
        logic_check(t, &logic, seed, per_type);
    }

    let by_category: BTreeMap<&str, serde_json::Value> = CATEGORIES
        .iter()
        .zip(&stats.by_category)
        .map(|(n, c)| (*n, c.json()))
        .collect();
    let logic_json: BTreeMap<&str, serde_json::Value> =
        ["int", "bool", "string, finite set", "string, no finite set"]
            .iter()
            .zip(&logic)
            .map(|(n, s)| {
                (
                    *n,
                    serde_json::json!({
                        "cases": s.cases.load(Relaxed),
                        "soundness_violations": s.soundness_violations.load(Relaxed),
                        "implies": s.implies.json(),
                        "unsat": s.unsat.json(),
                        "implies_against_extended_strings": s.implies_extended.json(),
                        "unsat_against_extended_strings": s.unsat_extended.json(),
                    }),
                )
            })
            .collect();
    let report = serde_json::json!({
        "label": "dc-policy differential oracle (SPEC §9.7); test statistics, not benchmark results",
        "seed": seed,
        "contains": {
            "cases": stats.cases.load(Relaxed),
            "wellformed_pairs": stats.wellformed_pairs.load(Relaxed),
            "malformed_scopes_rejected": stats.malformed_scopes.load(Relaxed),
            "undeclared_path_atoms_generated": stats.undeclared_atoms.load(Relaxed),
            "noncanonical_under_generated": stats.noncanonical_under.load(Relaxed),
            "reflexivity_checks": stats.reflexivity_checks.load(Relaxed),
            "reflexivity_failures": stats.reflexivity_failures.load(Relaxed),
            "contains_true": stats.contains_true.load(Relaxed),
            "soundness_violations": stats.soundness_violations.load(Relaxed),
            "completeness_overall": stats.overall.json(),
            "completeness_by_category": by_category,
            "completeness_when_no_child_rule_is_unsatisfiable": stats.overall_satisfiable_children.json(),
            "misses_by_cause": stats.misses.json(),
        },
        "implies_unsat_by_type": logic_json,
        "enumeration": {
            "ints": universe().ints.len(),
            "strings": universe().strs.len(),
            "strings_extended": universe().strs3.len(),
            "invocations_per_audience_tool": universe().by_mask.iter().map(Vec::len).sum::<usize>() + universe().extra.len(),
        },
        "elapsed_seconds": start.elapsed().as_secs_f64(),
    });
    let text = serde_json::to_string_pretty(&report).unwrap();
    println!("{text}");
    if let Ok(path) = std::env::var("DC_ORACLE_REPORT") {
        std::fs::write(path, text + "\n").unwrap();
    }
    assert_eq!(stats.soundness_violations.load(Relaxed), 0);
    assert_eq!(stats.reflexivity_failures.load(Relaxed), 0);
    assert!(
        logic
            .iter()
            .all(|s| s.soundness_violations.load(Relaxed) == 0)
    );
    // The generator must actually produce undeclared-path atoms, or the
    // D-28 assertion above tests nothing.
    assert!(stats.undeclared_atoms.load(Relaxed) > 0);
    assert!(stats.wellformed_pairs.load(Relaxed) > 0);
}

/// Printing and parsing, and the CBOR form, round-trip every well-formed
/// generated scope.
#[test]
fn text_and_cbor_round_trip() {
    let mut r = runner(env_u64("DC_ORACLE_SEED", 0xDC04) ^ 0x7e57, 0, 2048);
    r.run(&scope(), |f| {
        let Ok(s) = Scope::new(f) else { return Ok(()) };
        let text = s.to_string();
        let parsed = Scope::parse(&text);
        prop_assert_eq!(parsed.as_ref(), Ok(&s), "text: {}", text);
        let from_cbor = Scope::from_value(&s.to_value());
        prop_assert_eq!(from_cbor.as_ref(), Ok(&s));
        let from_policy = Scope::decode_policy(&s.canonical_bytes());
        prop_assert_eq!(from_policy.as_ref(), Ok(&s));
        Ok(())
    })
    .unwrap();
}
