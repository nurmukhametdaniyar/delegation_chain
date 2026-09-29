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
use dc_policy::logic::{implies_path, unsat_path};
use dc_policy::validate::is_canonical_abs;
use dc_policy::{
    Atom, Decision, Declaration, Invocation, Leaf, Literal, Op, Operand, Rule, Scope, ScopeForm,
    Type, atom_holds, contains, evaluate,
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
    by_category: [Counter; 6],
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

fn shards(total: u64) -> Vec<(u64, u32)> {
    let n = std::thread::available_parallelism()
        .map(|n| n.get() as u64)
        .unwrap_or(4)
        .max(1);
    (0..n)
        .map(|i| (i, (total / n + u64::from(i < total % n)) as u32))
        .collect()
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
    std::thread::scope(|scope| {
        for (shard, cases) in shards(total) {
            let (domain, extended) = (&domain, &extended);
            scope.spawn(move || {
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
            });
        }
    });
}

#[test]
fn differential_oracle() {
    let total = env_u64("DC_ORACLE_CASES", 4096);
    let seed = env_u64("DC_ORACLE_SEED", 0xDC04);
    let stats = Stats::default();
    let start = std::time::Instant::now();

    std::thread::scope(|scope| {
        for (shard, cases) in shards(total) {
            let stats = &stats;
            scope.spawn(move || {
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
                    let contained = ce.is_none();
                    stats.overall.record(contained, claimed);
                    stats.by_category[category([s1.form(), s2.form()])].record(contained, claimed);
                    Ok(())
                })
                .unwrap();
            });
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
