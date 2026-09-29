//! `Evaluate(scope, I)` (paper §6.3; SPEC §9.4).

use dc_cbor::{Key, Value};
use dc_types::{Identifier, Principal, is_identifier};

use crate::ast::{Atom, Decision, Literal, Op, Operand, Rule, Scope, ScopeForm, Type};
use crate::validate::{is_canonical_abs, seg_prefix};

/// The invocation I = (aud, tool, action, params).
#[derive(Clone, Copy, Debug)]
pub struct Invocation<'a> {
    pub aud: &'a Principal,
    pub tool: &'a Identifier,
    pub action: &'a Identifier,
    /// The parameter map (a text-keyed CBOR map).
    pub params: &'a Value,
}

/// A flattened parameter leaf. Byte strings, null, arrays and empty maps have
/// no type, and match no declaration (paper §6.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Leaf<'a> {
    Int(i128),
    Str(&'a str),
    Bool(bool),
    Untyped,
}

impl Leaf<'_> {
    fn ty(&self) -> Option<Type> {
        match self {
            Leaf::Int(_) => Some(Type::Int),
            Leaf::Str(_) => Some(Type::String),
            Leaf::Bool(_) => Some(Type::Bool),
            Leaf::Untyped => None,
        }
    }
}

/// Flattens nested maps to leaf paths joined by `.`, sorted by path. `None`
/// if any key fails the identifier grammar, in which case the invocation
/// matches no rule (D-23). A top-level empty map has no leaves; a nested
/// empty map is an untyped leaf.
pub fn flatten(params: &Value) -> Option<Vec<(String, Leaf<'_>)>> {
    fn walk<'a>(prefix: &str, m: &'a [(Key, Value)], out: &mut Vec<(String, Leaf<'a>)>) -> bool {
        for (k, v) in m {
            let Key::Text(k) = k else { return false };
            if !is_identifier(k) {
                return false;
            }
            let path = if prefix.is_empty() {
                k.clone()
            } else {
                format!("{prefix}.{k}")
            };
            let leaf = match v {
                Value::Map(inner) if !inner.is_empty() => {
                    if !walk(&path, inner, out) {
                        return false;
                    }
                    continue;
                }
                Value::Int(n) => Leaf::Int(*n),
                Value::Text(s) => Leaf::Str(s),
                Value::Bool(b) => Leaf::Bool(*b),
                _ => Leaf::Untyped,
            };
            out.push((path, leaf));
        }
        true
    }
    let top = params.as_map()?;
    let mut out = Vec::with_capacity(top.len());
    if !walk("", top, &mut out) {
        return None;
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Some(out)
}

fn lookup<'a, 'b>(leaves: &'b [(String, Leaf<'a>)], path: &str) -> Option<&'b Leaf<'a>> {
    leaves
        .binary_search_by(|(p, _)| p.as_str().cmp(path))
        .ok()
        .map(|i| &leaves[i].1)
}

fn lit_matches(l: &Literal, leaf: &Leaf<'_>) -> bool {
    match (l, leaf) {
        (Literal::Int(a), Leaf::Int(b)) => a == b,
        (Literal::Str(a), Leaf::Str(b)) => a == b,
        (Literal::Bool(a), Leaf::Bool(b)) => a == b,
        _ => false,
    }
}

/// Atom semantics (SPEC §9.4). String operators are bytewise; parameter
/// values and literals are NFC (paper §4.4, §6.1). A value that is not a
/// canonical absolute path fails `under`.
pub fn atom_holds(a: &Atom, leaf: &Leaf<'_>) -> bool {
    match (&a.op, &a.operand, leaf) {
        (Op::Lt, Operand::One(Literal::Int(c)), Leaf::Int(v)) => v < c,
        (Op::Le, Operand::One(Literal::Int(c)), Leaf::Int(v)) => v <= c,
        (Op::Ge, Operand::One(Literal::Int(c)), Leaf::Int(v)) => v >= c,
        (Op::Gt, Operand::One(Literal::Int(c)), Leaf::Int(v)) => v > c,
        (Op::Eq, Operand::One(l), leaf) => lit_matches(l, leaf),
        (Op::StartsWith, Operand::One(Literal::Str(c)), Leaf::Str(v)) => v.starts_with(c.as_str()),
        (Op::EndsWith, Operand::One(Literal::Str(c)), Leaf::Str(v)) => v.ends_with(c.as_str()),
        (Op::Contains, Operand::One(Literal::Str(c)), Leaf::Str(v)) => v.contains(c.as_str()),
        (Op::In, Operand::List(l), leaf) => l.iter().any(|x| lit_matches(x, leaf)),
        (Op::Under, Operand::One(Literal::Str(q)), Leaf::Str(v)) => {
            is_canonical_abs(v) && seg_prefix(q, v)
        }
        _ => false,
    }
}

/// Steps 1(a)–(d) for one rule.
fn rule_matches(r: &Rule, inv: &Invocation<'_>, leaves: &[(String, Leaf<'_>)]) -> bool {
    // (a) audience, tool, action.
    if &r.at != inv.aud || &r.tool != inv.tool || &r.action != inv.action {
        return false;
    }
    // (b) closed world: the leaf paths are exactly the declared ones, with the
    // declared types. Both lists are sorted by path.
    if leaves.len() != r.params.len()
        || !leaves
            .iter()
            .zip(&r.params)
            .all(|((lp, leaf), (dp, dt))| lp == dp && leaf.ty() == Some(*dt))
    {
        return false;
    }
    // (c) and (d). Step (c) never fires for a well-formed rule (D-28), but it
    // stays as a defensive check.
    r.atoms
        .iter()
        .all(|a| lookup(leaves, &a.path).is_some_and(|leaf| atom_holds(a, leaf)))
}

/// `Evaluate(S, I)`: `allow all` and `deny all` directly; otherwise the first
/// matching rule in declaration order decides; with no match, `deny`.
pub fn evaluate(scope: &Scope, inv: &Invocation<'_>) -> Decision {
    let rules = match scope.form() {
        ScopeForm::AllowAll => return Decision::Allow,
        ScopeForm::DenyAll => return Decision::Deny,
        ScopeForm::Rules(r) => r,
    };
    let Some(leaves) = flatten(inv.params) else {
        return Decision::Deny;
    };
    for r in rules {
        if rule_matches(r, inv, &leaves) {
            return if r.approval.is_empty() {
                Decision::Allow
            } else {
                Decision::AllowWithApproval(r.approval.iter().cloned().collect())
            };
        }
    }
    Decision::Deny
}
