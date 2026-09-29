//! Well-formedness (paper §6.1, revision 2026-09-29; SPEC §9.3) and size
//! limits (D-21).

use dc_cbor::{INT_MAX, INT_MIN};
use dc_types::{Kind, is_identifier};

use crate::ast::{Literal, Op, Operand, Rule, ScopeForm, Type};
use crate::error::{PolicyError, malformed};

/// Size limits (D-21).
pub const MAX_RULES: usize = 256;
pub const MAX_PARAMS: usize = 32;
pub const MAX_ATOMS: usize = 32;
pub const MAX_LIST: usize = 64;
pub const MAX_TEXT: usize = 1024;
pub const MAX_PATH_DEPTH: usize = 8;

/// `path ::= identifier ("." identifier)*`, at most 8 segments (D-21).
pub fn is_path(p: &str) -> bool {
    let mut n = 0;
    for seg in p.split('.') {
        n += 1;
        if n > MAX_PATH_DEPTH || !is_identifier(seg) {
            return false;
        }
    }
    true
}

/// A canonical absolute path (paper §6.1): `/` alone, or `/` followed by
/// non-empty segments joined by `/`, with no `.` or `..` segment and no
/// trailing `/`.
pub fn is_canonical_abs(p: &str) -> bool {
    if p == "/" {
        return true;
    }
    match p.strip_prefix('/') {
        Some(rest) => rest
            .split('/')
            .all(|seg| !seg.is_empty() && seg != "." && seg != ".."),
        None => false,
    }
}

/// `segments(q)` is a prefix of `segments(p)`, equality included (D-22).
/// Both must be canonical absolute paths.
pub fn seg_prefix(q: &str, p: &str) -> bool {
    if q == "/" {
        return true;
    }
    p == q || (p.starts_with(q) && p.as_bytes().get(q.len()) == Some(&b'/'))
}

/// `a` is a strict segment prefix of `b` (D-19): `a` and `a.b`.
fn strict_path_prefix(a: &str, b: &str) -> bool {
    b.len() > a.len() && b.starts_with(a) && b.as_bytes()[a.len()] == b'.'
}

fn check_text(s: &str, what: &str) -> Result<(), PolicyError> {
    if s.len() > MAX_TEXT {
        return malformed(format!("{what} longer than {MAX_TEXT} bytes (D-21)"));
    }
    Ok(())
}

fn check_literal(l: &Literal) -> Result<(), PolicyError> {
    match l {
        Literal::Int(n) if !(INT_MIN..=INT_MAX).contains(n) => {
            malformed("integer outside the CBOR range")
        }
        Literal::Str(s) => check_text(s, "string literal"),
        _ => Ok(()),
    }
}

pub(crate) fn validate_form(form: &ScopeForm) -> Result<(), PolicyError> {
    match form {
        ScopeForm::AllowAll | ScopeForm::DenyAll => Ok(()),
        ScopeForm::Rules(rules) => {
            if rules.is_empty() {
                return malformed("a rule list must have at least one rule");
            }
            if rules.len() > MAX_RULES {
                return malformed(format!("more than {MAX_RULES} rules (D-21)"));
            }
            rules.iter().try_for_each(validate_rule)
        }
    }
}

/// The three conditions of paper §6.1 "Well-formedness", plus D-21.
fn validate_rule(r: &Rule) -> Result<(), PolicyError> {
    // Condition 3: kinds of the principals.
    if r.at.kind() != Kind::Service {
        return malformed(format!("at names {}, which is not a service", r.at));
    }
    if let Some(p) = r.approval.iter().find(|p| p.kind() != Kind::Approver) {
        return malformed(format!("approval names {p}, which is not an approver"));
    }
    check_text(r.at.as_str(), "principal")?;
    check_text(r.tool.as_str(), "tool")?;
    check_text(r.action.as_str(), "action")?;
    for p in &r.approval {
        check_text(p.as_str(), "principal")?;
    }

    // Condition 1: declarations, and every where-path declared.
    if r.params.len() > MAX_PARAMS {
        return malformed(format!("more than {MAX_PARAMS} parameters (D-21)"));
    }
    for p in r.params.keys() {
        if !is_path(p) {
            return malformed(format!(
                "declared path {p:?} does not follow the path grammar"
            ));
        }
        check_text(p, "path")?;
    }
    for a in r.params.keys() {
        if let Some(b) = r.params.keys().find(|b| strict_path_prefix(a, b)) {
            return malformed(format!(
                "declared path {a:?} is a strict prefix of {b:?} (D-19)"
            ));
        }
    }
    if r.atoms.len() > MAX_ATOMS {
        return malformed(format!("more than {MAX_ATOMS} atoms (D-21)"));
    }
    for atom in &r.atoms {
        let Some(&ty) = r.params.get(&atom.path) else {
            return malformed(format!(
                "where clause names {:?}, which the rule does not declare (paper §6.1; D-28, P-15)",
                atom.path
            ));
        };
        // Condition 2: operator, declared type and operand.
        let ok = match (atom.op, &atom.operand) {
            (Op::Lt | Op::Le | Op::Ge | Op::Gt, Operand::One(Literal::Int(_))) => ty == Type::Int,
            (Op::Eq, Operand::One(l)) => l.ty() == ty,
            (Op::StartsWith | Op::EndsWith | Op::Contains, Operand::One(Literal::Str(_))) => {
                ty == Type::String
            }
            (Op::In, Operand::List(l)) => {
                if l.is_empty() || l.len() > MAX_LIST {
                    return malformed(format!("`in` list must have 1 to {MAX_LIST} elements"));
                }
                l.iter().all(|x| x.ty() == ty)
            }
            (Op::Under, Operand::One(Literal::Str(q))) => {
                if !is_canonical_abs(q) {
                    return malformed(format!(
                        "`under` operand {q:?} is not a canonical absolute path"
                    ));
                }
                ty == Type::String
            }
            _ => false,
        };
        if !ok {
            return malformed(format!(
                "`{} {} …` does not fit the declared type {ty} (paper §6.1; D-20)",
                atom.path,
                atom.op.text()
            ));
        }
        match &atom.operand {
            Operand::One(l) => check_literal(l)?,
            Operand::List(l) => l.iter().try_for_each(check_literal)?,
        }
    }
    Ok(())
}
