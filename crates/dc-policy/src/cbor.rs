//! The canonical CBOR form of a scope (SPEC §9.2, D-18):
//!
//! ```text
//! Scope := {1: 0} | {1: 1} | {1: 2, 2: [Rule, ...]}
//! Rule  := {1: at, 2: tool, 3: action, 4: {path: type}?, 5: [Atom]?, 6: [principal]?}
//! Atom  := [op, path, operand]
//! ```

use std::collections::BTreeSet;

use dc_cbor::nfc::is_nfc_deep;
use dc_cbor::schema::{Fields, tuple};
use dc_cbor::{Key, Limits, Value, decode_strict, encode};
use dc_types::digest::{Digest32, policy_hash};
use dc_types::{Identifier, Principal, RawScope};

use crate::ast::{Atom, Declaration, Literal, Op, Operand, Rule, Scope, ScopeForm, Type};
use crate::error::{PolicyError, malformed};

const FORM_ALLOW_ALL: u64 = 0;
const FORM_DENY_ALL: u64 = 1;
const FORM_RULES: u64 = 2;

fn literal_value(l: &Literal) -> Value {
    match l {
        Literal::Int(n) => Value::Int(*n),
        Literal::Str(s) => Value::text(s.clone()),
        Literal::Bool(b) => Value::Bool(*b),
    }
}

fn literal_of(v: &Value) -> Result<Literal, PolicyError> {
    match v {
        Value::Int(n) => Ok(Literal::Int(*n)),
        Value::Text(s) => Ok(Literal::Str(s.clone())),
        Value::Bool(b) => Ok(Literal::Bool(*b)),
        _ => malformed("atom operand is not an integer, string or boolean"),
    }
}

impl Scope {
    pub fn to_value(&self) -> Value {
        match self.form() {
            ScopeForm::AllowAll => Value::Map(vec![(Key::Uint(1), Value::uint(FORM_ALLOW_ALL))]),
            ScopeForm::DenyAll => Value::Map(vec![(Key::Uint(1), Value::uint(FORM_DENY_ALL))]),
            ScopeForm::Rules(rules) => Value::Map(vec![
                (Key::Uint(1), Value::uint(FORM_RULES)),
                (
                    Key::Uint(2),
                    Value::Array(rules.iter().map(rule_value).collect()),
                ),
            ]),
        }
    }

    pub fn to_raw(&self) -> RawScope {
        RawScope(self.to_value())
    }

    /// Canonical encoding: the policy document for policies (D-18).
    pub fn canonical_bytes(&self) -> Vec<u8> {
        encode(&self.to_value()).expect("a validated scope always encodes")
    }

    /// `policy_hash` of this scope as a policy document.
    pub fn policy_hash(&self) -> Digest32 {
        policy_hash(&self.canonical_bytes())
    }

    /// Parses and validates a scope AST. Used for scopes in session and
    /// delegation bodies, where a malformed scope is a line-2 rejection
    /// (D-28). NFC is not checked here: a body with non-NFC scope text is a
    /// canonical-form violation, which `dc-types` records for line 5 (D-55).
    pub fn from_value(v: &Value) -> Result<Scope, PolicyError> {
        Scope::new(form_of(v)?)
    }

    pub fn from_raw(raw: &RawScope) -> Result<Scope, PolicyError> {
        Scope::from_value(&raw.0)
    }

    /// Decodes a policy document for `LoadPolicy` (Algorithm 2 line 31). It
    /// must be canonical CBOR, all text must be NFC, the scope must be
    /// well-formed, and re-encoding must give back the same bytes. Any
    /// failure makes the policy unavailable (D-12, D-55).
    pub fn decode_policy(bytes: &[u8]) -> Result<Scope, PolicyError> {
        let v = decode_strict(bytes, Limits::BODY)
            .map_err(|e| PolicyError::Malformed(format!("policy is not canonical CBOR: {e}")))?;
        if !is_nfc_deep(&v) {
            return malformed("policy text is not NFC (D-55)");
        }
        let scope = Scope::from_value(&v)?;
        if scope.canonical_bytes() != bytes {
            return malformed("policy AST is not in canonical form");
        }
        Ok(scope)
    }
}

fn rule_value(r: &Rule) -> Value {
    let mut m = vec![
        (Key::Uint(1), Value::text(r.at.as_str())),
        (Key::Uint(2), Value::text(r.tool.as_str())),
        (Key::Uint(3), Value::text(r.action.as_str())),
    ];
    if !r.params.is_empty() {
        let decl = r
            .params
            .iter()
            .map(|(p, t)| (Key::Text(p.clone()), Value::uint(t.code())));
        m.push((
            Key::Uint(4),
            Value::map(decl).expect("declaration keys are unique"),
        ));
    }
    if !r.atoms.is_empty() {
        let atoms = r
            .atoms
            .iter()
            .map(|a| {
                let operand = match &a.operand {
                    Operand::One(l) => literal_value(l),
                    Operand::List(l) => Value::Array(l.iter().map(literal_value).collect()),
                };
                Value::Array(vec![
                    Value::uint(a.op.code()),
                    Value::text(a.path.clone()),
                    operand,
                ])
            })
            .collect();
        m.push((Key::Uint(5), Value::Array(atoms)));
    }
    if !r.approval.is_empty() {
        m.push((
            Key::Uint(6),
            Value::Array(r.approval.iter().map(|p| Value::text(p.as_str())).collect()),
        ));
    }
    Value::Map(m)
}

fn schema(e: dc_cbor::schema::SchemaError) -> PolicyError {
    PolicyError::Malformed(e.to_string())
}

fn form_of(v: &Value) -> Result<ScopeForm, PolicyError> {
    let mut f = Fields::new("Scope", v).map_err(schema)?;
    let form = f.get(1, Value::as_u64).map_err(schema)?;
    let form = match form {
        FORM_ALLOW_ALL => ScopeForm::AllowAll,
        FORM_DENY_ALL => ScopeForm::DenyAll,
        FORM_RULES => {
            let rules = f.req(2).map_err(schema)?;
            let rules = rules
                .as_array()
                .ok_or_else(|| PolicyError::Malformed("rules is not an array".into()))?;
            ScopeForm::Rules(rules.iter().map(rule_of).collect::<Result<_, _>>()?)
        }
        other => return malformed(format!("unknown scope form {other}")),
    };
    f.finish().map_err(schema)?;
    Ok(form)
}

fn text_field<T>(
    f: &mut Fields<'_>,
    key: u64,
    parse: impl FnOnce(&str) -> Option<T>,
    what: &str,
) -> Result<T, PolicyError> {
    let v = f.req(key).map_err(schema)?;
    v.as_text()
        .and_then(parse)
        .ok_or_else(|| PolicyError::Malformed(format!("rule {what} is invalid")))
}

fn rule_of(v: &Value) -> Result<Rule, PolicyError> {
    let mut f = Fields::new("Rule", v).map_err(schema)?;
    let at = text_field(&mut f, 1, |s| Principal::parse(s).ok(), "at")?;
    let tool = text_field(&mut f, 2, |s| Identifier::new(s).ok(), "tool")?;
    let action = text_field(&mut f, 3, |s| Identifier::new(s).ok(), "action")?;

    let mut params = Declaration::new();
    if let Some(d) = f.opt(4) {
        let entries = d
            .as_map()
            .ok_or_else(|| PolicyError::Malformed("params is not a map".into()))?;
        if entries.is_empty() {
            return malformed("params present but empty (SPEC §9.2: omitted when none)");
        }
        for (k, t) in entries {
            let (Key::Text(path), Some(ty)) = (k, t.as_u64().and_then(Type::from_code)) else {
                return malformed("params entry is not path: type (D-33)");
            };
            params.insert(path.clone(), ty);
        }
    }

    let mut atoms = vec![];
    if let Some(a) = f.opt(5) {
        let items = a
            .as_array()
            .ok_or_else(|| PolicyError::Malformed("where is not an array".into()))?;
        if items.is_empty() {
            return malformed("where present but empty (SPEC §9.2: omitted when none)");
        }
        for item in items {
            let parts = tuple("Atom", item, 3).map_err(schema)?;
            let op = parts[0]
                .as_u64()
                .and_then(Op::from_code)
                .ok_or_else(|| PolicyError::Malformed("unknown atom operator".into()))?;
            let path = parts[1]
                .as_text()
                .ok_or_else(|| PolicyError::Malformed("atom path is not text".into()))?
                .to_owned();
            let operand = match (op, &parts[2]) {
                (Op::In, Value::Array(l)) => {
                    Operand::List(l.iter().map(literal_of).collect::<Result<_, _>>()?)
                }
                (Op::In, _) => return malformed("`in` needs a list"),
                (_, x) => Operand::One(literal_of(x)?),
            };
            atoms.push(Atom { op, path, operand });
        }
    }

    let mut approval = BTreeSet::new();
    if let Some(a) = f.opt(6) {
        let items = a
            .as_array()
            .ok_or_else(|| PolicyError::Malformed("approval is not an array".into()))?;
        if items.is_empty() {
            return malformed("approval present but empty (SPEC §9.2: omitted when none)");
        }
        let mut prev: Option<Principal> = None;
        for item in items {
            let p = item
                .as_text()
                .and_then(|s| Principal::parse(s).ok())
                .ok_or_else(|| {
                    PolicyError::Malformed("approval entry is not a principal".into())
                })?;
            if prev.as_ref().is_some_and(|q| q >= &p) {
                return malformed("approval set not sorted and deduplicated (D-18)");
            }
            prev = Some(p.clone());
            approval.insert(p);
        }
    }
    f.finish().map_err(schema)?;
    Ok(Rule {
        at,
        tool,
        action,
        params,
        atoms,
        approval,
    })
}
