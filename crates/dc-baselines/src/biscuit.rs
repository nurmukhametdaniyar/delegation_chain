//! Arm E: Biscuit, via biscuit-auth 6.0 (SPEC §12.3; D-68).
//!
//! A positioning reference, not a like-for-like arm. Biscuit has no registry
//! resolution, no proof of possession, no revocation, no approval receipts,
//! no nonce cache and no parameter binding (paper Table 1).
//!
//! The mapping (D-68):
//!
//! - **Authority block** (the issuer's, DC's session body): a `right(aud,
//!   tool, action)` fact per rule of the session scope, an expiry check, and
//!   one check equivalent to the session scope.
//! - **One appended block per delegation**, each with an expiry check and a
//!   check equivalent to that delegation's scope. DC's N is Biscuit depth
//!   N − 1: depth 0 is the authority block alone, like DC's N = 1.
//! - **A scope as a check.** `check if body_1 or … or body_k`, one body per
//!   rule. A body requires the audience, tool and action; exactly the declared
//!   parameters, with their declared types (`param_count` and `.type()`); and
//!   every atom. A rule that requires approval also requires an
//!   `approved(service)` fact, which the authorizer never has, because
//!   Biscuit carries no receipts.
//! - **The authorizer**: facts `aud`, `tool`, `action`, `now`, `param_count`,
//!   and one `param(path, value)` per flattened parameter leaf (dc-policy's
//!   `flatten`). Policies: allow if the authority block grants the right, or
//!   grants `allow_all`.
//! - **Atoms.** Integer comparisons and `==` map directly; `starts_with`,
//!   `ends_with` and `contains` map to Biscuit's string methods; `in` to set
//!   membership. `under q` becomes `$p == q || $p.starts_with(q + "/")` (any
//!   value starting with `/` if q is `/`). Unlike DC, it does not check that
//!   the value is a canonical absolute path.
//! - **Differences from Evaluate.** DC's first matching rule decides; a check
//!   passes if any body matches. Where an approval rule precedes an
//!   overlapping permissive rule, Biscuit allows what DC sends for approval.
//!   Integers outside i64 get no `param` fact.
//!
//! Facts are built programmatically and the policies parsed once, so no
//! Datalog text is parsed in the timed operation beyond what the token
//! itself carries.

use std::collections::BTreeSet;
use std::time::Duration;

use biscuit_auth::builder::{
    Algorithm, AuthorizerBuilder, BlockBuilder, Policy, boolean, fact, int, string,
};
use biscuit_auth::datalog::SymbolTable;
use biscuit_auth::{AuthorizerLimits, Biscuit, KeyPair, PrivateKey, PublicKey};
use dc_cbor::Value;
use dc_policy::{Atom, Leaf, Literal, Op, Operand, Rule, Scope, ScopeForm, Type, flatten};
use dc_types::digest::sha256;
use dc_types::{Identifier, Principal};

pub use biscuit_auth::error::Token as BiscuitError;

/// What the verifier knows besides the token: the invocation and the time.
#[derive(Clone, Copy, Debug)]
pub struct Request<'a> {
    pub aud: &'a Principal,
    pub tool: &'a Identifier,
    pub action: &'a Identifier,
    pub params: &'a Value,
    pub now: u64,
}

/// Arm E's issuer and verifier, with a deterministic root key.
pub struct BiscuitArm {
    root: KeyPair,
    root_pk: PublicKey,
    policies: Vec<Policy>,
    limits: AuthorizerLimits,
}

const POLICIES: [&str; 2] = [
    "allow if right($aud, $tool, $action), aud($aud), tool($tool), action($action)",
    "allow if allow_all(true)",
];

fn keypair(seed: &[u8], label: &[u8]) -> KeyPair {
    let sk = PrivateKey::from_bytes(&sha256(&[b"dc-arm-e", seed, label]), Algorithm::Ed25519)
        .expect("32-byte Ed25519 seed");
    KeyPair::from(&sk)
}

/// A Datalog string literal.
fn q(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        if c == '"' || c == '\\' {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    out
}

fn lit(l: &Literal) -> String {
    match l {
        Literal::Int(i) => i.to_string(),
        Literal::Str(s) => q(s),
        Literal::Bool(b) => b.to_string(),
    }
}

fn type_name(t: Type) -> &'static str {
    match t {
        Type::Int => "integer",
        Type::String => "string",
        Type::Bool => "bool",
    }
}

fn atom_expr(a: &Atom, v: &str) -> String {
    match (&a.op, &a.operand) {
        (Op::Lt, Operand::One(l)) => format!("{v} < {}", lit(l)),
        (Op::Le, Operand::One(l)) => format!("{v} <= {}", lit(l)),
        (Op::Eq, Operand::One(l)) => format!("{v} == {}", lit(l)),
        (Op::Ge, Operand::One(l)) => format!("{v} >= {}", lit(l)),
        (Op::Gt, Operand::One(l)) => format!("{v} > {}", lit(l)),
        (Op::StartsWith, Operand::One(l)) => format!("{v}.starts_with({})", lit(l)),
        (Op::EndsWith, Operand::One(l)) => format!("{v}.ends_with({})", lit(l)),
        (Op::Contains, Operand::One(l)) => format!("{v}.contains({})", lit(l)),
        (Op::In, Operand::List(ls)) => {
            let items: Vec<String> = ls.iter().map(lit).collect();
            format!("{{{}}}.contains({v})", items.join(", "))
        }
        (Op::Under, Operand::One(Literal::Str(p))) if p == "/" => format!("{v}.starts_with(\"/\")"),
        (Op::Under, Operand::One(Literal::Str(p))) => {
            format!(
                "({v} == {} || {v}.starts_with({}))",
                q(p),
                q(&format!("{p}/"))
            )
        }
        // Unreachable for a well-formed scope (D-28).
        _ => "false".into(),
    }
}

/// One rule as a check body.
fn rule_body(r: &Rule) -> String {
    let mut parts = vec![
        "aud($aud), tool($tool), action($action)".to_owned(),
        format!(
            "$aud == {}, $tool == {}, $action == {}",
            q(r.at.as_str()),
            q(r.tool.as_str()),
            q(r.action.as_str())
        ),
        format!("param_count($n), $n == {}", r.params.len()),
    ];
    let var = |path: &str| {
        let j = r
            .params
            .keys()
            .position(|p| p == path)
            .unwrap_or(usize::MAX);
        format!("$p{j}")
    };
    for (path, ty) in &r.params {
        let v = var(path);
        parts.push(format!(
            "param({}, {v}), {v}.type() == {}",
            q(path),
            q(type_name(*ty))
        ));
    }
    for a in &r.atoms {
        parts.push(atom_expr(a, &var(&a.path)));
    }
    for s in &r.approval {
        parts.push(format!("approved({})", q(s.as_str())));
    }
    parts.join(", ")
}

/// A block's checks: expiry, and the scope.
pub fn block_code(scope: &Scope, exp: u64) -> String {
    let mut code = format!("check if now($now), $now <= {exp};\n");
    match scope.form() {
        ScopeForm::AllowAll => {}
        ScopeForm::DenyAll => code.push_str("check if false;\n"),
        ScopeForm::Rules(rules) => {
            let bodies: Vec<String> = rules.iter().map(rule_body).collect();
            code.push_str(&format!("check if {};\n", bodies.join(" or ")));
        }
    }
    code
}

/// The authority block's rights.
pub fn rights_code(scope: &Scope) -> String {
    match scope.form() {
        ScopeForm::AllowAll => "allow_all(true);\n".into(),
        ScopeForm::DenyAll => String::new(),
        ScopeForm::Rules(rules) => {
            let set: BTreeSet<String> = rules
                .iter()
                .map(|r| {
                    format!(
                        "right({}, {}, {});\n",
                        q(r.at.as_str()),
                        q(r.tool.as_str()),
                        q(r.action.as_str())
                    )
                })
                .collect();
            set.into_iter().collect()
        }
    }
}

impl BiscuitArm {
    pub fn new(seed: &[u8]) -> Self {
        let root = keypair(seed, b"root");
        let root_pk = root.public();
        BiscuitArm {
            root,
            root_pk,
            policies: POLICIES
                .iter()
                .map(|p| Policy::try_from(*p).expect("valid policy"))
                .collect(),
            // The default one-millisecond budget would make results depend on
            // load (Q6). Facts and iterations keep the library's defaults.
            limits: AuthorizerLimits {
                max_time: Duration::from_secs(1),
                ..AuthorizerLimits::default()
            },
        }
    }

    pub fn root_public_key(&self) -> PublicKey {
        self.root_pk
    }

    /// A token of depth `attenuations.len()`: the authority block for the
    /// session scope, then one block per delegation (scope, expiry).
    /// `nonce` makes the per-block keys, and so the token, deterministic.
    pub fn token(
        &self,
        session: &Scope,
        session_exp: u64,
        attenuations: &[(&Scope, u64)],
        nonce: &[u8],
    ) -> Result<Vec<u8>, BiscuitError> {
        let code = rights_code(session) + &block_code(session, session_exp);
        let mut token = Biscuit::builder().code(code)?.build_with_key_pair(
            &self.root,
            SymbolTable::default(),
            &keypair(nonce, b"next-0"),
        )?;
        for (i, (scope, exp)) in attenuations.iter().enumerate() {
            let next = keypair(nonce, format!("next-{}", i + 1).as_bytes());
            token = token
                .append_with_keypair(&next, BlockBuilder::new().code(block_code(scope, *exp))?)?;
        }
        token.to_vec()
    }

    /// The timed operation (SPEC §12.3): `Biscuit::from` (deserialize and
    /// verify every block's signature), authorizer construction, and
    /// `authorize`.
    pub fn verify(&self, token: &[u8], req: &Request<'_>) -> Result<(), BiscuitError> {
        let biscuit = Biscuit::from(token, self.root_pk)?;
        let mut b = AuthorizerBuilder::new()
            .fact(fact("aud", &[string(req.aud.as_str())]))?
            .fact(fact("tool", &[string(req.tool.as_str())]))?
            .fact(fact("action", &[string(req.action.as_str())]))?
            .fact(fact(
                "now",
                &[int(i64::try_from(req.now).unwrap_or(i64::MAX))],
            ))?;
        if let Some(leaves) = flatten(req.params) {
            b = b.fact(fact("param_count", &[int(leaves.len() as i64)]))?;
            for (path, leaf) in leaves {
                let value = match leaf {
                    Leaf::Int(i) => match i64::try_from(i) {
                        Ok(i) => int(i),
                        Err(_) => continue,
                    },
                    Leaf::Str(s) => string(s),
                    Leaf::Bool(v) => boolean(v),
                    Leaf::Untyped => continue,
                };
                b = b.fact(fact("param", &[string(&path), value]))?;
            }
        }
        for p in &self.policies {
            b = b.policy(p.clone())?;
        }
        let mut authorizer = b.set_limits(self.limits.clone()).build(&biscuit)?;
        authorizer.authorize().map(|_| ())
    }
}
