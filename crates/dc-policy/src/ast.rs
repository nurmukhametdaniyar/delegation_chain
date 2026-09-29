//! The scope AST (paper §6.1; SPEC §9.2, D-18).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use dc_types::{Identifier, Principal};

use crate::error::PolicyError;
use crate::validate::validate_form;

/// Parameter types. They are disjoint at the value level (paper §6.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Type {
    Int,
    String,
    Bool,
}

impl Type {
    /// `type_uint` of SPEC §9.2.
    pub const fn code(self) -> u64 {
        match self {
            Type::Int => 0,
            Type::String => 1,
            Type::Bool => 2,
        }
    }

    pub const fn from_code(c: u64) -> Option<Type> {
        match c {
            0 => Some(Type::Int),
            1 => Some(Type::String),
            2 => Some(Type::Bool),
            _ => None,
        }
    }

    pub const fn keyword(self) -> &'static str {
        match self {
            Type::Int => "int",
            Type::String => "string",
            Type::Bool => "bool",
        }
    }
}

/// Atom operators. The text `==` is `Eq` for every type; the path's declared
/// type says whether it is the numeric or the string operator (paper §6.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Op {
    Lt,
    Le,
    Eq,
    Ge,
    Gt,
    StartsWith,
    EndsWith,
    Contains,
    In,
    Under,
}

impl Op {
    pub const ALL: [Op; 10] = [
        Op::Lt,
        Op::Le,
        Op::Eq,
        Op::Ge,
        Op::Gt,
        Op::StartsWith,
        Op::EndsWith,
        Op::Contains,
        Op::In,
        Op::Under,
    ];

    /// `op_uint` of SPEC §9.2.
    pub const fn code(self) -> u64 {
        match self {
            Op::Lt => 0,
            Op::Le => 1,
            Op::Eq => 2,
            Op::Ge => 3,
            Op::Gt => 4,
            Op::StartsWith => 5,
            Op::EndsWith => 6,
            Op::Contains => 7,
            Op::In => 8,
            Op::Under => 9,
        }
    }

    pub fn from_code(c: u64) -> Option<Op> {
        Op::ALL.into_iter().find(|o| o.code() == c)
    }

    pub const fn text(self) -> &'static str {
        match self {
            Op::Lt => "<",
            Op::Le => "<=",
            Op::Eq => "==",
            Op::Ge => ">=",
            Op::Gt => ">",
            Op::StartsWith => "starts_with",
            Op::EndsWith => "ends_with",
            Op::Contains => "contains",
            Op::In => "in",
            Op::Under => "under",
        }
    }
}

/// A literal value in an atom.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Literal {
    Int(i128),
    Str(String),
    Bool(bool),
}

impl Literal {
    pub fn ty(&self) -> Type {
        match self {
            Literal::Int(_) => Type::Int,
            Literal::Str(_) => Type::String,
            Literal::Bool(_) => Type::Bool,
        }
    }
}

/// An atom's operand: one literal, or a list for `in`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Operand {
    One(Literal),
    List(Vec<Literal>),
}

/// `path op operand`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Atom {
    pub op: Op,
    /// A path: identifiers joined by `.`.
    pub path: String,
    pub operand: Operand,
}

/// A rule's parameter declaration: path to type. Ordered lexicographically
/// in memory; the CBOR encoder applies canonical key order.
pub type Declaration = BTreeMap<String, Type>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    /// The verifier this rule authorizes; kind `service`.
    pub at: Principal,
    pub tool: Identifier,
    pub action: Identifier,
    /// Empty when the rule has no `params` clause.
    pub params: Declaration,
    /// The `where` clause, a conjunction, in written order.
    pub atoms: Vec<Atom>,
    /// Required approval services; kind `approver`. Empty when none.
    pub approval: BTreeSet<Principal>,
}

impl Rule {
    /// Audience, tool, action and declaration: what step 3(b) of the
    /// containment procedure calls "agrees with" (paper §6.4).
    pub fn same_head(&self, other: &Rule) -> bool {
        self.at == other.at
            && self.tool == other.tool
            && self.action == other.action
            && self.params == other.params
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScopeForm {
    AllowAll,
    DenyAll,
    /// A non-empty list of rules; order is semantic (first match wins).
    Rules(Vec<Rule>),
}

/// A scope expression. Every public constructor validates, so a `Scope` is
/// well-formed (paper §6.1; SPEC §9.3, D-28). The only exception is the
/// test hook [`Scope::new_unchecked`], which records whether the form is
/// well-formed; `contains` returns false for one that is not (paper §6.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scope {
    form: ScopeForm,
    well_formed: bool,
}

impl Scope {
    pub fn new(form: ScopeForm) -> Result<Self, PolicyError> {
        validate_form(&form)?;
        Ok(Scope {
            form,
            well_formed: true,
        })
    }

    pub fn allow_all() -> Self {
        Scope {
            form: ScopeForm::AllowAll,
            well_formed: true,
        }
    }

    pub fn deny_all() -> Self {
        Scope {
            form: ScopeForm::DenyAll,
            well_formed: true,
        }
    }

    pub fn form(&self) -> &ScopeForm {
        &self.form
    }

    pub fn is_well_formed(&self) -> bool {
        self.well_formed
    }

    /// Builds a scope without rejecting it. For the P-15 regression tests
    /// only (SPEC §9.7).
    #[cfg(feature = "test-hooks")]
    pub fn new_unchecked(form: ScopeForm) -> Self {
        let well_formed = validate_form(&form).is_ok();
        Scope { form, well_formed }
    }
}

/// The result of `Evaluate` (paper §6.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    Allow,
    /// Sorted, non-empty.
    AllowWithApproval(Vec<Principal>),
    Deny,
}

impl Decision {
    /// The approval set of an accepting decision; `None` for `Deny`.
    pub fn approvals(&self) -> Option<&[Principal]> {
        match self {
            Decision::Allow => Some(&[]),
            Decision::AllowWithApproval(a) => Some(a),
            Decision::Deny => None,
        }
    }
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.keyword())
    }
}
