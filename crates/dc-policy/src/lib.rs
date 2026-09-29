//! The policy language (paper §6; SPEC §9): AST and canonical CBOR form,
//! text parser and printer, well-formedness, `Evaluate`, `implies`/`unsat`,
//! and `Contains`.
//!
//! A [`Scope`] can only be built by validating it (paper §6.1 "Well-
//! formedness"; D-17, D-19, D-20, D-21, D-28). A malformed policy is
//! unavailable at Algorithm 2 line 31 (D-12). A malformed scope inside a body
//! fails decoding at Algorithm 1 line 2.

mod ast;
mod cbor;
mod contains;
mod error;
mod eval;
pub mod logic;
mod text;
pub mod validate;

pub use ast::{Atom, Decision, Declaration, Literal, Op, Operand, Rule, Scope, ScopeForm, Type};
#[cfg(feature = "test-hooks")]
pub use contains::contains_pre_review;
pub use contains::{contains, subsumes};
pub use error::PolicyError;
pub use eval::{Invocation, Leaf, atom_holds, evaluate, flatten};
