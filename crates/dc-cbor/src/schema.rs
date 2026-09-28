//! Reading protocol structures: maps with unsigned-integer keys, where every
//! key must be known (D-01).

use thiserror::Error;

use crate::value::{Key, Value};

/// A protocol structure that does not match its schema. Always malformed
/// (Algorithm 1 line 2).
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum SchemaError {
    #[error("{0}: expected a map")]
    NotAMap(&'static str),
    #[error("{0}: expected an array")]
    NotAnArray(&'static str),
    #[error("{0}: map key is not an unsigned integer")]
    NonUintKey(&'static str),
    #[error("{0}: missing field {1}")]
    Missing(&'static str, u64),
    #[error("{0}: unknown field {1}")]
    Unknown(&'static str, u64),
    #[error("{0}: field {1} has the wrong type or value")]
    Invalid(&'static str, u64),
    #[error("{0}: wrong number of elements")]
    Arity(&'static str),
}

/// Field-by-field reader for a uint-keyed map. Every field must be claimed
/// with [`Fields::req`] or [`Fields::opt`]; [`Fields::finish`] rejects the
/// rest.
pub struct Fields<'a> {
    what: &'static str,
    entries: &'a [(Key, Value)],
    claimed: Vec<bool>,
}

impl<'a> Fields<'a> {
    pub fn new(what: &'static str, v: &'a Value) -> Result<Self, SchemaError> {
        let entries = v.as_map().ok_or(SchemaError::NotAMap(what))?;
        if entries.iter().any(|(k, _)| k.as_uint().is_none()) {
            return Err(SchemaError::NonUintKey(what));
        }
        Ok(Fields {
            what,
            entries,
            claimed: vec![false; entries.len()],
        })
    }

    pub fn what(&self) -> &'static str {
        self.what
    }

    pub fn opt(&mut self, key: u64) -> Option<&'a Value> {
        let i = self
            .entries
            .iter()
            .position(|(k, _)| k.as_uint() == Some(key))?;
        self.claimed[i] = true;
        Some(&self.entries[i].1)
    }

    pub fn req(&mut self, key: u64) -> Result<&'a Value, SchemaError> {
        self.opt(key).ok_or(SchemaError::Missing(self.what, key))
    }

    /// A required field, converted by `f`; `None` from `f` is a type error.
    pub fn get<T>(
        &mut self,
        key: u64,
        f: impl FnOnce(&'a Value) -> Option<T>,
    ) -> Result<T, SchemaError> {
        f(self.req(key)?).ok_or(SchemaError::Invalid(self.what, key))
    }

    /// An optional field, converted by `f`.
    pub fn get_opt<T>(
        &mut self,
        key: u64,
        f: impl FnOnce(&'a Value) -> Option<T>,
    ) -> Result<Option<T>, SchemaError> {
        match self.opt(key) {
            None => Ok(None),
            Some(v) => f(v).map(Some).ok_or(SchemaError::Invalid(self.what, key)),
        }
    }

    pub fn finish(self) -> Result<(), SchemaError> {
        match self.claimed.iter().position(|c| !c) {
            None => Ok(()),
            Some(i) => Err(SchemaError::Unknown(
                self.what,
                self.entries[i].0.as_uint().unwrap_or(u64::MAX),
            )),
        }
    }
}

/// An array of exactly `n` elements.
pub fn tuple<'a>(what: &'static str, v: &'a Value, n: usize) -> Result<&'a [Value], SchemaError> {
    let a = v.as_array().ok_or(SchemaError::NotAnArray(what))?;
    if a.len() != n {
        return Err(SchemaError::Arity(what));
    }
    Ok(a)
}
