//! Identifiers and principals (paper §5.2, §6.1; SPEC §6.1).

use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};

use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum IdentError {
    #[error("{0:?} does not follow the identifier grammar")]
    Identifier(String),
    #[error("{0:?} is not organization-id:kind:local-id")]
    Principal(String),
    #[error("{0:?} is not a known kind")]
    Kind(String),
}

/// `identifier ::= letter (letter | digit | "_" | "-")*`, with ASCII letters
/// and digits (D-08).
pub fn is_identifier(s: &str) -> bool {
    let b = s.as_bytes();
    match b.split_first() {
        Some((first, rest)) => {
            first.is_ascii_alphabetic()
                && rest
                    .iter()
                    .all(|c| c.is_ascii_alphanumeric() || *c == b'_' || *c == b'-')
        }
        None => false,
    }
}

/// A validated identifier.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Identifier(String);

impl Identifier {
    pub fn new(s: impl Into<String>) -> Result<Self, IdentError> {
        let s = s.into();
        if is_identifier(&s) {
            Ok(Identifier(s))
        } else {
            Err(IdentError::Identifier(s))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Identifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The kind component of a principal (paper §5.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    Agent,
    Signer,
    Approver,
    Issuer,
    /// Names a verifier; has no certificate (D-09).
    Service,
}

impl Kind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Kind::Agent => "agent",
            Kind::Signer => "signer",
            Kind::Approver => "approver",
            Kind::Issuer => "issuer",
            Kind::Service => "service",
        }
    }

    pub fn parse(s: &str) -> Option<Kind> {
        Some(match s {
            "agent" => Kind::Agent,
            "signer" => Kind::Signer,
            "approver" => Kind::Approver,
            "issuer" => Kind::Issuer,
            "service" => Kind::Service,
            _ => return None,
        })
    }

    /// Certificate kind code (D-09). Services have none.
    pub const fn cert_code(self) -> Option<u64> {
        match self {
            Kind::Agent => Some(0),
            Kind::Signer => Some(1),
            Kind::Approver => Some(2),
            Kind::Issuer => Some(3),
            Kind::Service => None,
        }
    }

    pub const fn from_cert_code(code: u64) -> Option<Kind> {
        match code {
            0 => Some(Kind::Agent),
            1 => Some(Kind::Signer),
            2 => Some(Kind::Approver),
            3 => Some(Kind::Issuer),
            _ => None,
        }
    }
}

/// `principal ::= identifier ":" identifier ":" identifier`, read as
/// organization-id : kind : local-id, where the kind is one of the five of
/// paper §5.2. Ordering and equality are bytewise on the text (D-15).
#[derive(Clone, Debug)]
pub struct Principal {
    text: String,
    org_end: usize,
    kind: Kind,
    local_start: usize,
}

impl Principal {
    pub fn parse(s: &str) -> Result<Self, IdentError> {
        let mut parts = s.split(':');
        let (Some(org), Some(kind), Some(local), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(IdentError::Principal(s.to_owned()));
        };
        if !(is_identifier(org) && is_identifier(kind) && is_identifier(local)) {
            return Err(IdentError::Principal(s.to_owned()));
        }
        let kind = Kind::parse(kind).ok_or_else(|| IdentError::Kind(kind.to_owned()))?;
        Ok(Principal {
            text: s.to_owned(),
            org_end: org.len(),
            kind,
            local_start: s.len() - local.len(),
        })
    }

    /// `org(x)`: the organization-id component.
    pub fn org(&self) -> &str {
        &self.text[..self.org_end]
    }

    pub fn kind(&self) -> Kind {
        self.kind
    }

    pub fn local(&self) -> &str {
        &self.text[self.local_start..]
    }

    pub fn as_str(&self) -> &str {
        &self.text
    }
}

impl PartialEq for Principal {
    fn eq(&self, other: &Self) -> bool {
        self.text == other.text
    }
}

impl Eq for Principal {}

impl Hash for Principal {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.text.hash(state);
    }
}

impl Ord for Principal {
    fn cmp(&self, other: &Self) -> Ordering {
        self.text.as_bytes().cmp(other.text.as_bytes())
    }
}

impl PartialOrd for Principal {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for Principal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}
