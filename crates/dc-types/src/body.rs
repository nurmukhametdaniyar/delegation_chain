//! Token bodies (paper §4.3; SPEC §7.1–§7.3).

use dc_cbor::schema::Fields;
use dc_cbor::{CanonViolation, Key, Limits, Value, decode, encode};
use dc_crypto::SigScheme;

use crate::digest::{Digest32, invocation_digest};
use crate::error::{BuildError, Malformed};
use crate::ident::{Identifier, Principal};
use crate::params::Params;
use crate::receipt::Receipt;
use crate::util::{arr16, arr32, bytes_n, identifier, principal, u64_of};

/// A scope expression as carried in a body: the canonical AST of SPEC §9.2,
/// kept as CBOR here. `dc-policy` validates and interprets it; a malformed
/// scope is a decoding failure at line 2 (D-28).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawScope(pub Value);

/// Body kind, key 1 of every body (D-13).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BodyKind {
    Session = 0,
    Delegation = 1,
    Invocation = 2,
}

impl BodyKind {
    pub const fn code(self) -> u64 {
        self as u64
    }
}

fn kind_field(f: &mut Fields<'_>, kind: BodyKind) -> Result<(), Malformed> {
    f.get(1, |v| (v.as_u64() == Some(kind.code())).then_some(()))?;
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionBody {
    pub issuer_id: Principal,
    pub issuer_pk: Vec<u8>,
    /// The orchestrator.
    pub subject_id: Principal,
    pub subject_pk: Vec<u8>,
    pub session_id: [u8; 16],
    pub policy_hash: Digest32,
    pub scope: RawScope,
    pub iat: u64,
    pub exp: u64,
    pub nonce: [u8; 16],
}

impl SessionBody {
    pub fn to_value(&self) -> Value {
        Value::Map(vec![
            (Key::Uint(1), Value::uint(BodyKind::Session.code())),
            (Key::Uint(2), Value::text(self.issuer_id.as_str())),
            (Key::Uint(3), Value::bytes(self.issuer_pk.clone())),
            (Key::Uint(4), Value::text(self.subject_id.as_str())),
            (Key::Uint(5), Value::bytes(self.subject_pk.clone())),
            (Key::Uint(6), Value::bytes(self.session_id.to_vec())),
            (Key::Uint(7), Value::bytes(self.policy_hash.to_vec())),
            (Key::Uint(8), self.scope.0.clone()),
            (Key::Uint(9), Value::uint(self.iat)),
            (Key::Uint(10), Value::uint(self.exp)),
            (Key::Uint(11), Value::bytes(self.nonce.to_vec())),
        ])
    }

    fn from_value(v: &Value, pk_len: usize) -> Result<Self, Malformed> {
        let mut f = Fields::new("SessionBody", v)?;
        kind_field(&mut f, BodyKind::Session)?;
        let b = SessionBody {
            issuer_id: f.get(2, principal)?,
            issuer_pk: f.get(3, |v| bytes_n(v, pk_len))?,
            subject_id: f.get(4, principal)?,
            subject_pk: f.get(5, |v| bytes_n(v, pk_len))?,
            session_id: f.get(6, arr16)?,
            policy_hash: f.get(7, arr32)?,
            scope: RawScope(f.req(8)?.clone()),
            iat: f.get(9, u64_of)?,
            exp: f.get(10, u64_of)?,
            nonce: f.get(11, arr16)?,
        };
        f.finish()?;
        Ok(b)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DelegationBody {
    pub delegator_id: Principal,
    pub delegator_pk: Vec<u8>,
    pub delegatee_id: Principal,
    pub delegatee_pk: Vec<u8>,
    /// The attenuated sub-scope.
    pub scope: RawScope,
    pub hop_index: u64,
    pub session_id: [u8; 16],
    pub exp: u64,
    pub nonce: [u8; 16],
}

impl DelegationBody {
    pub fn to_value(&self) -> Value {
        Value::Map(vec![
            (Key::Uint(1), Value::uint(BodyKind::Delegation.code())),
            (Key::Uint(2), Value::text(self.delegator_id.as_str())),
            (Key::Uint(3), Value::bytes(self.delegator_pk.clone())),
            (Key::Uint(4), Value::text(self.delegatee_id.as_str())),
            (Key::Uint(5), Value::bytes(self.delegatee_pk.clone())),
            (Key::Uint(6), self.scope.0.clone()),
            (Key::Uint(7), Value::uint(self.hop_index)),
            (Key::Uint(8), Value::bytes(self.session_id.to_vec())),
            (Key::Uint(9), Value::uint(self.exp)),
            (Key::Uint(10), Value::bytes(self.nonce.to_vec())),
        ])
    }

    fn from_value(v: &Value, pk_len: usize) -> Result<Self, Malformed> {
        let mut f = Fields::new("DelegationBody", v)?;
        kind_field(&mut f, BodyKind::Delegation)?;
        let b = DelegationBody {
            delegator_id: f.get(2, principal)?,
            delegator_pk: f.get(3, |v| bytes_n(v, pk_len))?,
            delegatee_id: f.get(4, principal)?,
            delegatee_pk: f.get(5, |v| bytes_n(v, pk_len))?,
            scope: RawScope(f.req(6)?.clone()),
            hop_index: f.get(7, u64_of)?,
            session_id: f.get(8, arr16)?,
            exp: f.get(9, u64_of)?,
            nonce: f.get(10, arr16)?,
        };
        f.finish()?;
        Ok(b)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct InvocationBody<S: SigScheme> {
    pub invoker_id: Principal,
    pub invoker_pk: Vec<u8>,
    /// The verifier this invocation is addressed to (a service principal).
    pub aud: Principal,
    pub tool: Identifier,
    pub action: Identifier,
    pub params: Params,
    pub params_hash: Digest32,
    /// Sorted by `approver_id`, at most one per approver (D-15). Key 9 is
    /// omitted when empty (D-14).
    pub receipts: Vec<Receipt<S>>,
    pub nbf: u64,
    pub exp: u64,
    pub nonce: [u8; 16],
}

impl<S: SigScheme> InvocationBody<S> {
    /// Sorts receipts into canonical order (D-15), refusing two for one
    /// approver.
    pub fn set_receipts(&mut self, mut receipts: Vec<Receipt<S>>) -> Result<(), BuildError> {
        receipts.sort_by(|a, b| a.approval.approver_id.cmp(&b.approval.approver_id));
        if receipts
            .windows(2)
            .any(|w| w[0].approval.approver_id == w[1].approval.approver_id)
        {
            return Err(BuildError::Receipts("two receipts for one approver"));
        }
        self.receipts = receipts;
        Ok(())
    }

    fn value(&self, with_receipts: bool) -> Result<Value, BuildError> {
        let mut m = vec![
            (Key::Uint(1), Value::uint(BodyKind::Invocation.code())),
            (Key::Uint(2), Value::text(self.invoker_id.as_str())),
            (Key::Uint(3), Value::bytes(self.invoker_pk.clone())),
            (Key::Uint(4), Value::text(self.aud.as_str())),
            (Key::Uint(5), Value::text(self.tool.as_str())),
            (Key::Uint(6), Value::text(self.action.as_str())),
            (Key::Uint(7), self.params.canonical_value()?),
            (Key::Uint(8), Value::bytes(self.params_hash.to_vec())),
        ];
        if with_receipts && !self.receipts.is_empty() {
            m.push((
                Key::Uint(9),
                Value::Array(self.receipts.iter().map(Receipt::to_value).collect()),
            ));
        }
        m.push((Key::Uint(10), Value::uint(self.nbf)));
        m.push((Key::Uint(11), Value::uint(self.exp)));
        m.push((Key::Uint(12), Value::bytes(self.nonce.to_vec())));
        Ok(Value::Map(m))
    }

    pub fn to_value(&self) -> Result<Value, BuildError> {
        self.value(true)
    }

    /// InvocationDigest(B_N): the canonical body with key 9 removed (D-06).
    pub fn invocation_digest(&self) -> Result<Digest32, BuildError> {
        Ok(invocation_digest(&encode(&self.value(false)?)?))
    }

    fn from_value(v: &Value) -> Result<Self, Malformed> {
        let mut f = Fields::new("InvocationBody", v)?;
        kind_field(&mut f, BodyKind::Invocation)?;
        let invoker_id = f.get(2, principal)?;
        let invoker_pk = f.get(3, |v| bytes_n(v, S::PK_LEN))?;
        let aud = f.get(4, principal)?;
        let tool = f.get(5, identifier)?;
        let action = f.get(6, identifier)?;
        let params = Params::from_decoded(f.req(7)?)?;
        let params_hash = f.get(8, arr32)?;
        let receipts = match f.opt(9) {
            None => vec![],
            Some(r) => {
                let items = r.as_array().ok_or(Malformed::Receipts("not an array"))?;
                if items.is_empty() {
                    return Err(Malformed::Receipts("present but empty (D-14)"));
                }
                let receipts: Vec<Receipt<S>> = items
                    .iter()
                    .map(Receipt::from_value)
                    .collect::<Result<_, _>>()?;
                for w in receipts.windows(2) {
                    match w[0].approval.approver_id.cmp(&w[1].approval.approver_id) {
                        std::cmp::Ordering::Less => {}
                        std::cmp::Ordering::Equal => {
                            return Err(Malformed::Receipts("two receipts for one approver"));
                        }
                        std::cmp::Ordering::Greater => {
                            return Err(Malformed::Receipts("not sorted by approver_id"));
                        }
                    }
                }
                receipts
            }
        };
        let b = InvocationBody {
            invoker_id,
            invoker_pk,
            aud,
            tool,
            action,
            params,
            params_hash,
            receipts,
            nbf: f.get(10, u64_of)?,
            exp: f.get(11, u64_of)?,
            nonce: f.get(12, arr16)?,
        };
        f.finish()?;
        Ok(b)
    }
}

/// A body of any kind.
#[derive(Clone, Debug, PartialEq)]
pub enum Body<S: SigScheme> {
    Session(SessionBody),
    Delegation(DelegationBody),
    Invocation(InvocationBody<S>),
}

impl<S: SigScheme> Body<S> {
    pub fn kind(&self) -> BodyKind {
        match self {
            Body::Session(_) => BodyKind::Session,
            Body::Delegation(_) => BodyKind::Delegation,
            Body::Invocation(_) => BodyKind::Invocation,
        }
    }

    /// `sid(B)`: the identifier of the party that signed the body (paper §4.6).
    pub fn signer_id(&self) -> &Principal {
        match self {
            Body::Session(b) => &b.issuer_id,
            Body::Delegation(b) => &b.delegator_id,
            Body::Invocation(b) => &b.invoker_id,
        }
    }

    /// `spk(B)`: that party's public key, as named in the body.
    pub fn signer_pk(&self) -> &[u8] {
        match self {
            Body::Session(b) => &b.issuer_pk,
            Body::Delegation(b) => &b.delegator_pk,
            Body::Invocation(b) => &b.invoker_pk,
        }
    }

    pub fn exp(&self) -> u64 {
        match self {
            Body::Session(b) => b.exp,
            Body::Delegation(b) => b.exp,
            Body::Invocation(b) => b.exp,
        }
    }

    /// `scope(B)`: the session scope or delegation sub-scope.
    pub fn scope(&self) -> Option<&RawScope> {
        match self {
            Body::Session(b) => Some(&b.scope),
            Body::Delegation(b) => Some(&b.scope),
            Body::Invocation(_) => None,
        }
    }

    pub fn to_value(&self) -> Result<Value, BuildError> {
        Ok(match self {
            Body::Session(b) => b.to_value(),
            Body::Delegation(b) => b.to_value(),
            Body::Invocation(b) => b.to_value()?,
        })
    }

    /// `Canon(B)`. At line 5 the verifier compares this with the received
    /// bytes. Parameter text is NFC-normalized here, so non-NFC input
    /// re-encodes differently (D-31).
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, BuildError> {
        Ok(encode(&self.to_value()?)?)
    }
}

/// The result of decoding one received body at Algorithm 1 line 2.
#[derive(Clone, Debug)]
pub struct DecodedBody<S: SigScheme> {
    pub body: Body<S>,
    /// The first canonical-form violation in the received bytes, rejected
    /// at line 5 (D-31).
    pub violation: Option<CanonViolation>,
}

/// Decodes a body under the schema its own `kind` field names, whatever its
/// position in the chain (D-32). Malformed input is an error (line 2); a
/// canonical-form violation is recorded (line 5).
pub fn decode_body<S: SigScheme>(bytes: &[u8]) -> Result<DecodedBody<S>, Malformed> {
    let (v, mut violation) = decode(bytes, Limits::BODY)?;
    let kind = v
        .get(&Key::Uint(1))
        .and_then(Value::as_u64)
        .ok_or(Malformed::NoKind)?;
    let body = match kind {
        0 => Body::Session(SessionBody::from_value(&v, S::PK_LEN)?),
        1 => Body::Delegation(DelegationBody::from_value(&v, S::PK_LEN)?),
        2 => Body::Invocation(InvocationBody::from_value(&v)?),
        k => return Err(Malformed::UnknownKind(k)),
    };
    if violation.is_none()
        && let Body::Invocation(inv) = &body
        && !inv.params.is_nfc()
    {
        violation = Some(CanonViolation::NonNfc);
    }
    Ok(DecodedBody { body, violation })
}
