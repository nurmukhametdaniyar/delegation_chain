//! Approval receipts (paper §4.5; SPEC §7.4).

use dc_cbor::schema::{Fields, tuple};
use dc_cbor::{Key, Limits, Value, decode_strict, encode};
use dc_crypto::SigScheme;

use crate::digest::{Digest32, approval_message};
use crate::error::{BuildError, Malformed};
use crate::ident::Principal;
use crate::util::{bytes_n, principal, u64_of};

/// Maximum attestation size (SPEC §7.4).
pub const MAX_ATTESTATION: usize = 256;

/// The body an approval service signs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalBody {
    pub approver_id: Principal,
    pub approver_pk: Vec<u8>,
    pub invocation_digest: Digest32,
    /// Opaque data identifying the human approver.
    pub attestation: Vec<u8>,
    pub iat: u64,
    pub exp: u64,
}

impl ApprovalBody {
    pub fn to_value(&self) -> Value {
        Value::Map(vec![
            (Key::Uint(1), Value::text(self.approver_id.as_str())),
            (Key::Uint(2), Value::bytes(self.approver_pk.clone())),
            (Key::Uint(3), Value::bytes(self.invocation_digest.to_vec())),
            (Key::Uint(4), Value::bytes(self.attestation.clone())),
            (Key::Uint(5), Value::uint(self.iat)),
            (Key::Uint(6), Value::uint(self.exp)),
        ])
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, BuildError> {
        if self.attestation.len() > MAX_ATTESTATION {
            return Err(BuildError::Receipts("attestation longer than 256 bytes"));
        }
        Ok(encode(&self.to_value())?)
    }

    pub fn from_value(v: &Value, pk_len: usize) -> Result<Self, Malformed> {
        let mut f = Fields::new("ApprovalBody", v)?;
        let body = ApprovalBody {
            approver_id: f.get(1, principal)?,
            approver_pk: f.get(2, |v| bytes_n(v, pk_len))?,
            invocation_digest: f.get(3, |v| v.as_bytes()?.try_into().ok())?,
            attestation: f.get(4, |v| {
                v.as_bytes()
                    .filter(|b| b.len() <= MAX_ATTESTATION)
                    .map(<[u8]>::to_vec)
            })?,
            iat: f.get(5, u64_of)?,
            exp: f.get(6, u64_of)?,
        };
        f.finish()?;
        Ok(body)
    }
}

/// `[approval_body_bytes, sig]`.
#[derive(Clone, Debug, PartialEq)]
pub struct Receipt<S: SigScheme> {
    pub approval: ApprovalBody,
    /// Canonical encoding of `approval`, as signed.
    pub approval_bytes: Vec<u8>,
    pub sig: S::Signature,
}

impl<S: SigScheme> Receipt<S> {
    pub fn new(approval: ApprovalBody, sig: S::Signature) -> Result<Self, BuildError> {
        let approval_bytes = approval.canonical_bytes()?;
        Ok(Receipt {
            approval,
            approval_bytes,
            sig,
        })
    }

    /// The message the approver signed (D-07).
    pub fn message(&self) -> Digest32 {
        approval_message(&self.approval_bytes)
    }

    pub fn to_value(&self) -> Value {
        Value::Array(vec![
            Value::bytes(self.approval_bytes.clone()),
            Value::bytes(S::sig_bytes(&self.sig)),
        ])
    }

    /// The approval body must be canonical: a non-canonical nested
    /// structure is malformed (`L02`), since line 5 covers bodies only
    /// (D-50). The signature is validated here (D-30).
    pub fn from_value(v: &Value) -> Result<Self, Malformed> {
        let parts = tuple("Receipt", v, 2)?;
        let approval_bytes = parts[0]
            .as_bytes()
            .ok_or(Malformed::Receipts("approval body is not a byte string"))?;
        let sig_bytes = parts[1]
            .as_bytes()
            .ok_or(Malformed::Receipts("signature is not a byte string"))?;
        let approval_value = decode_strict(approval_bytes, Limits::BODY)?;
        let approval = ApprovalBody::from_value(&approval_value, S::PK_LEN)?;
        let sig = S::sig_from_bytes(sig_bytes)?;
        Ok(Receipt {
            approval,
            approval_bytes: approval_bytes.to_vec(),
            sig,
        })
    }
}
