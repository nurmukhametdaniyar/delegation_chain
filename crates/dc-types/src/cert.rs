//! Certificates, revocation assertions and PoP challenges (paper §5.2,
//! §5.3, §5.6; SPEC §6.3–§6.5). Each signed structure travels as
//! `[body_bytes, sig]`, canonically encoded.

use dc_cbor::schema::{Fields, tuple};
use dc_cbor::{Key, Limits, Value, decode_strict, encode};
use dc_crypto::SigScheme;

use crate::digest::{Digest32, cert_message, pop_message, revocation_message};
use crate::error::{BuildError, Malformed};
use crate::ident::{IdentError, Identifier, Kind, Principal};
use crate::util::{arr16, bytes_n, identifier, principal, u64_of};

pub const CERT_VERSION: u64 = 1;

fn kind_code(kind: Kind) -> Result<u64, BuildError> {
    kind.cert_code()
        .ok_or_else(|| BuildError::Ident(IdentError::Kind(kind.as_str().to_owned())))
}

fn kind_of(v: &Value) -> Option<Kind> {
    Kind::from_cert_code(v.as_u64()?)
}

/// Splits `[body_bytes, sig]`; both parts must be byte strings, and the whole
/// and the body must be canonical.
fn signed_pair<'a>(
    what: &'static str,
    outer: &'a Value,
) -> Result<(&'a [u8], &'a [u8]), Malformed> {
    let parts = tuple(what, outer, 2)?;
    match (parts[0].as_bytes(), parts[1].as_bytes()) {
        (Some(b), Some(s)) => Ok((b, s)),
        _ => Err(Malformed::Certificate("parts are not byte strings")),
    }
}

fn assemble<S: SigScheme>(body_bytes: &[u8], sig: &S::Signature) -> Vec<u8> {
    encode(&Value::Array(vec![
        Value::bytes(body_bytes.to_vec()),
        Value::bytes(S::sig_bytes(sig)),
    ]))
    .expect("two byte strings always encode")
}

/// The certificate body (SPEC §6.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertBody {
    pub identifier: Principal,
    pub pk: Vec<u8>,
    /// Must equal the identifier's kind component; never `Service` (D-09).
    pub kind: Kind,
    pub registry_id: Identifier,
    pub registry_pk: Vec<u8>,
    pub iat: u64,
    pub nbf: u64,
    pub exp: u64,
    pub serial: u64,
}

impl CertBody {
    pub fn to_value(&self) -> Result<Value, BuildError> {
        Ok(Value::Map(vec![
            (Key::Uint(1), Value::uint(CERT_VERSION)),
            (Key::Uint(2), Value::text(self.identifier.as_str())),
            (Key::Uint(3), Value::bytes(self.pk.clone())),
            (Key::Uint(4), Value::uint(kind_code(self.kind)?)),
            (Key::Uint(5), Value::text(self.registry_id.as_str())),
            (Key::Uint(6), Value::bytes(self.registry_pk.clone())),
            (Key::Uint(7), Value::uint(self.iat)),
            (Key::Uint(8), Value::uint(self.nbf)),
            (Key::Uint(9), Value::uint(self.exp)),
            (Key::Uint(10), Value::uint(self.serial)),
        ]))
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, BuildError> {
        Ok(encode(&self.to_value()?)?)
    }

    fn from_value(v: &Value, pk_len: usize) -> Result<Self, Malformed> {
        let mut f = Fields::new("CertBody", v)?;
        f.get(1, |v| (v.as_u64() == Some(CERT_VERSION)).then_some(()))?;
        let body = CertBody {
            identifier: f.get(2, principal)?,
            pk: f.get(3, |v| bytes_n(v, pk_len))?,
            kind: f.get(4, kind_of)?,
            registry_id: f.get(5, identifier)?,
            registry_pk: f.get(6, |v| bytes_n(v, pk_len))?,
            iat: f.get(7, u64_of)?,
            nbf: f.get(8, u64_of)?,
            exp: f.get(9, u64_of)?,
            serial: f.get(10, u64_of)?,
        };
        f.finish()?;
        if body.kind != body.identifier.kind() {
            return Err(Malformed::Certificate(
                "kind does not match the identifier's kind component",
            ));
        }
        Ok(body)
    }
}

/// A certificate as it travels: the canonical encoding of `[body, sig]`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Certificate(pub Vec<u8>);

impl Certificate {
    pub fn assemble<S: SigScheme>(body_bytes: &[u8], sig: &S::Signature) -> Self {
        Certificate(assemble::<S>(body_bytes, sig))
    }
}

/// A decoded certificate. Its signature has been parsed and validated
/// (D-30), but not yet verified against any root (Algorithm 1 line 24).
#[derive(Clone, Debug)]
pub struct ParsedCert<S: SigScheme> {
    pub body: CertBody,
    pub body_bytes: Vec<u8>,
    pub sig: S::Signature,
}

impl<S: SigScheme> ParsedCert<S> {
    pub fn decode(cert: &Certificate) -> Result<Self, Malformed> {
        let outer = decode_strict(&cert.0, Limits::BODY)?;
        let (body_bytes, sig) = signed_pair("Certificate", &outer)?;
        let body = CertBody::from_value(&decode_strict(body_bytes, Limits::BODY)?, S::PK_LEN)?;
        Ok(ParsedCert {
            body,
            body_bytes: body_bytes.to_vec(),
            sig: S::sig_from_bytes(sig)?,
        })
    }

    /// What the registry signed (D-07).
    pub fn message(&self) -> Digest32 {
        cert_message(&self.body_bytes)
    }
}

/// A revocation assertion body (SPEC §6.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevocationBody {
    pub registry_id: Identifier,
    pub serial: u64,
    pub revoked_at: u64,
}

impl RevocationBody {
    pub fn to_value(&self) -> Value {
        Value::Map(vec![
            (Key::Uint(1), Value::text(self.registry_id.as_str())),
            (Key::Uint(2), Value::uint(self.serial)),
            (Key::Uint(3), Value::uint(self.revoked_at)),
        ])
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        encode(&self.to_value()).expect("revocation bodies always encode")
    }

    fn from_value(v: &Value) -> Result<Self, Malformed> {
        let mut f = Fields::new("RevocationBody", v)?;
        let body = RevocationBody {
            registry_id: f.get(1, identifier)?,
            serial: f.get(2, u64_of)?,
            revoked_at: f.get(3, u64_of)?,
        };
        f.finish()?;
        Ok(body)
    }
}

/// A revocation assertion as it travels: `[body, sig]`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RevocationAssertion(pub Vec<u8>);

impl RevocationAssertion {
    pub fn assemble<S: SigScheme>(body_bytes: &[u8], sig: &S::Signature) -> Self {
        RevocationAssertion(assemble::<S>(body_bytes, sig))
    }
}

#[derive(Clone, Debug)]
pub struct ParsedRevocation<S: SigScheme> {
    pub body: RevocationBody,
    pub body_bytes: Vec<u8>,
    pub sig: S::Signature,
}

impl<S: SigScheme> ParsedRevocation<S> {
    pub fn decode(a: &RevocationAssertion) -> Result<Self, Malformed> {
        let outer = decode_strict(&a.0, Limits::BODY)?;
        let (body_bytes, sig) = signed_pair("RevocationAssertion", &outer)?;
        let body = RevocationBody::from_value(&decode_strict(body_bytes, Limits::BODY)?)?;
        Ok(ParsedRevocation {
            body,
            body_bytes: body_bytes.to_vec(),
            sig: S::sig_from_bytes(sig)?,
        })
    }

    pub fn message(&self) -> Digest32 {
        revocation_message(&self.body_bytes)
    }
}

/// A registry-issued PoP challenge (paper §5.3; SPEC §6.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PopChallenge {
    pub identifier: Principal,
    pub pk: Vec<u8>,
    pub kind: Kind,
    pub registry_id: Identifier,
    pub nonce: [u8; 16],
    pub timestamp: u64,
}

impl PopChallenge {
    pub fn to_value(&self) -> Result<Value, BuildError> {
        Ok(Value::Map(vec![
            (Key::Uint(1), Value::text(self.identifier.as_str())),
            (Key::Uint(2), Value::bytes(self.pk.clone())),
            (Key::Uint(3), Value::uint(kind_code(self.kind)?)),
            (Key::Uint(4), Value::text(self.registry_id.as_str())),
            (Key::Uint(5), Value::bytes(self.nonce.to_vec())),
            (Key::Uint(6), Value::uint(self.timestamp)),
        ]))
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, BuildError> {
        Ok(encode(&self.to_value()?)?)
    }

    /// What the registrant signs under the PoP DST (D-07).
    pub fn message(&self) -> Result<Digest32, BuildError> {
        Ok(pop_message(&self.canonical_bytes()?))
    }

    pub fn decode(bytes: &[u8], pk_len: usize) -> Result<Self, Malformed> {
        let v = decode_strict(bytes, Limits::BODY)?;
        let mut f = Fields::new("PopChallenge", &v)?;
        let c = PopChallenge {
            identifier: f.get(1, principal)?,
            pk: f.get(2, |v| bytes_n(v, pk_len))?,
            kind: f.get(3, kind_of)?,
            registry_id: f.get(4, identifier)?,
            nonce: f.get(5, arr16)?,
            timestamp: f.get(6, u64_of)?,
        };
        f.finish()?;
        Ok(c)
    }
}
