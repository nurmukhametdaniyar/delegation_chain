//! One organization's registry (paper §5.1–§5.3, §5.6; SPEC §6.2–§6.5).

use std::collections::HashMap;
use std::sync::{Mutex, RwLock};

use dc_crypto::{Dst, SigScheme};
use dc_types::digest::{cert_message, pop_message, revocation_message};
use dc_types::{
    CertBody, Certificate, Clock, Identifier, Kind, PopChallenge, Principal, RevocationAssertion,
    RevocationBody,
};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use thiserror::Error;

use crate::Resolver;

/// PoP nonces are single-use and live 60 seconds (D-11).
pub const POP_NONCE_TTL: u64 = 60;

/// The longest validity window a registry issues, measured from issuance:
/// the longest default lifetime (D-10). It bounds how long a revoked binding
/// must be remembered (D-65).
pub const MAX_CERT_LIFETIME: u64 = 7 * 24 * 3600;

/// Default certificate lifetimes (D-10).
pub const fn default_lifetime(kind: Kind) -> u64 {
    match kind {
        Kind::Approver => 7 * 24 * 3600,
        _ => 24 * 3600,
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum RegistryError {
    #[error("service identifiers name verifiers and get no certificate (D-09)")]
    ServiceKind,
    #[error("the challenge nonce was not issued by this registry")]
    NonceUnknown,
    #[error("the challenge nonce was already used (D-11)")]
    NonceUsed,
    #[error("the challenge nonce expired (D-11)")]
    NonceExpired,
    #[error("the presented challenge differs from the one issued")]
    ChallengeMismatch,
    #[error("identifier {0} is outside this registry's namespace")]
    WrongOrg(String),
    #[error("identifier kind does not match the requested kind")]
    KindMismatch,
    #[error("public key rejected: {0}")]
    InvalidKey(dc_crypto::CryptoError),
    #[error("proof of possession does not verify")]
    BadPop,
    #[error("unknown certificate serial {0}")]
    UnknownSerial(u64),
    #[error("the identifier and key binding has been revoked (D-65)")]
    RevokedBinding,
    #[error("the validity window ends more than the maximum lifetime after issuance (D-65)")]
    LifetimeTooLong,
    #[error("could not encode: {0}")]
    Build(#[from] dc_types::BuildError),
}

struct Pending {
    challenge: PopChallenge,
    issued_at: u64,
    used: bool,
}

/// A certificate as the resolver keeps it, with its validity window.
struct Stored {
    nbf: u64,
    exp: u64,
    cert: Certificate,
}

#[derive(Default)]
struct State {
    pending: HashMap<[u8; 16], Pending>,
    next_serial: u64,
    /// Every certificate binding each (identifier, key), oldest first, for
    /// resolution (D-26).
    certs: HashMap<(String, Vec<u8>), Vec<Stored>>,
    /// Every issued certificate body, by serial.
    issued: HashMap<u64, CertBody>,
    /// Revoked bindings, which are never certified again (D-65).
    revoked: std::collections::HashSet<(String, Vec<u8>)>,
}

/// A registry: a root key pair, PoP-checked registration, issuance and
/// revocation. The root key signs certificates and revocations only; it
/// never signs sessions (paper §4.1).
pub struct Registry<S: SigScheme, C: Clock> {
    id: Identifier,
    root_sk: S::SecretKey,
    root_pk: S::PublicKey,
    clock: C,
    rng: Mutex<ChaCha20Rng>,
    state: RwLock<State>,
}

impl<S: SigScheme, C: Clock> Registry<S, C> {
    /// `id` is the organization identifier (`registry_id = org`, SPEC §6.2).
    /// Nonces come from a seeded generator, so runs are reproducible.
    pub fn new(id: Identifier, root_ikm: &[u8; 32], clock: C, nonce_seed: u64) -> Self {
        let root_sk = S::keygen(root_ikm);
        let root_pk = S::public_key(&root_sk);
        Registry {
            id,
            root_sk,
            root_pk,
            clock,
            rng: Mutex::new(ChaCha20Rng::seed_from_u64(nonce_seed)),
            state: RwLock::new(State {
                next_serial: 1,
                ..State::default()
            }),
        }
    }

    pub fn id(&self) -> &Identifier {
        &self.id
    }

    pub fn root_pk(&self) -> &S::PublicKey {
        &self.root_pk
    }

    /// Step 1 of SPEC §6.4: issue a challenge. The registrant's claims are
    /// checked at registration, where a failure is final; only a service
    /// kind is refused here, since it cannot be encoded (D-09).
    pub fn challenge(
        &self,
        identifier: &Principal,
        pk: &[u8],
        kind: Kind,
    ) -> Result<PopChallenge, RegistryError> {
        if kind == Kind::Service {
            return Err(RegistryError::ServiceKind);
        }
        let mut nonce = [0u8; 16];
        self.rng.lock().unwrap().fill_bytes(&mut nonce);
        let now = self.clock.now();
        let challenge = PopChallenge {
            identifier: identifier.clone(),
            pk: pk.to_vec(),
            kind,
            registry_id: self.id.clone(),
            nonce,
            timestamp: now,
        };
        self.state.write().unwrap().pending.insert(
            nonce,
            Pending {
                challenge: challenge.clone(),
                issued_at: now,
                used: false,
            },
        );
        Ok(challenge)
    }

    /// Steps 3–4 of SPEC §6.4, with the default lifetime (D-10).
    pub fn register(
        &self,
        challenge: &PopChallenge,
        pop: &S::Signature,
    ) -> Result<Certificate, RegistryError> {
        let now = self.clock.now();
        self.register_with_validity(challenge, pop, now, now + default_lifetime(challenge.kind))
    }

    /// Registration with an explicit validity window, for scheduled rotation
    /// with overlapping certificates (paper §5.5; SPEC §6.6). The nonce is
    /// consumed by the first attempt, whatever its outcome.
    pub fn register_with_validity(
        &self,
        challenge: &PopChallenge,
        pop: &S::Signature,
        nbf: u64,
        exp: u64,
    ) -> Result<Certificate, RegistryError> {
        let now = self.clock.now();
        {
            let mut st = self.state.write().unwrap();
            let p = st
                .pending
                .get_mut(&challenge.nonce)
                .ok_or(RegistryError::NonceUnknown)?;
            if p.used {
                return Err(RegistryError::NonceUsed);
            }
            p.used = true;
            if now > p.issued_at + POP_NONCE_TTL {
                return Err(RegistryError::NonceExpired);
            }
            if p.challenge != *challenge {
                return Err(RegistryError::ChallengeMismatch);
            }
        }
        if challenge.kind == Kind::Service {
            return Err(RegistryError::ServiceKind);
        }
        if challenge.identifier.kind() != challenge.kind {
            return Err(RegistryError::KindMismatch);
        }
        if challenge.identifier.org() != self.id.as_str() || challenge.registry_id != self.id {
            return Err(RegistryError::WrongOrg(
                challenge.identifier.as_str().to_owned(),
            ));
        }
        let pk = S::pk_from_bytes(&challenge.pk).map_err(RegistryError::InvalidKey)?;
        if self.state.read().unwrap().revoked.contains(&(
            challenge.identifier.as_str().to_owned(),
            challenge.pk.clone(),
        )) {
            return Err(RegistryError::RevokedBinding);
        }
        if exp > now.saturating_add(MAX_CERT_LIFETIME) {
            return Err(RegistryError::LifetimeTooLong);
        }
        let msg = pop_message(&challenge.canonical_bytes()?);
        if !S::verify(&pk, &msg, Dst::Pop, pop) {
            return Err(RegistryError::BadPop);
        }
        let mut st = self.state.write().unwrap();
        let serial = st.next_serial;
        st.next_serial += 1;
        let body = CertBody {
            identifier: challenge.identifier.clone(),
            pk: challenge.pk.clone(),
            kind: challenge.kind,
            registry_id: self.id.clone(),
            registry_pk: S::pk_bytes(&self.root_pk),
            iat: now,
            nbf,
            exp,
            serial,
        };
        let cert = self.sign_cert(&body)?;
        st.certs
            .entry((body.identifier.as_str().to_owned(), body.pk.clone()))
            .or_default()
            .push(Stored {
                nbf,
                exp,
                cert: cert.clone(),
            });
        st.issued.insert(serial, body);
        Ok(cert)
    }

    fn sign_cert(&self, body: &CertBody) -> Result<Certificate, RegistryError> {
        let bytes = body.canonical_bytes()?;
        let sig = S::sign(&self.root_sk, &cert_message(&bytes), Dst::Cert);
        Ok(Certificate::assemble::<S>(&bytes, &sig))
    }

    /// Revokes the binding (identifier and key) of the certificate with
    /// `serial`, timestamped now. The assertion names the binding and keeps
    /// the serial for audit. Every certificate for that binding, earlier or
    /// later, is thereby revoked, and the registry will not certify the
    /// binding again (D-65, P-29). Resolution keeps returning certificates
    /// (D-26); verifiers reject them once they have ingested the assertion.
    pub fn revoke(&self, serial: u64) -> Result<RevocationAssertion, RegistryError> {
        let (identifier, pk) = {
            let st = self.state.read().unwrap();
            let c = st
                .issued
                .get(&serial)
                .ok_or(RegistryError::UnknownSerial(serial))?;
            (c.identifier.clone(), c.pk.clone())
        };
        self.state
            .write()
            .unwrap()
            .revoked
            .insert((identifier.as_str().to_owned(), pk.clone()));
        let body = RevocationBody {
            registry_id: self.id.clone(),
            serial,
            revoked_at: self.clock.now(),
            identifier,
            pk,
        }
        .canonical_bytes();
        let sig = S::sign(&self.root_sk, &revocation_message(&body), Dst::Revoke);
        Ok(RevocationAssertion::assemble::<S>(&body, &sig))
    }

    /// The serials of every certificate issued for a binding, oldest first.
    pub fn serials_of(&self, id: &Principal, pk: &[u8]) -> Vec<u64> {
        let st = self.state.read().unwrap();
        let mut v: Vec<u64> = st
            .issued
            .iter()
            .filter(|(_, c)| &c.identifier == id && c.pk == pk)
            .map(|(s, _)| *s)
            .collect();
        v.sort_unstable();
        v
    }

    /// Models a compromised registry root (T5b) or a misbehaving registry
    /// (T5d): signs any certificate body, bypassing every registration check.
    #[cfg(feature = "test-hooks")]
    pub fn root_sign_arbitrary(&self, body: &CertBody) -> Certificate {
        self.sign_cert(body).expect("encodable body")
    }

    /// Registers a certificate made outside `register` as the binding's only
    /// certificate, so that the resolver serves it whatever its content.
    /// Used with [`Registry::root_sign_arbitrary`].
    #[cfg(feature = "test-hooks")]
    pub fn publish_arbitrary(&self, identifier: &Principal, pk: &[u8], cert: Certificate) {
        let stored = Stored {
            // Never "valid at t", which does not matter for an only entry.
            nbf: u64::MAX,
            exp: 0,
            cert,
        };
        self.state
            .write()
            .unwrap()
            .certs
            .insert((identifier.as_str().to_owned(), pk.to_vec()), vec![stored]);
    }
}

impl<S: SigScheme, C: Clock> Resolver for Registry<S, C> {
    /// The newest certificate binding `id` to `pk` that is valid at `t`
    /// (`nbf ≤ t ≤ exp`, D-35) if there is one, and otherwise the newest,
    /// valid or not, so that line 27 can still reject an expired or
    /// not-yet-valid binding (D-26 as revised for P-30).
    fn resolve(&self, id: &Principal, pk: &[u8], t: u64) -> Option<Certificate> {
        let st = self.state.read().unwrap();
        let list = st.certs.get(&(id.as_str().to_owned(), pk.to_vec()))?;
        list.iter()
            .rev()
            .find(|c| c.nbf <= t && t <= c.exp)
            .or_else(|| list.last())
            .map(|c| c.cert.clone())
    }
}

/// The registrant's side of SPEC §6.4: request a challenge, sign it under
/// the PoP DST, register.
pub fn enroll<S: SigScheme, C: Clock>(
    registry: &Registry<S, C>,
    identifier: &Principal,
    sk: &S::SecretKey,
) -> Result<Certificate, RegistryError> {
    let pk = S::pk_bytes(&S::public_key(sk));
    let ch = registry.challenge(identifier, &pk, identifier.kind())?;
    let pop = S::sign(sk, &ch.message()?, Dst::Pop);
    registry.register(&ch, &pop)
}

/// As [`enroll`], with an explicit validity window.
pub fn enroll_with_validity<S: SigScheme, C: Clock>(
    registry: &Registry<S, C>,
    identifier: &Principal,
    sk: &S::SecretKey,
    nbf: u64,
    exp: u64,
) -> Result<Certificate, RegistryError> {
    let pk = S::pk_bytes(&S::public_key(sk));
    let ch = registry.challenge(identifier, &pk, identifier.kind())?;
    let pop = S::sign(sk, &ch.message()?, Dst::Pop);
    registry.register_with_validity(&ch, &pop, nbf, exp)
}
