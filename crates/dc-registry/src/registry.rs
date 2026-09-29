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
    #[error("could not encode: {0}")]
    Build(#[from] dc_types::BuildError),
}

struct Pending {
    challenge: PopChallenge,
    issued_at: u64,
    used: bool,
}

#[derive(Default)]
struct State {
    pending: HashMap<[u8; 16], Pending>,
    next_serial: u64,
    /// Latest certificate binding each (identifier, key), for resolution.
    latest: HashMap<(String, Vec<u8>), Certificate>,
    /// Every issued certificate body, by serial.
    issued: HashMap<u64, CertBody>,
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
        st.latest.insert(
            (body.identifier.as_str().to_owned(), body.pk.clone()),
            cert.clone(),
        );
        st.issued.insert(serial, body);
        Ok(cert)
    }

    fn sign_cert(&self, body: &CertBody) -> Result<Certificate, RegistryError> {
        let bytes = body.canonical_bytes()?;
        let sig = S::sign(&self.root_sk, &cert_message(&bytes), Dst::Cert);
        Ok(Certificate::assemble::<S>(&bytes, &sig))
    }

    /// Issues a revocation assertion for `serial`, timestamped now (paper
    /// §5.6). Resolution keeps returning the certificate (D-26); verifiers
    /// reject it once they have ingested the assertion.
    pub fn revoke(&self, serial: u64) -> Result<RevocationAssertion, RegistryError> {
        if !self.state.read().unwrap().issued.contains_key(&serial) {
            return Err(RegistryError::UnknownSerial(serial));
        }
        let body = RevocationBody {
            registry_id: self.id.clone(),
            serial,
            revoked_at: self.clock.now(),
        }
        .canonical_bytes();
        let sig = S::sign(&self.root_sk, &revocation_message(&body), Dst::Revoke);
        Ok(RevocationAssertion::assemble::<S>(&body, &sig))
    }

    /// Models a compromised registry root (T5b) or a misbehaving registry
    /// (T5d): signs any certificate body, bypassing every registration check.
    #[cfg(feature = "test-hooks")]
    pub fn root_sign_arbitrary(&self, body: &CertBody) -> Certificate {
        self.sign_cert(body).expect("encodable body")
    }

    /// Registers a certificate made outside `register`, so that the resolver
    /// serves it. Used with [`Registry::root_sign_arbitrary`].
    #[cfg(feature = "test-hooks")]
    pub fn publish_arbitrary(&self, identifier: &Principal, pk: &[u8], cert: Certificate) {
        self.state
            .write()
            .unwrap()
            .latest
            .insert((identifier.as_str().to_owned(), pk.to_vec()), cert);
    }
}

impl<S: SigScheme, C: Clock> Resolver for Registry<S, C> {
    /// The most recently issued certificate binding `id` to `pk`, valid or
    /// not (D-26). `t` is not consulted: validity is line 27's job.
    fn resolve(&self, id: &Principal, pk: &[u8], _t: u64) -> Option<Certificate> {
        self.state
            .read()
            .unwrap()
            .latest
            .get(&(id.as_str().to_owned(), pk.to_vec()))
            .cloned()
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
