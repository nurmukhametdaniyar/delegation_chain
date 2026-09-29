//! The signing parties of paper §3.1 and §4.1 (SPEC §8.1, §8.2, §8.4).

use dc_crypto::{Dst, SigScheme};
use dc_policy::Scope;
use dc_types::digest::{Digest32, approval_message, m_delegation, m_invocation, m_session};
use dc_types::{ApprovalBody, Body, InvocationBody, Principal, RawScope, Receipt, SessionBody};
use rand_core::RngCore;

use crate::ChainError;

/// What an issuance produces: B_0, its bytes, m_0 and σ_0 (SPEC §8.1).
#[derive(Clone, Debug)]
pub struct Issued<S: SigScheme> {
    pub body: SessionBody,
    pub bytes: Vec<u8>,
    pub m0: Digest32,
    pub sig: S::Signature,
}

/// The organization's issuance service. It holds a key certified with kind
/// `issuer`; the registry root never signs sessions (paper §4.1).
pub struct IssuanceService<S: SigScheme> {
    id: Principal,
    sk: S::SecretKey,
    pk: Vec<u8>,
}

impl<S: SigScheme> IssuanceService<S> {
    pub fn new(id: Principal, sk: S::SecretKey) -> Self {
        let pk = S::pk_bytes(&S::public_key(&sk));
        IssuanceService { id, sk, pk }
    }

    pub fn id(&self) -> &Principal {
        &self.id
    }

    pub fn pk(&self) -> &[u8] {
        &self.pk
    }

    /// Builds and signs B_0, naming this service as issuer. The session id
    /// and nonce come from `rng`.
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        &self,
        subject_id: &Principal,
        subject_pk: &[u8],
        scope: &Scope,
        policy_hash: Digest32,
        now: u64,
        ttl: u64,
        rng: &mut impl RngCore,
    ) -> Result<Issued<S>, ChainError> {
        let mut session_id = [0u8; 16];
        let mut nonce = [0u8; 16];
        rng.fill_bytes(&mut session_id);
        rng.fill_bytes(&mut nonce);
        let body = SessionBody {
            issuer_id: self.id.clone(),
            issuer_pk: self.pk.clone(),
            subject_id: subject_id.clone(),
            subject_pk: subject_pk.to_vec(),
            session_id,
            policy_hash,
            scope: scope.to_raw(),
            iat: now,
            exp: now + ttl,
            nonce,
        };
        self.sign(body)
    }

    /// Signs an arbitrary session body (for tests that build odd sessions).
    pub fn sign(&self, body: SessionBody) -> Result<Issued<S>, ChainError> {
        let bytes = Body::<S>::Session(body.clone()).canonical_bytes()?;
        let m0 = m_session(&bytes);
        let sig = S::sign(&self.sk, &m0, Dst::Chain);
        Ok(Issued {
            body,
            bytes,
            m0,
            sig,
        })
    }
}

/// What a signing service may refuse before signing. The paper leaves this
/// open (P-12); the default accepts everything, and the verifier's checks
/// never depend on it.
pub trait EnforcementPolicy<S: SigScheme>: Send + Sync {
    fn check(&self, body: &Body<S>) -> Result<(), String>;
}

/// The default enforcement policy: accept.
pub struct AcceptAll;

impl<S: SigScheme> EnforcementPolicy<S> for AcceptAll {
    fn check(&self, _body: &Body<S>) -> Result<(), String> {
        Ok(())
    }
}

/// A body signed by a signing service: its canonical bytes, m_k and σ_k.
#[derive(Clone, Debug)]
pub struct Signed<S: SigScheme> {
    pub bytes: Vec<u8>,
    pub m: Digest32,
    pub sig: S::Signature,
}

/// Holds one agent's key and signs on its behalf (paper §3.1; SPEC §8.2).
/// It receives the body and m_{k−1}, never a bare digest, and computes m_k
/// itself.
pub struct SigningService<S: SigScheme> {
    agent: Principal,
    sk: S::SecretKey,
    pk: Vec<u8>,
    policy: Box<dyn EnforcementPolicy<S>>,
}

impl<S: SigScheme> SigningService<S> {
    pub fn new(agent: Principal, sk: S::SecretKey) -> Self {
        Self::with_policy(agent, sk, Box::new(AcceptAll))
    }

    pub fn with_policy(
        agent: Principal,
        sk: S::SecretKey,
        policy: Box<dyn EnforcementPolicy<S>>,
    ) -> Self {
        let pk = S::pk_bytes(&S::public_key(&sk));
        SigningService {
            agent,
            sk,
            pk,
            policy,
        }
    }

    pub fn agent(&self) -> &Principal {
        &self.agent
    }

    pub fn pk(&self) -> &[u8] {
        &self.pk
    }

    /// SPEC §8.2: check that the body names this agent and key as signer,
    /// run the enforcement hook, compute m_k with the tag of the body's kind,
    /// and sign.
    pub fn sign(&self, body: &Body<S>, m_prev: &Digest32) -> Result<Signed<S>, ChainError> {
        let tagged = match body {
            Body::Session(_) => return Err(ChainError::NotAgentBody),
            Body::Delegation(_) => m_delegation,
            Body::Invocation(_) => m_invocation,
        };
        if body.signer_id() != &self.agent || body.signer_pk() != self.pk.as_slice() {
            return Err(ChainError::NotMyBody);
        }
        self.policy.check(body).map_err(ChainError::Enforcement)?;
        let bytes = body.canonical_bytes()?;
        let m = tagged(m_prev, &bytes);
        let sig = S::sign(&self.sk, &m, Dst::Chain);
        Ok(Signed { bytes, m, sig })
    }
}

/// Default approval validity window, seconds (SPEC §8.4).
pub const APPROVAL_WINDOW: u64 = 300;

/// Signs approval receipts. Human approval is simulated as automatic (SPEC
/// §8.4).
pub struct ApprovalService<S: SigScheme> {
    id: Principal,
    sk: S::SecretKey,
    pk: Vec<u8>,
    window: u64,
    attestation: Vec<u8>,
}

impl<S: SigScheme> ApprovalService<S> {
    pub fn new(id: Principal, sk: S::SecretKey) -> Self {
        let pk = S::pk_bytes(&S::public_key(&sk));
        ApprovalService {
            id,
            sk,
            pk,
            window: APPROVAL_WINDOW,
            attestation: b"simulated-human-approval".to_vec(),
        }
    }

    pub fn with_window(mut self, window: u64) -> Self {
        self.window = window;
        self
    }

    pub fn id(&self) -> &Principal {
        &self.id
    }

    pub fn pk(&self) -> &[u8] {
        &self.pk
    }

    /// Approves the invocation as it stands, over InvocationDigest (D-06),
    /// which excludes any receipts already attached.
    pub fn approve(&self, inv: &InvocationBody<S>, now: u64) -> Result<Receipt<S>, ChainError> {
        let approval = ApprovalBody {
            approver_id: self.id.clone(),
            approver_pk: self.pk.clone(),
            invocation_digest: inv.invocation_digest()?,
            attestation: self.attestation.clone(),
            iat: now,
            exp: now + self.window,
        };
        self.sign(approval)
    }

    /// Signs an arbitrary approval body (for tests).
    pub fn sign(&self, approval: ApprovalBody) -> Result<Receipt<S>, ChainError> {
        let msg = approval_message(&approval.canonical_bytes()?);
        let sig = S::sign(&self.sk, &msg, Dst::Receipt);
        Ok(Receipt::new(approval, sig)?)
    }
}

/// A convenience: the raw form of a validated scope, for building bodies.
pub fn raw(scope: &Scope) -> RawScope {
    scope.to_raw()
}
