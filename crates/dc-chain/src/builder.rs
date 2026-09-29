//! Chain construction (SPEC §8.3).

use dc_crypto::{ChainScheme, Dst, SigScheme};
use dc_policy::{Decision, Invocation, Scope, evaluate};
use dc_types::digest::{Digest32, chain_digests};
use dc_types::{
    Body, DelegationBody, Envelope, Identifier, InvocationBody, Params, Principal, Receipt,
};
use rand_core::RngCore;

use crate::ChainError;
use crate::services::{ApprovalService, Issued, SigningService};

type Sig<C> = <<C as ChainScheme>::Base as SigScheme>::Signature;
type Sk<C> = <<C as ChainScheme>::Base as SigScheme>::SecretKey;

/// A finished chain.
#[derive(Clone, Debug)]
pub struct Chain<C: ChainScheme> {
    pub bodies: Vec<Body<C::Base>>,
    /// Canonical bytes of each body, as carried in the envelope.
    pub bytes: Vec<Vec<u8>>,
    /// m_0 … m_N.
    pub digests: Vec<Digest32>,
    /// σ_0 … σ_N individually. An observer of the running aggregate can
    /// recover these by subtraction (paper §4.3); the Theorem 3 tests use
    /// them to build the aggregates an attacker could.
    pub parts: Vec<Sig<C>>,
    pub sigs: C::WireSigs,
}

impl<C: ChainScheme> Chain<C> {
    pub fn envelope(&self) -> Envelope {
        Envelope {
            bodies: self.bytes.clone(),
            sigs: C::to_wire(&self.sigs),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.envelope().to_bytes()
    }

    /// N, the number of bodies after the session body.
    pub fn n(&self) -> usize {
        self.bodies.len() - 1
    }
}

/// Builds a chain hop by hop, as the paper's participants would: the issuer
/// signs B_0, each holder's signing service signs its delegation, and the
/// last holder signs the invocation. The running aggregate (or signature
/// list) grows with each hop.
///
/// The builder is mechanical: it sets the fields an honest participant sets
/// (hop index, session id, the chaining of identifiers and keys), but it
/// does not check containment or expiry. That is the verifier's job, and the
/// security suite needs to build chains that fail those checks.
///
/// A builder can be cloned before `invoke`, so that one prefix carries many
/// invocations, the pattern arms B and D cache for (SPEC §12.1).
#[derive(Clone)]
pub struct ChainBuilder<C: ChainScheme> {
    chain: Chain<C>,
    session_id: [u8; 16],
    holder: (Principal, Vec<u8>),
    scope: Scope,
}

impl<C: ChainScheme> ChainBuilder<C> {
    /// Starts from an issued session. `scope` is the session scope, which
    /// the builder keeps to evaluate invocations (step 2 of SPEC §8.3).
    pub fn start(issued: Issued<C::Base>, scope: Scope) -> Self {
        let holder = (
            issued.body.subject_id.clone(),
            issued.body.subject_pk.clone(),
        );
        ChainBuilder {
            session_id: issued.body.session_id,
            holder,
            scope,
            chain: Chain {
                sigs: C::start(issued.sig.clone()),
                parts: vec![issued.sig],
                digests: vec![issued.m0],
                bytes: vec![issued.bytes],
                bodies: vec![Body::Session(issued.body)],
            },
        }
    }

    /// The agent that holds the chain now: the session subject, or the last
    /// delegatee.
    pub fn holder(&self) -> &Principal {
        &self.holder.0
    }

    /// The scope the holder holds.
    pub fn scope(&self) -> &Scope {
        &self.scope
    }

    /// The expiry of the last body.
    pub fn exp(&self) -> u64 {
        self.chain.bodies.last().map(Body::exp).unwrap_or(0)
    }

    pub fn session_id(&self) -> [u8; 16] {
        self.session_id
    }

    /// Appends a delegation from the holder to `(to_id, to_pk)`, signed by
    /// the holder's signing service.
    pub fn delegate(
        &mut self,
        signer: &SigningService<C::Base>,
        to_id: &Principal,
        to_pk: &[u8],
        scope: Scope,
        exp: u64,
        rng: &mut impl RngCore,
    ) -> Result<(), ChainError> {
        let mut nonce = [0u8; 16];
        rng.fill_bytes(&mut nonce);
        let body = Body::Delegation(DelegationBody {
            delegator_id: self.holder.0.clone(),
            delegator_pk: self.holder.1.clone(),
            delegatee_id: to_id.clone(),
            delegatee_pk: to_pk.to_vec(),
            scope: scope.to_raw(),
            hop_index: self.chain.bodies.len() as u64,
            session_id: self.session_id,
            exp,
            nonce,
        });
        self.push(signer, body)?;
        self.holder = (to_id.clone(), to_pk.to_vec());
        self.scope = scope;
        Ok(())
    }

    fn push(
        &mut self,
        signer: &SigningService<C::Base>,
        body: Body<C::Base>,
    ) -> Result<(), ChainError> {
        let prev = *self.chain.digests.last().expect("B_0 is always present");
        let signed = signer.sign(&body, &prev)?;
        C::accumulate(&mut self.chain.sigs, signed.sig.clone());
        self.chain.parts.push(signed.sig);
        self.chain.digests.push(signed.m);
        self.chain.bytes.push(signed.bytes);
        self.chain.bodies.push(body);
        Ok(())
    }

    /// Step 1 of SPEC §8.3: the invocation body without receipts, with its
    /// `params_hash`.
    #[allow(clippy::too_many_arguments)]
    pub fn invocation_body(
        &self,
        aud: &Principal,
        tool: &Identifier,
        action: &Identifier,
        params: Params,
        nbf: u64,
        exp: u64,
        rng: &mut impl RngCore,
    ) -> Result<InvocationBody<C::Base>, ChainError> {
        let mut nonce = [0u8; 16];
        rng.fill_bytes(&mut nonce);
        Ok(InvocationBody {
            invoker_id: self.holder.0.clone(),
            invoker_pk: self.holder.1.clone(),
            aud: aud.clone(),
            tool: tool.clone(),
            action: action.clone(),
            params_hash: params.hash()?,
            params,
            receipts: vec![],
            nbf,
            exp,
            nonce,
        })
    }

    /// Step 2: evaluate the holder's own scope to learn which approvals the
    /// invocation needs. `Err(Denied)` if the scope denies it.
    pub fn required_approvals(
        &self,
        inv: &InvocationBody<C::Base>,
    ) -> Result<Vec<Principal>, ChainError> {
        let d = evaluate(
            &self.scope,
            &Invocation {
                aud: &inv.aud,
                tool: &inv.tool,
                action: &inv.action,
                params: inv.params.value(),
            },
        );
        match d {
            Decision::Allow => Ok(vec![]),
            Decision::AllowWithApproval(a) => Ok(a),
            Decision::Deny => Err(ChainError::Denied),
        }
    }

    /// Steps 4–5: embed the receipts (sorted, D-15), sign m_N and finish.
    pub fn invoke(
        mut self,
        signer: &SigningService<C::Base>,
        mut inv: InvocationBody<C::Base>,
        receipts: Vec<Receipt<C::Base>>,
    ) -> Result<Chain<C>, ChainError> {
        inv.set_receipts(receipts)?;
        self.push(signer, Body::Invocation(inv))?;
        Ok(self.chain)
    }

    /// All of SPEC §8.3's invocation steps: build the body, find the required
    /// approvals, collect a receipt from each required service among
    /// `approvers`, embed, sign.
    #[allow(clippy::too_many_arguments)]
    pub fn invoke_approved(
        self,
        signer: &SigningService<C::Base>,
        aud: &Principal,
        tool: &Identifier,
        action: &Identifier,
        params: Params,
        nbf: u64,
        exp: u64,
        approvers: &[&ApprovalService<C::Base>],
        now: u64,
        rng: &mut impl RngCore,
    ) -> Result<Chain<C>, ChainError> {
        let inv = self.invocation_body(aud, tool, action, params, nbf, exp, rng)?;
        let mut receipts = vec![];
        for needed in self.required_approvals(&inv)? {
            let service = approvers
                .iter()
                .find(|a| *a.id() == needed)
                .ok_or_else(|| ChainError::NoApprover(needed.clone()))?;
            receipts.push(service.approve(&inv, now)?);
        }
        self.invoke(signer, inv, receipts)
    }
}

/// Signs `bodies` in position order with `keys`, computing each digest with
/// the tag its position implies, as the verifier will (Algorithm 2 line 47),
/// and accumulating the signatures. It bypasses the signing services, as an
/// attacker holding the keys could. The security suite uses it to build
/// altered chains that are nevertheless correctly signed.
pub fn assemble<C: ChainScheme>(
    bodies: Vec<Body<C::Base>>,
    keys: &[&Sk<C>],
) -> Result<Chain<C>, ChainError> {
    if bodies.is_empty() || bodies.len() != keys.len() {
        return Err(ChainError::CountMismatch);
    }
    let bytes: Vec<Vec<u8>> = bodies
        .iter()
        .map(Body::canonical_bytes)
        .collect::<Result<_, _>>()?;
    let refs: Vec<&[u8]> = bytes.iter().map(Vec::as_slice).collect();
    let digests = chain_digests(&refs);
    let parts: Vec<Sig<C>> = digests
        .iter()
        .zip(keys)
        .map(|(m, sk)| C::Base::sign(sk, m, Dst::Chain))
        .collect();
    let mut sigs = C::start(parts[0].clone());
    for s in &parts[1..] {
        C::accumulate(&mut sigs, s.clone());
    }
    Ok(Chain {
        bodies,
        bytes,
        digests,
        parts,
        sigs,
    })
}

/// The wire signatures for an arbitrary list of individual signatures:
/// what an attacker who recovered them could present (Theorem 3 tests).
pub fn combine<C: ChainScheme>(parts: &[Sig<C>]) -> Option<C::WireSigs> {
    let (first, rest) = parts.split_first()?;
    let mut sigs = C::start(first.clone());
    for s in rest {
        C::accumulate(&mut sigs, s.clone());
    }
    Some(sigs)
}
