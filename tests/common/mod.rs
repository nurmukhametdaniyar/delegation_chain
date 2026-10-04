//! Shared fixtures for the workspace-level suites (SPEC §11.2, §11.3).
#![allow(dead_code)]

use std::marker::PhantomData;
use std::sync::Arc;

use dc_cbor::{Key, Value};
use dc_chain::{Chain, ChainBuilder, World, assemble, combine};
#[cfg(feature = "aggregate-variant")]
use dc_crypto::{Bls, BlsAggregate};
use dc_crypto::{ChainScheme, Dst, SigScheme};
#[cfg(not(feature = "aggregate-variant"))]
use dc_crypto::{Ed25519, Ed25519List};
use dc_policy::Scope;
use dc_registry::{Directory, MemoryPolicyStore};
use dc_types::digest::{Digest32, chain_digests};
use dc_types::{
    Body, Envelope, Identifier, InvocationBody, ManualClock, Params, Principal, Receipt,
};
use dc_verifier::{Verifier, VerifierConfig};

/// The instantiation the suites run against (D-84): the default, Ed25519
/// per hop (paper §4.2), or, with the root package's `aggregate-variant`
/// feature, the BLS aggregate variant (paper §4.8).
#[cfg(not(feature = "aggregate-variant"))]
pub type A = Ed25519List;
#[cfg(not(feature = "aggregate-variant"))]
pub type S = Ed25519;
#[cfg(feature = "aggregate-variant")]
pub type A = BlsAggregate;
#[cfg(feature = "aggregate-variant")]
pub type S = Bls;
/// The verifier of an arm, over the test world's resolver, store and clock.
pub type VOf<C> = Verifier<C, Directory, Arc<MemoryPolicyStore>, Arc<ManualClock>>;
pub type V = VOf<A>;
pub type Sk = <S as SigScheme>::SecretKey;
pub type SkOf<C> = <<C as ChainScheme>::Base as SigScheme>::SecretKey;

pub const T0: u64 = 1_790_000_000;
pub const PAYMENTS: &str = "orgb:service:payments";
pub const FILES: &str = "orgb:service:files";
pub const ISSUER: &str = "orga:issuer:main";
pub const FINANCE: &str = "orga:approver:finance";
pub const AUDIT: &str = "orga:approver:audit";

/// The paper's §6.2 example, verbatim.
pub const POLICY: &str = r#"allow at=orgb:service:payments
  tool=payments action=transfer
  params { amount: int,
           to_account: string }
  where amount <= 1000
allow at=orgb:service:payments
  tool=payments action=transfer
  params { amount: int,
           to_account: string }
  where amount <= 100000
        and to_account in
            ["acct_vendor_a", "acct_vendor_b"]
  approval requires orga:approver:finance
allow at=orgb:service:files
  tool=files action=read
  params { file: string }
  where file under "/home/agent/workspace""#;

pub fn p(s: &str) -> Principal {
    Principal::parse(s).unwrap()
}

pub fn id(s: &str) -> Identifier {
    Identifier::new(s).unwrap()
}

pub fn agent(i: usize) -> String {
    format!("orga:agent:a{i}")
}

pub fn transfer(amount: u64, to: &str) -> Params {
    Params::new(
        Value::map(vec![
            (Key::from("amount"), Value::uint(amount)),
            (Key::from("to_account"), Value::text(to)),
        ])
        .unwrap(),
    )
    .unwrap()
}

/// The policy with rule 1's bound replaced: a tighter or wider variant.
pub fn policy_with_bound(bound: u64) -> Scope {
    Scope::parse(&POLICY.replacen("amount <= 1000\n", &format!("amount <= {bound}\n"), 1)).unwrap()
}

/// A world with organizations `orga` (issuer, agents a1–a6, approvers
/// finance and audit) and `orgb` (the verifiers), and the §6.2 policy
/// published, for the arm whose chain scheme is `C`. Registries use the
/// arm's base scheme (SPEC §12).
pub struct ArmSuite<C: ChainScheme> {
    pub w: World<C::Base>,
    pub policy: Scope,
    pub hash: Digest32,
    arm: PhantomData<C>,
}

/// The suite for the instantiation under test (`A`).
pub type Suite = ArmSuite<A>;

impl<C: ChainScheme> ArmSuite<C> {
    pub fn new() -> Self {
        let mut w = World::new(0x5ec, T0);
        w.org("orgb");
        w.enroll(ISSUER, ISSUER).unwrap();
        for i in 1..=6 {
            w.enroll(&agent(i), &agent(i)).unwrap();
        }
        w.enroll(FINANCE, FINANCE).unwrap();
        w.enroll(AUDIT, AUDIT).unwrap();
        let policy = Scope::parse(POLICY).unwrap();
        let hash = w.publish(&policy);
        ArmSuite {
            w,
            policy,
            hash,
            arm: PhantomData,
        }
    }

    pub fn now(&self) -> u64 {
        self.w.now()
    }

    pub fn sk(&self, label: &str) -> SkOf<C> {
        self.w.secret(label)
    }

    pub fn pk(&self, label: &str) -> Vec<u8> {
        self.w.pk(label)
    }

    /// A verifier for `self_id`, with `orga`'s policy pinned.
    pub fn verifier_as(&self, self_id: &str, config: VerifierConfig) -> VOf<C> {
        self.verifier_for::<C>(self_id, config)
    }

    /// A verifier for arm `D`, which shares this arm's base scheme and wire
    /// format (C-batch on arm C's chains), with `orga`'s policy pinned.
    pub fn verifier_for<D: ChainScheme<Base = C::Base>>(
        &self,
        self_id: &str,
        config: VerifierConfig,
    ) -> VOf<D> {
        let v = Verifier::new(
            p(self_id),
            self.w.roots(),
            self.w.directory(),
            self.w.policies(),
            self.w.clock(),
            config,
        );
        v.pin("orga", self.hash);
        v
    }

    pub fn verifier(&self) -> VOf<C> {
        self.verifier_as(PAYMENTS, VerifierConfig::default())
    }

    /// An honest chain, fully specified. `issuer` and each entry of
    /// `agents` are (identifier, key label). `agents[0]` receives the session
    /// with scope `scopes[0]`; each `agents[i]` delegates `scopes[i + 1]` to
    /// `agents[i + 1]`; the last agent invokes `params` at `aud`, with a
    /// receipt from each required approver found in `approvers` (identifier,
    /// key label). Every body expires at now + 3600; the invocation is valid
    /// from now.
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        &mut self,
        issuer: (&str, &str),
        agents: &[(&str, &str)],
        scopes: &[Scope],
        aud: &str,
        tool: &str,
        action: &str,
        params: Params,
        approvers: &[(&str, &str)],
    ) -> Chain<C> {
        let b = self.prefix(issuer, agents, scopes);
        let now = self.now();
        self.invoke_on(
            b,
            *agents.last().unwrap(),
            aud,
            tool,
            action,
            params,
            (now, now + 3600),
            approvers,
        )
    }

    /// The session and delegations of an honest chain (see [`Self::build`]),
    /// as a builder the last agent can invoke on. Clone it to invoke on the
    /// same prefix many times. Every body expires at now + 3600.
    pub fn prefix(
        &mut self,
        issuer: (&str, &str),
        agents: &[(&str, &str)],
        scopes: &[Scope],
    ) -> ChainBuilder<C> {
        assert_eq!(agents.len(), scopes.len());
        let now = self.now();
        let exp = now + 3600;
        let iss = dc_chain::IssuanceService::<C::Base>::new(p(issuer.0), self.sk(issuer.1));
        let svc = |s: &Self, (id, key): (&str, &str)| s.w.agent_service(id, key);
        let first = svc(self, agents[0]);
        let issued = iss
            .issue(
                first.agent(),
                first.pk(),
                &scopes[0],
                self.hash,
                now,
                3600,
                self.w.rng(),
            )
            .unwrap();
        let mut b = ChainBuilder::<C>::start(issued, scopes[0].clone());
        for i in 1..agents.len() {
            let from = svc(self, agents[i - 1]);
            let to = svc(self, agents[i]);
            b.delegate(
                &from,
                to.agent(),
                to.pk(),
                scopes[i].clone(),
                exp,
                self.w.rng(),
            )
            .unwrap();
        }
        b
    }

    /// The invocation step on a prefix: `signer` (identifier, key label)
    /// invokes with validity `window`, with a receipt from each required
    /// approver found in `approvers`.
    #[allow(clippy::too_many_arguments)]
    pub fn invoke_on(
        &mut self,
        b: ChainBuilder<C>,
        signer: (&str, &str),
        aud: &str,
        tool: &str,
        action: &str,
        params: Params,
        window: (u64, u64),
        approvers: &[(&str, &str)],
    ) -> Chain<C> {
        let now = self.now();
        let signer = self.w.agent_service(signer.0, signer.1);
        let inv = b
            .invocation_body(
                &p(aud),
                &id(tool),
                &id(action),
                params,
                window.0,
                window.1,
                self.w.rng(),
            )
            .unwrap();
        let mut receipts = vec![];
        if let Ok(needed) = b.required_approvals(&inv) {
            for n in needed {
                if let Some((aid, key)) = approvers.iter().find(|(aid, _)| p(aid) == n) {
                    let svc = dc_chain::ApprovalService::<C::Base>::new(p(aid), self.sk(key));
                    receipts.push(svc.approve(&inv, now).unwrap());
                }
            }
        }
        b.invoke(&signer, inv, receipts).unwrap()
    }

    /// An honest chain from the default parties: issuer, a1 … a_N, finance
    /// and audit, each under its own key.
    pub fn chain_with(
        &mut self,
        scopes: &[Scope],
        aud: &str,
        tool: &str,
        action: &str,
        params: Params,
    ) -> Chain<C> {
        let names: Vec<String> = (1..=scopes.len()).map(agent).collect();
        let agents: Vec<(&str, &str)> = names.iter().map(|n| (n.as_str(), n.as_str())).collect();
        self.build(
            (ISSUER, ISSUER),
            &agents,
            scopes,
            aud,
            tool,
            action,
            params,
            &[(FINANCE, FINANCE), (AUDIT, AUDIT)],
        )
    }

    /// An honest chain of N bodies after the session (N − 1 delegations),
    /// every scope the policy, invoking a 500-unit transfer at payments.
    pub fn chain(&mut self, n: usize) -> Chain<C> {
        let scopes = vec![self.policy.clone(); n];
        self.chain_with(
            &scopes,
            PAYMENTS,
            "payments",
            "transfer",
            transfer(500, "acct_vendor_a"),
        )
    }

    /// A chain whose invocation needs the finance approval.
    pub fn approval_chain(&mut self, n: usize) -> Chain<C> {
        let scopes = vec![self.policy.clone(); n];
        self.chain_with(
            &scopes,
            PAYMENTS,
            "payments",
            "transfer",
            transfer(5000, "acct_vendor_a"),
        )
    }

    /// The secret key of each body's signer, by the default label (the
    /// signer's identifier).
    pub fn keys_for(&self, bodies: &[Body<C::Base>]) -> Vec<SkOf<C>> {
        bodies
            .iter()
            .map(|b| self.sk(b.signer_id().as_str()))
            .collect()
    }

    /// Re-signs altered bodies as an attacker holding the keys would.
    pub fn resign(&self, bodies: Vec<Body<C::Base>>, keys: &[SkOf<C>]) -> Chain<C> {
        let refs: Vec<&SkOf<C>> = keys.iter().collect();
        assemble::<C>(bodies, &refs).unwrap()
    }

    /// Re-signs altered bodies with each signer's own key.
    pub fn resign_default(&self, bodies: Vec<Body<C::Base>>) -> Chain<C> {
        let keys = self.keys_for(&bodies);
        self.resign(bodies, &keys)
    }

    /// A fresh invocation nonce, so that a rebuilt chain is not a replay.
    pub fn fresh(&mut self, inv: &mut InvocationBody<C::Base>) {
        use rand_core_shim::fill;
        fill(self.w.rng(), &mut inv.nonce);
    }
}

/// Signs raw body bytes (for bodies no typed value can express) with
/// position tags, and assembles the envelope.
pub fn sign_raw(bytes: Vec<Vec<u8>>, keys: &[Sk]) -> Vec<u8> {
    let refs: Vec<&[u8]> = bytes.iter().map(Vec::as_slice).collect();
    let m = chain_digests(&refs);
    let parts: Vec<_> = m
        .iter()
        .zip(keys)
        .map(|(m, k)| S::sign(k, m, Dst::Chain))
        .collect();
    let sigs = combine::<A>(&parts).unwrap();
    Envelope {
        bodies: bytes,
        sigs: A::to_wire(&sigs),
    }
    .to_bytes()
}

/// The invocation of a chain.
pub fn invocation(c: &Chain<A>) -> InvocationBody<S> {
    match c.bodies.last().unwrap() {
        Body::Invocation(i) => i.clone(),
        _ => panic!("last body is not an invocation"),
    }
}

/// A body's CBOR map with field `key` replaced or removed.
pub fn with_field(v: &Value, key: u64, new: Option<Value>) -> Vec<u8> {
    let mut m: Vec<(Key, Value)> = v
        .as_map()
        .unwrap()
        .iter()
        .filter(|(k, _)| *k != Key::Uint(key))
        .cloned()
        .collect();
    if let Some(x) = new {
        m.push((Key::Uint(key), x));
    }
    dc_cbor::encode(&Value::map(m).unwrap()).unwrap()
}

pub fn receipts(c: &[Receipt<S>]) -> Value {
    Value::Array(c.iter().map(Receipt::to_value).collect())
}

/// Fills a byte array from the world's generator.
pub mod rand_core_shim {
    pub fn fill(rng: &mut rand_chacha::ChaCha20Rng, out: &mut [u8]) {
        use rand_core::RngCore;
        rng.fill_bytes(out);
    }
}
