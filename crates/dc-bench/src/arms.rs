//! The arms under test (SPEC §12) and the states they are measured in
//! (SPEC §13.5), behind one interface, [`Subject`].
//!
//! Every arm's timed operation is one call of [`Subject::verify`] on the
//! chain's bytes. The call reads the verifier's clock and runs the whole of
//! Algorithms 1–2 (or arm E's `Biscuit::from` + authorizer + `authorize`).
//! The virtual call through `dyn Subject` is the same for every arm.

use std::sync::Arc;
use std::time::Duration;

use dc_baselines::biscuit::{BiscuitArm, Request};
use dc_baselines::{BlsIndividual, Ed25519Batch, Ed25519List};
use dc_cbor::Value;
use dc_crypto::{Bls, BlsAggregate, ChainScheme, Ed25519, PrefixScheme};
use dc_registry::{Directory, MemoryPolicyStore, WithLatency};
use dc_types::{Clock, Identifier, ManualClock, Principal};
use dc_verifier::{Path, PrefixVerifier, Verifier, VerifierConfig};
use serde::{Deserialize, Serialize};

use crate::workload::{Profile, Setting, T0, invocation, p};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Arm {
    A,
    AInd,
    B,
    C,
    CBatch,
    D,
    E,
    /// Supplementary: arm A with blst's thread pool (D-29).
    AMt,
}

impl Arm {
    pub const ALL: [Arm; 8] = [
        Arm::A,
        Arm::AInd,
        Arm::B,
        Arm::C,
        Arm::CBatch,
        Arm::D,
        Arm::E,
        Arm::AMt,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Arm::A => "A",
            Arm::AInd => "A-ind",
            Arm::B => "B",
            Arm::C => "C",
            Arm::CBatch => "C-batch",
            Arm::D => "D",
            Arm::E => "E",
            Arm::AMt => "A-mt",
        }
    }

    pub fn parse(s: &str) -> Option<Arm> {
        Arm::ALL.into_iter().find(|a| a.label() == s)
    }

    /// The wire family whose chains the arm verifies.
    pub fn family(self) -> Family {
        match self {
            Arm::A | Arm::B | Arm::AMt => Family::BlsAggregate,
            Arm::AInd => Family::BlsList,
            Arm::C | Arm::CBatch | Arm::D => Family::Ed25519List,
            Arm::E => Family::Biscuit,
        }
    }

    /// Only the A-mt build may run A-mt rows, and only the default build
    /// may run the others (SPEC §12, D-29).
    pub fn matches_build(self) -> bool {
        (self == Arm::AMt) == dc_crypto::BLST_THREADED
    }
}

/// Chains of one wire format, shared by the arms that verify it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Family {
    BlsAggregate,
    BlsList,
    Ed25519List,
    Biscuit,
}

impl Family {
    pub fn label(self) -> &'static str {
        match self {
            Family::BlsAggregate => "bls-aggregate",
            Family::BlsList => "bls-list",
            Family::Ed25519List => "ed25519-list",
            Family::Biscuit => "biscuit",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum State {
    /// A fresh verifier, with empty caches, for every call.
    Cold,
    /// Caches filled by separate warm-up chains (D-40).
    Warm,
    /// Arms B and D: chains share prefixes (D-39).
    WarmPrefix,
    /// Arms B and D: every chain has a new prefix; caches otherwise warm.
    PrefixMiss,
    /// Cold, with this many milliseconds injected per resolver and policy-
    /// store call (Q5, SPEC §13.4).
    ColdRtt(u64),
    /// Arm E: Biscuit keeps no state between calls.
    Stateless,
}

impl State {
    pub fn label(self) -> String {
        match self {
            State::Cold => "cold".into(),
            State::Warm => "warm".into(),
            State::WarmPrefix => "warm+prefix".into(),
            State::PrefixMiss => "prefix-miss".into(),
            State::ColdRtt(ms) => format!("cold+rtt{ms}ms"),
            State::Stateless => "stateless".into(),
        }
    }

    pub fn parse(s: &str) -> Option<State> {
        match s {
            "cold" => Some(State::Cold),
            "warm" => Some(State::Warm),
            "warm+prefix" => Some(State::WarmPrefix),
            "prefix-miss" => Some(State::PrefixMiss),
            "stateless" => Some(State::Stateless),
            _ => s
                .strip_prefix("cold+rtt")
                .and_then(|r| r.strip_suffix("ms"))
                .and_then(|ms| ms.parse().ok())
                .map(State::ColdRtt),
        }
    }

    /// Whether every call gets a new verifier.
    pub fn is_cold(self) -> bool {
        matches!(self, State::Cold | State::ColdRtt(_))
    }
}

/// The result of one verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub accepted: bool,
    /// Arms B and D: whether the prefix cache was used.
    pub path: Option<Path>,
}

pub trait Subject: Send + Sync {
    fn verify(&self, chain: &[u8]) -> Outcome;
    /// Resolver and policy-store calls so far (Q5 only; zeros otherwise).
    fn calls(&self) -> (u64, u64) {
        (0, 0)
    }
}

type Plain<C> = Verifier<C, Directory, Arc<MemoryPolicyStore>, Arc<ManualClock>>;
type Rtt<C> = Verifier<
    C,
    Arc<WithLatency<Directory>>,
    Arc<WithLatency<Arc<MemoryPolicyStore>>>,
    Arc<ManualClock>,
>;

impl<C: ChainScheme> Subject for Plain<C> {
    fn verify(&self, chain: &[u8]) -> Outcome {
        Outcome {
            accepted: Verifier::verify(self, chain).is_ok(),
            path: None,
        }
    }
}

struct RttSubject<C: ChainScheme> {
    v: Rtt<C>,
    resolver: Arc<WithLatency<Directory>>,
    store: Arc<WithLatency<Arc<MemoryPolicyStore>>>,
}

impl<C: ChainScheme> Subject for RttSubject<C> {
    fn verify(&self, chain: &[u8]) -> Outcome {
        Outcome {
            accepted: self.v.verify(chain).is_ok(),
            path: None,
        }
    }
    fn calls(&self) -> (u64, u64) {
        (self.resolver.calls(), self.store.calls())
    }
}

struct PrefixSubject<C: PrefixScheme> {
    v: PrefixVerifier<C, Directory, Arc<MemoryPolicyStore>, Arc<ManualClock>>,
    clock: Arc<ManualClock>,
}

impl<C: PrefixScheme> Subject for PrefixSubject<C> {
    /// `verify_traced` is `verify` with the path returned: `verify` reads
    /// the clock and calls it.
    fn verify(&self, chain: &[u8]) -> Outcome {
        let (r, path) = self.v.verify_traced(chain, self.clock.now());
        Outcome {
            accepted: r.is_ok(),
            path: Some(path),
        }
    }
}

/// Arm E with its request. Biscuit has no audience check of its own; the
/// authorizer supplies the invocation's audience, tool, action and
/// parameters as facts (D-68).
pub struct BiscuitSubject {
    arm: Arc<BiscuitArm>,
    aud: Principal,
    tool: Identifier,
    action: Identifier,
    params: Value,
}

impl Subject for BiscuitSubject {
    fn verify(&self, token: &[u8]) -> Outcome {
        let req = Request {
            aud: &self.aud,
            tool: &self.tool,
            action: &self.action,
            params: &self.params,
            now: T0,
        };
        Outcome {
            accepted: self.arm.verify(token, &req).is_ok(),
            path: None,
        }
    }
}

/// The worlds of both base schemes, and arm E's issuer.
pub struct Worlds {
    pub bls: Setting<Bls>,
    pub ed25519: Setting<Ed25519>,
    pub biscuit: Arc<BiscuitArm>,
}

impl Worlds {
    pub fn new() -> Self {
        Worlds {
            bls: Setting::new(),
            ed25519: Setting::new(),
            biscuit: Arc::new(BiscuitArm::new(&crate::workload::SEED.to_le_bytes())),
        }
    }
}

impl Default for Worlds {
    fn default() -> Self {
        Self::new()
    }
}

fn plain<C: ChainScheme>(
    s: &Setting<C::Base>,
    profile: Profile,
    config: VerifierConfig,
) -> Plain<C> {
    let v = Verifier::new(
        p(profile.aud()),
        s.roots(),
        s.directory(),
        s.store(),
        s.clock(),
        config,
    );
    v.pin("orga", s.hash(profile));
    v
}

fn rtt<C: ChainScheme>(s: &Setting<C::Base>, profile: Profile, ms: u64) -> RttSubject<C> {
    let delay = Duration::from_millis(ms);
    let resolver = Arc::new(WithLatency::new(s.directory(), delay));
    let store = Arc::new(WithLatency::new(s.store(), delay));
    let v = Verifier::new(
        p(profile.aud()),
        s.roots(),
        resolver.clone(),
        store.clone(),
        s.clock(),
        VerifierConfig::default(),
    );
    v.pin("orga", s.hash(profile));
    RttSubject { v, resolver, store }
}

fn prefix<C: PrefixScheme>(s: &Setting<C::Base>, profile: Profile) -> PrefixSubject<C> {
    PrefixSubject {
        v: PrefixVerifier::new(plain::<C>(s, profile, VerifierConfig::default())),
        clock: s.clock(),
    }
}

/// A new verifier for (arm, state, profile). A cold state calls this before
/// every verification, outside the timed region.
pub fn subject(w: &Worlds, arm: Arm, state: State, profile: Profile) -> Box<dyn Subject> {
    let warm = VerifierConfig::default();
    match (arm, state) {
        (Arm::A | Arm::AMt, State::ColdRtt(ms)) => {
            Box::new(rtt::<BlsAggregate>(&w.bls, profile, ms))
        }
        (Arm::C, State::ColdRtt(ms)) => Box::new(rtt::<Ed25519List>(&w.ed25519, profile, ms)),
        (Arm::A | Arm::AMt, _) => Box::new(plain::<BlsAggregate>(&w.bls, profile, warm)),
        (Arm::AInd, _) => Box::new(plain::<BlsIndividual>(&w.bls, profile, warm)),
        (Arm::C, _) => Box::new(plain::<Ed25519List>(&w.ed25519, profile, warm)),
        (Arm::CBatch, _) => Box::new(plain::<Ed25519Batch>(&w.ed25519, profile, warm)),
        (Arm::B, _) => Box::new(prefix::<BlsAggregate>(&w.bls, profile)),
        (Arm::D, _) => Box::new(prefix::<Ed25519List>(&w.ed25519, profile)),
        (Arm::E, _) => {
            let (tool, action, params) = invocation(profile);
            Box::new(BiscuitSubject {
                arm: w.biscuit.clone(),
                aud: p(profile.aud()),
                tool,
                action,
                params: params.value().clone(),
            })
        }
    }
}
