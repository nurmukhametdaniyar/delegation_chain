//! Workload profiles and chain generation (SPEC §13.2, D-38, D-40, D-71).
//!
//! Everything is derived from [`SEED`]: the world (keys, registries,
//! certificates), the policies, the large profile's rule-dropping order, and
//! every chain's nonces and session ids. The same seed gives the same bytes
//! in every process, so a verifier built in one process accepts chains
//! generated in another.

use std::sync::Arc;

use dc_cbor::{Key, Value};
use dc_chain::{ApprovalService, ChainBuilder, IssuanceService, SigningService, World};
use dc_crypto::{ChainScheme, SigScheme};
use dc_policy::Scope;
use dc_registry::{Directory, MemoryPolicyStore};
use dc_types::digest::{Digest32, sha256};
use dc_types::{Identifier, ManualClock, Params, Principal};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use serde::{Deserialize, Serialize};

/// The workload seed, recorded in the frozen plan.
pub const SEED: u64 = 0xDC_2026_0929;
/// Every chain is issued and verified at this time.
pub const T0: u64 = 1_790_000_000;
/// Agents per agent organization (D-40). Chains alternate between two agent
/// organizations, so a chain of N ≤ 10 hops never repeats an identity.
pub const POOL: usize = 12;
pub const AGENT_ORGS: [&str; 2] = ["orga", "orgc"];
pub const ISSUER: &str = "orga:issuer:main";
pub const FINANCE: &str = "orga:approver:finance";
pub const PAYMENTS: &str = "orgb:service:payments";
pub const FILES: &str = "orgb:service:files";
/// Body lifetime from T0, and the invocation's window.
pub const BODY_TTL: u64 = 3600;
pub const INVOCATION_TTL: u64 = 600;
/// The most hops any profile needs (N = 10).
pub const MAX_N: usize = 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Profile {
    Small,
    Medium,
    MediumApproval,
    Large,
}

impl Profile {
    pub const ALL: [Profile; 4] = [
        Profile::Small,
        Profile::Medium,
        Profile::MediumApproval,
        Profile::Large,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Profile::Small => "small",
            Profile::Medium => "medium",
            Profile::MediumApproval => "medium-approval",
            Profile::Large => "large",
        }
    }

    pub fn parse(s: &str) -> Option<Profile> {
        Profile::ALL.into_iter().find(|p| p.label() == s)
    }

    /// The verifier the invocation is addressed to.
    pub fn aud(self) -> &'static str {
        match self {
            Profile::Large => FILES,
            _ => PAYMENTS,
        }
    }
}

// ---- policies ----

/// The paper's §6.2 example, verbatim (the medium profile).
pub const PAPER_POLICY: &str = r#"allow at=orgb:service:payments
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

fn small_policy() -> String {
    "allow at=orgb:service:payments\n  tool=payments action=transfer\n  params { amount: int, to: string }\n  where amount <= 1000".into()
}

/// The medium profile after hop k: odd hops tighten rule 1's bound by 10,
/// even hops rule 2's by 1,000; one bound per hop (SPEC §13.2).
fn medium_policy(k: usize) -> String {
    let r1 = 1000 - 10 * k.div_ceil(2) as u64;
    let r2 = 100_000 - 1000 * (k / 2) as u64;
    PAPER_POLICY
        .replacen("amount <= 1000\n", &format!("amount <= {r1}\n"), 1)
        .replacen("amount <= 100000\n", &format!("amount <= {r2}\n"), 1)
}

/// One of the large profile's 16 rules: tool `t` (0–3), rule `j` (0–3).
/// Tools 0–1 are payment tools at the payments service, 2–3 file tools at
/// the files service. Rule 0 of each payment tool requires approval and
/// precedes the permissive rule 1 it overlaps (paper §6.3). The target, the
/// last rule, has its size bound tightened by one per hop.
fn large_rule(t: usize, j: usize, hop: usize) -> String {
    let (aud, tool, action) = [
        (PAYMENTS, "payments", "transfer"),
        (PAYMENTS, "refunds", "issue"),
        (FILES, "files", "read"),
        (FILES, "archive", "restore"),
    ][t];
    let head = format!("allow at={aud}\n  tool={tool} action={action}\n");
    if t < 2 {
        let params = "  params { amount: int, memo: string, to_account: string, urgent: bool }\n";
        let body = match j {
            0 => "  where amount <= 100000 and to_account in [\"acct_vendor_a\", \"acct_vendor_b\"] and urgent == false\n  approval requires orga:approver:finance".to_string(),
            1 => "  where amount <= 1000 and to_account in [\"acct_vendor_a\", \"acct_vendor_b\", \"acct_vendor_c\"] and urgent == false".to_string(),
            2 => "  where amount <= 500 and to_account starts_with \"acct_internal_\" and memo contains \"payroll\"".to_string(),
            _ => "  where amount <= 50 and to_account ends_with \"_petty\" and urgent == true".to_string(),
        };
        format!("{head}{params}{body}")
    } else {
        let params = "  params { owner: string, path: string, recursive: bool, size: int }\n";
        let size = if (t, j) == (3, 3) {
            4_000_000 - hop as u64
        } else {
            1_000_000 * (j as u64 + 1)
        };
        format!(
            "{head}{params}  where path under \"/data/{tool}/{j}\" and size <= {size} and owner starts_with \"team_{j}\""
        )
    }
}

const LARGE_TARGET: (usize, usize) = (3, 3);
const LARGE_KEPT: [(usize, usize); 3] = [(0, 0), (1, 0), LARGE_TARGET];
const LARGE_MIN_RULES: usize = 4;

/// The large profile's rules after hop k (D-38): hops drop 2 rules each,
/// in a seeded order, never an approval rule and never the target, until 4
/// rules remain; every hop tightens the target's size bound.
fn large_policy(k: usize) -> String {
    let mut droppable: Vec<(usize, usize)> = (0..4)
        .flat_map(|t| (0..4).map(move |j| (t, j)))
        .filter(|r| !LARGE_KEPT.contains(r))
        .collect();
    // Fisher–Yates with the workload seed.
    let mut rng = ChaCha20Rng::seed_from_u64(SEED ^ 0x1a6e);
    for i in (1..droppable.len()).rev() {
        let j = (rng.next_u64() % (i as u64 + 1)) as usize;
        droppable.swap(i, j);
    }
    let dropped_count = (2 * k).min(16 - LARGE_MIN_RULES);
    let dropped = &droppable[..dropped_count];
    let mut rules = vec![];
    for t in 0..4 {
        for j in 0..4 {
            if !dropped.contains(&(t, j)) {
                rules.push(large_rule(t, j, k));
            }
        }
    }
    rules.join("\n")
}

fn policy_text(profile: Profile, hop: usize) -> String {
    match profile {
        Profile::Small => small_policy(),
        Profile::Medium | Profile::MediumApproval => medium_policy(hop),
        Profile::Large => large_policy(hop),
    }
}

/// The scope each hop holds: `hop_scopes(p)[0]` is the session scope (the
/// policy itself), `[k]` the scope delegated at hop k, for k ≤ 9.
pub fn hop_scopes(profile: Profile) -> Vec<Scope> {
    (0..MAX_N)
        .map(|k| Scope::parse(&policy_text(profile, k)).expect("workload policies are well formed"))
        .collect()
}

fn map(entries: Vec<(&str, Value)>) -> Value {
    let entries: Vec<(Key, Value)> = entries
        .into_iter()
        .map(|(k, v)| (Key::from(k), v))
        .collect();
    Value::map(entries).expect("distinct keys")
}

/// The invocation of each profile: (tool, action, params).
pub fn invocation(profile: Profile) -> (Identifier, Identifier, Params) {
    let id = |s: &str| Identifier::new(s).expect("identifier");
    let (tool, action, value) = match profile {
        Profile::Small => (
            "payments",
            "transfer",
            map(vec![
                ("amount", Value::uint(500)),
                ("to", Value::text("acct_vendor_a")),
            ]),
        ),
        // Rule 1 (no approval).
        Profile::Medium => (
            "payments",
            "transfer",
            map(vec![
                ("amount", Value::uint(500)),
                ("to_account", Value::text("acct_vendor_a")),
            ]),
        ),
        // Over rule 1's bound, inside rule 2's: one finance receipt.
        Profile::MediumApproval => (
            "payments",
            "transfer",
            map(vec![
                ("amount", Value::uint(5000)),
                ("to_account", Value::text("acct_vendor_a")),
            ]),
        ),
        // Only the last rule matches (Evaluate's worst case).
        Profile::Large => (
            "archive",
            "restore",
            map(vec![
                ("owner", Value::text("team_3_ops")),
                ("path", Value::text("/data/archive/3/snapshot.tar")),
                ("recursive", Value::Bool(false)),
                ("size", Value::uint(1000)),
            ]),
        ),
    };
    (
        id(tool),
        id(action),
        Params::new(value).expect("canonical params"),
    )
}

// ---- the world ----

/// Agent identity `idx` of agent organization `org`.
pub fn agent_id(org: &str, idx: usize) -> String {
    format!("{org}:agent:p{idx}")
}

/// The agent at hop k of a chain whose rotation index is `i`: hops
/// alternate between the two agent organizations, and within one
/// organization hops k and k + 2 are two pool positions apart (D-40).
pub fn hop_agent(i: usize, k: usize) -> String {
    agent_id(AGENT_ORGS[k % 2], (i + k) % POOL)
}

/// The organizations, registries, parties and policies, for one base scheme.
pub struct Setting<S: SigScheme> {
    pub world: World<S>,
    pub issuer: IssuanceService<S>,
    pub finance: ApprovalService<S>,
    agents: Vec<(String, SigningService<S>)>,
    /// Per profile: the hop scopes and the policy hash.
    pub policies: Vec<(Profile, Vec<Scope>, Digest32)>,
}

impl<S: SigScheme> Setting<S> {
    /// Deterministic in [`SEED`]: enrolment order, and so every serial and
    /// certificate, is fixed.
    pub fn new() -> Self {
        let mut world = World::<S>::new(SEED, T0);
        world.org("orgb");
        world.enroll(ISSUER, ISSUER).expect("enrol issuer");
        world.enroll(FINANCE, FINANCE).expect("enrol approver");
        let mut agents = vec![];
        for org in AGENT_ORGS {
            for idx in 0..POOL {
                let id = agent_id(org, idx);
                world.enroll(&id, &id).expect("enrol agent");
                let svc = world.agent_service(&id, &id);
                agents.push((id, svc));
            }
        }
        let policies = Profile::ALL
            .into_iter()
            .map(|p| {
                let scopes = hop_scopes(p);
                let hash = world.publish(&scopes[0]);
                (p, scopes, hash)
            })
            .collect();
        let issuer = IssuanceService::new(p(ISSUER), world.secret(ISSUER));
        let finance = ApprovalService::new(p(FINANCE), world.secret(FINANCE));
        Setting {
            world,
            issuer,
            finance,
            agents,
            policies,
        }
    }

    pub fn agent(&self, id: &str) -> &SigningService<S> {
        &self
            .agents
            .iter()
            .find(|(a, _)| a == id)
            .expect("pool agent")
            .1
    }

    pub fn scopes(&self, profile: Profile) -> &[Scope] {
        &self.policy(profile).1
    }

    pub fn hash(&self, profile: Profile) -> Digest32 {
        self.policy(profile).2
    }

    fn policy(&self, profile: Profile) -> &(Profile, Vec<Scope>, Digest32) {
        self.policies
            .iter()
            .find(|(p, _, _)| *p == profile)
            .expect("every profile is published")
    }

    pub fn roots(&self) -> std::collections::HashMap<String, S::PublicKey> {
        self.world.roots()
    }

    pub fn directory(&self) -> Directory {
        self.world.directory()
    }

    pub fn store(&self) -> Arc<MemoryPolicyStore> {
        self.world.policies()
    }

    pub fn clock(&self) -> Arc<ManualClock> {
        self.world.clock()
    }

    /// The session and N − 1 delegations of chain `i`, as a builder its
    /// holder can invoke on.
    pub fn prefix<C: ChainScheme<Base = S>>(
        &self,
        profile: Profile,
        n: usize,
        i: usize,
        rng: &mut ChaCha20Rng,
    ) -> (ChainBuilder<C>, String) {
        assert!((1..=MAX_N).contains(&n));
        let scopes = self.scopes(profile);
        let first = self.agent(&hop_agent(i, 0));
        let issued = self
            .issuer
            .issue(
                first.agent(),
                first.pk(),
                &scopes[0],
                self.hash(profile),
                T0,
                BODY_TTL,
                rng,
            )
            .expect("issue");
        let mut b = ChainBuilder::<C>::start(issued, scopes[0].clone());
        for (k, scope) in scopes.iter().enumerate().take(n).skip(1) {
            let from = self.agent(&hop_agent(i, k - 1));
            let to = self.agent(&hop_agent(i, k));
            b.delegate(from, to.agent(), to.pk(), scope.clone(), T0 + BODY_TTL, rng)
                .expect("delegate");
        }
        (b, hop_agent(i, n - 1))
    }

    /// A fresh invocation on a prefix, with a receipt if the profile needs
    /// one.
    pub fn invoke<C: ChainScheme<Base = S>>(
        &self,
        profile: Profile,
        b: &ChainBuilder<C>,
        holder: &str,
        rng: &mut ChaCha20Rng,
    ) -> Vec<u8> {
        let (tool, action, params) = invocation(profile);
        let inv = b
            .invocation_body(
                &p(profile.aud()),
                &tool,
                &action,
                params,
                T0,
                T0 + INVOCATION_TTL,
                rng,
            )
            .expect("invocation body");
        let receipts = if profile == Profile::MediumApproval {
            vec![self.finance.approve(&inv, T0).expect("receipt")]
        } else {
            vec![]
        };
        b.clone()
            .invoke(self.agent(holder), inv, receipts)
            .expect("invoke")
            .to_bytes()
    }
}

impl<S: SigScheme> Default for Setting<S> {
    fn default() -> Self {
        Self::new()
    }
}

pub fn p(s: &str) -> Principal {
    Principal::parse(s).expect("principal")
}

// ---- chain sets ----

/// How a set's chains relate (SPEC §13.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Layout {
    /// Every chain has its own session and delegations.
    Fresh,
    /// `prefixes` prefixes, each carrying count / prefixes invocations,
    /// presented round-robin (D-39).
    Prefixed { prefixes: usize },
}

/// The deterministic seed of one set.
pub fn set_seed(tag: &str) -> u64 {
    u64::from_le_bytes(
        sha256(&[b"dc-bench-set", &SEED.to_le_bytes(), tag.as_bytes()])[..8]
            .try_into()
            .expect("8 bytes"),
    )
}

/// `count` chains of arm scheme `C` for (profile, N), in presentation order.
pub fn chains<C: ChainScheme>(
    setting: &Setting<C::Base>,
    profile: Profile,
    n: usize,
    layout: Layout,
    count: usize,
    tag: &str,
) -> Vec<Vec<u8>> {
    let mut rng = ChaCha20Rng::seed_from_u64(set_seed(tag));
    match layout {
        Layout::Fresh => (0..count)
            .map(|i| {
                let (b, holder) = setting.prefix::<C>(profile, n, i, &mut rng);
                setting.invoke(profile, &b, &holder, &mut rng)
            })
            .collect(),
        Layout::Prefixed { prefixes } => {
            let pre: Vec<(ChainBuilder<C>, String)> = (0..prefixes)
                .map(|i| setting.prefix::<C>(profile, n, i, &mut rng))
                .collect();
            (0..count)
                .map(|j| {
                    let (b, holder) = &pre[j % prefixes];
                    setting.invoke(profile, b, holder, &mut rng)
                })
                .collect()
        }
    }
}

/// Arm E's tokens for (profile, N): the session scope in the authority
/// block and the N − 1 delegation scopes as appended blocks (depth N − 1,
/// D-68). Each token has its own block keys, so no two are equal.
pub fn biscuit_tokens(
    arm: &dc_baselines::biscuit::BiscuitArm,
    profile: Profile,
    n: usize,
    count: usize,
    tag: &str,
) -> Vec<Vec<u8>> {
    let scopes = hop_scopes(profile);
    let exp = T0 + BODY_TTL;
    let attenuations: Vec<(&Scope, u64)> = scopes[1..n].iter().map(|s| (s, exp)).collect();
    (0..count)
        .map(|i| {
            let nonce = format!("{tag}/{i}");
            arm.token(&scopes[0], exp, &attenuations, nonce.as_bytes())
                .expect("biscuit token")
        })
        .collect()
}
