//! SPEC §11.3 with every cached configuration, including warm+prefix for
//! arms B and D (SPEC §12.1). For each wire format, the uncached verifier
//! and every cached configuration must return the same decision, and the
//! same reject variant, on 10,000 randomized chains, valid and mutated:
//!
//! - BLS aggregate: A uncached, A warm, B warm+prefix;
//! - Ed25519 list: C uncached and warm, C-batch uncached and warm, D
//!   warm+prefix;
//! - BLS list: A-ind uncached and warm.
//!
//! The prefix caches only matter when prefixes repeat, so three chains in
//! four are new invocations on one of 12 stored prefixes: one delegation,
//! many invocations, the deployment pattern of SPEC §12.2. The rest start a
//! new prefix. A prefix is cached only once a chain on it is accepted.
//! Invocation-level mutations (another holder, an expiry beyond the
//! prefix's, a future nbf, a missing approval) exercise the hit path's
//! rejections, and whole-chain mutations exercise its misses.
//!
//! Interleaved events, as `cache_equivalence.rs` (SPEC §11.3, D-65):
//! revocations followed by emergency rotation, certificate expiry (clock
//! advances), new-key rotations, same-key renewals (from now, future-dated,
//! and shortening; P-30), renewals followed by revocation of the older or
//! the newer certificate; plus pin changes: P2 is pinned at 1/2 of the run,
//! unpinned at 3/4 and pinned again at 7/8.
//!
//! `DC_EQUIV_CHAINS` sets the number of chains per family (default
//! 10,000); `DC_EQUIV_REPORT_DIR` names a directory for one JSON report per
//! family.

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;

use common::*;
use dc_baselines::{BlsIndividual, Ed25519Batch, Ed25519List};
use dc_chain::{ChainBuilder, ChainError};
use dc_crypto::{BlsAggregate, ChainScheme, PrefixScheme};
use dc_registry::{Directory, MemoryPolicyStore, RegistryError, Resolver};
use dc_types::digest::Digest32;
use dc_types::{Body, ManualClock, ParsedCert, RevocationAssertion};
use dc_verifier::{Accepted, Path, PrefixVerifier, Reject, VerifierConfig};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

type PV<C> = PrefixVerifier<C, Directory, Arc<MemoryPolicyStore>, Arc<ManualClock>>;

/// A verifier configuration under test.
trait Config {
    fn verify(&self, chain: &[u8], t: u64) -> (Result<Accepted, Reject>, Option<Path>);
    fn ingest(&self, a: &RevocationAssertion);
    fn pin(&self, org: &str, hash: Digest32);
    fn unpin(&self, org: &str, hash: &Digest32);
}

impl<C: ChainScheme> Config for VOf<C> {
    fn verify(&self, chain: &[u8], t: u64) -> (Result<Accepted, Reject>, Option<Path>) {
        (self.verify_at(chain, t), None)
    }
    fn ingest(&self, a: &RevocationAssertion) {
        self.ingest_revocation(a).unwrap();
    }
    fn pin(&self, org: &str, hash: Digest32) {
        VOf::<C>::pin(self, org, hash);
    }
    fn unpin(&self, org: &str, hash: &Digest32) {
        VOf::<C>::unpin(self, org, hash);
    }
}

impl<C: PrefixScheme> Config for PV<C> {
    fn verify(&self, chain: &[u8], t: u64) -> (Result<Accepted, Reject>, Option<Path>) {
        let (r, path) = self.verify_traced(chain, t);
        (r, Some(path))
    }
    fn ingest(&self, a: &RevocationAssertion) {
        self.ingest_revocation(a).unwrap();
    }
    fn pin(&self, org: &str, hash: Digest32) {
        PV::<C>::pin(self, org, hash);
    }
    fn unpin(&self, org: &str, hash: &Digest32) {
        PV::<C>::unpin(self, org, hash);
    }
}

type Configs = Vec<(&'static str, Box<dyn Config>)>;

/// Stored prefixes; a new prefix replaces a random one when full.
const POOL: usize = 12;

fn pick<'a, T>(rng: &mut ChaCha20Rng, v: &'a [T]) -> &'a T {
    &v[(rng.next_u64() % v.len() as u64) as usize]
}

fn chance(rng: &mut ChaCha20Rng, per_mille: u64) -> bool {
    rng.next_u64() % 1000 < per_mille
}

fn outcome(r: &Result<Accepted, Reject>) -> String {
    match r {
        Ok(_) => "accept".into(),
        Err(e) => format!("L{:02}", e.line()),
    }
}

/// A stored prefix: the builder after the last delegation, and who holds it.
struct Prefix<C: ChainScheme> {
    builder: ChainBuilder<C>,
    agents: Vec<(String, String)>,
    hash: Digest32,
    exp: u64,
}

fn run<C: ChainScheme>(family: &str, seed: u64, make: impl FnOnce(&ArmSuite<C>) -> Configs) {
    let total: usize = std::env::var("DC_EQUIV_CHAINS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10_000);
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let mut s = ArmSuite::<C>::new();
    let now = s.now();
    let mut keys: BTreeMap<String, Vec<String>> =
        (1..=6).map(|i| (agent(i), vec![agent(i)])).collect();
    for (i, life) in [(1, 2_000), (2, 4_000), (3, 6_000)] {
        let id = format!("orga:agent:s{i}");
        s.w.enroll_window(&id, &id, now, now + life).unwrap();
        keys.insert(id.clone(), vec![id]);
    }
    let (p1, h1) = (s.policy.clone(), s.hash);
    let p2 = policy_with_bound(700);
    let h2 = s.w.publish(&p2);

    let configs = make(&s);
    let mut counts: BTreeMap<String, u64> = BTreeMap::new();
    let mut events: BTreeMap<&str, u64> = BTreeMap::new();
    let mut paths: BTreeMap<&str, BTreeMap<String, u64>> = BTreeMap::new();
    let mut recent: Vec<Vec<u8>> = vec![];
    let mut prefixes: Vec<Prefix<C>> = vec![];
    let mut rotation = 0;
    let mut revoke = |s: &mut ArmSuite<C>,
                      rng: &mut ChaCha20Rng,
                      keys: &mut BTreeMap<String, Vec<String>>,
                      serial: u64,
                      id: &str,
                      label: &str,
                      configs: &Configs| {
        let a = s.w.org("orga").revoke(serial).unwrap();
        for (_, c) in configs {
            c.ingest(&a);
        }
        // Emergency rotation to a fresh key; the revoked key usually leaves
        // the pool, and sometimes stays so that chains still name it.
        rotation += 1;
        let fresh = format!("{id}-rot{rotation}");
        let t = s.now();
        s.w.enroll_window(id, &fresh, t, t + 20_000).unwrap();
        let pool = keys.get_mut(id).unwrap();
        if chance(rng, 800) {
            pool.retain(|l| l != label);
        }
        pool.push(fresh);
    };
    let mut rotation_labels = 1_000_000;

    for step in 0..total {
        // ---- interleaved events ----
        for (at, what) in [
            (total / 2, "pin P2"),
            (3 * total / 4, "unpin P2"),
            (7 * total / 8, "pin P2 again"),
        ] {
            if step == at {
                for (_, c) in &configs {
                    if what == "unpin P2" {
                        c.unpin("orga", &h2);
                    } else {
                        c.pin("orga", h2);
                    }
                }
                *events.entry(what).or_default() += 1;
            }
        }
        if chance(&mut rng, 20) {
            s.w.clock().advance(1 + rng.next_u64() % 200);
            *events.entry("clock advance").or_default() += 1;
        }
        if chance(&mut rng, 3) {
            let ids: Vec<String> = keys.keys().cloned().collect();
            let id = pick(&mut rng, &ids).clone();
            let label = pick(&mut rng, &keys[&id]).clone();
            let reg = s.w.org("orga");
            if let Some(cert) = reg.resolve(&p(&id), &s.pk(&label), s.now()) {
                let serial = ParsedCert::<C::Base>::decode(&cert).unwrap().body.serial;
                revoke(&mut s, &mut rng, &mut keys, serial, &id, &label, &configs);
                *events.entry("revocation").or_default() += 1;
            }
        }
        if chance(&mut rng, 5) {
            let ids: Vec<String> = keys.keys().cloned().collect();
            let id = pick(&mut rng, &ids).clone();
            let label = pick(&mut rng, &keys[&id]).clone();
            match s.w.enroll(&id, &label) {
                Ok(_) => *events.entry("renewal").or_default() += 1,
                Err(ChainError::Registry(RegistryError::RevokedBinding)) => {
                    *events
                        .entry("renewal refused (revoked binding)")
                        .or_default() += 1
                }
                Err(e) => panic!("renewal: {e}"),
            }
        }
        for (kind, per_mille) in [("future-dated renewal", 3), ("shortening renewal", 3)] {
            // P-30: renewals whose window starts later, or ends early.
            if chance(&mut rng, per_mille) {
                let ids: Vec<String> = keys.keys().cloned().collect();
                let id = pick(&mut rng, &ids).clone();
                let label = pick(&mut rng, &keys[&id]).clone();
                let t = s.now();
                let (nbf, exp) = if kind == "future-dated renewal" {
                    let nbf = t + 1 + rng.next_u64() % 3000;
                    (nbf, nbf + 20_000)
                } else {
                    (t, t + 50 + rng.next_u64() % 2000)
                };
                match s.w.enroll_window(&id, &label, nbf, exp) {
                    Ok(_) => *events.entry(kind).or_default() += 1,
                    Err(ChainError::Registry(RegistryError::RevokedBinding)) => {
                        *events
                            .entry("renewal refused (revoked binding)")
                            .or_default() += 1
                    }
                    Err(e) => panic!("{kind}: {e}"),
                }
            }
        }
        if chance(&mut rng, 3) {
            let ids: Vec<String> = keys.keys().cloned().collect();
            let id = pick(&mut rng, &ids).clone();
            let label = pick(&mut rng, &keys[&id]).clone();
            if s.w.enroll(&id, &label).is_ok() {
                let serials = s.w.org("orga").serials_of(&p(&id), &s.pk(&label));
                let older = chance(&mut rng, 500);
                let serial = serials[serials.len() - if older { 2 } else { 1 }];
                revoke(&mut s, &mut rng, &mut keys, serial, &id, &label, &configs);
                *events
                    .entry(if older {
                        "renewal then revocation of the older certificate"
                    } else {
                        "renewal then revocation of the newer certificate"
                    })
                    .or_default() += 1;
            }
        }
        if chance(&mut rng, 5) {
            let ids: Vec<String> = keys.keys().cloned().collect();
            let id = pick(&mut rng, &ids).clone();
            rotation_labels += 1;
            let label = format!("{id}-rot{rotation_labels}");
            let t = s.now();
            s.w.enroll_window(&id, &label, t, t + 20_000).unwrap();
            keys.get_mut(&id).unwrap().push(label);
            *events.entry("rotation").or_default() += 1;
        }

        // ---- a chain ----
        let bytes = if !recent.is_empty() && chance(&mut rng, 30) {
            *events.entry("replay").or_default() += 1;
            pick(&mut rng, &recent).clone()
        } else {
            let reuse = !prefixes.is_empty() && chance(&mut rng, 750);
            let i = if reuse {
                (rng.next_u64() % prefixes.len() as u64) as usize
            } else {
                // A new prefix of 1–4 agents.
                let n = 1 + (rng.next_u64() % 4) as usize;
                let mut ids: Vec<String> = keys.keys().cloned().collect();
                let mut agents: Vec<(String, String)> = vec![];
                for _ in 0..n {
                    let i = (rng.next_u64() % ids.len() as u64) as usize;
                    let id = ids.remove(i);
                    let label = pick(&mut rng, &keys[&id]).clone();
                    agents.push((id, label));
                }
                let (session, hash) = if chance(&mut rng, 250) {
                    (p2.clone(), h2)
                } else {
                    (p1.clone(), h1)
                };
                s.hash = hash;
                let mut bound = if hash == h2 { 700 } else { 1000 };
                let mut scopes = vec![session];
                for _ in 1..n {
                    if chance(&mut rng, 50) {
                        bound += 500; // a widening: line 34
                    } else if chance(&mut rng, 500) {
                        bound -= 1 + rng.next_u64() % 50;
                    }
                    scopes.push(policy_with_bound(bound));
                }
                let refs: Vec<(&str, &str)> = agents
                    .iter()
                    .map(|(a, b)| (a.as_str(), b.as_str()))
                    .collect();
                let builder = s.prefix((ISSUER, ISSUER), &refs, &scopes);
                let exp = builder.exp();
                let entry = Prefix {
                    builder,
                    agents,
                    hash,
                    exp,
                };
                if prefixes.len() < POOL {
                    prefixes.push(entry);
                    prefixes.len() - 1
                } else {
                    let j = (rng.next_u64() % POOL as u64) as usize;
                    prefixes[j] = entry;
                    j
                }
            };
            *events
                .entry(if reuse {
                    "invocation on a stored prefix"
                } else {
                    "new prefix"
                })
                .or_default() += 1;
            let pre = &prefixes[i];
            s.hash = pre.hash;
            let amount = *pick(&mut rng, &[400, 500, 900, 5000, 200_000]);
            let to = *pick(&mut rng, &["acct_vendor_a", "acct_vendor_b", "acct_other"]);
            let aud = if chance(&mut rng, 30) {
                FILES
            } else {
                PAYMENTS
            };
            let approvers: &[(&str, &str)] = if chance(&mut rng, 50) {
                &[(AUDIT, AUDIT)] // finance's receipt is missing: line 40
            } else {
                &[(FINANCE, FINANCE), (AUDIT, AUDIT)]
            };
            let now = s.now();
            let holder = pre.agents.last().unwrap().clone();
            let agents = pre.agents.clone();
            let exp = pre.exp;
            let builder = pre.builder.clone();
            let c = s.invoke_on(
                builder,
                (&holder.0, &holder.1),
                aud,
                "payments",
                "transfer",
                transfer(amount, to),
                (now, exp.min(now + 600)),
                approvers,
            );
            let keys_now = keys_by_label(&s, &agents);
            // Mutations, about half the time.
            match rng.next_u64() % 16 {
                0 | 1 => {
                    let mut b = c.to_bytes();
                    let i = (rng.next_u64() % b.len() as u64) as usize;
                    b[i] ^= 1 << (rng.next_u64() % 8);
                    b
                }
                2 => {
                    let mut ks = keys_now;
                    let i = (rng.next_u64() % ks.len() as u64) as usize;
                    ks[i] = s.sk("stranger");
                    s.resign(c.bodies.clone(), &ks).to_bytes()
                }
                3 if c.n() >= 2 => {
                    let mut env = c.envelope();
                    env.bodies.remove(1);
                    env.to_bytes()
                }
                4 if c.n() >= 3 => {
                    let mut env = c.envelope();
                    env.bodies.swap(1, 2);
                    env.to_bytes()
                }
                5 => {
                    // Not yet valid: line 13.
                    let mut bodies = c.bodies.clone();
                    let Body::Invocation(inv) = bodies.last_mut().unwrap() else {
                        unreachable!()
                    };
                    inv.nbf = s.now() + 50;
                    s.resign(bodies, &keys_now).to_bytes()
                }
                6 => {
                    // Another agent invokes on the prefix: line 18 or 20.
                    let ids: Vec<String> = keys.keys().cloned().collect();
                    let other = pick(&mut rng, &ids).clone();
                    let label = pick(&mut rng, &keys[&other]).clone();
                    let mut bodies = c.bodies.clone();
                    let Body::Invocation(inv) = bodies.last_mut().unwrap() else {
                        unreachable!()
                    };
                    inv.invoker_id = p(&other);
                    inv.invoker_pk = s.pk(&label);
                    let mut ks = keys_now;
                    *ks.last_mut().unwrap() = s.sk(&label);
                    s.resign(bodies, &ks).to_bytes()
                }
                7 => {
                    // The invocation outlives the prefix: line 15.
                    let mut bodies = c.bodies.clone();
                    let Body::Invocation(inv) = bodies.last_mut().unwrap() else {
                        unreachable!()
                    };
                    inv.exp = exp + 100;
                    s.resign(bodies, &keys_now).to_bytes()
                }
                _ => c.to_bytes(),
            }
        };
        let t = s.now();
        let results: Vec<(Result<Accepted, Reject>, Option<Path>)> =
            configs.iter().map(|(_, c)| c.verify(&bytes, t)).collect();
        for ((name, _), (r, path)) in configs.iter().zip(&results).skip(1) {
            assert_eq!(
                r, &results[0].0,
                "{family}, step {step}: {name} disagrees with {}",
                configs[0].0
            );
            if let Some(path) = path {
                let key = format!(
                    "{} {}",
                    if *path == Path::Hit { "hit" } else { "miss" },
                    outcome(r)
                );
                *paths.entry(name).or_default().entry(key).or_default() += 1;
            }
        }
        *counts.entry(outcome(&results[0].0)).or_default() += 1;
        recent.push(bytes);
        if recent.len() > 50 {
            recent.remove(0);
        }
    }

    let hits: BTreeMap<&str, u64> = paths
        .iter()
        .map(|(name, m)| {
            (
                *name,
                m.iter()
                    .filter(|(k, _)| k.starts_with("hit"))
                    .map(|(_, v)| v)
                    .sum(),
            )
        })
        .collect();
    let report = serde_json::json!({
        "label": format!("SPEC §11.3 cache equivalence, {family}; test statistics"),
        "configurations": configs.iter().map(|(n, _)| *n).collect::<Vec<_>>(),
        "chains": total,
        "outcomes": counts,
        "events": events,
        "prefix_cache_paths": paths,
        "prefix_cache_hits": hits,
    });
    println!("{}", serde_json::to_string_pretty(&report).unwrap());
    if let Ok(dir) = std::env::var("DC_EQUIV_REPORT_DIR") {
        let name = family.to_lowercase().replace([' ', '+'], "-");
        std::fs::write(
            format!("{dir}/cache-equivalence-m7-{name}.json"),
            serde_json::to_string_pretty(&report).unwrap() + "\n",
        )
        .unwrap();
    }
    assert!(counts.get("accept").copied().unwrap_or(0) > (total / 10) as u64);
    assert!(counts.len() >= 10, "{counts:?}");
    for (name, h) in &hits {
        assert!(
            *h > (total / 5) as u64,
            "{name}: only {h} prefix-cache hits"
        );
    }
}

/// Signing keys in chain order: issuer, then each agent under its label.
fn keys_by_label<C: ChainScheme>(s: &ArmSuite<C>, agents: &[(String, String)]) -> Vec<SkOf<C>> {
    let mut v = vec![s.sk(ISSUER)];
    v.extend(agents.iter().map(|(_, l)| s.sk(l)));
    v
}

#[test]
fn bls_aggregate_a_uncached_a_warm_b_warm_prefix() {
    run::<BlsAggregate>("BLS aggregate", 0xe9b, |s| {
        vec![
            (
                "A uncached",
                Box::new(s.verifier_as(PAYMENTS, VerifierConfig::uncached())),
            ),
            ("A warm", Box::new(s.verifier())),
            ("B warm+prefix", Box::new(PrefixVerifier::new(s.verifier()))),
        ]
    });
}

#[test]
fn ed25519_list_c_c_batch_d_warm_prefix() {
    run::<Ed25519List>("Ed25519 list", 0xe9d, |s| {
        let batch = s.verifier_for::<Ed25519Batch>(PAYMENTS, VerifierConfig::uncached());
        let batch_warm = s.verifier_for::<Ed25519Batch>(PAYMENTS, VerifierConfig::default());
        vec![
            (
                "C uncached",
                Box::new(s.verifier_as(PAYMENTS, VerifierConfig::uncached())),
            ),
            ("C warm", Box::new(s.verifier())),
            ("C-batch uncached", Box::new(batch)),
            ("C-batch warm", Box::new(batch_warm)),
            ("D warm+prefix", Box::new(PrefixVerifier::new(s.verifier()))),
        ]
    });
}

#[test]
fn bls_list_a_ind() {
    run::<BlsIndividual>("BLS list", 0xe9a, |s| {
        vec![
            (
                "A-ind uncached",
                Box::new(s.verifier_as(PAYMENTS, VerifierConfig::uncached())),
            ),
            ("A-ind warm", Box::new(s.verifier())),
        ]
    });
}
