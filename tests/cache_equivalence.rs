//! SPEC §11.3, warm state: an uncached verifier and a warm one (certificate
//! and policy caches, paper §5.4) must return the same decision, and the same
//! reject variant, on 10,000 randomized chains, valid and mutated. Revocations,
//! certificate expiry (by advancing the clock), new pins and key rotations are
//! interleaved. The warm+prefix configurations join at M7.
//!
//! `DC_EQUIV_CHAINS` sets the number of chains (default 10,000);
//! `DC_EQUIV_REPORT` names a JSON file for the outcome counts.

mod common;

use std::collections::BTreeMap;

use common::*;
use dc_crypto::SigScheme;
use dc_registry::Resolver;
use dc_types::{Body, ParsedCert};
use dc_verifier::VerifierConfig;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

fn pick<'a, T>(rng: &mut ChaCha20Rng, v: &'a [T]) -> &'a T {
    &v[(rng.next_u64() % v.len() as u64) as usize]
}

fn chance(rng: &mut ChaCha20Rng, per_mille: u64) -> bool {
    rng.next_u64() % 1000 < per_mille
}

fn outcome(r: &Result<dc_verifier::Accepted, dc_verifier::Reject>) -> String {
    match r {
        Ok(_) => "accept".into(),
        Err(e) => format!("L{:02}", e.line()),
    }
}

#[test]
fn uncached_and_warm_verifiers_agree() {
    let total: usize = std::env::var("DC_EQUIV_CHAINS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10_000);
    let mut rng = ChaCha20Rng::seed_from_u64(0xe9);
    let mut s = Suite::new();
    let now = s.now();

    // Agents: a1–a6 with the default 24-hour certificates, and s1–s3 whose
    // certificates expire during the run.
    let mut keys: BTreeMap<String, Vec<String>> =
        (1..=6).map(|i| (agent(i), vec![agent(i)])).collect();
    for (i, life) in [(1, 2_000), (2, 4_000), (3, 6_000)] {
        let id = format!("orga:agent:s{i}");
        s.w.enroll_window(&id, &id, now, now + life).unwrap();
        keys.insert(id.clone(), vec![id]);
    }
    let p1 = s.policy.clone();
    let h1 = s.hash;
    let p2 = policy_with_bound(700);
    let h2 = s.w.publish(&p2);

    let uncached = s.verifier_as(PAYMENTS, VerifierConfig::uncached());
    let warm = s.verifier();
    let mut counts: BTreeMap<String, u64> = BTreeMap::new();
    let mut events: BTreeMap<&str, u64> = BTreeMap::new();
    let mut recent: Vec<Vec<u8>> = vec![];
    let mut rotation = 0;

    for step in 0..total {
        // ---- interleaved events ----
        if step == total / 2 {
            // A new pin: chains naming P2 start being accepted.
            uncached.pin("orga", h2);
            warm.pin("orga", h2);
            *events.entry("new pin").or_default() += 1;
        }
        if chance(&mut rng, 20) {
            s.w.clock().advance(1 + rng.next_u64() % 200);
            *events.entry("clock advance").or_default() += 1;
        }
        if chance(&mut rng, 3) {
            // Revocation, followed by emergency rotation to a fresh key. The
            // revoked key usually leaves the pool; sometimes it stays, so
            // that chains still name it (line 27).
            let ids: Vec<String> = keys.keys().cloned().collect();
            let id = pick(&mut rng, &ids).clone();
            let label = pick(&mut rng, &keys[&id]).clone();
            let reg = s.w.org("orga");
            if let Some(cert) = reg.resolve(&p(&id), &s.pk(&label), s.now()) {
                let serial = ParsedCert::<S>::decode(&cert).unwrap().body.serial;
                let a = reg.revoke(serial).unwrap();
                uncached.ingest_revocation(&a).unwrap();
                warm.ingest_revocation(&a).unwrap();
                *events.entry("revocation").or_default() += 1;
                rotation += 1;
                let fresh = format!("{id}-rot{rotation}");
                let t = s.now();
                s.w.enroll_window(&id, &fresh, t, t + 20_000).unwrap();
                let pool = keys.get_mut(&id).unwrap();
                if chance(&mut rng, 800) {
                    pool.retain(|l| *l != label);
                }
                pool.push(fresh);
            }
        }
        if chance(&mut rng, 5) {
            // Scheduled rotation to a new key, overlapping the old one.
            let ids: Vec<String> = keys.keys().cloned().collect();
            let id = pick(&mut rng, &ids).clone();
            rotation += 1;
            let label = format!("{id}-rot{rotation}");
            let t = s.now();
            s.w.enroll_window(&id, &label, t, t + 20_000).unwrap();
            keys.get_mut(&id).unwrap().push(label);
            *events.entry("rotation").or_default() += 1;
        }

        // ---- a chain ----
        let bytes = if !recent.is_empty() && chance(&mut rng, 30) {
            // Replay of a recent chain.
            pick(&mut rng, &recent).clone()
        } else {
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
            let amount = *pick(&mut rng, &[400, 500, 900, 5000, 200_000]);
            let to = *pick(&mut rng, &["acct_vendor_a", "acct_vendor_b", "acct_other"]);
            let aud = if chance(&mut rng, 30) {
                FILES
            } else {
                PAYMENTS
            };
            let refs: Vec<(&str, &str)> = agents
                .iter()
                .map(|(a, b)| (a.as_str(), b.as_str()))
                .collect();
            let c = s.build(
                (ISSUER, ISSUER),
                &refs,
                &scopes,
                aud,
                "payments",
                "transfer",
                transfer(amount, to),
                &[(FINANCE, FINANCE), (AUDIT, AUDIT)],
            );
            // Mutations, half the time.
            match rng.next_u64() % 12 {
                0 | 1 => {
                    let mut b = c.to_bytes();
                    let i = (rng.next_u64() % b.len() as u64) as usize;
                    b[i] ^= 1 << (rng.next_u64() % 8);
                    b
                }
                2 => {
                    let mut ks = s.keys_for(&c.bodies);
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
                    let mut bodies = c.bodies.clone();
                    let Body::Invocation(inv) = bodies.last_mut().unwrap() else {
                        unreachable!()
                    };
                    inv.nbf = s.now() + 50;
                    s.resign(bodies, &keys_by_label(&s, &agents)).to_bytes()
                }
                _ => c.to_bytes(),
            }
        };
        let (a, b) = (uncached.verify(&bytes), warm.verify(&bytes));
        assert_eq!(a, b, "step {step}: uncached and warm disagree");
        *counts.entry(outcome(&a)).or_default() += 1;
        recent.push(bytes);
        if recent.len() > 50 {
            recent.remove(0);
        }
    }

    let report = serde_json::json!({
        "label": "SPEC §11.3 cache equivalence, warm state; test statistics",
        "chains": total,
        "outcomes": counts,
        "events": events,
        "warm_cached_certificates_at_end": warm.cached_certificates(),
    });
    println!("{}", serde_json::to_string_pretty(&report).unwrap());
    if let Ok(path) = std::env::var("DC_EQUIV_REPORT") {
        std::fs::write(path, serde_json::to_string_pretty(&report).unwrap() + "\n").unwrap();
    }
    // The run must exercise both acceptance and a spread of rejections.
    assert!(counts.get("accept").copied().unwrap_or(0) > (total / 10) as u64);
    assert!(counts.len() >= 8, "{counts:?}");
}

/// Signing keys in chain order: issuer, then each agent under its label.
fn keys_by_label(s: &Suite, agents: &[(String, String)]) -> Vec<<S as SigScheme>::SecretKey> {
    let mut v = vec![s.sk(ISSUER)];
    v.extend(agents.iter().map(|(_, l)| s.sk(l)));
    v
}

/// A probe beyond SPEC §11.3's events: the registry renews a certificate for
/// the same key (a new certificate binding the same identifier to the same
/// key), then revokes the renewal. Resolution returns the most recent
/// certificate (paper §5.4; D-26), so the uncached verifier sees the revoked
/// renewal and rejects at line 27. The warm verifier still holds the older,
/// unrevoked certificate for the same binding, and eviction on revocation only
/// touches the revoked serial (§5.4, D-37), so it accepts. The caches are not
/// transparent here (P-29). This test records the behaviour; it does not
/// endorse it.
#[test]
fn renewal_of_the_same_key_then_revocation_diverges() {
    let mut s = Suite::new();
    let uncached = s.verifier_as(PAYMENTS, VerifierConfig::uncached());
    let warm = s.verifier();
    // Both verify a chain through a2, and the warm one caches a2's
    // certificate.
    let c = s.chain(3);
    assert!(uncached.verify(&c.to_bytes()).is_ok());
    let c = s.chain(3);
    assert!(warm.verify(&c.to_bytes()).is_ok());
    // Renewal: a second certificate for (a2, a2's key), then its revocation.
    let now = s.now();
    let renewed =
        s.w.enroll_window(&agent(2), &agent(2), now, now + 48 * 3600)
            .unwrap();
    let serial = ParsedCert::<S>::decode(&renewed).unwrap().body.serial;
    let a = s.w.org("orga").revoke(serial).unwrap();
    uncached.ingest_revocation(&a).unwrap();
    warm.ingest_revocation(&a).unwrap();
    let c = s.chain(3).to_bytes();
    assert_eq!(
        uncached.verify(&c),
        Err(dc_verifier::Reject::L27CertificateNotValid { k: 2 })
    );
    assert!(
        warm.verify(&c).is_ok(),
        "warm verifier used its cached, older certificate"
    );
}
