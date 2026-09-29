//! SPEC §5.7's required test: on at least 10,000 randomized chains, valid
//! and invalid, arm B's cached check returns exactly the decision of
//! `aggregate_verify`.
//!
//! Chains are synthetic: random body bytes, position-tagged digests
//! (Algorithm 2 line 47), keys from a pool, and the running aggregate. Each
//! prefix is followed by 1–5 invocations, as in the deployment pattern arm B
//! is for, and its Miller-loop product P is computed once and reused. A
//! mutation that changes the prefix changes m_{N−1}, which is a prefix-cache
//! miss, so P is then recomputed from the mutated prefix.
//!
//! Mutations: a flipped bit in a prefix body or in the last body; a prefix
//! or last signature made by another key or over another message; a
//! signature left out of or added to the aggregate; a prefix key or the
//! last key replaced. Plus valid chains.
//!
//! The run is split into 64 fixed shards, each with its own seed, and
//! gives the same counts on any number of threads (as D-58).
//! `DC_PAIRING_CASES` sets the number of chains (default 10,000),
//! `DC_PAIRING_THREADS` the number of threads (default: all cores);
//! `DC_PAIRING_REPORT` names a JSON file for the counts.

use std::collections::BTreeMap;
use std::sync::Mutex;

use dc_crypto::pairing_cache::{prefix_product, verify_with_prefix};
use dc_crypto::{Bls, BlsAggregate, ChainScheme, Dst, SigScheme};
use dc_types::digest::{chain_digests, sha256};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

type Pk = <Bls as SigScheme>::PublicKey;
type Sk = <Bls as SigScheme>::SecretKey;
type Sig = <Bls as SigScheme>::Signature;

const SHARDS: u64 = 64;
const POOL: usize = 16;

const KINDS: [&str; 10] = [
    "valid",
    "bit flip in a prefix body",
    "bit flip in the last body",
    "prefix signature by another key",
    "last signature by another key",
    "last signature over another message",
    "signature missing from the aggregate",
    "extra signature in the aggregate",
    "prefix key replaced",
    "last key replaced",
];

fn below(rng: &mut ChaCha20Rng, n: usize) -> usize {
    (rng.next_u64() % n as u64) as usize
}

fn aggregate(parts: &[Sig]) -> Sig {
    let mut acc = BlsAggregate::start(parts[0]);
    for s in &parts[1..] {
        BlsAggregate::accumulate(&mut acc, *s);
    }
    acc
}

#[derive(Default)]
struct Counts {
    cases: u64,
    agree: u64,
    by_kind: BTreeMap<&'static str, (u64, u64)>, // (accepts, rejects)
    prefixes: u64,
    p_reused: u64,
}

fn shard(seed: u64, cases: u64, keys: &[(Sk, Pk)]) -> Counts {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let mut c = Counts::default();
    while c.cases < cases {
        // A prefix: B_0 … B_{N−1}, N in 1..=10.
        let n = 1 + below(&mut rng, 10);
        let body = |rng: &mut ChaCha20Rng| {
            let mut b = vec![0u8; 40 + below(rng, 260)];
            rng.fill_bytes(&mut b);
            b
        };
        let prefix: Vec<Vec<u8>> = (0..n).map(|_| body(&mut rng)).collect();
        let prefix_keys: Vec<usize> = (0..n).map(|_| below(&mut rng, POOL)).collect();
        c.prefixes += 1;
        let mut cached_p = None;
        for _ in 0..1 + below(&mut rng, 5) {
            if c.cases == cases {
                break;
            }
            let mut bodies = prefix.clone();
            bodies.push(body(&mut rng));
            let mut who = prefix_keys.clone();
            who.push(below(&mut rng, POOL));
            let refs: Vec<&[u8]> = bodies.iter().map(Vec::as_slice).collect();
            let m = chain_digests(&refs);
            let mut parts: Vec<Sig> = m
                .iter()
                .zip(&who)
                .map(|(m, &i)| Bls::sign(&keys[i].0, m, Dst::Chain))
                .collect();
            let mut pks: Vec<usize> = who.clone();
            let other = |rng: &mut ChaCha20Rng, i: usize| (i + 1 + below(rng, POOL - 1)) % POOL;

            let kind = below(&mut rng, KINDS.len());
            let mut prefix_changed = false;
            match kind {
                1 | 2 => {
                    let k = if kind == 1 { below(&mut rng, n) } else { n };
                    let i = below(&mut rng, bodies[k].len());
                    bodies[k][i] ^= 1 << below(&mut rng, 8);
                    prefix_changed = kind == 1;
                }
                3 => {
                    let k = below(&mut rng, n);
                    parts[k] = Bls::sign(&keys[other(&mut rng, who[k])].0, &m[k], Dst::Chain);
                }
                4 => parts[n] = Bls::sign(&keys[other(&mut rng, who[n])].0, &m[n], Dst::Chain),
                5 => {
                    let mut x = m[n];
                    x[below(&mut rng, 32)] ^= 1;
                    parts[n] = Bls::sign(&keys[who[n]].0, &x, Dst::Chain);
                }
                6 => {
                    parts.remove(below(&mut rng, n + 1));
                }
                7 => {
                    let mut x = [0u8; 32];
                    rng.fill_bytes(&mut x);
                    parts.push(Bls::sign(&keys[below(&mut rng, POOL)].0, &x, Dst::Chain));
                }
                8 => {
                    let k = below(&mut rng, n);
                    pks[k] = other(&mut rng, pks[k]);
                    prefix_changed = true;
                }
                9 => pks[n] = other(&mut rng, pks[n]),
                _ => {}
            }
            let sig = if parts.is_empty() {
                // Only possible for N + 1 = 1, which does not occur.
                unreachable!()
            } else {
                aggregate(&parts)
            };
            // The verifier recomputes the digests from the received bodies.
            let refs: Vec<&[u8]> = bodies.iter().map(Vec::as_slice).collect();
            let m = chain_digests(&refs);
            let pk_refs: Vec<&Pk> = pks.iter().map(|&i| &keys[i].1).collect();

            let reference = BlsAggregate::verify_chain(&pk_refs, &m, &sig);
            let p = if prefix_changed {
                prefix_product(&pk_refs[..n], &m[..n])
            } else {
                if cached_p.is_some() {
                    c.p_reused += 1;
                }
                *cached_p.get_or_insert_with(|| prefix_product(&pk_refs[..n], &m[..n]))
            };
            let cached = p.is_some_and(|p| verify_with_prefix(&p, pk_refs[n], &m[n], &sig));

            c.cases += 1;
            if cached == reference {
                c.agree += 1;
            } else {
                eprintln!(
                    "seed {seed}: kind {}: aggregate_verify {reference}, cached {cached}",
                    KINDS[kind]
                );
            }
            let e = c.by_kind.entry(KINDS[kind]).or_default();
            if reference {
                e.0 += 1;
            } else {
                e.1 += 1;
            }
        }
    }
    c
}

#[test]
fn pairing_cache_agrees_with_aggregate_verify() {
    let total: u64 = std::env::var("DC_PAIRING_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10_000);
    let keys: Vec<(Sk, Pk)> = (0..POOL)
        .map(|i| {
            let sk = Bls::keygen(&sha256(&[b"dc-pairing-cache", &[i as u8]]));
            let pk = Bls::public_key(&sk);
            (sk, pk)
        })
        .collect();
    let results = Mutex::new(Vec::new());
    let next = std::sync::atomic::AtomicU64::new(0);
    let threads = std::env::var("DC_PAIRING_THREADS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| std::thread::available_parallelism().map_or(4, |n| n.get()));
    std::thread::scope(|s| {
        for _ in 0..threads {
            s.spawn(|| {
                loop {
                    let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if i >= SHARDS {
                        break;
                    }
                    let cases = total / SHARDS + u64::from(i < total % SHARDS);
                    let c = shard(0x57000 + i, cases, &keys);
                    results.lock().unwrap().push((i, c));
                }
            });
        }
    });
    let mut results = results.into_inner().unwrap();
    results.sort_by_key(|(i, _)| *i);
    let mut all = Counts::default();
    for (_, c) in results {
        all.cases += c.cases;
        all.agree += c.agree;
        all.prefixes += c.prefixes;
        all.p_reused += c.p_reused;
        for (k, (a, r)) in c.by_kind {
            let e = all.by_kind.entry(k).or_default();
            e.0 += a;
            e.1 += r;
        }
    }
    let report = serde_json::json!({
        "label": "SPEC §5.7 pairing-cache equivalence (arm B); test statistics",
        "chains": all.cases,
        "agreeing_with_aggregate_verify": all.agree,
        "disagreeing": all.cases - all.agree,
        "distinct_prefixes": all.prefixes,
        "checks_reusing_a_cached_prefix_product": all.p_reused,
        "by_mutation": all.by_kind.iter().map(|(k, (a, r))| {
            (k.to_string(), serde_json::json!({"accepted": a, "rejected": r}))
        }).collect::<serde_json::Map<_, _>>(),
        "shards": SHARDS,
        "threads": threads,
    });
    println!("{}", serde_json::to_string_pretty(&report).unwrap());
    if let Ok(path) = std::env::var("DC_PAIRING_REPORT") {
        std::fs::write(path, serde_json::to_string_pretty(&report).unwrap() + "\n").unwrap();
    }
    assert!(all.cases >= total);
    assert_eq!(all.agree, all.cases);
    // Valid chains are accepted, and every mutation kind is rejected.
    for (k, (a, r)) in &all.by_kind {
        if *k == "valid" {
            assert_eq!(*r, 0, "valid chains rejected");
        } else {
            assert_eq!(*a, 0, "{k} accepted");
        }
    }
}
