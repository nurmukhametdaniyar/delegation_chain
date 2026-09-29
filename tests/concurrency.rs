//! SPEC §11.2 "T3b (Theorem 5, concurrent)": 64 threads present the same
//! chain at once; 1,000 rounds, a fresh chain each round. Exactly one
//! verification may accept per round; every other must be rejected at line
//! 17 (the early lookup) or line 50 (the atomic insert).
//!
//! `DC_REPLAY_ROUNDS` sets the number of rounds (default 1,000);
//! `DC_REPLAY_REPORT` names a JSON file for the statistics.

mod common;

use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Barrier};

use common::*;
use dc_verifier::Reject;

const THREADS: usize = 64;

#[test]
fn theorem_5_concurrent_replay() {
    let rounds: usize = std::env::var("DC_REPLAY_ROUNDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1000);
    let mut s = Suite::new();
    let v = Arc::new(s.verifier());
    // Warm the certificate and policy caches, as a deployed verifier would be.
    assert!(v.verify(&s.chain(1).to_bytes()).is_ok());
    let chains: Vec<Vec<u8>> = (0..rounds).map(|_| s.chain(1).to_bytes()).collect();

    let accepts: Vec<AtomicU64> = (0..rounds).map(|_| AtomicU64::new(0)).collect();
    let (l17, l50, other) = (AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0));
    let barrier = Barrier::new(THREADS);
    std::thread::scope(|scope| {
        for _ in 0..THREADS {
            scope.spawn(|| {
                for (r, chain) in chains.iter().enumerate() {
                    // All threads start each round together.
                    barrier.wait();
                    match v.verify(chain) {
                        Ok(_) => {
                            accepts[r].fetch_add(1, Relaxed);
                        }
                        Err(Reject::L17Replay) => {
                            l17.fetch_add(1, Relaxed);
                        }
                        Err(Reject::L50Replay) => {
                            l50.fetch_add(1, Relaxed);
                        }
                        Err(e) => {
                            eprintln!("round {r}: unexpected {e}");
                            other.fetch_add(1, Relaxed);
                        }
                    }
                }
            });
        }
    });

    let per_round: Vec<u64> = accepts.iter().map(|a| a.load(Relaxed)).collect();
    let mut histogram = std::collections::BTreeMap::new();
    for a in &per_round {
        *histogram.entry(*a).or_insert(0u64) += 1;
    }
    let report = serde_json::json!({
        "label": "SPEC §11.2 T3b concurrent replay (Theorem 5); test statistics",
        "threads": THREADS,
        "rounds": rounds,
        "verifications": THREADS * rounds,
        "rounds_by_accept_count": histogram.iter().map(|(k, v)| (k.to_string(), *v)).collect::<std::collections::BTreeMap<_, _>>(),
        "rejected_at_line_17": l17.load(Relaxed),
        "rejected_at_line_50": l50.load(Relaxed),
        "other_rejections": other.load(Relaxed),
    });
    println!("{}", serde_json::to_string_pretty(&report).unwrap());
    if let Ok(path) = std::env::var("DC_REPLAY_REPORT") {
        std::fs::write(path, serde_json::to_string_pretty(&report).unwrap() + "\n").unwrap();
    }
    assert_eq!(other.load(Relaxed), 0);
    assert!(
        per_round.iter().all(|a| *a == 1),
        "accepts per round: {histogram:?}"
    );
    assert_eq!(
        l17.load(Relaxed) + l50.load(Relaxed),
        ((THREADS - 1) * rounds) as u64
    );
}
