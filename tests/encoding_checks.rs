//! The counts behind D-87's cost model: how many keys and signatures go
//! through D-81's canonical-encoding checks in one verification, in each of
//! M9's states of arms C and D (`dc_bench::encoding::LOADS`). They run on
//! the benchmark's own chains and subjects, warmed as the harness warms
//! them. Counts need `count-ops`, which the workspace tests enable.

use dc_bench::arms::{Arm, State, Worlds, subject};
use dc_bench::encoding::{LOADS, NS};
use dc_bench::harness::{SetKey, generate};
use dc_bench::plan::Config;
use dc_bench::workload::Profile;
use dc_crypto::ops;
use dc_verifier::Path;

// Without counts every check would read zero.
const _: () = assert!(ops::ENABLED, "needs count-ops");

/// The harness warms with 1,000 chains. Forty already resolve every
/// identity of the medium profile's pools and fill all ten prefixes.
const WARMUP: usize = 40;
const COUNTED: usize = 10;

/// (keys, signatures) checked by each counted verification, as
/// `harness::measure` runs the configuration.
fn counted(w: &Worlds, arm: Arm, state: State, n: usize) -> Vec<(u64, u64)> {
    let c = Config {
        arm,
        state,
        n,
        profile: Profile::Medium,
        warmup: WARMUP,
        measured: COUNTED,
    };
    let expect = match state {
        State::WarmPrefix => Some(Path::Hit),
        State::PrefixMiss => Some(Path::Miss),
        _ => None,
    };
    let persistent = (!state.is_cold()).then(|| subject(w, arm, state, c.profile));
    let mut out = vec![];
    for (i, chain) in generate(w, &SetKey::of(&c)).iter().enumerate() {
        let fresh;
        let s = match &persistent {
            Some(s) => s.as_ref(),
            None => {
                fresh = subject(w, arm, state, c.profile);
                fresh.as_ref()
            }
        };
        ops::reset();
        let o = s.verify(chain);
        let k = ops::snapshot();
        assert!(o.accepted, "{}: chain {i} was rejected", c.id());
        if i >= WARMUP {
            if let Some(p) = expect {
                assert_eq!(o.path, Some(p), "{}: chain {i}", c.id());
            }
            out.push((k.key_encoding_checks, k.sig_encoding_checks));
        }
    }
    out
}

#[test]
fn checks_per_verification_match_the_cost_model() {
    let w = Worlds::new();
    for load in &LOADS {
        let arm = Arm::parse(load.arm).unwrap();
        let state = State::parse(load.state).unwrap();
        for n in NS {
            assert_eq!(
                counted(&w, arm, state, n),
                vec![load.checks(n); COUNTED],
                "{} N={n}: (keys, signatures)",
                load.label
            );
        }
    }
}
