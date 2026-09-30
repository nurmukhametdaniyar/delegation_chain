//! The grid, iteration counts and seeds (SPEC §13.3–§13.5). The frozen plan
//! (`BENCH_PLAN_FROZEN.md`) is written from this module, and `dc-bench plan`
//! prints it, so the two cannot drift.

use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use serde::{Deserialize, Serialize};

use crate::arms::{Arm, State};
use crate::workload::{Layout, Profile, SEED};

pub const NS: [usize; 5] = [1, 2, 3, 5, 10];
pub const PROFILES: [Profile; 3] = [Profile::Small, Profile::Medium, Profile::Large];
/// Q5's injected latency per resolver or policy-store call (SPEC §13.4).
pub const RTT_MS: [u64; 4] = [0, 1, 20, 80];
/// Q6's thread counts (D-43); 14 includes the efficiency cores.
pub const THREADS: [usize; 6] = [1, 2, 4, 8, 10, 14];
pub const THROUGHPUT_ARMS: [Arm; 4] = [Arm::A, Arm::B, Arm::C, Arm::D];
/// Runs of the full grid, each in its own process (SPEC §13.5).
pub const RUNS: usize = 3;
/// Bootstrap resamples (SPEC §13.6).
pub const BOOTSTRAP: usize = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Mode {
    /// The frozen plan's counts.
    Full,
    /// M8's dry run: 10 iterations per configuration. Its numbers are never
    /// reported.
    Dry,
}

impl Mode {
    pub fn label(self) -> &'static str {
        match self {
            Mode::Full => "full",
            Mode::Dry => "dry",
        }
    }
}

/// One latency configuration: one row group of `results/raw/run*.csv`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub arm: Arm,
    pub state: State,
    pub n: usize,
    pub profile: Profile,
    pub warmup: usize,
    pub measured: usize,
}

impl Config {
    pub fn layout(&self) -> Layout {
        match self.state {
            State::WarmPrefix => Layout::Prefixed { prefixes: 10 },
            _ => Layout::Fresh,
        }
    }

    pub fn chains(&self) -> usize {
        self.warmup + self.measured
    }

    pub fn id(&self) -> String {
        format!(
            "{} {} N={} {}",
            self.arm.label(),
            self.state.label(),
            self.n,
            self.profile.label()
        )
    }
}

/// (warm-up, measured) for a state.
pub fn counts(mode: Mode, state: State) -> (usize, usize) {
    match (mode, state) {
        (Mode::Dry, _) => (10, 10),
        // D-44: the injected-latency configurations are dominated by sleeps.
        // Every one keeps at least 200 measured verifications.
        (Mode::Full, State::ColdRtt(1)) => (100, 2_000),
        (Mode::Full, State::ColdRtt(20)) => (20, 300),
        (Mode::Full, State::ColdRtt(80)) => (20, 200),
        // SPEC §13.5; for warm+prefix, 10 prefixes × 1,100, the first 100 per
        // prefix warm-up (D-39).
        (Mode::Full, _) => (1_000, 10_000),
    }
}

/// Every latency configuration, in canonical order.
pub fn grid(mode: Mode) -> Vec<Config> {
    let mut v = vec![];
    let mut add = |arm: Arm, state: State, n: usize, profile: Profile| {
        let (warmup, measured) = counts(mode, state);
        v.push(Config {
            arm,
            state,
            n,
            profile,
            warmup,
            measured,
        });
    };
    let cells = || {
        NS.iter()
            .flat_map(|&n| PROFILES.iter().map(move |&p| (n, p)))
            .chain(std::iter::once((3, Profile::MediumApproval)))
    };
    // Q1, Q3, Q4: A, A-ind, C, C-batch, cold and warm.
    for arm in [Arm::A, Arm::AInd, Arm::C, Arm::CBatch] {
        for state in [State::Cold, State::Warm] {
            for (n, p) in cells() {
                add(arm, state, n, p);
            }
        }
    }
    // B and D: warm+prefix (hit) and prefix-miss.
    for arm in [Arm::B, Arm::D] {
        for state in [State::WarmPrefix, State::PrefixMiss] {
            for (n, p) in cells() {
                add(arm, state, n, p);
            }
        }
    }
    // Supplementary A-mt: warm only, same N and profiles as A (D-29).
    for (n, p) in cells() {
        add(Arm::AMt, State::Warm, n, p);
    }
    // Q9: arm E. No approvals, so no medium-approval (D-68).
    for n in NS {
        for p in PROFILES {
            add(Arm::E, State::Stateless, n, p);
        }
    }
    // Q5: A and C, cold, N = 3, medium, with injected latency.
    for arm in [Arm::A, Arm::C] {
        for ms in RTT_MS {
            add(arm, State::ColdRtt(ms), 3, Profile::Medium);
        }
    }
    v
}

/// The seed that orders run `run`'s configurations (SPEC §13.5).
pub fn order_seed(run: usize) -> u64 {
    SEED ^ (0x0de5_0000 + run as u64)
}

/// `configs` in run `run`'s random order.
pub fn shuffled(mut configs: Vec<Config>, run: usize) -> Vec<Config> {
    let mut rng = ChaCha20Rng::seed_from_u64(order_seed(run));
    for i in (1..configs.len()).rev() {
        let j = (rng.next_u64() % (i as u64 + 1)) as usize;
        configs.swap(i, j);
    }
    configs
}

/// Q6's workload: prefixes × invocations per prefix, and warm-up chains.
pub fn throughput_counts(mode: Mode) -> (usize, usize, usize) {
    match mode {
        Mode::Full => (100, 1_000, 1_000),
        Mode::Dry => (10, 10, 10),
    }
}

/// Q10's entries per structure.
pub fn memory_entries(mode: Mode) -> usize {
    match mode {
        Mode::Full => 100_000,
        Mode::Dry => 1_000,
    }
}
