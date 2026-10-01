//! The calibration probe (frozen plan §5, amendment 1): a fixed,
//! deterministic, CPU-bound workload of about 100 ms, run on the measuring
//! thread (QoS user-interactive) before and after every configuration.
//! A probe more than 5% slower than the run's baseline (the median of 5
//! probes after the settle) flags the configuration, as a pmset warning
//! does.
//!
//! The workload is 100 BLS verifications and 1,000 Ed25519 `verify_strict`
//! calls on inputs derived from fixed seeds, all valid. It uses the same
//! crates and build as the arms, and its inputs are built once, outside
//! any timing.
//!
//! Every probe, baseline probes included, is preceded by a fixed busy spin
//! of [`WARMUP`] on the same thread, outside the probe's timing, so that a
//! probe never starts from an idle core. This was added after runs 1 and 2,
//! because probes that followed Q5's sleep-dominated configurations ran up
//! to 37% slow (BENCH_LOG.md, 2026-10-01; D-76).

use std::hint::black_box;
use std::time::{Duration, Instant};

use dc_crypto::{Bls, Dst, Ed25519, SigScheme};
use dc_types::digest::sha256;

pub const BLS_VERIFICATIONS: usize = 100;
pub const ED25519_VERIFICATIONS: usize = 1_000;
/// A probe slower than baseline × this flags its configuration.
pub const SLOW: f64 = 1.05;
/// Probes in a run's baseline.
pub const BASELINE_PROBES: usize = 5;
/// The busy spin before every probe.
pub const WARMUP: Duration = Duration::from_millis(200);

/// One probe: its time, and the busy spin that preceded it.
#[derive(Clone, Copy, Debug)]
pub struct Sample {
    pub ns: u64,
    pub warmup_ns: u64,
}

/// A fixed busy spin of [`WARMUP`] on the calling thread. Returns its
/// duration in nanoseconds.
pub fn spin() -> u64 {
    let t = Instant::now();
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    while t.elapsed() < WARMUP {
        for _ in 0..1000 {
            x = black_box(x.rotate_left(5) ^ x.wrapping_mul(0x0100_0000_01b3));
        }
    }
    black_box(x);
    t.elapsed().as_nanos() as u64
}

type Triple<S> = (
    <S as SigScheme>::PublicKey,
    [u8; 32],
    <S as SigScheme>::Signature,
);

fn triple<S: SigScheme>(i: usize) -> Triple<S> {
    let sk = S::keygen(&sha256(&[b"dc-bench-probe-key", &(i as u64).to_le_bytes()]));
    let m = sha256(&[b"dc-bench-probe-msg", &(i as u64).to_le_bytes()]);
    let sig = S::sign(&sk, &m, Dst::Chain);
    (S::public_key(&sk), m, sig)
}

pub struct Probe {
    bls: Vec<Triple<Bls>>,
    ed: Vec<Triple<Ed25519>>,
}

impl Probe {
    /// 8 distinct BLS and 8 distinct Ed25519 triples, cycled.
    pub fn new() -> Self {
        Probe {
            bls: (0..8).map(triple::<Bls>).collect(),
            ed: (0..8).map(triple::<Ed25519>).collect(),
        }
    }

    /// The busy spin, then one probe. Only the probe is timed. Panics if a
    /// verification fails, which would mean the probe is not the fixed
    /// workload it claims to be.
    pub fn run(&self) -> Sample {
        let warmup_ns = spin();
        let t = Instant::now();
        let mut ok = true;
        for i in 0..BLS_VERIFICATIONS {
            let (pk, m, s) = &self.bls[i % self.bls.len()];
            ok &= Bls::verify(black_box(pk), black_box(m), Dst::Chain, black_box(s));
        }
        for i in 0..ED25519_VERIFICATIONS {
            let (pk, m, s) = &self.ed[i % self.ed.len()];
            ok &= Ed25519::verify(black_box(pk), black_box(m), Dst::Chain, black_box(s));
        }
        let ns = t.elapsed().as_nanos() as u64;
        assert!(ok, "the calibration probe's inputs must all verify");
        Sample { ns, warmup_ns }
    }

    /// The median of `BASELINE_PROBES` probes, each after its spin.
    pub fn baseline(&self) -> (u64, Vec<Sample>) {
        let samples: Vec<Sample> = (0..BASELINE_PROBES).map(|_| self.run()).collect();
        let mut v: Vec<u64> = samples.iter().map(|s| s.ns).collect();
        v.sort_unstable();
        (v[v.len() / 2], samples)
    }
}

impl Default for Probe {
    fn default() -> Self {
        Self::new()
    }
}

/// Whether a probe is more than 5% slower than the baseline.
pub fn slow(probe_ns: u64, baseline_ns: u64) -> bool {
    probe_ns as f64 > SLOW * baseline_ns as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_spin_lasts_the_warmup() {
        let ns = spin();
        assert!(ns >= WARMUP.as_nanos() as u64);
    }

    #[test]
    fn five_percent_rule() {
        assert!(!slow(105, 100));
        assert!(slow(106, 100));
        assert!(!slow(90, 100));
    }
}
