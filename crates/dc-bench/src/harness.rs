//! Measurement (SPEC §13.5).
//!
//! - **Isolation.** Every chain is generated before measurement starts,
//!   written to a per-run directory, and loaded before its configuration
//!   runs. Each timed operation is exactly one [`Subject::verify`] call on
//!   the chain's bytes, timed with `Instant` in nanoseconds.
//! - **States.** A cold configuration builds a new verifier before every
//!   call, outside the timer. Every other state uses one verifier for the
//!   whole configuration.
//! - **Checks.** Every verification must accept, and arms B and D must hit
//!   (warm+prefix) or miss (prefix-miss) on every measured call. Otherwise
//!   the configuration fails and produces no numbers.

use std::fs;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::time::Instant;

use dc_baselines::{BlsIndividual, Ed25519List};
use dc_crypto::BlsAggregate;
use dc_types::Envelope;
use dc_verifier::Path as CachePath;
use hdrhistogram::Histogram;
use serde::Serialize;

use crate::arms::{Arm, Family, State, Subject, Worlds, subject};
use crate::plan::Config;
use crate::qos;
use crate::workload::{Layout, Profile, biscuit_tokens, chains};

// ---- chain sets ----

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SetKey {
    pub family: Family,
    pub profile: Profile,
    pub n: usize,
    pub layout: Layout,
    pub count: usize,
}

impl SetKey {
    pub fn of(c: &Config) -> SetKey {
        SetKey {
            family: c.arm.family(),
            profile: c.profile,
            n: c.n,
            layout: c.layout(),
            count: c.chains(),
        }
    }

    /// The set's name, and the seed tag of its random stream.
    pub fn tag(&self) -> String {
        let layout = match self.layout {
            Layout::Fresh => "fresh".to_owned(),
            Layout::Prefixed { prefixes } => format!("prefixed{prefixes}"),
        };
        format!(
            "{}-{}-n{}-{layout}-{}",
            self.family.label(),
            self.profile.label(),
            self.n,
            self.count
        )
    }

    fn file(&self, dir: &Path) -> PathBuf {
        dir.join(format!("{}.bin", self.tag()))
    }
}

/// Generates a set.
pub fn generate(w: &Worlds, key: &SetKey) -> Vec<Vec<u8>> {
    let tag = key.tag();
    let (p, n, l, c) = (key.profile, key.n, key.layout, key.count);
    match key.family {
        Family::BlsAggregate => chains::<BlsAggregate>(&w.bls, p, n, l, c, &tag),
        Family::BlsList => chains::<BlsIndividual>(&w.bls, p, n, l, c, &tag),
        Family::Ed25519List => chains::<Ed25519List>(&w.ed25519, p, n, l, c, &tag),
        Family::Biscuit => biscuit_tokens(&w.biscuit, p, n, c, &tag),
    }
}

fn write_set(path: &Path, set: &[Vec<u8>]) -> std::io::Result<()> {
    let mut f = BufWriter::new(fs::File::create(path)?);
    f.write_all(&(set.len() as u64).to_le_bytes())?;
    for c in set {
        f.write_all(&(c.len() as u32).to_le_bytes())?;
        f.write_all(c)?;
    }
    f.flush()
}

fn read_set(path: &Path) -> std::io::Result<Vec<Vec<u8>>> {
    let mut f = BufReader::new(fs::File::open(path)?);
    let mut n8 = [0u8; 8];
    f.read_exact(&mut n8)?;
    let n = u64::from_le_bytes(n8) as usize;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let mut l4 = [0u8; 4];
        f.read_exact(&mut l4)?;
        let mut c = vec![0u8; u32::from_le_bytes(l4) as usize];
        f.read_exact(&mut c)?;
        out.push(c);
    }
    Ok(out)
}

/// A run's pre-generated chains, on disk.
pub struct SetStore {
    dir: PathBuf,
}

impl SetStore {
    /// Generates every set in `keys` into `dir`, on all cores. Nothing is
    /// timed while this runs.
    pub fn build(w: &Worlds, keys: &[SetKey], dir: &Path, threads: usize) -> std::io::Result<Self> {
        fs::create_dir_all(dir)?;
        let mut keys: Vec<SetKey> = keys.to_vec();
        keys.sort_by_key(|k| k.tag());
        keys.dedup();
        let next = AtomicUsize::new(0);
        let errors = Mutex::new(vec![]);
        std::thread::scope(|s| {
            for _ in 0..threads.max(1) {
                s.spawn(|| {
                    loop {
                        let i = next.fetch_add(1, Ordering::Relaxed);
                        let Some(k) = keys.get(i) else { break };
                        let set = generate(w, k);
                        if let Err(e) = write_set(&k.file(dir), &set) {
                            errors.lock().unwrap().push(e);
                        }
                    }
                });
            }
        });
        if let Some(e) = errors.into_inner().unwrap().pop() {
            return Err(e);
        }
        Ok(SetStore {
            dir: dir.to_owned(),
        })
    }

    pub fn load(&self, key: &SetKey) -> std::io::Result<Vec<Vec<u8>>> {
        read_set(&key.file(&self.dir))
    }

    pub fn remove(self) -> std::io::Result<()> {
        fs::remove_dir_all(&self.dir)
    }
}

// ---- latency ----

pub struct Measured {
    /// Nanoseconds per measured call, in order.
    pub ns: Vec<u64>,
    /// Resolver and policy-store calls over the measured calls (Q5).
    pub resolver_calls: u64,
    pub store_calls: u64,
}

/// Runs one configuration on its chains (warm-up first, then measured).
pub fn measure(w: &Worlds, c: &Config, chains: &[Vec<u8>]) -> Result<Measured, String> {
    assert_eq!(chains.len(), c.chains(), "{}: wrong set", c.id());
    let expect = match c.state {
        State::WarmPrefix => Some(CachePath::Hit),
        State::PrefixMiss => Some(CachePath::Miss),
        _ => None,
    };
    let persistent = (!c.state.is_cold()).then(|| subject(w, c.arm, c.state, c.profile));
    let mut ns = Vec::with_capacity(c.measured);
    let (mut resolver_calls, mut store_calls) = (0, 0);
    for (i, chain) in chains.iter().enumerate() {
        let fresh;
        let s: &dyn Subject = match &persistent {
            Some(s) => s.as_ref(),
            None => {
                fresh = subject(w, c.arm, c.state, c.profile);
                fresh.as_ref()
            }
        };
        let t0 = Instant::now();
        let o = s.verify(std::hint::black_box(chain));
        let dt = t0.elapsed();
        std::hint::black_box(o);
        if !o.accepted {
            return Err(format!("{}: chain {i} was rejected", c.id()));
        }
        if i >= c.warmup {
            ns.push(dt.as_nanos() as u64);
            if let Some(p) = expect
                && o.path != Some(p)
            {
                return Err(format!(
                    "{}: chain {i} took {:?}, expected {p:?}",
                    c.id(),
                    o.path
                ));
            }
            if c.state.is_cold() {
                let (r, st) = s.calls();
                resolver_calls += r;
                store_calls += st;
            }
        }
    }
    Ok(Measured {
        ns,
        resolver_calls,
        store_calls,
    })
}

// ---- throughput (Q6) ----

#[derive(Clone, Debug, Serialize)]
pub struct ThroughputRow {
    pub arm: Arm,
    pub threads: usize,
    pub chains: usize,
    pub accepted: usize,
    pub wall_ns: u64,
    pub p50_ns: u64,
    pub p99_ns: u64,
    pub qos_ok: bool,
}

/// Verifies all of `chains` on `threads` threads sharing one verifier,
/// after `warm` warms its certificate caches (SPEC §13.5).
pub fn throughput(
    w: &Worlds,
    arm: Arm,
    threads: usize,
    warm: &[Vec<u8>],
    chains: &[Vec<u8>],
) -> Result<ThroughputRow, String> {
    let state = match arm {
        Arm::B | Arm::D => State::WarmPrefix,
        _ => State::Warm,
    };
    let s: Arc<dyn Subject> = Arc::from(subject(w, arm, state, Profile::Medium));
    for c in warm {
        if !s.verify(c).accepted {
            return Err(format!("Q6 {}: a warm-up chain was rejected", arm.label()));
        }
    }
    let next = AtomicUsize::new(0);
    let barrier = Barrier::new(threads + 1);
    let results = Mutex::new(vec![]);
    let start = std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| {
                let qos = qos::set_user_interactive();
                let mut h =
                    Histogram::<u64>::new_with_bounds(1, 60_000_000_000, 3).expect("bounds");
                let mut accepted = 0usize;
                barrier.wait();
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(c) = chains.get(i) else { break };
                    let t0 = Instant::now();
                    let o = s.verify(c);
                    let dt = t0.elapsed().as_nanos() as u64;
                    if o.accepted {
                        accepted += 1;
                    }
                    let _ = h.record(dt.max(1));
                }
                results.lock().unwrap().push((h, accepted, qos));
            });
        }
        barrier.wait();
        Instant::now()
    });
    // The scope returns once every thread has finished.
    let wall = start.elapsed().as_nanos() as u64;
    let results = results.into_inner().unwrap();
    let mut merged = Histogram::<u64>::new_with_bounds(1, 60_000_000_000, 3).expect("bounds");
    let mut accepted = 0;
    let mut qos_ok = true;
    for (h, a, q) in &results {
        merged.add(h).expect("same bounds");
        accepted += a;
        qos_ok &= q;
    }
    if accepted != chains.len() {
        return Err(format!(
            "Q6 {} × {threads}: {} of {} accepted",
            arm.label(),
            accepted,
            chains.len()
        ));
    }
    Ok(ThroughputRow {
        arm,
        threads,
        chains: chains.len(),
        accepted,
        wall_ns: wall,
        p50_ns: merged.value_at_quantile(0.50),
        p99_ns: merged.value_at_quantile(0.99),
        qos_ok,
    })
}

// ---- bytes (Q2) ----

#[derive(Clone, Debug, Serialize)]
pub struct BytesRow {
    pub arm: String,
    pub n: usize,
    pub profile: String,
    pub sampled: usize,
    pub total_mean: f64,
    pub total_min: usize,
    pub total_max: usize,
    /// Bytes of the body strings; `None` for arm E.
    pub bodies_mean: Option<f64>,
    /// Bytes of the signature strings; `None` for arm E.
    pub sigs_mean: Option<f64>,
}

/// Sizes of `set`, one wire family's chains.
pub fn bytes_row(
    label: &str,
    n: usize,
    profile: Profile,
    set: &[Vec<u8>],
    envelope: bool,
) -> BytesRow {
    let totals: Vec<usize> = set.iter().map(Vec::len).collect();
    let mean = |v: &[usize]| v.iter().sum::<usize>() as f64 / v.len() as f64;
    let (bodies, sigs) = if envelope {
        let mut b = vec![];
        let mut s = vec![];
        for c in set {
            let env = Envelope::from_bytes(c).expect("generated chains decode");
            b.push(env.bodies.iter().map(Vec::len).sum());
            s.push(match &env.sigs {
                dc_crypto::WireForm::Single(x) => x.len(),
                dc_crypto::WireForm::List(l) => l.iter().map(Vec::len).sum(),
            });
        }
        (Some(mean(&b)), Some(mean(&s)))
    } else {
        (None, None)
    };
    BytesRow {
        arm: label.to_owned(),
        n,
        profile: profile.label().to_owned(),
        sampled: set.len(),
        total_mean: mean(&totals),
        total_min: *totals.iter().min().unwrap_or(&0),
        total_max: *totals.iter().max().unwrap_or(&0),
        bodies_mean: bodies,
        sigs_mean: sigs,
    }
}
