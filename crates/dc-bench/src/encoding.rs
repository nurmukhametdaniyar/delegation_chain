//! The cost of D-81's canonical-encoding checks (exploratory, not
//! pre-registered; D-87).
//!
//! - **Why.** D-81 added decode-time checks to the default instantiation
//!   after M9: a key's y below p, and a signature's R below p and s below
//!   ℓ. The measured binaries did not have them, and the paper reads the
//!   default instantiation's latencies as the protocol's cost.
//! - **What is timed.** The checks themselves, as the decoders call them
//!   (`Ed25519::canonical_key`, `Ed25519::canonical_signature`):
//!   - on honest inputs, a pool of 1,024 keys and signatures from seeded
//!     keys;
//!   - on the worst inputs that pass, whose bytes sit just below the bounds,
//!     so that every byte is compared.
//!
//!   For context, the whole decoders, `sig_from_bytes` and `pk_from_bytes`,
//!   are timed too.
//! - **How.** Calls are timed in batches, and each batch gives one figure
//!   in nanoseconds per call. Three runs, each in its own process, on M9's
//!   machine state, with pmset and the calibration probe read around each
//!   operation.
//! - **What it adds to a chain.** Each of the chain's N+1 signers
//!   contributes its signature, and, on a certificate-cache miss, its
//!   certificate's signature and key ([`LOADS`]). The counts times the
//!   checks' medians are the added cost.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;
use std::time::Instant;

use dc_crypto::{Dst, Ed25519, SigScheme};

use crate::report::{decompress, hex, us};
use crate::stats::quantile_sorted;

pub const RUNS: usize = 3;
/// Batches per operation per run.
pub const BATCHES: usize = 200;
/// The chain lengths of the report (medium profile).
pub const NS: [usize; 3] = [1, 3, 10];

/// What one verification puts through the checks in one of M9's states of
/// arms C and D, on the medium profile, per signer: each of the chain's N+1
/// signers contributes `keys` keys and `sigs` signatures.
/// `tests/encoding_checks.rs` checks these counts on the benchmark's own
/// chains and subjects (count-ops).
pub struct Load {
    pub arm: &'static str,
    pub state: &'static str,
    pub label: &'static str,
    pub keys: u64,
    pub sigs: u64,
}

impl Load {
    /// (keys, signatures) checked in one verification of a chain of `n`.
    pub fn checks(&self, n: usize) -> (u64, u64) {
        let signers = n as u64 + 1;
        (signers * self.keys, signers * self.sigs)
    }
}

pub const LOADS: [Load; 4] = [
    // Certificates cached: the chain's signatures only.
    Load {
        arm: "C",
        state: "warm",
        label: "C, warm",
        keys: 0,
        sigs: 1,
    },
    // A fresh verifier: each signer's certificate is decoded too, its
    // signature and its key (line 24).
    Load {
        arm: "C",
        state: "cold",
        label: "C, cold",
        keys: 1,
        sigs: 2,
    },
    // The hit path still decodes every signature (`decode_sigs`).
    Load {
        arm: "D",
        state: "warm+prefix",
        label: "D, hit",
        keys: 0,
        sigs: 1,
    },
    // A new prefix, with certificates cached.
    Load {
        arm: "D",
        state: "prefix-miss",
        label: "D, miss",
        keys: 0,
        sigs: 1,
    },
];

/// One timed operation.
pub struct Op {
    pub id: &'static str,
    pub what: &'static str,
    /// Calls per batch.
    pub calls: usize,
}

pub const OPS: [Op; 6] = [
    Op {
        id: "sig-check-honest",
        what: "signature checks (R's y < p, s < ℓ), honest signatures",
        calls: 100_000,
    },
    Op {
        id: "sig-check-worst",
        what: "signature checks, worst passing input (R's y = p − 1, s = ℓ − 1)",
        calls: 100_000,
    },
    Op {
        id: "key-check-honest",
        what: "key check (y < p), honest keys",
        calls: 100_000,
    },
    Op {
        id: "key-check-worst",
        what: "key check, worst passing input (y = p − 1)",
        calls: 100_000,
    },
    Op {
        id: "sig-decode",
        what: "the whole signature decoder (`sig_from_bytes`), honest signatures",
        calls: 100_000,
    },
    Op {
        id: "key-decode",
        what: "the whole key decoder (`pk_from_bytes`: the check, decompression, the small-order test), honest keys",
        calls: 2_000,
    },
];

/// The inputs: honest pools and the worst passing inputs.
pub struct Inputs {
    sigs: Vec<[u8; 64]>,
    keys: Vec<[u8; 32]>,
    worst_sig: [u8; 64],
    worst_key: [u8; 32],
}

impl Inputs {
    pub fn new() -> Self {
        let mut sigs = Vec::with_capacity(1024);
        let mut keys = Vec::with_capacity(1024);
        for i in 0..1024u32 {
            let mut seed = [0u8; 32];
            seed[..4].copy_from_slice(&i.to_le_bytes());
            seed[4] = 0xd8;
            let sk = Ed25519::keygen(&seed);
            let mut msg = [0u8; 32];
            msg[..4].copy_from_slice(&i.to_le_bytes());
            let sig = Ed25519::sig_bytes(&Ed25519::sign(&sk, &msg, Dst::Chain));
            sigs.push(sig.try_into().expect("64 bytes"));
            let pk = Ed25519::pk_bytes(&Ed25519::public_key(&sk));
            keys.push(pk.try_into().expect("32 bytes"));
        }
        // p − 1 = 2^255 − 20 and ℓ − 1, little-endian: both pass, and both
        // agree with their bound in every byte but the lowest, so the
        // comparison runs the full length.
        let mut worst_key = [0xffu8; 32];
        worst_key[0] = 0xec;
        worst_key[31] = 0x7f;
        let l_minus_1: [u8; 32] = [
            0xec, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
        ];
        let mut worst_sig = [0u8; 64];
        worst_sig[..32].copy_from_slice(&worst_key);
        worst_sig[32..].copy_from_slice(&l_minus_1);
        assert!(Ed25519::canonical_key(&worst_key));
        assert!(Ed25519::canonical_signature(&worst_sig));
        Inputs {
            sigs,
            keys,
            worst_sig,
            worst_key,
        }
    }
}

impl Default for Inputs {
    fn default() -> Self {
        Self::new()
    }
}

/// One batch of `op`: nanoseconds for `op.calls` calls.
fn batch(op: &Op, inp: &Inputs) -> u64 {
    let n = op.calls;
    let t = Instant::now();
    let mut ok = 0usize;
    match op.id {
        "sig-check-honest" => {
            for i in 0..n {
                ok += usize::from(Ed25519::canonical_signature(std::hint::black_box(
                    &inp.sigs[i & 1023],
                )));
            }
        }
        "sig-check-worst" => {
            for _ in 0..n {
                ok += usize::from(Ed25519::canonical_signature(std::hint::black_box(
                    &inp.worst_sig,
                )));
            }
        }
        "key-check-honest" => {
            for i in 0..n {
                ok += usize::from(Ed25519::canonical_key(std::hint::black_box(
                    &inp.keys[i & 1023],
                )));
            }
        }
        "key-check-worst" => {
            for _ in 0..n {
                ok += usize::from(Ed25519::canonical_key(std::hint::black_box(&inp.worst_key)));
            }
        }
        "sig-decode" => {
            for i in 0..n {
                ok += usize::from(
                    Ed25519::sig_from_bytes(std::hint::black_box(&inp.sigs[i & 1023])).is_ok(),
                );
            }
        }
        "key-decode" => {
            for i in 0..n {
                ok += usize::from(
                    Ed25519::pk_from_bytes(std::hint::black_box(&inp.keys[i & 1023])).is_ok(),
                );
            }
        }
        other => panic!("unknown operation {other}"),
    }
    let ns = t.elapsed().as_nanos() as u64;
    // Every input is valid, so every call accepts.
    assert_eq!(
        std::hint::black_box(ok),
        n,
        "{}: an input was rejected",
        op.id
    );
    ns
}

/// Runs one operation's batches and returns their nanoseconds.
pub type Batches<'a> = &'a mut dyn FnMut() -> Vec<u64>;
/// Takes an operation's id and its batches, and runs them between the
/// thermal readings.
pub type Around<'a> = &'a mut dyn FnMut(&str, Batches<'_>) -> Result<Vec<u64>, String>;

/// Measures every operation: a few warm-up batches, then `batches` timed.
/// `around(id, f)` runs `f` between the thermal readings.
pub fn measure(
    inp: &Inputs,
    batches: usize,
    around: Around<'_>,
) -> Result<BTreeMap<&'static str, Vec<u64>>, String> {
    let mut out = BTreeMap::new();
    for op in &OPS {
        let v = around(op.id, &mut || {
            for _ in 0..10 {
                std::hint::black_box(batch(op, inp));
            }
            (0..batches).map(|_| batch(op, inp)).collect()
        })?;
        out.insert(op.id, v);
    }
    Ok(out)
}

pub fn header() -> [&'static str; 5] {
    ["run", "op", "batch", "calls", "ns"]
}

/// The raw data, read from verified archives.
#[derive(Default)]
pub struct Data {
    /// op → run → nanoseconds per call, one per batch.
    pub per_call: BTreeMap<String, BTreeMap<usize, Vec<f64>>>,
    /// (run, op, signal) of each flagged operation (recorded, not re-run).
    pub flagged: Vec<(usize, String, String)>,
    pub runs: usize,
    pub archives: usize,
}

/// Checks every archive under `dir/archive` against its manifest, then
/// reads it.
pub fn load(dir: &Path) -> Result<Data, String> {
    let adir = dir.join("archive");
    let manifest = fs::read_to_string(adir.join("MANIFEST.sha256"))
        .map_err(|_| format!("no {}", adir.join("MANIFEST.sha256").display()))?;
    let mut d = Data::default();
    for line in manifest.lines().filter(|l| !l.trim().is_empty()) {
        let (want, name) = line
            .split_once("  ")
            .ok_or_else(|| format!("malformed manifest line: {line}"))?;
        let path = adir.join(name);
        let bytes = fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let got = hex(&dc_types::digest::sha256(&[&bytes]));
        if got != want {
            return Err(format!(
                "manifest mismatch for {name}: expected {want}, got {got}"
            ));
        }
        d.archives += 1;
        let file = name.strip_suffix(".zst").unwrap_or(name);
        if file.ends_with("-meta.json") {
            d.runs += 1;
            continue;
        }
        let data = decompress(&path)?;
        let mut rd = csv::Reader::from_reader(&data[..]);
        if let Some(stem) = file.strip_suffix("-thermal.csv") {
            let run: usize = stem
                .strip_prefix("run")
                .and_then(|r| r.parse().ok())
                .ok_or_else(|| format!("unexpected archive {name}"))?;
            let mut m: BTreeMap<String, (bool, bool)> = BTreeMap::new();
            for r in rd.records() {
                let r = r.map_err(|e| format!("{file}: {e}"))?;
                if &r[2] == "before" || &r[2] == "after" {
                    let e = m.entry(r[1].to_owned()).or_default();
                    e.0 |= &r[6] == "true";
                    e.1 |= &r[9] == "true";
                }
            }
            for (op, (pm, pr)) in m {
                let sig = match (pm, pr) {
                    (true, true) => "pmset and probe",
                    (true, false) => "pmset",
                    (false, true) => "probe",
                    (false, false) => continue,
                };
                d.flagged.push((run, op, sig.to_owned()));
            }
            continue;
        }
        for r in rd.records() {
            let r = r.map_err(|e| format!("{file}: {e}"))?;
            let num = |i: usize| -> Result<f64, String> {
                r[i].parse()
                    .map_err(|_| format!("{file}: bad number {}", &r[i]))
            };
            let (run, calls, ns) = (num(0)? as usize, num(3)?, num(4)?);
            d.per_call
                .entry(r[1].to_owned())
                .or_default()
                .entry(run)
                .or_default()
                .push(ns / calls);
        }
    }
    Ok(d)
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(f64::total_cmp);
    quantile_sorted(&v, 0.5)
}

impl Data {
    /// The pooled median, in ns per call, and each run's median.
    pub fn op(&self, id: &str) -> Result<(f64, BTreeMap<usize, f64>), String> {
        let runs = self
            .per_call
            .get(id)
            .ok_or_else(|| format!("no batches for {id}"))?;
        let all: Vec<f64> = runs.values().flatten().copied().collect();
        let per_run = runs.iter().map(|(r, v)| (*r, median(v.clone()))).collect();
        Ok((median(all), per_run))
    }

    pub fn flags(&self) -> String {
        if self.flagged.is_empty() {
            return "none was flagged".into();
        }
        format!(
            "flagged and not re-run: {}",
            self.flagged
                .iter()
                .map(|(r, o, s)| format!("run {r}: `{o}` ({s})"))
                .collect::<Vec<_>>()
                .join("; ")
        )
    }

    /// The generated block of BENCHMARKS.md §8. `m9(arm, state, n)` is M9's
    /// pooled median in ns (medium profile).
    pub fn markdown(
        &self,
        m9: &dyn Fn(&str, &str, usize) -> Result<f64, String>,
    ) -> Result<String, String> {
        let ns2 = |x: f64| format!("{x:.2}");
        let mut w = String::new();
        let _ = writeln!(
            w,
            "#### The checks\n\nNanoseconds per call: the median of all batches, pooled over {} runs, and each run's median. {} batches per operation per run.\n\n| Operation | Calls per batch | Median, ns | Per run, ns |\n|---|---|---|---|",
            self.runs, BATCHES
        );
        for op in &OPS {
            let (m, runs) = self.op(op.id)?;
            let _ = writeln!(
                w,
                "| {} | {} | {} | {} |",
                op.what,
                op.calls,
                ns2(m),
                runs.values()
                    .map(|x| ns2(*x))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        let (sig, _) = self.op("sig-check-honest")?;
        let (sig_worst, _) = self.op("sig-check-worst")?;
        let (key, _) = self.op("key-check-honest")?;
        let (key_worst, _) = self.op("key-check-worst")?;
        let _ = writeln!(
            w,
            "\n#### What they add to a chain (medium profile)\n\nEach of a chain's N + 1 signers contributes its signature. A warm verifier (arm C) and a prefix-cache hit or miss (arm D) find every signer's certificate cached, so they check N + 1 signatures and no key. A cold verifier (arm C) also decodes each signer's certificate, its signature and its key. `tests/encoding_checks.rs` checks these counts on M9's chains and subjects. \"Added\" is the counts times the honest medians, with the worst-input medians in brackets. The shares are of M9's pooled medians.\n\n| N | Arm, state | Signatures, keys checked | Added, ns | M9 median, µs | Share |\n|---|---|---|---|---|---|"
        );
        let pct = |x: f64| format!("{:.4}%", 100.0 * x);
        for n in NS {
            for load in &LOADS {
                let (keys, sigs) = load.checks(n);
                let added = sigs as f64 * sig + keys as f64 * key;
                let worst = sigs as f64 * sig_worst + keys as f64 * key_worst;
                let m = m9(load.arm, load.state, n)?;
                let _ = writeln!(
                    w,
                    "| {n} | {} | {sigs}, {keys} | {} [{}] | {} | {} [{}] |",
                    load.label,
                    ns2(added),
                    ns2(worst),
                    us(m),
                    pct(added / m),
                    pct(worst / m),
                );
            }
        }
        let _ = writeln!(
            w,
            "\nThermal readings around each operation: {}.",
            self.flags()
        );
        Ok(w.trim_end().to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_operation_accepts_its_inputs() {
        let inp = Inputs::new();
        for op in &OPS {
            let small = Op { calls: 64, ..*op };
            batch(&small, &inp);
        }
    }
}
