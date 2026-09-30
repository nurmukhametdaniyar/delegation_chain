//! `results/env.json` (SPEC §13.5, D-45): the machine, the toolchain, the
//! build, and the crate versions that affect a measurement. Everything is
//! read from local tools and files.

use std::path::Path;
use std::process::Command;

use serde_json::{Value, json};

/// Crates whose versions affect a measurement (SPEC §3.2).
const CRATES: [&str; 13] = [
    "blst",
    "ed25519-dalek",
    "curve25519-dalek",
    "sha2",
    "unicode-normalization",
    "biscuit-auth",
    "dashmap",
    "zeroize",
    "proptest",
    "criterion",
    "hdrhistogram",
    "stats_alloc",
    "rand_chacha",
];

fn cmd(program: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(program).args(args).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

fn sysctl(name: &str) -> Value {
    cmd("sysctl", &["-n", name]).map_or(Value::Null, Value::String)
}

/// Versions from `Cargo.lock`, which pins every crate (SPEC §3.2).
fn lock_versions(root: &Path) -> Value {
    let lock = std::fs::read_to_string(root.join("Cargo.lock")).unwrap_or_default();
    let mut out = serde_json::Map::new();
    let mut name: Option<String> = None;
    for line in lock.lines() {
        if let Some(n) = line.strip_prefix("name = ") {
            name = Some(n.trim_matches('"').to_owned());
        } else if let (Some(v), Some(n)) = (line.strip_prefix("version = "), name.take())
            && CRATES.contains(&n.as_str())
        {
            let v = v.trim_matches('"').to_owned();
            match out.get_mut(&n) {
                // Two major versions of one crate (sha2 0.9 comes with biscuit-auth).
                Some(Value::String(prev)) if *prev != v => {
                    let joined = format!("{prev}, {v}");
                    out.insert(n, Value::String(joined));
                }
                Some(_) => {}
                None => {
                    out.insert(n, Value::String(v));
                }
            }
        }
    }
    Value::Object(out)
}

/// The curve25519-dalek backend in use. Its SIMD backends are x86_64-only;
/// elsewhere it uses the serial u64 backend (D-45).
fn curve25519_backend() -> &'static str {
    if cfg!(target_arch = "x86_64") {
        "auto (AVX2/AVX-512 SIMD if the CPU has them, else serial u64)"
    } else {
        "serial u64 (the SIMD backends are x86_64-only)"
    }
}

/// `blst`'s assembly path: ADX on x86_64 when available, armv8 on aarch64.
fn blst_path() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "armv8 assembly (no ADX path on aarch64)"
    } else if cfg!(target_arch = "x86_64") {
        "x86_64 assembly (ADX chosen at runtime if the CPU has it)"
    } else {
        "portable C"
    }
}

/// M9's preconditions (frozen plan §5): AC power, High Power mode, and an
/// idle machine. Idle means a 1-minute load average below 2.0, and no other
/// process using more than 25% of a core, both fixed before any measurement.
pub fn requirements() -> Value {
    let battery = cmd("pmset", &["-g", "batt"]).unwrap_or_default();
    let ac = battery
        .lines()
        .next()
        .is_some_and(|l| l.contains("'AC Power'"));
    let pmset = cmd("pmset", &["-g"]).unwrap_or_default();
    let powermode = pmset
        .lines()
        .map(str::trim)
        .find(|l| l.split_whitespace().next() == Some("powermode"))
        .and_then(|l| l.split_whitespace().nth(1))
        .map(str::to_owned);
    // powermode 2 is High Power (0 automatic, 1 Low Power).
    let high_power = powermode.as_deref() == Some("2");
    let load: Option<f64> = cmd("sysctl", &["-n", "vm.loadavg"])
        .and_then(|s| {
            s.trim_matches(['{', '}', ' '])
                .split_whitespace()
                .next()
                .map(str::to_owned)
        })
        .and_then(|s| s.parse().ok());
    let me = std::process::id();
    let busy: Vec<Value> = cmd("ps", &["-Ao", "pid=,pcpu=,comm="])
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let pid: u32 = it.next()?.parse().ok()?;
            let pcpu: f64 = it.next()?.parse().ok()?;
            let comm = it.collect::<Vec<_>>().join(" ");
            (pid != me && pcpu > 25.0).then(|| json!({"pid": pid, "pcpu": pcpu, "command": comm}))
        })
        .collect();
    let idle = load.is_some_and(|l| l < 2.0) && busy.is_empty();
    json!({
        "ac_power": ac,
        "powermode": powermode,
        "high_power_mode": high_power,
        "idle": {"loadavg_1m": load, "busy_processes": busy, "ok": idle},
        "ok": ac && high_power && idle,
        "rule": "AC power, High Power mode (pmset powermode 2), 1-minute load average < 2.0, no other process > 25% CPU",
    })
}

pub fn capture(root: &Path) -> Value {
    let pmset = cmd("pmset", &["-g"]).unwrap_or_default();
    let pick = |key: &str| {
        pmset
            .lines()
            .map(str::trim)
            .find(|l| l.split_whitespace().next() == Some(key))
            .map(|l| l.split_whitespace().nth(1).unwrap_or("").to_owned())
    };
    let battery = cmd("pmset", &["-g", "batt"]).unwrap_or_default();
    let power_source = battery
        .lines()
        .next()
        .and_then(|l| l.split('\'').nth(1))
        .map(str::to_owned);
    let dirty = cmd("git", &["status", "--porcelain"]).map(|s| !s.is_empty());
    json!({
        "cpu": {
            "model": sysctl("machdep.cpu.brand_string"),
            "logical_cores": sysctl("hw.ncpu"),
            "performance_cores": sysctl("hw.perflevel0.physicalcpu"),
            "efficiency_cores": sysctl("hw.perflevel1.physicalcpu"),
            "base_frequency_hz": sysctl("hw.cpufrequency"),
            "max_frequency_hz": sysctl("hw.cpufrequency_max"),
            "memory_bytes": sysctl("hw.memsize"),
            "frequency_governor": "none: macOS exposes no governor or turbo control (D-45)",
        },
        "os": {
            "product": cmd("sw_vers", &["-productVersion"]),
            "build": cmd("sw_vers", &["-buildVersion"]),
            "kernel": cmd("uname", &["-a"]),
        },
        "power": {
            "source": power_source,
            "lowpowermode": pick("lowpowermode"),
            "powermode": pick("powermode"),
        },
        "toolchain": {
            "rustc": cmd("rustc", &["-vV"]),
            "rustflags_at_build": env!("DC_BENCH_RUSTFLAGS"),
            "rustflags_now": std::env::var("RUSTFLAGS").ok(),
            "profile": env!("DC_BENCH_PROFILE"),
            "target_cpu_native": env!("DC_BENCH_RUSTFLAGS").contains("target-cpu=native"),
            "note": "target-cpu=native reaches Rust code only; blst's C and assembly are built by cc, which ignores RUSTFLAGS (SPEC §3.3)",
        },
        "crates": lock_versions(root),
        "blst": {
            "path": blst_path(),
            "threaded": dc_crypto::BLST_THREADED,
        },
        "curve25519_dalek_backend": curve25519_backend(),
        "count_ops": dc_crypto::ops::ENABLED,
        "pinning": "none: macOS has no working thread-affinity API on Apple Silicon; measuring threads use QoS user-interactive (D-42)",
        "timer": "std::time::Instant (mach_absolute_time on macOS)",
        "git": {
            "commit": cmd("git", &["rev-parse", "HEAD"]),
            "dirty": dirty,
        },
        "date_utc": cmd("date", &["-u", "+%Y-%m-%dT%H:%M:%SZ"]),
        "zstd": cmd("zstd", &["--version"]),
        "thermal": crate::thermal::read(),
        "m9_requirements": requirements(),
    })
}
