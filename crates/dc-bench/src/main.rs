//! `dc-bench`: the benchmark harness (SPEC §13; the frozen plan).
//!
//! ```text
//! dc-bench all     [--mode full|dry] [--out DIR]    everything (SPEC §13.8)
//! dc-bench run     --run R [--mode M] [--out DIR] [--arm A]... [--only ID]... [--rerun] [--no-throughput]
//! dc-bench bytes   [--mode M] [--out DIR]           Q2
//! dc-bench env     [--out DIR]                      results/env.json
//! dc-bench archive [--mode M] [--out DIR]           zstd archives of raw/ and their SHA-256 manifest
//! dc-bench report  [--mode M] [--out DIR] [--criterion DIR]
//! dc-bench plan    [--mode M]                       the grid, as the frozen plan states it
//! ```
//!
//! `--mode dry` is M8's dry run: 10 iterations per configuration, written to
//! `results/dry-run/`. Its numbers are never reported, and it does not
//! require the machine state that a full run does.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::{Duration, Instant};

use dc_bench::arms::{Arm, Family, State, Worlds};
use dc_bench::harness::{BytesRow, SetKey, SetStore, bytes_row, generate, measure, throughput};
use dc_bench::plan::{
    Config, Mode, NS, PROFILES, RUNS, THREADS, THROUGHPUT_ARMS, grid, order_seed, shuffled,
    throughput_counts,
};
use dc_bench::probe::{self, Probe};
use dc_bench::workload::{Layout, Profile, hop_agent, p};
use dc_bench::{env, qos, report, thermal};
use dc_registry::Resolver;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use serde_json::{Value, json};

struct Args {
    cmd: String,
    mode: Mode,
    out: Option<PathBuf>,
    run: usize,
    arms: Vec<Arm>,
    only: Vec<String>,
    rerun: bool,
    throughput: bool,
    criterion: Option<PathBuf>,
}

fn parse() -> Result<Args, String> {
    let mut it = std::env::args().skip(1);
    let cmd = it
        .next()
        .ok_or("usage: dc-bench <all|run|bytes|env|archive|report|plan> [options]")?;
    let mut a = Args {
        cmd,
        mode: Mode::Full,
        out: None,
        run: 1,
        arms: vec![],
        only: vec![],
        rerun: false,
        throughput: true,
        criterion: None,
    };
    while let Some(flag) = it.next() {
        let mut val = || it.next().ok_or(format!("{flag} needs a value"));
        match flag.as_str() {
            "--mode" => {
                a.mode = match val()?.as_str() {
                    "full" => Mode::Full,
                    "dry" => Mode::Dry,
                    m => return Err(format!("unknown mode {m}")),
                }
            }
            "--out" => a.out = Some(PathBuf::from(val()?)),
            "--run" => a.run = val()?.parse().map_err(|_| "bad --run")?,
            "--arm" => {
                let s = val()?;
                a.arms
                    .push(Arm::parse(&s).ok_or(format!("unknown arm {s}"))?);
            }
            "--only" => a.only.push(val()?),
            "--rerun" => a.rerun = true,
            "--no-throughput" => a.throughput = false,
            "--criterion" => a.criterion = Some(PathBuf::from(val()?)),
            f => return Err(format!("unknown option {f}")),
        }
    }
    Ok(a)
}

/// The workspace root (for Cargo.lock and target/).
fn root() -> PathBuf {
    let mut d = std::env::current_dir().expect("cwd");
    loop {
        if d.join("Cargo.lock").exists() && d.join("crates").exists() {
            return d;
        }
        if !d.pop() {
            return std::env::current_dir().expect("cwd");
        }
    }
}

fn out_dir(a: &Args) -> PathBuf {
    a.out.clone().unwrap_or_else(|| match a.mode {
        Mode::Full => root().join("results"),
        Mode::Dry => root().join("results/dry-run"),
    })
}

fn threads() -> usize {
    std::thread::available_parallelism().map_or(4, |n| n.get())
}

fn main() -> ExitCode {
    let a = match parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("dc-bench: {e}");
            return ExitCode::from(2);
        }
    };
    let r = match a.cmd.as_str() {
        "plan" => cmd_plan(&a),
        "env" => cmd_env(&a).map(|_| ()),
        "run" => cmd_run(&a),
        "bytes" => cmd_bytes(&a),
        "archive" => archive(&out_dir(&a)),
        "report" => cmd_report(&a),
        "all" => cmd_all(&a),
        c => Err(format!("unknown command {c}")),
    };
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("dc-bench: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_plan(a: &Args) -> Result<(), String> {
    let g = grid(a.mode);
    println!(
        "{} latency configurations ({} mode):",
        g.len(),
        a.mode.label()
    );
    for c in &g {
        println!(
            "  {:<44} warm-up {:>5}  measured {:>6}",
            c.id(),
            c.warmup,
            c.measured
        );
    }
    let (pre, per, warm) = throughput_counts(a.mode);
    println!(
        "Q6: arms {:?}, threads {:?}, {pre} prefixes × {per} invocations, {warm} warm-up chains",
        THROUGHPUT_ARMS.map(Arm::label),
        THREADS
    );
    for r in 1..=RUNS {
        println!("run {r}: order seed {:#x}", order_seed(r));
    }
    Ok(())
}

fn cmd_env(a: &Args) -> Result<Value, String> {
    let out = out_dir(a);
    fs::create_dir_all(&out).map_err(|e| e.to_string())?;
    let v = env::capture(&root());
    fs::write(
        out.join("env.json"),
        serde_json::to_string_pretty(&v).unwrap() + "\n",
    )
    .map_err(|e| e.to_string())?;
    Ok(v)
}

/// The frozen plan's machine state for a full run: AC power and High Power
/// mode at once, and an idle machine within 10 minutes (the harness's own
/// builds can leave the machine busy for a while). A dry run only warns.
fn require(mode: Mode) -> Result<Value, String> {
    let mut r = env::requirements();
    if mode == Mode::Dry {
        if r["ok"] != json!(true) {
            eprintln!("dc-bench: dry run on a machine that a full run would refuse: {r}");
        }
        return Ok(r);
    }
    if r["ac_power"] != json!(true) || r["high_power_mode"] != json!(true) {
        return Err(format!(
            "aborting: a full run needs AC power and High Power mode: {r}"
        ));
    }
    let deadline = Instant::now() + Duration::from_secs(600);
    while r["ok"] != json!(true) {
        if Instant::now() > deadline {
            return Err(format!(
                "aborting: the machine did not become idle within 10 minutes: {r}"
            ));
        }
        eprintln!(
            "dc-bench: waiting for the machine to become idle: {}",
            r["idle"]
        );
        std::thread::sleep(Duration::from_secs(15));
        r = env::requirements();
    }
    Ok(r)
}

/// The id of a Q6 configuration, as `--only` names it.
fn q6_id(arm: Arm, t: usize) -> String {
    format!("Q6 {} x{t}", arm.label())
}

/// The thermal and calibration-probe readings around each configuration,
/// and the safety valve (frozen plan §5).
///
/// - **Rows.** Every reading goes to `run*-thermal.csv`, including the 5
///   baseline probes.
/// - **Flags.** A configuration is flagged if pmset records a warning, or if
///   either of its probes is more than 5% slower than the run's baseline.
/// - **The valve.** In a main run process, once more than 10% of the
///   process's configurations are flagged, the run aborts rather than
///   re-running them. A re-run process records its flags but has no valve.
struct Monitor {
    w: csv::Writer<fs::File>,
    run: usize,
    probe: Probe,
    baseline: u64,
    total: usize,
    valve: bool,
    /// (configuration, signal) of each flagged configuration.
    flagged: Vec<(String, &'static str)>,
}

impl Monitor {
    fn new(
        mut w: csv::Writer<fs::File>,
        run: usize,
        total: usize,
        valve: bool,
    ) -> Result<Self, String> {
        w.write_record([
            "run",
            "config",
            "phase",
            "cpu_speed_limit",
            "thermal_warning",
            "performance_warning",
            "pmset_warning",
            "probe_ns",
            "baseline_ns",
            "probe_slow",
            "throttled",
        ])
        .map_err(|e| e.to_string())?;
        let probe = Probe::new();
        let (baseline, samples) = probe.baseline();
        let mut m = Monitor {
            w,
            run,
            probe,
            baseline,
            total,
            valve,
            flagged: vec![],
        };
        let pm = thermal::read();
        for (k, ns) in samples.iter().enumerate() {
            m.row("baseline", &format!("baseline-{}", k + 1), &pm, *ns, false)?;
        }
        eprintln!("run {run}: probe baseline {:.1} ms", baseline as f64 / 1e6);
        Ok(m)
    }

    fn row(
        &mut self,
        id: &str,
        phase: &str,
        pm: &thermal::Reading,
        probe_ns: u64,
        judged: bool,
    ) -> Result<(), String> {
        let [limit, tw, pw, pm_flag] = pm.fields();
        let slow = judged && probe::slow(probe_ns, self.baseline);
        let throttled = judged && (pm.throttled() || slow);
        self.w
            .write_record([
                &self.run.to_string(),
                id,
                phase,
                &limit,
                &tw,
                &pw,
                &pm_flag,
                &probe_ns.to_string(),
                &self.baseline.to_string(),
                &slow.to_string(),
                &throttled.to_string(),
            ])
            .map_err(|e| e.to_string())?;
        self.w.flush().map_err(|e| e.to_string())
    }

    /// Readings before a configuration: pmset, then the probe.
    fn before(&mut self, id: &str) -> Result<(thermal::Reading, u64), String> {
        let pm = thermal::read();
        let ns = self.probe.run_ns();
        self.row(id, "before", &pm, ns, true)?;
        Ok((pm, ns))
    }

    /// Readings after it: the probe, then pmset. Returns the abort reason if
    /// the safety valve trips.
    fn after(
        &mut self,
        id: &str,
        before: (thermal::Reading, u64),
    ) -> Result<Option<String>, String> {
        let ns = self.probe.run_ns();
        let pm = thermal::read();
        self.row(id, "after", &pm, ns, true)?;
        let pmset = before.0.throttled() || pm.throttled();
        let slow = probe::slow(before.1, self.baseline) || probe::slow(ns, self.baseline);
        let signal = match (pmset, slow) {
            (true, true) => Some("pmset and probe"),
            (true, false) => Some("pmset"),
            (false, true) => Some("probe"),
            (false, false) => None,
        };
        if let Some(sig) = signal {
            self.flagged.push((id.to_owned(), sig));
            eprintln!("run {}: {id} flagged ({sig})", self.run);
        }
        if self.valve && self.flagged.len() * 10 > self.total {
            return Ok(Some(format!(
                "aborting run {}: {} of its {} configurations are flagged (more than 10%); the machine is not in a usable state (frozen plan §5)",
                self.run,
                self.flagged.len(),
                self.total
            )));
        }
        Ok(None)
    }
}

fn cmd_run(a: &Args) -> Result<(), String> {
    let requirements = require(a.mode)?;
    let out = out_dir(a);
    let raw = out.join("raw");
    fs::create_dir_all(&raw).map_err(|e| e.to_string())?;
    let started = Instant::now();
    let qos_main = qos::set_user_interactive();
    let build = if dc_crypto::BLST_THREADED {
        "amt"
    } else {
        "main"
    };
    let worlds = Worlds::new();

    // The configurations this build may run (D-29), in this run's order.
    let configs: Vec<Config> = shuffled(
        grid(a.mode)
            .into_iter()
            .filter(|c| c.arm.matches_build())
            .filter(|c| a.arms.is_empty() || a.arms.contains(&c.arm))
            .filter(|c| a.only.is_empty() || a.only.contains(&c.id()))
            .collect(),
        a.run,
    );
    let (pre, per, warm_n) = throughput_counts(a.mode);
    let mut tp_order: Vec<(Arm, usize)> = if a.throughput && !dc_crypto::BLST_THREADED {
        THROUGHPUT_ARMS
            .iter()
            .flat_map(|&arm| THREADS.iter().map(move |&t| (arm, t)))
            .filter(|&(arm, t)| a.only.is_empty() || a.only.contains(&q6_id(arm, t)))
            .collect()
    } else {
        vec![]
    };
    let mut rng = ChaCha20Rng::seed_from_u64(order_seed(a.run) ^ 0x7_4600);
    for i in (1..tp_order.len()).rev() {
        let j = (rng.next_u64() % (i as u64 + 1)) as usize;
        tp_order.swap(i, j);
    }
    let tp_key = |family: Family| SetKey {
        family,
        profile: Profile::Medium,
        n: 3,
        layout: Layout::Prefixed { prefixes: pre },
        count: pre * per,
    };
    let tp_warm = |family: Family| SetKey {
        family,
        profile: Profile::Medium,
        n: 3,
        layout: Layout::Fresh,
        count: warm_n,
    };
    let mut keys: Vec<SetKey> = configs.iter().map(SetKey::of).collect();
    let tp_families: BTreeSet<Family> = tp_order.iter().map(|(arm, _)| arm.family()).collect();
    for &f in &tp_families {
        keys.push(tp_key(f));
        keys.push(tp_warm(f));
    }
    let stem = format!(
        "run{}{}{}",
        a.run,
        if dc_crypto::BLST_THREADED { "-amt" } else { "" },
        if a.rerun { "-rerun" } else { "" }
    );
    let set_dir = root()
        .join("target/dc-bench-sets")
        .join(format!("{}-{stem}-{build}", a.mode.label()));
    eprintln!("{stem}: generating {} chain sets…", keys.len());
    let gen_started = Instant::now();
    let store = SetStore::build(&worlds, &keys, &set_dir, threads()).map_err(|e| e.to_string())?;
    let generation_s = gen_started.elapsed().as_secs_f64();
    // Let the machine settle after generating on every core (D-72).
    std::thread::sleep(Duration::from_secs(if a.mode == Mode::Full {
        30
    } else {
        1
    }));
    // The probe baseline, after the settle, on this measuring thread.
    let mut monitor = Monitor::new(
        csv::Writer::from_path(raw.join(format!("{stem}-thermal.csv")))
            .map_err(|e| e.to_string())?,
        a.run,
        configs.len() + tp_order.len(),
        !a.rerun,
    )?;
    let mut abort: Option<String> = None;

    let csv_w = |name: String| csv::Writer::from_path(raw.join(name)).map_err(|e| e.to_string());
    let mut lat = csv_w(format!("{stem}.csv"))?;
    lat.write_record(["run", "arm", "state", "N", "profile", "iter", "ns"])
        .map_err(|e| e.to_string())?;
    let mut calls = csv_w(format!("{stem}-calls.csv"))?;
    calls
        .write_record([
            "run",
            "arm",
            "state",
            "N",
            "profile",
            "verifications",
            "resolver_calls",
            "store_calls",
        ])
        .map_err(|e| e.to_string())?;
    let mut timings = vec![];
    for (i, c) in configs.iter().enumerate() {
        let t = Instant::now();
        let chains = store.load(&SetKey::of(c)).map_err(|e| e.to_string())?;
        let before = monitor.before(&c.id())?;
        let m = measure(&worlds, c, &chains)?;
        abort = monitor.after(&c.id(), before)?;
        drop(chains);
        let (arm, state, n, profile) = (
            c.arm.label(),
            c.state.label(),
            c.n.to_string(),
            c.profile.label(),
        );
        let run = a.run.to_string();
        for (iter, ns) in m.ns.iter().enumerate() {
            lat.write_record([
                run.as_str(),
                arm,
                &state,
                &n,
                profile,
                &iter.to_string(),
                &ns.to_string(),
            ])
            .map_err(|e| e.to_string())?;
        }
        if matches!(c.state, State::ColdRtt(_)) {
            calls
                .write_record([
                    run.as_str(),
                    arm,
                    &state,
                    &n,
                    profile,
                    &m.ns.len().to_string(),
                    &m.resolver_calls.to_string(),
                    &m.store_calls.to_string(),
                ])
                .map_err(|e| e.to_string())?;
        }
        lat.flush().map_err(|e| e.to_string())?;
        let secs = t.elapsed().as_secs_f64();
        timings.push(json!({"config": c.id(), "seconds": secs}));
        eprintln!("[{}/{}] {} ({secs:.1} s)", i + 1, configs.len(), c.id());
        if abort.is_some() {
            break;
        }
    }
    calls.flush().map_err(|e| e.to_string())?;

    let mut tp_rows = vec![];
    if !tp_order.is_empty() && abort.is_none() {
        let mut w = csv_w(format!("{stem}-throughput.csv"))?;
        w.write_record([
            "run", "arm", "threads", "chains", "accepted", "wall_ns", "p50_ns", "p99_ns", "qos_ok",
        ])
        .map_err(|e| e.to_string())?;
        // Per family: the warm-up chains and the measured chains.
        type Sets = Vec<(Family, Vec<Vec<u8>>, Vec<Vec<u8>>)>;
        let sets: Sets = tp_families
            .iter()
            .map(|&f| Ok((f, store.load(&tp_warm(f))?, store.load(&tp_key(f))?)))
            .collect::<std::io::Result<_>>()
            .map_err(|e| e.to_string())?;
        for (arm, t) in tp_order {
            let (_, warm, chains) = sets.iter().find(|s| s.0 == arm.family()).expect("family");
            // The probe runs single-threaded on this thread (frozen plan §5).
            let before = monitor.before(&q6_id(arm, t))?;
            let r = throughput(&worlds, arm, t, warm, chains)?;
            abort = monitor.after(&q6_id(arm, t), before)?;
            eprintln!(
                "{}: {:.0} accepted/s",
                q6_id(arm, t),
                r.accepted as f64 / (r.wall_ns as f64 / 1e9)
            );
            w.write_record([
                a.run.to_string(),
                arm.label().to_owned(),
                t.to_string(),
                r.chains.to_string(),
                r.accepted.to_string(),
                r.wall_ns.to_string(),
                r.p50_ns.to_string(),
                r.p99_ns.to_string(),
                r.qos_ok.to_string(),
            ])
            .map_err(|e| e.to_string())?;
            tp_rows.push(r);
            if abort.is_some() {
                break;
            }
        }
        w.flush().map_err(|e| e.to_string())?;
    }
    store.remove().map_err(|e| e.to_string())?;

    let meta = json!({
        "run": a.run,
        "mode": a.mode.label(),
        "build": build,
        "rerun": a.rerun,
        "only": a.only,
        "blst_threaded": dc_crypto::BLST_THREADED,
        "requirements_at_start": requirements,
        "qos_user_interactive_main_thread": qos_main,
        "order_seed": order_seed(a.run),
        "order": configs.iter().map(Config::id).collect::<Vec<_>>(),
        "generation_seconds": generation_s,
        "config_seconds": timings,
        "throughput_qos_ok": tp_rows.iter().all(|r| r.qos_ok),
        "probe_baseline_ns": monitor.baseline,
        "configurations_in_process": monitor.total,
        "flagged": monitor.flagged.iter().map(|(id, sig)| json!({"config": id, "signal": sig})).collect::<Vec<_>>(),
        "aborted": abort,
        "total_seconds": started.elapsed().as_secs_f64(),
        "rustflags_at_build": env!("DC_BENCH_RUSTFLAGS"),
    });
    fs::write(
        raw.join(format!("{stem}-meta.json")),
        serde_json::to_string_pretty(&meta).unwrap() + "\n",
    )
    .map_err(|e| e.to_string())?;
    match abort {
        Some(reason) => Err(reason),
        None => Ok(()),
    }
}

fn cmd_bytes(a: &Args) -> Result<(), String> {
    let out = out_dir(a);
    fs::create_dir_all(&out).map_err(|e| e.to_string())?;
    let w = Worlds::new();
    let sample = 20;
    let mut rows: Vec<BytesRow> = vec![];
    // Every N from 1 to 10, so that the A-against-C break-even is exact
    // (frozen plan §6); arm E on the grid's N.
    for profile in Profile::ALL {
        for n in 1..=10 {
            for (label, family) in [
                ("A (also B, A-mt)", Family::BlsAggregate),
                ("A-ind", Family::BlsList),
                ("C (also C-batch, D)", Family::Ed25519List),
            ] {
                let key = SetKey {
                    family,
                    profile,
                    n,
                    layout: Layout::Fresh,
                    count: sample,
                };
                rows.push(bytes_row(label, n, profile, &generate(&w, &key), true));
            }
        }
    }
    for profile in PROFILES {
        for n in NS {
            let key = SetKey {
                family: Family::Biscuit,
                profile,
                n,
                layout: Layout::Fresh,
                count: sample,
            };
            rows.push(bytes_row("E", n, profile, &generate(&w, &key), false));
        }
    }
    // Certificate sizes, from the registries (§13.7).
    let agent = hop_agent(0, 0);
    let bls_cert = w
        .bls
        .directory()
        .resolve(&p(&agent), &w.bls.world.pk(&agent), dc_bench::workload::T0)
        .ok_or("no BLS certificate")?;
    let ed_cert = w
        .ed25519
        .directory()
        .resolve(
            &p(&agent),
            &w.ed25519.world.pk(&agent),
            dc_bench::workload::T0,
        )
        .ok_or("no Ed25519 certificate")?;
    let inline: Vec<Value> = rows
        .iter()
        .filter(|r| r.arm.starts_with('A') || r.arm.starts_with('C'))
        .map(|r| {
            let cert = if r.arm.starts_with('C') {
                ed_cert.0.len()
            } else {
                bls_cert.0.len()
            };
            json!({"arm": r.arm, "n": r.n, "profile": r.profile,
                   "total_with_inline_certificates": r.total_mean + ((r.n + 1) * cert) as f64})
        })
        .collect();
    let v = json!({
        "sampled_per_cell": sample,
        "rows": rows,
        "certificate_bytes": {"bls": bls_cert.0.len(), "ed25519": ed_cert.0.len()},
        "inline_certificates": inline,
    });
    fs::write(
        out.join("bytes.json"),
        serde_json::to_string_pretty(&v).unwrap() + "\n",
    )
    .map_err(|e| e.to_string())
}

/// Compresses every file in `raw/` with zstd into `archive/`, and writes
/// `archive/MANIFEST.sha256` (`shasum -a 256 -c` format) over the archives.
/// The archives stay out of git; the manifest is committed (frozen plan §5).
fn archive(out: &Path) -> Result<(), String> {
    let raw = out.join("raw");
    let dir = out.join("archive");
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let mut names: Vec<String> = fs::read_dir(&raw)
        .map_err(|e| format!("{}: {e}", raw.display()))?
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .collect();
    names.sort();
    let mut manifest = String::new();
    for name in names {
        let target = dir.join(format!("{name}.zst"));
        let st = Command::new("zstd")
            .args(["-q", "-f", "-10", "-o"])
            .arg(&target)
            .arg(raw.join(&name))
            .status()
            .map_err(|e| format!("zstd: {e}"))?;
        if !st.success() {
            return Err(format!("zstd failed on {name}"));
        }
        let bytes = fs::read(&target).map_err(|e| e.to_string())?;
        let h = dc_types::digest::sha256(&[&bytes]);
        let hex: String = h.iter().map(|b| format!("{b:02x}")).collect();
        manifest.push_str(&format!("{hex}  {name}.zst\n"));
    }
    fs::write(dir.join("MANIFEST.sha256"), manifest).map_err(|e| e.to_string())
}

fn cmd_report(a: &Args) -> Result<(), String> {
    let out = out_dir(a);
    let criterion = a.criterion.clone().unwrap_or_else(|| out.join("criterion"));
    report::report(&out, &criterion, threads(), a.mode == Mode::Dry)
}

fn run_child(cmd: &mut Command, what: &str) -> Result<(), String> {
    eprintln!("== {what}");
    let st = cmd.status().map_err(|e| format!("{what}: {e}"))?;
    if st.success() {
        Ok(())
    } else {
        Err(format!("{what} failed: {st}"))
    }
}

/// (run, A-mt build?) → configurations with a throttled thermal reading.
fn throttled(raw: &Path) -> BTreeMap<(usize, bool), BTreeSet<String>> {
    let mut out: BTreeMap<(usize, bool), BTreeSet<String>> = BTreeMap::new();
    for e in fs::read_dir(raw).into_iter().flatten().flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if !name.ends_with("-thermal.csv") || name.contains("-rerun") {
            continue;
        }
        let amt = name.contains("-amt");
        let Ok(mut r) = csv::Reader::from_path(e.path()) else {
            continue;
        };
        for rec in r.records().flatten() {
            if rec.get(10) == Some("true") {
                let run: usize = rec.get(0).and_then(|x| x.parse().ok()).unwrap_or(0);
                out.entry((run, amt))
                    .or_default()
                    .insert(rec.get(1).unwrap_or("").to_owned());
            }
        }
    }
    out
}

/// Which signals flagged configuration `id` in a thermal CSV: "pmset",
/// "probe", "pmset and probe", or "none".
fn signals(file: &Path, id: &str) -> String {
    let Ok(mut r) = csv::Reader::from_path(file) else {
        return "none".into();
    };
    let (mut pm, mut pr) = (false, false);
    for rec in r.records().flatten().filter(|rec| rec.get(1) == Some(id)) {
        pm |= rec.get(6) == Some("true");
        pr |= rec.get(9) == Some("true");
    }
    match (pm, pr) {
        (true, true) => "pmset and probe".into(),
        (true, false) => "pmset".into(),
        (false, true) => "probe".into(),
        (false, false) => "none".into(),
    }
}

/// Appends a BENCH_LOG.md entry for each thermal re-run (SPEC Appendix B),
/// with the medians of the original and the re-run, read from the CSVs.
fn log_reruns(
    log: &Path,
    raw: &Path,
    reruns: &BTreeMap<(usize, bool), BTreeSet<String>>,
) -> Result<(), String> {
    if reruns.is_empty() {
        return Ok(());
    }
    let median_of = |file: &Path, id: &str| -> Option<f64> {
        let mut r = csv::Reader::from_path(file).ok()?;
        let mut v: Vec<f64> = r
            .records()
            .flatten()
            .filter(|rec| format!("{} {} N={} {}", &rec[1], &rec[2], &rec[3], &rec[4]) == id)
            .filter_map(|rec| rec[6].parse().ok())
            .collect();
        if v.is_empty() {
            return None;
        }
        v.sort_by(f64::total_cmp);
        Some(dc_bench::stats::quantile_sorted(&v, 0.5))
    };
    let date = Command::new("date")
        .args(["-u", "+%Y-%m-%d"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .unwrap_or_default();
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log)
        .map_err(|e| e.to_string())?;
    for ((run, amt), ids) in reruns {
        let stem = format!("run{run}{}", if *amt { "-amt" } else { "" });
        let mut lines = vec![];
        for id in ids {
            let before = median_of(&raw.join(format!("{stem}.csv")), id);
            let after = median_of(&raw.join(format!("{stem}-rerun.csv")), id);
            let original = signals(&raw.join(format!("{stem}-thermal.csv")), id);
            let again = signals(&raw.join(format!("{stem}-rerun-thermal.csv")), id);
            lines.push(format!(
                "- `{id}`: flagged by {original}; original median {} ns, re-run median {} ns; re-run {}{}",
                before.map_or("n/a".into(), |x| format!("{x:.0}")),
                after.map_or("n/a".into(), |x| format!("{x:.0}")),
                if again == "none" { "not flagged".to_owned() } else { format!("flagged again, by {again}") },
                if id.starts_with("Q6 ") {
                    " (Q6: see the throughput CSVs)"
                } else {
                    ""
                }
            ));
        }
        writeln!(
            f,
            "\n## {date} — throttling re-run, run {run}{}\nReason: before or after these configurations, `pmset -g therm` recorded a warning, or a calibration probe ran more than 5% slower than the run's baseline (frozen plan §5). They were re-run after the main runs; the report uses the re-run samples, and the originals stay in the archive.\nConfigurations re-run:\n{}",
            if *amt { " (A-mt build)" } else { "" },
            lines.join("\n")
        )
        .map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Everything the frozen plan lists, from one command.
fn cmd_all(a: &Args) -> Result<(), String> {
    let out = out_dir(a);
    let root = root();
    fs::create_dir_all(&out).map_err(|e| e.to_string())?;
    let me = std::env::current_exe().map_err(|e| e.to_string())?;
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let mode = a.mode.label();
    let outs = out.to_string_lossy().to_string();
    if !env!("DC_BENCH_RUSTFLAGS").contains("target-cpu=native") {
        let msg = "not built with RUSTFLAGS=\"-C target-cpu=native\" (SPEC §3.3)";
        if a.mode == Mode::Full {
            return Err(format!("aborting: {msg}"));
        }
        eprintln!("dc-bench: warning: {msg}");
    }
    // AC power and High Power mode are checked before anything is built.
    if a.mode == Mode::Full {
        let r = env::requirements();
        if r["ac_power"] != json!(true) || r["high_power_mode"] != json!(true) {
            cmd_env(a)?;
            return Err(format!(
                "aborting: a full run needs AC power and High Power mode: {r}"
            ));
        }
    }
    // The supplementary A-mt build: blst with its thread pool (D-29).
    run_child(
        Command::new(&cargo)
            .current_dir(&root)
            .args([
                "build",
                "--release",
                "-p",
                "dc-bench",
                "--bins",
                "--no-default-features",
                "--target-dir",
            ])
            .arg(root.join("target/a-mt")),
        "build A-mt",
    )?;
    run_child(
        Command::new(&cargo).current_dir(&root).args([
            "build",
            "--release",
            "-p",
            "dc-bench",
            "--bins",
        ]),
        "build dc-bench binaries",
    )?;
    // env.json records the machine once it is idle, before the first run.
    require(a.mode)?;
    let env = cmd_env(a)?;
    if a.mode == Mode::Full && env["m9_requirements"]["ok"] != json!(true) {
        return Err(
            "aborting: env.json does not confirm AC power, High Power mode and an idle machine"
                .into(),
        );
    }
    let amt = root.join("target/a-mt/release/dc-bench");
    let runs = if a.mode == Mode::Dry { 1 } else { RUNS };
    for r in 1..=runs {
        let rs = r.to_string();
        run_child(
            Command::new(&me).args(["run", "--run", &rs, "--mode", mode, "--out", &outs]),
            &format!("run {r}"),
        )?;
        run_child(
            Command::new(&amt).args(["run", "--run", &rs, "--mode", mode, "--out", &outs]),
            &format!("run {r}, A-mt"),
        )?;
    }
    // Thermal re-runs (frozen plan §5), whatever their result.
    let raw = out.join("raw");
    let reruns = throttled(&raw);
    for ((run, is_amt), ids) in &reruns {
        let rs = run.to_string();
        let bin = if *is_amt { &amt } else { &me };
        let mut c = Command::new(bin);
        c.args([
            "run", "--run", &rs, "--mode", mode, "--out", &outs, "--rerun",
        ]);
        for id in ids {
            c.args(["--only", id]);
        }
        run_child(
            &mut c,
            &format!(
                "thermal re-run, run {run}{}",
                if *is_amt { ", A-mt" } else { "" }
            ),
        )?;
    }
    let log = if a.mode == Mode::Full {
        root.join("BENCH_LOG.md")
    } else {
        out.join("BENCH_LOG.dry.md")
    };
    log_reruns(&log, &raw, &reruns)?;
    cmd_bytes(a)?;
    let memory = me.with_file_name("dc-bench-memory");
    run_child(
        Command::new(memory).args(["--mode", mode, "--out", &outs]),
        "memory (Q10)",
    )?;
    let crit_dir = out.join("criterion");
    let mut bench = Command::new(&cargo);
    bench
        .current_dir(&root)
        .env("CRITERION_HOME", &crit_dir)
        .args(["bench", "-p", "dc-bench", "--", "--noplot"]);
    if a.mode == Mode::Dry {
        bench.args([
            "--warm-up-time",
            "0.05",
            "--measurement-time",
            "0.1",
            "--sample-size",
            "10",
        ]);
    }
    run_child(&mut bench, "criterion benches (Q7, Q8, primitives)")?;
    archive(&out)?;
    report::report(&out, &crit_dir, threads(), a.mode == Mode::Dry)?;
    let plot = root.join("scripts/plot.sh");
    if let Err(e) = run_child(Command::new("bash").arg(plot).arg(&out), "plots") {
        eprintln!("dc-bench: {e}; the summary is complete without plots");
    }
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(out.join("runs.log"))
        .map_err(|e| e.to_string())?;
    writeln!(
        f,
        "all ({mode}) finished; thermal re-runs: {}",
        reruns.values().map(BTreeSet::len).sum::<usize>()
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}
