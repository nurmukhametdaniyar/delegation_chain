//! `dc-bench`: the benchmark harness (SPEC §13; the frozen plan).
//!
//! ```text
//! dc-bench all     [--mode full|dry] [--out DIR] [--resume]   everything (SPEC §13.8)
//! dc-bench run     --run R [--mode M] [--out DIR] [--arm A]... [--only ID]... [--rerun] [--no-throughput]
//! dc-bench bytes   [--mode M] [--out DIR]           Q2
//! dc-bench env     [--out DIR]                      results/env.json
//! dc-bench archive [--mode M] [--out DIR]           zstd archives of raw/ and their SHA-256 manifest
//! dc-bench report  [--mode M] [--out DIR] [--criterion DIR]
//! dc-bench plan    [--mode M]                       the grid, as the frozen plan states it
//! dc-bench benchmarks [--out DIR]                    BENCHMARKS.md from the verified results
//! dc-bench paper   [--out DIR]                      paper tables and figures (`paper/`)
//! dc-bench phases  [--mode M] [--out DIR] [--resume] the exploratory phase breakdown (D-77)
//! ```
//!
//! `phases` needs a build with `--features phase-timing`, and such a build
//! refuses `all` and `run`: phase timing never enters a headline run (SPEC
//! §10.3). It writes to `results/exploratory/phases/`.
//!
//! `all --resume` continues an interrupted `all`: it skips every run process
//! and re-run that completed, redoes an aborted one (setting its files aside
//! first), and records the machine at the restart in `env-resume.json`,
//! keeping the first `env.json`. Without `--resume`, `all` refuses to start
//! over measured data.
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
use dc_bench::{env, phases, qos, report, thermal};
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
    resume: bool,
    throughput: bool,
    criterion: Option<PathBuf>,
}

fn parse() -> Result<Args, String> {
    let mut it = std::env::args().skip(1);
    let cmd = it.next().ok_or(
        "usage: dc-bench <all|run|bytes|env|archive|report|plan|benchmarks|paper|phases> [options]",
    )?;
    let mut a = Args {
        cmd,
        mode: Mode::Full,
        out: None,
        run: 1,
        arms: vec![],
        only: vec![],
        rerun: false,
        resume: false,
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
            "--resume" => a.resume = true,
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
        "benchmarks" => {
            let out = out_dir(&a);
            let root = root();
            dc_bench::benchmarks::render(
                &out,
                &a.criterion.clone().unwrap_or_else(|| out.join("criterion")),
                &root.join("crates/dc-bench/BENCHMARKS.template.md"),
                &root.join("BENCHMARKS.md"),
                threads(),
            )
        }
        "paper" => {
            let out = out_dir(&a);
            let root = root();
            dc_bench::paper::render(
                &out,
                &a.criterion.clone().unwrap_or_else(|| out.join("criterion")),
                &root,
                &root.join("paper"),
                threads(),
            )
        }
        "all" => cmd_all(&a),
        "phases" => cmd_phases(&a),
        "phases-run" => cmd_phases_run(&a),
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
    write_env(a, "env.json")
}

/// `env.json` at a fresh start; `env-resume.json` at a resume, keeping the
/// first.
fn env_name(a: &Args) -> &'static str {
    if a.resume {
        "env-resume.json"
    } else {
        "env.json"
    }
}

fn write_env(a: &Args, name: &str) -> Result<Value, String> {
    let out = out_dir(a);
    fs::create_dir_all(&out).map_err(|e| e.to_string())?;
    let v = env::capture(&root());
    fs::write(
        out.join(name),
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
    /// The whole run's configurations: main and A-mt processes, Q6 included
    /// (D-76, revised).
    total: usize,
    /// Configurations already flagged in this run's other process (the main
    /// process, when this is the A-mt process).
    prior: usize,
    valve: bool,
    /// (configuration, signal) of each flagged configuration.
    flagged: Vec<(String, &'static str)>,
}

impl Monitor {
    fn new(
        mut w: csv::Writer<fs::File>,
        run: usize,
        total: usize,
        prior: usize,
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
            "warmup_ns",
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
            prior,
            valve,
            flagged: vec![],
        };
        let pm = thermal::read();
        for (k, sample) in samples.iter().enumerate() {
            m.row(
                "baseline",
                &format!("baseline-{}", k + 1),
                &pm,
                *sample,
                false,
            )?;
        }
        eprintln!("run {run}: probe baseline {:.1} ms", baseline as f64 / 1e6);
        Ok(m)
    }

    fn row(
        &mut self,
        id: &str,
        phase: &str,
        pm: &thermal::Reading,
        sample: probe::Sample,
        judged: bool,
    ) -> Result<(), String> {
        let probe_ns = sample.ns;
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
                &sample.warmup_ns.to_string(),
            ])
            .map_err(|e| e.to_string())?;
        self.w.flush().map_err(|e| e.to_string())
    }

    /// Readings before a configuration: pmset, then the probe.
    fn before(&mut self, id: &str) -> Result<(thermal::Reading, u64), String> {
        let pm = thermal::read();
        let sample = self.probe.run();
        self.row(id, "before", &pm, sample, true)?;
        Ok((pm, sample.ns))
    }

    /// Readings after it: the probe, then pmset. Returns the abort reason if
    /// the safety valve trips.
    fn after(
        &mut self,
        id: &str,
        before: (thermal::Reading, u64),
    ) -> Result<Option<String>, String> {
        let sample = self.probe.run();
        let ns = sample.ns;
        let pm = thermal::read();
        self.row(id, "after", &pm, sample, true)?;
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
        if self.valve && valve_trips(self.prior, self.flagged.len(), self.total) {
            return Ok(Some(format!(
                "aborting run {}: {} of the run's {} configurations are flagged ({} in this process, {} in its main process), more than 10%; the machine is not in a usable state (frozen plan §5; D-76)",
                self.run,
                self.prior + self.flagged.len(),
                self.total,
                self.flagged.len(),
                self.prior
            )));
        }
        Ok(None)
    }
}

/// The safety valve, per run (D-76, revised): more than 10% of the run's
/// configurations flagged, counting both of its processes.
fn valve_trips(prior: usize, flagged: usize, total: usize) -> bool {
    (prior + flagged) * 10 > total
}

/// Every configuration of run `r` in `mode`: the latency grid of both builds
/// and the Q6 rows.
fn run_total(mode: Mode) -> usize {
    grid(mode).len() + THROUGHPUT_ARMS.len() * THREADS.len()
}

/// The files a run process writes, for stem `stem`.
fn stem_files(stem: &str) -> [String; 5] {
    [
        format!("{stem}.csv"),
        format!("{stem}-calls.csv"),
        format!("{stem}-thermal.csv"),
        format!("{stem}-throughput.csv"),
        format!("{stem}-meta.json"),
    ]
}

/// A process's state from its meta file: `None` if it never ran, else
/// whether it completed (did not abort), and its flagged count.
fn process_state(raw: &Path, stem: &str) -> Option<(bool, usize)> {
    let m: Value =
        serde_json::from_str(&fs::read_to_string(raw.join(format!("{stem}-meta.json"))).ok()?)
            .ok()?;
    let flagged = m["flagged"].as_array().map_or(0, Vec::len);
    Some((m["aborted"].is_null(), flagged))
}

/// Moves an aborted process's files out of `raw/` into
/// `results/aborted/<stem>-attempt-<k>/`, so that its redo cannot mix with
/// them. They are kept, never read by the report.
fn set_aside(out: &Path, stem: &str) -> Result<PathBuf, String> {
    let mut k = 1;
    let dest = loop {
        let d = out.join("aborted").join(format!("{stem}-attempt-{k}"));
        if !d.exists() {
            break d;
        }
        k += 1;
    };
    fs::create_dir_all(&dest).map_err(|e| e.to_string())?;
    for f in stem_files(stem) {
        let src = out.join("raw").join(&f);
        if src.exists() {
            fs::rename(&src, dest.join(&f)).map_err(|e| e.to_string())?;
        }
    }
    Ok(dest)
}

/// A headline run must not be timed phase by phase (SPEC §10.3; D-77).
fn headline_build() -> Result<(), String> {
    if dc_crypto::phases::ENABLED {
        return Err(
            "this build times phases (`phase-timing`); headline runs must not use it (SPEC §10.3)"
                .into(),
        );
    }
    Ok(())
}

fn cmd_run(a: &Args) -> Result<(), String> {
    headline_build()?;
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
    // Measured data are never overwritten. A completed process is final; an
    // aborted or partial one is set aside before its redo.
    match process_state(&raw, &stem) {
        Some((true, _)) => {
            return Err(format!(
                "{stem} already completed in {}; refusing to overwrite measured data (`all --resume` skips it)",
                raw.display()
            ));
        }
        _ if stem_files(&stem).iter().any(|f| raw.join(f).exists()) => {
            let d = set_aside(&out, &stem)?;
            eprintln!(
                "{stem}: the earlier, unfinished attempt's files were moved to {}",
                d.display()
            );
        }
        _ => {}
    }
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
        if a.rerun {
            configs.len() + tp_order.len()
        } else {
            run_total(a.mode)
        },
        // The A-mt process continues its run's count from the main process.
        if dc_crypto::BLST_THREADED && !a.rerun {
            process_state(&raw, &format!("run{}", a.run)).map_or(0, |s| s.1)
        } else {
            0
        },
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
        "probe_warmup_ns": probe::WARMUP.as_nanos() as u64,
        "configurations_in_run": monitor.total,
        "flagged_earlier_in_run": monitor.prior,
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
    headline_build()?;
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
    // A fresh start never runs over measured data (D-76).
    let raw = out.join("raw");
    let completed: Vec<String> = fs::read_dir(&raw)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            e.file_name()
                .to_str()?
                .strip_suffix("-meta.json")
                .map(str::to_owned)
        })
        .filter(|stem| matches!(process_state(&raw, stem), Some((true, _))))
        .collect();
    if !a.resume && !completed.is_empty() {
        return Err(format!(
            "{} already holds completed run processes ({}); use `all --resume`, or move them away to start over",
            raw.display(),
            completed.join(", ")
        ));
    }
    // AC power and High Power mode are checked before anything is built.
    if a.mode == Mode::Full {
        let r = env::requirements();
        if r["ac_power"] != json!(true) || r["high_power_mode"] != json!(true) {
            write_env(a, env_name(a))?;
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
    // env.json (or env-resume.json) records the machine once it is idle,
    // before the first run of this invocation.
    require(a.mode)?;
    let env = write_env(a, env_name(a))?;
    if a.mode == Mode::Full && env["m9_requirements"]["ok"] != json!(true) {
        return Err(format!(
            "aborting: {} does not confirm AC power, High Power mode and an idle machine",
            env_name(a)
        ));
    }
    let amt = root.join("target/a-mt/release/dc-bench");
    let runs = if a.mode == Mode::Dry { 1 } else { RUNS };
    for r in 1..=runs {
        let rs = r.to_string();
        for (bin, stem, what) in [
            (&me, format!("run{r}"), format!("run {r}")),
            (&amt, format!("run{r}-amt"), format!("run {r}, A-mt")),
        ] {
            if matches!(process_state(&raw, &stem), Some((true, _))) {
                eprintln!("== {what}: completed earlier, skipped");
                continue;
            }
            run_child(
                Command::new(bin).args(["run", "--run", &rs, "--mode", mode, "--out", &outs]),
                &what,
            )?;
        }
    }
    // Throttling re-runs (frozen plan §5), whatever their result.
    let mut reruns = throttled(&raw);
    reruns.retain(|(run, is_amt), _| {
        let stem = format!("run{run}{}-rerun", if *is_amt { "-amt" } else { "" });
        let done = matches!(process_state(&raw, &stem), Some((true, _)));
        if done {
            eprintln!("== re-runs of {stem}: completed earlier, skipped");
        }
        !done
    });
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

/// Where the phase breakdown writes: `results/exploratory/phases/`, or
/// under `results/dry-run/` for a dry run.
fn phases_dir(a: &Args) -> PathBuf {
    a.out.clone().unwrap_or_else(|| match a.mode {
        Mode::Full => root().join("results/exploratory/phases"),
        Mode::Dry => root().join("results/dry-run/exploratory/phases"),
    })
}

/// The exploratory phase breakdown (D-77; not pre-registered): one
/// `phases-run` process per run, on the machine state M9 required, then the
/// archives and their manifest. It is never part of `all`.
fn cmd_phases(a: &Args) -> Result<(), String> {
    if !dc_crypto::phases::ENABLED {
        return Err("`phases` needs a build with `--features phase-timing` (D-77)".into());
    }
    if !env!("DC_BENCH_RUSTFLAGS").contains("target-cpu=native") {
        let msg = "not built with RUSTFLAGS=\"-C target-cpu=native\" (SPEC §3.3)";
        if a.mode == Mode::Full {
            return Err(format!("aborting: {msg}"));
        }
        eprintln!("dc-bench: warning: {msg}");
    }
    let out = phases_dir(a);
    let raw = out.join("raw");
    let runs = if a.mode == Mode::Dry { 1 } else { phases::RUNS };
    let completed: Vec<usize> = (1..=runs)
        .filter(|r| matches!(process_state(&raw, &format!("run{r}")), Some((true, _))))
        .collect();
    if !a.resume && !completed.is_empty() {
        return Err(format!(
            "{} already holds completed phase runs {completed:?}; use `phases --resume`, or move them away to start over",
            raw.display()
        ));
    }
    if a.mode == Mode::Full {
        let r = env::requirements();
        if r["ac_power"] != json!(true) || r["high_power_mode"] != json!(true) {
            return Err(format!(
                "aborting: the phase breakdown needs M9's machine state, AC power and High Power mode: {r}"
            ));
        }
    }
    require(a.mode)?;
    fs::create_dir_all(&out).map_err(|e| e.to_string())?;
    let env = env::capture(&root());
    fs::write(
        out.join(env_name(a)),
        serde_json::to_string_pretty(&env).unwrap() + "\n",
    )
    .map_err(|e| e.to_string())?;
    if a.mode == Mode::Full && env["m9_requirements"]["ok"] != json!(true) {
        return Err(format!(
            "aborting: {} does not confirm AC power, High Power mode and an idle machine",
            env_name(a)
        ));
    }
    let me = std::env::current_exe().map_err(|e| e.to_string())?;
    let outs = out.to_string_lossy().to_string();
    for r in 1..=runs {
        if completed.contains(&r) {
            eprintln!("== phase run {r}: completed earlier, skipped");
            continue;
        }
        run_child(
            Command::new(&me).args([
                "phases-run",
                "--run",
                &r.to_string(),
                "--mode",
                a.mode.label(),
                "--out",
                &outs,
            ]),
            &format!("phase run {r}"),
        )?;
    }
    archive(&out)?;
    let log = if a.mode == Mode::Full {
        root().join("BENCH_LOG.md")
    } else {
        out.join("BENCH_LOG.dry.md")
    };
    log_phases(&log, &out)
}

/// Appends the BENCH_LOG.md entry of a completed phase breakdown, from its
/// verified archives (D-77).
fn log_phases(log: &Path, out: &Path) -> Result<(), String> {
    let d = phases::load(out)?;
    let date = Command::new("date")
        .args(["-u", "+%Y-%m-%d"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .unwrap_or_default();
    let configs: BTreeSet<String> = d
        .metas
        .values()
        .flat_map(|m| m["order"].as_array().cloned().unwrap_or_default())
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect();
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log)
        .map_err(|e| e.to_string())?;
    writeln!(
        f,
        "\n## {date} — Exploratory run (not pre-registered): the phase breakdown\nReason: the author asked, after M10, what share of a warm verification goes to decoding, policy (Contains and Evaluate), identity and cryptography.\n- **What ran.** {}, each in its own process, of the frozen grid's configurations {}, with M9's chain sets and counts.\n- **The build.** `dc-bench` with `--features phase-timing` (D-77). Such a build refuses `all` and `run`, so it never makes a headline run (SPEC §10.3).\n- **Machine state.** M9's: AC power, High Power mode and an idle machine, checked before the first run and recorded in `results/exploratory/phases/env.json`.\n- **Thermal readings.** pmset and the calibration probe were recorded around each configuration, as in M9, but not acted on: {}.\n- **Where the results go.** `BENCHMARKS.md` §8 (exploratory) only, never the summary or a verdict. The raw data are in {} archives under `results/exploratory/phases/archive/`, pinned by the committed `MANIFEST.sha256`.\n\nConfigurations re-run: none. This run measured configurations M9 had already measured, with a different build, and replaces none of M9's samples.",
        match d.metas.len() {
            1 => "1 run".to_owned(),
            k => format!("{k} runs"),
        },
        configs
            .iter()
            .map(|c| format!("`{c}`"))
            .collect::<Vec<_>>()
            .join(", "),
        d.flags(),
        d.archives
    )
    .map_err(|e| e.to_string())
}

/// One run process of the phase breakdown: the configurations of
/// [`phases::configs`] in this run's order, measured as M9 measured them,
/// with the thermal and probe readings around each (recorded, not acted on).
fn cmd_phases_run(a: &Args) -> Result<(), String> {
    if !dc_crypto::phases::ENABLED {
        return Err("`phases-run` needs a build with `--features phase-timing` (D-77)".into());
    }
    let requirements = require(a.mode)?;
    let out = phases_dir(a);
    let raw = out.join("raw");
    fs::create_dir_all(&raw).map_err(|e| e.to_string())?;
    let started = Instant::now();
    let qos_main = qos::set_user_interactive();
    let worlds = Worlds::new();
    let configs = shuffled(phases::configs(a.mode), a.run);
    let stem = format!("run{}", a.run);
    match process_state(&raw, &stem) {
        Some((true, _)) => {
            return Err(format!(
                "{stem} already completed in {}; refusing to overwrite measured data",
                raw.display()
            ));
        }
        _ if stem_files(&stem).iter().any(|f| raw.join(f).exists()) => {
            let d = set_aside(&out, &stem)?;
            eprintln!(
                "{stem}: the earlier, unfinished attempt's files were moved to {}",
                d.display()
            );
        }
        _ => {}
    }
    let keys: Vec<SetKey> = configs.iter().map(SetKey::of).collect();
    let set_dir = root()
        .join("target/dc-bench-sets")
        .join(format!("{}-phases-{stem}", a.mode.label()));
    eprintln!("phases {stem}: generating {} chain sets…", keys.len());
    let gen_started = Instant::now();
    let store = SetStore::build(&worlds, &keys, &set_dir, threads()).map_err(|e| e.to_string())?;
    let generation_s = gen_started.elapsed().as_secs_f64();
    std::thread::sleep(Duration::from_secs(if a.mode == Mode::Full {
        30
    } else {
        1
    }));
    let mut monitor = Monitor::new(
        csv::Writer::from_path(raw.join(format!("{stem}-thermal.csv")))
            .map_err(|e| e.to_string())?,
        a.run,
        configs.len(),
        0,
        false,
    )?;
    let mut w =
        csv::Writer::from_path(raw.join(format!("{stem}.csv"))).map_err(|e| e.to_string())?;
    w.write_record(phases::header())
        .map_err(|e| e.to_string())?;
    let mut timings = vec![];
    for (i, c) in configs.iter().enumerate() {
        let t = Instant::now();
        let chains = store.load(&SetKey::of(c)).map_err(|e| e.to_string())?;
        let before = monitor.before(&c.id())?;
        let m = phases::measure(&worlds, c, &chains)?;
        monitor.after(&c.id(), before)?;
        drop(chains);
        let fixed = [
            a.run.to_string(),
            c.arm.label().to_owned(),
            c.state.label(),
            c.n.to_string(),
            c.profile.label().to_owned(),
        ];
        for (iter, s) in m.iter().enumerate() {
            let mut rec: Vec<String> = fixed.to_vec();
            rec.push(iter.to_string());
            rec.push(s.ns.to_string());
            rec.extend(s.phases.iter().map(u64::to_string));
            w.write_record(&rec).map_err(|e| e.to_string())?;
        }
        w.flush().map_err(|e| e.to_string())?;
        let secs = t.elapsed().as_secs_f64();
        timings.push(json!({"config": c.id(), "seconds": secs}));
        eprintln!("[{}/{}] {} ({secs:.1} s)", i + 1, configs.len(), c.id());
    }
    store.remove().map_err(|e| e.to_string())?;
    let meta = json!({
        "run": a.run,
        "mode": a.mode.label(),
        "build": "phase-timing",
        "exploratory": "not pre-registered (D-77)",
        "blst_threaded": dc_crypto::BLST_THREADED,
        "requirements_at_start": requirements,
        "qos_user_interactive_main_thread": qos_main,
        "order_seed": order_seed(a.run),
        "order": configs.iter().map(Config::id).collect::<Vec<_>>(),
        "generation_seconds": generation_s,
        "config_seconds": timings,
        "probe_baseline_ns": monitor.baseline,
        "probe_warmup_ns": probe::WARMUP.as_nanos() as u64,
        "flagged": monitor.flagged.iter().map(|(id, sig)| json!({"config": id, "signal": sig})).collect::<Vec<_>>(),
        "aborted": Value::Null,
        "total_seconds": started.elapsed().as_secs_f64(),
        "rustflags_at_build": env!("DC_BENCH_RUSTFLAGS"),
    });
    fs::write(
        raw.join(format!("{stem}-meta.json")),
        serde_json::to_string_pretty(&meta).unwrap() + "\n",
    )
    .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_valve_counts_the_whole_run() {
        // Run 2 of M9: 6 flagged in the main process, 2 in A-mt, of 255.
        assert!(!valve_trips(6, 2, 255));
        // 26 of 255 is more than 10%; 25 is not.
        assert!(valve_trips(20, 6, 255));
        assert!(!valve_trips(20, 5, 255));
        assert_eq!(run_total(Mode::Full), 255);
    }
}
