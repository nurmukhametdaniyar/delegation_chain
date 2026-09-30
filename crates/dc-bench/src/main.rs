//! `dc-bench`: the benchmark harness (SPEC §13).
//!
//! ```text
//! dc-bench all    [--mode full|dry] [--out DIR]    everything, as SPEC §13.8 asks
//! dc-bench run    --run R [--mode M] [--out DIR] [--arm A]... [--no-throughput]
//! dc-bench bytes  [--mode M] [--out DIR]           Q2
//! dc-bench env    [--out DIR]                      results/env.json
//! dc-bench report [--out DIR] [--criterion DIR] [--dry]
//! dc-bench plan   [--mode M]                       the grid, for BENCH_PLAN_FROZEN.md
//! ```
//!
//! `--mode dry` is M8's dry run: 10 iterations per configuration, written to
//! `results/dry-run/`. Its numbers are never reported.

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, ExitCode};
use std::time::Instant;

use dc_bench::arms::{Arm, Family, State, Worlds};
use dc_bench::harness::{BytesRow, SetKey, SetStore, bytes_row, generate, measure, throughput};
use dc_bench::plan::{
    Config, Mode, NS, PROFILES, RUNS, THREADS, THROUGHPUT_ARMS, grid, order_seed, shuffled,
    throughput_counts,
};
use dc_bench::workload::{Layout, Profile, hop_agent, p};
use dc_bench::{env, qos, report};
use dc_registry::Resolver;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use serde_json::json;

struct Args {
    cmd: String,
    mode: Mode,
    out: Option<PathBuf>,
    run: usize,
    arms: Vec<Arm>,
    throughput: bool,
    criterion: Option<PathBuf>,
    dry_flag: bool,
}

fn parse() -> Result<Args, String> {
    let mut it = std::env::args().skip(1);
    let cmd = it
        .next()
        .ok_or("usage: dc-bench <all|run|bytes|env|report|plan> [options]")?;
    let mut a = Args {
        cmd,
        mode: Mode::Full,
        out: None,
        run: 1,
        arms: vec![],
        throughput: true,
        criterion: None,
        dry_flag: false,
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
            "--no-throughput" => a.throughput = false,
            "--criterion" => a.criterion = Some(PathBuf::from(val()?)),
            "--dry" => a.dry_flag = true,
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
        "env" => cmd_env(&a),
        "run" => cmd_run(&a),
        "bytes" => cmd_bytes(&a),
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

fn cmd_env(a: &Args) -> Result<(), String> {
    let out = out_dir(a);
    fs::create_dir_all(&out).map_err(|e| e.to_string())?;
    let v = env::capture(&root());
    fs::write(
        out.join("env.json"),
        serde_json::to_string_pretty(&v).unwrap() + "\n",
    )
    .map_err(|e| e.to_string())
}

fn cmd_run(a: &Args) -> Result<(), String> {
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
            .collect(),
        a.run,
    );
    let do_throughput = a.throughput && !dc_crypto::BLST_THREADED;
    let (pre, per, warm_n) = throughput_counts(a.mode);
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
    if do_throughput {
        for f in [Family::BlsAggregate, Family::Ed25519List] {
            keys.push(tp_key(f));
            keys.push(tp_warm(f));
        }
    }
    let set_dir = root().join("target/dc-bench-sets").join(format!(
        "{}-run{}-{build}",
        a.mode.label(),
        a.run
    ));
    eprintln!("run {}: generating {} chain sets…", a.run, keys.len());
    let gen_started = Instant::now();
    let store = SetStore::build(&worlds, &keys, &set_dir, threads()).map_err(|e| e.to_string())?;
    let generation_s = gen_started.elapsed().as_secs_f64();
    // Let the machine settle after generating on every core (D-72).
    std::thread::sleep(std::time::Duration::from_secs(if a.mode == Mode::Full {
        30
    } else {
        1
    }));

    let suffix = if dc_crypto::BLST_THREADED { "-amt" } else { "" };
    let mut lat = csv::Writer::from_path(raw.join(format!("run{}{suffix}.csv", a.run)))
        .map_err(|e| e.to_string())?;
    lat.write_record(["run", "arm", "state", "N", "profile", "iter", "ns"])
        .map_err(|e| e.to_string())?;
    let mut calls = csv::Writer::from_path(raw.join(format!("run{}{suffix}-calls.csv", a.run)))
        .map_err(|e| e.to_string())?;
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
        let m = measure(&worlds, c, &chains)?;
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
    }
    calls.flush().map_err(|e| e.to_string())?;

    let mut tp_rows = vec![];
    if do_throughput {
        let mut w = csv::Writer::from_path(raw.join(format!("run{}-throughput.csv", a.run)))
            .map_err(|e| e.to_string())?;
        w.write_record([
            "run", "arm", "threads", "chains", "accepted", "wall_ns", "p50_ns", "p99_ns", "qos_ok",
        ])
        .map_err(|e| e.to_string())?;
        let mut order: Vec<(Arm, usize)> = THROUGHPUT_ARMS
            .iter()
            .flat_map(|&arm| THREADS.iter().map(move |&t| (arm, t)))
            .collect();
        let mut rng = ChaCha20Rng::seed_from_u64(order_seed(a.run) ^ 0x7_4600);
        for i in (1..order.len()).rev() {
            let j = (rng.next_u64() % (i as u64 + 1)) as usize;
            order.swap(i, j);
        }
        // Per family: the warm-up chains and the measured chains.
        type Sets = Vec<(Family, Vec<Vec<u8>>, Vec<Vec<u8>>)>;
        let sets: Sets = [Family::BlsAggregate, Family::Ed25519List]
            .into_iter()
            .map(|f| Ok((f, store.load(&tp_warm(f))?, store.load(&tp_key(f))?)))
            .collect::<std::io::Result<_>>()
            .map_err(|e| e.to_string())?;
        for (arm, t) in order {
            let (_, warm, chains) = sets.iter().find(|s| s.0 == arm.family()).expect("family");
            let r = throughput(&worlds, arm, t, warm, chains)?;
            eprintln!(
                "Q6 {} × {t}: {:.0} accepted/s",
                arm.label(),
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
        }
        w.flush().map_err(|e| e.to_string())?;
    }
    store.remove().map_err(|e| e.to_string())?;

    let meta = json!({
        "run": a.run,
        "mode": a.mode.label(),
        "build": build,
        "blst_threaded": dc_crypto::BLST_THREADED,
        "qos_user_interactive_main_thread": qos_main,
        "order_seed": order_seed(a.run),
        "order": configs.iter().map(Config::id).collect::<Vec<_>>(),
        "generation_seconds": generation_s,
        "config_seconds": timings,
        "throughput_qos_ok": tp_rows.iter().all(|r| r.qos_ok),
        "total_seconds": started.elapsed().as_secs_f64(),
        "rustflags_at_build": env!("DC_BENCH_RUSTFLAGS"),
    });
    fs::write(
        raw.join(format!("run{}{suffix}-meta.json", a.run)),
        serde_json::to_string_pretty(&meta).unwrap() + "\n",
    )
    .map_err(|e| e.to_string())
}

fn cmd_bytes(a: &Args) -> Result<(), String> {
    let out = out_dir(a);
    fs::create_dir_all(&out).map_err(|e| e.to_string())?;
    let w = Worlds::new();
    let sample = 20;
    let mut rows: Vec<BytesRow> = vec![];
    let mut cells: Vec<(usize, Profile)> = NS
        .iter()
        .flat_map(|&n| PROFILES.iter().map(move |&p| (n, p)))
        .collect();
    cells.push((3, Profile::MediumApproval));
    for (n, profile) in cells {
        for (label, family, envelope) in [
            ("A (also B, A-mt)", Family::BlsAggregate, true),
            ("A-ind", Family::BlsList, true),
            ("C (also C-batch, D)", Family::Ed25519List, true),
            ("E", Family::Biscuit, false),
        ] {
            if family == Family::Biscuit && profile == Profile::MediumApproval {
                continue;
            }
            let key = SetKey {
                family,
                profile,
                n,
                layout: Layout::Fresh,
                count: sample,
            };
            let set = generate(&w, &key);
            rows.push(bytes_row(label, n, profile, &set, envelope));
        }
    }
    // Certificate sizes, from the registries (§13.7).
    let agent = hop_agent(0, 0);
    let bls_cert = w
        .bls
        .directory()
        .resolve(&p(&agent), &w.bls.world.pk(&agent), 0)
        .ok_or("no BLS certificate")?;
    let ed_cert = w
        .ed25519
        .directory()
        .resolve(&p(&agent), &w.ed25519.world.pk(&agent), 0)
        .ok_or("no Ed25519 certificate")?;
    let inline: Vec<serde_json::Value> = rows
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

fn cmd_report(a: &Args) -> Result<(), String> {
    let out = out_dir(a);
    let criterion = a.criterion.clone().unwrap_or_else(|| out.join("criterion"));
    report::report(
        &out,
        &criterion,
        threads(),
        a.dry_flag || a.mode == Mode::Dry,
    )
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

/// Everything SPEC §13.8 lists, from one command.
fn cmd_all(a: &Args) -> Result<(), String> {
    let out = out_dir(a);
    let root = root();
    fs::create_dir_all(&out).map_err(|e| e.to_string())?;
    let me = std::env::current_exe().map_err(|e| e.to_string())?;
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let mode = a.mode.label();
    let outs = out.to_string_lossy().to_string();
    if !env!("DC_BENCH_RUSTFLAGS").contains("target-cpu=native") {
        eprintln!(
            "dc-bench: warning: not built with RUSTFLAGS=\"-C target-cpu=native\" (SPEC §3.3); env.json records it"
        );
    }
    cmd_env(a)?;
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
    writeln!(f, "all ({mode}) finished").map_err(|e| e.to_string())?;
    Ok(())
}
