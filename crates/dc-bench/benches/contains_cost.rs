//! Exploratory, not in the frozen plan (D-98): `Contains` after D-97's
//! memoization, up to D-21's size bounds.
//!
//! - For rules ∈ {16, 32, 64, 128, 256} × atoms ∈ {8, 16, 32}: the frozen
//!   generator's worst case, the alternating family, and the costliest
//!   padding D-98's search found (`intlist2`).
//! - The search's runners-up, at the most rules that fit.
//! - At each of `SWEEP_BOUNDS`, every padding of the search that fits, so
//!   that a candidate with lower bounds is judged by its own worst input.
//!
//! A cell runs only where its scopes fit a body with `BODY_SPARE` to spare.
//! Every timed call's result is checked outside the timer. The inputs are
//! constructions found by reading the procedure and by a small search; the
//! worst of them is a lower bound on the worst case.

use std::time::{Duration, Instant};

use criterion::{BenchmarkId, Criterion, SamplingMode, black_box, criterion_group, criterion_main};
use dc_bench::bounds::{
    COST_CELLS, Pad, RUNNERS_UP, SWEEP_BOUNDS, WORST_FOUND, fits, frozen_worst, max_rules, padded,
    search_pads,
};
use dc_policy::{Scope, contains};

/// `iters` calls of `f`, timed one by one; each must return true.
fn timed(iters: u64, f: impl Fn() -> bool) -> Duration {
    let mut total = Duration::ZERO;
    for _ in 0..iters {
        let t = Instant::now();
        let ok = black_box(f());
        total += t.elapsed();
        assert!(ok, "the construction no longer passes");
    }
    total
}

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("contains-cost");
    g.sampling_mode(SamplingMode::Flat)
        .sample_size(10)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(10));
    let mut pair = |name: String, id: String, s1: Scope, s2: Scope| {
        if fits(&s1) && fits(&s2) {
            g.bench_with_input(BenchmarkId::new(name, id), &(), |b, _| {
                b.iter_custom(|iters| timed(iters, || contains(&s1, &s2)))
            });
        }
    };
    for (rules, atoms) in COST_CELLS {
        let id = format!("r{rules}_a{atoms}");
        pair(
            "frozen-worst".into(),
            id.clone(),
            frozen_worst(rules, atoms, 1000),
            frozen_worst(rules, atoms, 999),
        );
        for (name, pad) in [("alternating", Pad::Bounds), ("intlist2", WORST_FOUND)] {
            let (x, y) = (
                padded(pad, rules, atoms, true),
                padded(pad, rules, atoms, false),
            );
            pair(name.into(), id.clone(), y, x);
        }
    }
    for (pad, atoms) in RUNNERS_UP {
        if let Some(rules) = max_rules(pad, atoms) {
            let (x, y) = (
                padded(pad, rules, atoms, true),
                padded(pad, rules, atoms, false),
            );
            pair(pad.label(), format!("r{rules}_a{atoms}"), y, x);
        }
    }
    for (rules, atoms) in SWEEP_BOUNDS {
        for pad in search_pads() {
            let (x, y) = (
                padded(pad, rules, atoms, true),
                padded(pad, rules, atoms, false),
            );
            pair(
                format!("sweep/{}", pad.label()),
                format!("r{rules}_a{atoms}"),
                y,
                x,
            );
        }
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
