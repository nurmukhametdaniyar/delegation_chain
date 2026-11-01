//! Exploratory, not in the frozen plan (D-95): `Contains` at D-21's size
//! bounds. The frozen Q8 matrix (`policy.rs`; D-73) stops at 64 rules × 8
//! atoms, and its worst case never reaches step 3(b)'s shadow scan. D-21
//! allows 256 rules × 32 atoms, and D-03 caps every body, and so every
//! scope, at 64 KiB.
//!
//! For rules ∈ {64, 128, 256} × atoms ∈ {8, 16, 32}: `frozen-worst`, the
//! frozen generator's worst case, and `alternating`, Contains(Y, X) for the
//! scopes of [`dc_bench::bounds::alternating`] with the shortest head. A
//! cell runs only where its scopes fit in a body with `BODY_SPARE` bytes to
//! spare; the others are reported as skipped.
//!
//! Every timed call's result is checked, so that a construction that stops
//! passing fails the run instead of timing an early `false`; the check is
//! outside the timer. Contains(X, Y), the other direction of a link, is
//! checked end to end in `tests/scope_bounds.rs`.

use std::time::{Duration, Instant};

use criterion::{BenchmarkId, Criterion, SamplingMode, black_box, criterion_group, criterion_main};
use dc_bench::bounds::{CELLS, SHORT_HEAD, alternating, fits, frozen_worst};
use dc_policy::contains;

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
    let mut g = c.benchmark_group("bounds/contains");
    // One call takes up to tens of seconds at the bounds: one call per
    // sample, ten samples.
    g.sampling_mode(SamplingMode::Flat)
        .sample_size(10)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(10));
    for (rules, atoms) in CELLS {
        let id = format!("r{rules}_a{atoms}");
        let (parent, child) = (
            frozen_worst(rules, atoms, 1000),
            frozen_worst(rules, atoms, 999),
        );
        if fits(&parent) && fits(&child) {
            g.bench_with_input(BenchmarkId::new("frozen-worst", &id), &(), |b, _| {
                b.iter_custom(|iters| timed(iters, || contains(&parent, &child)))
            });
        } else {
            eprintln!("bounds/contains/frozen-worst/{id}: skipped, larger than a body");
        }
        let x = alternating(SHORT_HEAD, "x", rules, atoms, true);
        let y = alternating(SHORT_HEAD, "x", rules, atoms, false);
        if fits(&x) && fits(&y) {
            g.bench_with_input(BenchmarkId::new("alternating", &id), &(), |b, _| {
                b.iter_custom(|iters| timed(iters, || contains(&y, &x)))
            });
        } else {
            eprintln!("bounds/contains/alternating/{id}: skipped, larger than a body");
        }
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
