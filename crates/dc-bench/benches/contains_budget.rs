//! Exploratory and PROTOTYPE (D-99): how long `Contains` runs under a work
//! budget before it gives up, on the costliest inputs of D-98. Needs
//! `--features work-budget`, whose counting build is never a headline one.
//!
//! The budgets: the largest count of any `Contains` call the workload
//! profiles make (computed here, `BUDGETS[0]`), and two with headroom. Each
//! input's full count is far above every budget, so every timed call must
//! give up.

use std::time::{Duration, Instant};

use criterion::{BenchmarkId, Criterion, SamplingMode, black_box, criterion_group, criterion_main};
use dc_bench::bounds::{Pad, RUNNERS_UP, WORST_FOUND, max_rules, padded};
use dc_bench::workload::{Profile, hop_scopes};
use dc_policy::contains_within;

/// Budgets with headroom over the profiles' largest count (D-99).
pub const HEADROOM: [u64; 2] = [16_384, 1 << 20];

fn bench(c: &mut Criterion) {
    let profiles_max = Profile::ALL
        .iter()
        .flat_map(|&p| {
            let s = hop_scopes(p);
            let calls: Vec<u64> = std::iter::once(contains_within(&s[0], &s[0], u64::MAX).work)
                .chain((1..s.len()).map(|k| contains_within(&s[k - 1], &s[k], u64::MAX).work))
                .collect();
            calls
        })
        .max()
        .expect("profiles");
    let mut inputs = vec![(Pad::Bounds, 32), (WORST_FOUND, 32)];
    inputs.extend(RUNNERS_UP);
    let mut g = c.benchmark_group("contains-budget");
    g.sampling_mode(SamplingMode::Flat)
        .sample_size(10)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(10));
    for budget in std::iter::once(profiles_max).chain(HEADROOM) {
        for (pad, atoms) in &inputs {
            let rules = max_rules(*pad, *atoms).expect("fits");
            let (x, y) = (
                padded(*pad, rules, *atoms, true),
                padded(*pad, rules, *atoms, false),
            );
            g.bench_with_input(
                BenchmarkId::new(
                    format!("b{budget}"),
                    format!("{}_r{rules}_a{atoms}", pad.label()),
                ),
                &(),
                |b, _| {
                    b.iter_custom(|iters| {
                        let mut total = Duration::ZERO;
                        for _ in 0..iters {
                            let t = Instant::now();
                            let w = black_box(contains_within(&y, &x, budget));
                            total += t.elapsed();
                            assert!(w.exhausted && !w.answer, "the budget must run out");
                        }
                        total
                    })
                },
            );
        }
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
