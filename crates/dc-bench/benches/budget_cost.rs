//! Exploratory (D-100): `Contains` under the default work budget on every
//! input of `dc_bench::budget::contains_inputs`, and lines 2 and 5 on every
//! body of `dc_bench::budget::body_scopes`. Each call is checked outside the
//! timer: `Contains`'s answer against the count, line 2's scope against the
//! one encoded.

use std::time::{Duration, Instant};

use criterion::{Criterion, SamplingMode, black_box, criterion_group, criterion_main};
use dc_bench::budget::{body_scopes, contains_inputs, delegation_body, line2, line5};
use dc_bench::workload::Setting;
use dc_crypto::Ed25519;
use dc_policy::{DEFAULT_BUDGET, contains_within};

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("budget-cost");
    g.sampling_mode(SamplingMode::Flat)
        .sample_size(10)
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(2));
    for (label, parent, child) in contains_inputs() {
        let expect = contains_within(&parent, &child, DEFAULT_BUDGET);
        g.bench_function(format!("contains/{label}"), |b| {
            b.iter_custom(|iters| {
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    let t = Instant::now();
                    let w = black_box(contains_within(&parent, &child, DEFAULT_BUDGET));
                    total += t.elapsed();
                    assert_eq!(w, expect, "deterministic");
                }
                total
            })
        });
    }
    let setting = Setting::<Ed25519>::new();
    for (label, scope) in body_scopes() {
        let bytes = delegation_body(&setting, &scope);
        g.bench_function(format!("line2/{label}"), |b| {
            b.iter_custom(|iters| {
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    let t = Instant::now();
                    let s = black_box(line2(black_box(&bytes)));
                    total += t.elapsed();
                    assert!(s.as_ref() == Some(&scope), "line 2 decodes the scope");
                }
                total
            })
        });
        let decoded = dc_types::decode_body::<Ed25519>(&bytes).expect("decodes");
        g.bench_function(format!("line5/{label}"), |b| {
            b.iter_custom(|iters| {
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    let t = Instant::now();
                    let ok = black_box(line5(&decoded, black_box(&bytes)));
                    total += t.elapsed();
                    assert!(ok, "canonical");
                }
                total
            })
        });
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
