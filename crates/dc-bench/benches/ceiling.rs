//! Exploratory (D-101): each charged operation class of `Contains` at the
//! size bounds (`ceiling/class/…`), its fixed per-call cost (`overhead`),
//! every search input at the default budget (`contains`), and lines 2 and
//! 5 on bodies filled to the proposed limits (`line2`, `line5`) and to the
//! proposed rule limit in today's 64 KiB body (`line2-64k`, `line5-64k`),
//! all from `dc_bench::ceiling`. Each call's result is checked outside the timer.

use std::time::{Duration, Instant};

use criterion::{Criterion, SamplingMode, black_box, criterion_group, criterion_main};
use dc_bench::budget::{delegation_body_within, line2_within, line5};
use dc_bench::ceiling::{
    admitted, bodies, bodies_today, contains_inputs, overhead_inputs, probes, proposed,
};
use dc_bench::workload::Setting;
use dc_crypto::Ed25519;
use dc_policy::{DEFAULT_BUDGET, contains_within};

/// Times `f` per call, checking each result against `ok`.
fn timed<T>(f: impl Fn() -> T, ok: impl Fn(&T) -> bool) -> impl FnMut(u64) -> Duration {
    move |iters| {
        let mut total = Duration::ZERO;
        for _ in 0..iters {
            let t = Instant::now();
            let r = black_box(f());
            total += t.elapsed();
            assert!(ok(&r), "unexpected result");
        }
        total
    }
}

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("ceiling");
    g.sampling_mode(SamplingMode::Flat)
        .sample_size(10)
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(2));
    for p in probes() {
        let expect = p.run();
        g.bench_function(format!("class/{}", p.label), |b| {
            b.iter_custom(timed(|| p.run(), |r| *r == expect))
        });
    }
    for (label, parent, child) in overhead_inputs() {
        g.bench_function(format!("overhead/{label}"), |b| {
            b.iter_custom(timed(
                || contains_within(&parent, &child, 0),
                |w| w.exhausted,
            ))
        });
    }
    for (label, parent, child) in contains_inputs() {
        let expect = contains_within(&parent, &child, DEFAULT_BUDGET);
        g.bench_function(format!("contains/{label}"), |b| {
            b.iter_custom(timed(
                || contains_within(&parent, &child, DEFAULT_BUDGET),
                |w| *w == expect,
            ))
        });
    }
    let setting = Setting::<Ed25519>::new();
    let limits = proposed(&admitted());
    for (kind, set, max) in [
        ("", bodies(limits), limits.body),
        ("-64k", bodies_today(limits), dc_cbor::MAX_BODY_SIZE),
    ] {
        let decoding = dc_cbor::Limits {
            max_size: max,
            ..dc_cbor::Limits::BODY
        };
        for (label, scope) in set {
            let bytes = delegation_body_within(&setting, &scope, max);
            g.bench_function(format!("line2{kind}/{label}"), |b| {
                b.iter_custom(timed(
                    || line2_within(&bytes, max),
                    |s| s.as_ref() == Some(&scope),
                ))
            });
            let decoded =
                dc_types::decode_body_within::<Ed25519>(&bytes, decoding).expect("decodes");
            g.bench_function(format!("line5{kind}/{label}"), |b| {
                b.iter_custom(timed(|| line5(&decoded, &bytes), |ok| *ok))
            });
        }
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
