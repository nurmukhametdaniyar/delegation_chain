//! D-100's inputs are what they claim to be: the new paddings keep the
//! alternating family's answers (both directions contained), and every
//! body built to fill 64 KiB passes lines 2 and 5 with its scope intact.

use dc_bench::bounds::{Pad, padded, search_pads};
use dc_bench::budget::{body_scopes, delegation_body, line2, line5, pads};
use dc_bench::workload::Setting;
use dc_crypto::Ed25519;
use dc_policy::contains;

#[test]
fn new_paddings_keep_the_alternating_answers() {
    let old = search_pads();
    let new: Vec<Pad> = pads().into_iter().filter(|p| !old.contains(p)).collect();
    assert!(!new.is_empty());
    for pad in new {
        for atoms in [4, 8] {
            let (x, y) = (padded(pad, 3, atoms, true), padded(pad, 3, atoms, false));
            assert!(
                contains(&y, &x) && contains(&x, &y),
                "{} at {atoms} atoms",
                pad.label()
            );
        }
    }
}

#[test]
fn every_body_passes_lines_2_and_5() {
    let setting = Setting::<Ed25519>::new();
    for (label, scope) in body_scopes() {
        let bytes = delegation_body(&setting, &scope);
        assert_eq!(line2(&bytes).as_ref(), Some(&scope), "{label}");
        let d = dc_types::decode_body::<Ed25519>(&bytes).unwrap();
        assert!(line5(&d, &bytes), "{label}");
        println!("{label}: {} bytes", bytes.len());
    }
}

#[test]
#[ignore = "prints D-101's admitted shapes; run with --ignored --nocapture"]
fn print_admitted_shapes() {
    let rows = dc_bench::ceiling::admitted();
    for r in &rows {
        println!(
            "{} a{} b{}: rules {} bytes {} fit {} W {}",
            r["family"],
            r["atoms"],
            r["bytes_per_string"],
            r["max_admitted_rules"],
            r["scope_bytes_at_max"],
            r["largest_fitting_rules"],
            r["work_at_max"]
        );
    }
    println!("{:?}", dc_bench::ceiling::proposed(&rows));
}

/// A quick, unreported pre-flight of D-101's derivation: each probe's time
/// per unit, the fixed cost, and every search input against the ceiling
/// they imply. The measured version is `benches/ceiling.rs`.
#[test]
#[ignore = "timing pre-flight; run with --release --ignored --nocapture"]
fn preflight_ceiling() {
    use std::time::Instant;
    let med = |f: &dyn Fn()| {
        let mut v: Vec<u128> = (0..7)
            .map(|_| {
                let t = Instant::now();
                f();
                t.elapsed().as_nanos()
            })
            .collect();
        v.sort_unstable();
        v[3] as f64
    };
    let mut worst = (0.0, String::new());
    for p in dc_bench::ceiling::probes() {
        let ns = med(&|| {
            std::hint::black_box(p.run());
        });
        let u = ns / p.charge as f64;
        println!(
            "{:40} charge {:8} {:10.0} ns {:6.1} ns/unit",
            p.label, p.charge, ns, u
        );
        if u > worst.0 {
            worst = (u, p.label.clone());
        }
    }
    let mut fixed: f64 = 0.0;
    for (l, a, b) in dc_bench::ceiling::overhead_inputs() {
        let ns = med(&|| {
            std::hint::black_box(dc_policy::contains_within(&a, &b, 0));
        });
        println!("overhead {l:40} {ns:10.0} ns");
        fixed = fixed.max(ns);
    }
    let ceiling = dc_policy::DEFAULT_BUDGET as f64 * worst.0 + fixed;
    println!(
        "worst {:.1} ns/unit ({}); ceiling {:.2} ms",
        worst.0,
        worst.1,
        ceiling / 1e6
    );
    let mut top: Vec<(f64, String)> = dc_bench::ceiling::contains_inputs()
        .into_iter()
        .map(|(l, a, b)| {
            let ns = med(&|| {
                std::hint::black_box(dc_policy::contains_within(
                    &a,
                    &b,
                    dc_policy::DEFAULT_BUDGET,
                ));
            });
            (ns, l)
        })
        .collect();
    top.sort_by(|a, b| b.0.total_cmp(&a.0));
    for (ns, l) in top.iter().take(12) {
        println!(
            "{l:40} {:8.3} ms {:5.0}% of the ceiling",
            ns / 1e6,
            100.0 * ns / ceiling
        );
    }
}

/// D-101: every `Contains` call a verification of the small, medium,
/// medium-approval and large profiles makes (the ceiling and each link up to
/// N = 10) stays below an eighth of the default budget.
#[test]
fn the_profiles_stay_well_inside_the_budget() {
    use dc_bench::workload::{Profile, hop_scopes};
    use dc_policy::{DEFAULT_BUDGET, contains_within};
    for p in Profile::ALL {
        let s = hop_scopes(p);
        let calls = std::iter::once((&s[0], &s[0])).chain((1..s.len()).map(|k| (&s[k - 1], &s[k])));
        for (a, b) in calls {
            let w = contains_within(a, b, u64::MAX);
            assert!(w.answer);
            assert!(w.work < DEFAULT_BUDGET / 8, "{}: {}", p.label(), w.work);
        }
    }
}

/// Unreported: the scan probes against the composite probes they bound,
/// each timed over a warm loop.
#[test]
#[ignore = "timing pre-flight; run with --release --ignored --nocapture"]
fn preflight_scan_probes_warm() {
    use std::time::Instant;
    for p in dc_bench::ceiling::probes() {
        if !(p.label.starts_with("scan/") || p.label.starts_with("str-admissible/")) {
            continue;
        }
        for _ in 0..50 {
            std::hint::black_box(p.run());
        }
        let n = if p.label.starts_with("scan/") {
            20_000
        } else {
            200
        };
        let t = Instant::now();
        for _ in 0..n {
            std::hint::black_box(p.run());
        }
        let ns = t.elapsed().as_nanos() as f64 / n as f64;
        println!(
            "{:40} {:10.0} ns {:6.1} ns/unit",
            p.label,
            ns,
            ns / p.charge as f64
        );
    }
}
