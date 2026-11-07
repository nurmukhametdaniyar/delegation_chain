//! D-98's bounded search for inputs that make the memoized `Contains` cost
//! more than the alternating family (`dc_bench::bounds::padded`). For each
//! padding kind and size, and 8, 16, 24 or 32 atoms a rule, it takes the most
//! rules (up to 256) for which both scopes fit a body, checks that both
//! directions still pass, and times one Contains(Y, X) call. One call is
//! a ranking, not a measurement: the costliest candidates are measured by
//! `benches/contains_cost.rs`. Run with `--release`.
use std::time::Instant;

use dc_bench::bounds::{fits, padded, search_pads};
use dc_policy::contains;

fn main() {
    let pads = search_pads();
    println!("pad atoms rules seconds");
    for pad in pads {
        for atoms in [8, 16, 24, 32] {
            let ok = |r: usize| {
                fits(&padded(pad, r, atoms, true)) && fits(&padded(pad, r, atoms, false))
            };
            if !ok(2) {
                println!("{} {atoms} - larger than a body at 2 rules", pad.label());
                continue;
            }
            let (mut lo, mut hi) = (2usize, dc_policy::validate::MAX_RULES);
            while lo < hi {
                let mid = (lo + hi).div_ceil(2);
                if ok(mid) { lo = mid } else { hi = mid - 1 }
            }
            let (x, y) = (padded(pad, lo, atoms, true), padded(pad, lo, atoms, false));
            assert!(contains(&x, &y), "{} {atoms} {lo}", pad.label());
            let t = Instant::now();
            assert!(contains(&y, &x), "{} {atoms} {lo}", pad.label());
            println!(
                "{} {atoms} {lo} {:.3}",
                pad.label(),
                t.elapsed().as_secs_f64()
            );
        }
    }
}
