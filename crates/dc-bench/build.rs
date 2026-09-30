//! Records the flags this crate was compiled with, for `results/env.json`
//! (SPEC §3.3, §13.5): benchmarks must be built with
//! `RUSTFLAGS="-C target-cpu=native"` for all arms.

fn main() {
    let flags = std::env::var("CARGO_ENCODED_RUSTFLAGS")
        .unwrap_or_default()
        .replace('\u{1f}', " ");
    println!("cargo:rustc-env=DC_BENCH_RUSTFLAGS={flags}");
    let profile = std::env::var("PROFILE").unwrap_or_default();
    println!("cargo:rustc-env=DC_BENCH_PROFILE={profile}");
    println!("cargo:rerun-if-env-changed=CARGO_ENCODED_RUSTFLAGS");
}
