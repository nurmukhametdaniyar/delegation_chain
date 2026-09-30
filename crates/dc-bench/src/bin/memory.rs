//! Q10: memory per entry of the nonce cache, the certificate cache and the
//! prefix cache (SPEC §13.5, D-41). `stats_alloc` is this binary's global
//! allocator, so our code has no `unsafe impl GlobalAlloc`.
//!
//! Bytes retained are allocated minus freed bytes over a region. Caches are
//! measured by difference, between two verifiers that run the same chains
//! and differ only in the cache under test: certificate caching on vs off,
//! and a prefix verifier vs a plain warm verifier. Everything else they
//! retain (nonce entries, the policy cache) cancels out.
//!
//! `dc-bench-memory [--mode full|dry] [--out DIR]` writes `DIR/memory.json`.

use std::alloc::System;
use std::path::PathBuf;

use dc_baselines::Ed25519List;
use dc_bench::plan::{Mode, memory_entries};
use dc_bench::workload::{Layout, Profile, SEED, Setting, T0, chains, p};
use dc_chain::{ChainBuilder, IssuanceService, World};
use dc_crypto::{Bls, BlsAggregate, ChainScheme, Ed25519, PrefixScheme, SigScheme};
use dc_policy::Scope;
use dc_types::Params;
use dc_verifier::{NonceCache, PrefixVerifier, Verifier, VerifierConfig, nonce_key};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde_json::json;
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

fn retained<T>(f: impl FnOnce() -> T) -> (T, i64) {
    let region = Region::new(GLOBAL);
    let out = f();
    let s = region.change();
    (out, s.bytes_allocated as i64 - s.bytes_deallocated as i64)
}

fn row(structure: &str, entries: usize, bytes: i64) -> serde_json::Value {
    json!({
        "structure": structure,
        "entries": entries,
        "bytes": bytes,
        "bytes_per_entry": bytes as f64 / entries as f64,
    })
}

fn nonce_cache(pk_len: usize, k: usize) -> i64 {
    let pk = vec![7u8; pk_len];
    let (cache, bytes) = retained(|| {
        let c = NonceCache::new();
        for i in 0..k as u64 {
            let mut nonce = [0u8; 16];
            nonce[..8].copy_from_slice(&i.to_le_bytes());
            c.insert_if_absent(nonce_key(&pk, &nonce), T0 + 3600, T0);
        }
        c
    });
    assert_eq!(cache.len(), k);
    bytes
}

const SMALL: &str = "allow at=orgb:service:payments\n  tool=payments action=transfer\n  params { amount: int, to: string }\n  where amount <= 1000";

/// The world, the policy hash, and the chains.
type Signers<S> = (World<S>, [u8; 32], Vec<Vec<u8>>);

/// `k` chains with N = 1, each by a distinct, freshly enrolled agent.
fn distinct_signers<C: ChainScheme>(k: usize) -> Signers<C::Base> {
    let mut world = World::<C::Base>::new(SEED ^ 0x0a10c, T0);
    world.org("orgb");
    world
        .enroll("orga:issuer:main", "orga:issuer:main")
        .expect("issuer");
    let scope = Scope::parse(SMALL).expect("policy");
    let hash = world.publish(&scope);
    let issuer =
        IssuanceService::<C::Base>::new(p("orga:issuer:main"), world.secret("orga:issuer:main"));
    let (tool, action, params) = dc_bench::workload::invocation(Profile::Small);
    let mut rng = ChaCha20Rng::seed_from_u64(SEED ^ 0x0a10d);
    let mut out = Vec::with_capacity(k);
    for i in 0..k {
        let id = format!("orga:agent:m{i}");
        world.enroll(&id, &id).expect("agent");
        let agent = world.agent_service(&id, &id);
        let issued = issuer
            .issue(agent.agent(), agent.pk(), &scope, hash, T0, 3600, &mut rng)
            .expect("issue");
        let b = ChainBuilder::<C>::start(issued, scope.clone());
        let inv = b
            .invocation_body(
                &p("orgb:service:payments"),
                &tool,
                &action,
                Params::new(params.value().clone()).expect("params"),
                T0,
                T0 + 600,
                &mut rng,
            )
            .expect("invocation");
        out.push(b.invoke(&agent, inv, vec![]).expect("invoke").to_bytes());
    }
    (world, hash, out)
}

fn certificate_cache<C: ChainScheme>(k: usize) -> (usize, i64) {
    let (world, hash, set) = distinct_signers::<C>(k);
    let make = |cache: bool| {
        let v = Verifier::<C, _, _, _>::new(
            p("orgb:service:payments"),
            world.roots(),
            world.directory(),
            world.policies(),
            world.clock(),
            VerifierConfig {
                cache_certificates: cache,
                ..VerifierConfig::default()
            },
        );
        v.pin("orga", hash);
        v
    };
    let run = |cache: bool| {
        let v = make(cache);
        let (v, bytes) = retained(|| {
            for c in &set {
                assert!(v.verify(c).is_ok());
            }
            v
        });
        (v.cached_certificates(), bytes)
    };
    let (entries, on) = run(true);
    let (_, off) = run(false);
    // The issuer's certificate and one per agent.
    (entries, on - off)
}

fn prefix_cache<C: PrefixScheme>(k: usize) -> (usize, i64) {
    let setting = Setting::<C::Base>::new();
    let set = chains::<C>(&setting, Profile::Medium, 3, Layout::Fresh, k, "q10-prefix");
    let plain = || {
        let v = Verifier::<C, _, _, _>::new(
            p(Profile::Medium.aud()),
            setting.roots(),
            setting.directory(),
            setting.store(),
            setting.clock(),
            VerifierConfig::default(),
        );
        v.pin("orga", setting.hash(Profile::Medium));
        v
    };
    let pv = PrefixVerifier::new(plain());
    let (pv, with) = retained(|| {
        for c in &set {
            assert!(pv.verify(c).is_ok());
        }
        pv
    });
    let v = plain();
    let (_, without) = retained(|| {
        for c in &set {
            assert!(v.verify(c).is_ok());
        }
    });
    (pv.cached_prefixes(), with - without)
}

fn main() {
    let mut mode = Mode::Full;
    let mut out = PathBuf::from("results");
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--mode" => {
                mode = if args.next().as_deref() == Some("dry") {
                    Mode::Dry
                } else {
                    Mode::Full
                };
            }
            "--out" => out = PathBuf::from(args.next().expect("--out DIR")),
            _ => panic!("unknown option {a}"),
        }
    }
    let k = memory_entries(mode);
    let mut rows = vec![];
    rows.push(row(
        "nonce cache (48-byte BLS invoker keys)",
        k,
        nonce_cache(<Bls as SigScheme>::PK_LEN, k),
    ));
    rows.push(row(
        "nonce cache (32-byte Ed25519 invoker keys)",
        k,
        nonce_cache(<Ed25519 as SigScheme>::PK_LEN, k),
    ));
    eprintln!("Q10: certificate cache, arm A…");
    let (e, b) = certificate_cache::<BlsAggregate>(k);
    rows.push(row("certificate cache, BLS (arms A, A-ind, B)", e, b));
    eprintln!("Q10: certificate cache, arm C…");
    let (e, b) = certificate_cache::<Ed25519List>(k);
    rows.push(row("certificate cache, Ed25519 (arms C, C-batch, D)", e, b));
    eprintln!("Q10: prefix cache, arm B…");
    let (e, b) = prefix_cache::<BlsAggregate>(k);
    rows.push(row("prefix cache, arm B (N = 3, medium)", e, b));
    eprintln!("Q10: prefix cache, arm D…");
    let (e, b) = prefix_cache::<Ed25519List>(k);
    rows.push(row("prefix cache, arm D (N = 3, medium)", e, b));
    let v = json!({
        "label": "Q10 memory per entry; bytes retained (allocated − freed), by difference for the caches",
        "mode": mode.label(),
        "rows": rows,
    });
    std::fs::create_dir_all(&out).expect("out dir");
    std::fs::write(
        out.join("memory.json"),
        serde_json::to_string_pretty(&v).unwrap() + "\n",
    )
    .expect("write");
}
