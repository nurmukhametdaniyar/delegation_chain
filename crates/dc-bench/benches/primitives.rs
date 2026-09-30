//! Primitive micro-benchmarks (SPEC §13.5): BLS, Ed25519, CBOR and SHA-256.
//!
//! `blst` has no safe hash-to-G2 on points. `bls/hash_to_g2_proxy` times a
//! pairing context plus one `Pairing::aggregate` with no signature (hash to
//! G2, then queue the pair), and `bls/pairing_context` times the context
//! alone; the difference estimates hash-to-G2 (D-73).

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use dc_bench::workload::{Layout, Profile, Setting, chains};
use dc_crypto::blst::{Pairing, blst_fp12, blst_p1_affine, blst_p2_affine};
use dc_crypto::{Bls, BlsAggregate, ChainScheme, Dst, Ed25519, SigScheme};
use dc_types::digest::{chain_digests, m_delegation, sha256};
use dc_types::{Body, BodyKind, Envelope, decode_body};

fn keys<S: SigScheme>(n: usize) -> Vec<S::SecretKey> {
    (0..n)
        .map(|i| S::keygen(&sha256(&[b"dc-bench-primitive", &[i as u8]])))
        .collect()
}

fn msgs(n: usize) -> Vec<[u8; 32]> {
    (0..n).map(|i| sha256(&[b"m", &[i as u8]])).collect()
}

fn bls(c: &mut Criterion) {
    let sks = keys::<Bls>(11);
    let pks: Vec<_> = sks.iter().map(Bls::public_key).collect();
    let m = msgs(11);
    let sig0 = Bls::sign(&sks[0], &m[0], Dst::Chain);
    c.bench_function("bls/sign", |b| {
        b.iter(|| Bls::sign(&sks[0], black_box(&m[0]), Dst::Chain))
    });
    c.bench_function("bls/verify", |b| {
        b.iter(|| Bls::verify(&pks[0], black_box(&m[0]), Dst::Chain, &sig0))
    });
    let mut g = c.benchmark_group("bls/aggregate_verify");
    for n in 2..=11 {
        let parts: Vec<_> = (0..n)
            .map(|i| Bls::sign(&sks[i], &m[i], Dst::Chain))
            .collect();
        let mut agg = BlsAggregate::start(parts[0]);
        for s in &parts[1..] {
            BlsAggregate::accumulate(&mut agg, *s);
        }
        let refs: Vec<_> = pks[..n].iter().collect();
        g.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter(|| BlsAggregate::verify_chain(&refs, black_box(&m[..n]), &agg))
        });
    }
    g.finish();
    let pk_aff: &blst_p1_affine = (&pks[0]).into();
    let sig_aff: &blst_p2_affine = (&sig0).into();
    c.bench_function("bls/pairing_context", |b| {
        b.iter(|| black_box(Pairing::new(true, Dst::Chain.bls())))
    });
    c.bench_function("bls/hash_to_g2_proxy", |b| {
        b.iter(|| {
            let mut p = Pairing::new(true, Dst::Chain.bls());
            black_box(p.aggregate(pk_aff, false, &(), false, black_box(&m[1]), &[]));
            black_box(p)
        })
    });
    c.bench_function("bls/miller_loop", |b| {
        b.iter(|| blst_fp12::miller_loop(black_box(sig_aff), black_box(pk_aff)))
    });
    let f = blst_fp12::miller_loop(sig_aff, pk_aff);
    c.bench_function("bls/final_exp", |b| b.iter(|| black_box(&f).final_exp()));
}

fn ed25519(c: &mut Criterion) {
    let sks = keys::<Ed25519>(11);
    let pks: Vec<_> = sks.iter().map(Ed25519::public_key).collect();
    let m = msgs(11);
    let sigs: Vec<_> = (0..11)
        .map(|i| Ed25519::sign(&sks[i], &m[i], Dst::Chain))
        .collect();
    c.bench_function("ed25519/sign", |b| {
        b.iter(|| Ed25519::sign(&sks[0], black_box(&m[0]), Dst::Chain))
    });
    c.bench_function("ed25519/verify_strict", |b| {
        b.iter(|| Ed25519::verify(&pks[0], black_box(&m[0]), Dst::Chain, &sigs[0]))
    });
    let mut g = c.benchmark_group("ed25519/verify_batch");
    for n in 2..=11 {
        let refs: Vec<_> = pks[..n].iter().collect();
        g.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter(|| Ed25519::verify_batch(&refs, black_box(&m[..n]), &sigs[..n]))
        });
    }
    g.finish();
}

fn cbor_and_digests(c: &mut Criterion) {
    let setting = Setting::<Bls>::new();
    let chain =
        chains::<BlsAggregate>(&setting, Profile::Medium, 3, Layout::Fresh, 1, "bench-cbor")
            .pop()
            .expect("one chain");
    let env = Envelope::from_bytes(&chain).expect("decode");
    for (k, kind) in [(0, "session"), (1, "delegation"), (3, "invocation")] {
        let bytes = &env.bodies[k];
        let body: Body<Bls> = decode_body::<Bls>(bytes).expect("body").body;
        assert_eq!(
            body.kind(),
            [
                BodyKind::Session,
                BodyKind::Delegation,
                BodyKind::Delegation,
                BodyKind::Invocation
            ][k]
        );
        c.bench_function(&format!("cbor/decode/{kind}"), |b| {
            b.iter(|| decode_body::<Bls>(black_box(bytes)))
        });
        c.bench_function(&format!("cbor/encode/{kind}"), |b| {
            b.iter(|| black_box(&body).canonical_bytes())
        });
    }
    let refs: Vec<&[u8]> = env.bodies.iter().map(Vec::as_slice).collect();
    c.bench_function("sha256/chain_digests_medium_n3", |b| {
        b.iter(|| chain_digests(black_box(&refs)))
    });
    let prev = [7u8; 32];
    c.bench_function("sha256/one_delegation_digest", |b| {
        b.iter(|| m_delegation(black_box(&prev), black_box(&env.bodies[1])))
    });
}

criterion_group!(benches, bls, ed25519, cbor_and_digests);
criterion_main!(benches);
