//! Q7: signing-side costs (SPEC §13.1): per-hop signing including the
//! digest, adding to the aggregate, receipt signing, and issuance, for both
//! base schemes.

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use dc_bench::workload::{Layout, Profile, Setting, T0, chains, hop_agent};
use dc_crypto::{Bls, BlsAggregate, ChainScheme, Dst, Ed25519, SigScheme};
use dc_types::{Body, Envelope, decode_body};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

fn scheme<S: SigScheme, C: ChainScheme<Base = S>>(c: &mut Criterion, name: &str) {
    let setting = Setting::<S>::new();
    let chain = chains::<C>(
        &setting,
        Profile::MediumApproval,
        3,
        Layout::Fresh,
        1,
        "bench-signing",
    )
    .pop()
    .expect("one chain");
    let env = Envelope::from_bytes(&chain).expect("decode");
    let delegation: Body<S> = decode_body::<S>(&env.bodies[1]).expect("body").body;
    let Body::Invocation(inv) = decode_body::<S>(&env.bodies[3]).expect("body").body else {
        panic!("invocation")
    };
    let signer = setting.agent(&hop_agent(0, 0));
    let prev = [9u8; 32];
    c.bench_function(&format!("signing/{name}/hop"), |b| {
        b.iter(|| {
            signer
                .sign(black_box(&delegation), black_box(&prev))
                .expect("sign")
        })
    });
    let sk = setting.world.secret("x");
    let s1 = S::sign(&sk, &prev, Dst::Chain);
    let s2 = S::sign(&sk, &[1u8; 32], Dst::Chain);
    let acc = C::start(s1);
    c.bench_function(&format!("signing/{name}/aggregate_add"), |b| {
        b.iter(|| {
            let mut a = acc.clone();
            C::accumulate(&mut a, black_box(s2.clone()));
            a
        })
    });
    c.bench_function(&format!("signing/{name}/receipt"), |b| {
        b.iter(|| {
            setting
                .finance
                .approve(black_box(&inv), T0)
                .expect("receipt")
        })
    });
    let scope = setting.scopes(Profile::Medium)[0].clone();
    let hash = setting.hash(Profile::Medium);
    let subject = setting.agent(&hop_agent(0, 0));
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    c.bench_function(&format!("signing/{name}/issue"), |b| {
        b.iter(|| {
            setting
                .issuer
                .issue(
                    subject.agent(),
                    subject.pk(),
                    black_box(&scope),
                    hash,
                    T0,
                    3600,
                    &mut rng,
                )
                .expect("issue")
        })
    });
}

fn bench(c: &mut Criterion) {
    scheme::<Bls, BlsAggregate>(c, "bls");
    scheme::<Ed25519, dc_baselines::Ed25519List>(c, "ed25519");
}

criterion_group!(benches, bench);
criterion_main!(benches);
