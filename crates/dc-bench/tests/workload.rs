//! Every profile's chains are accepted at every N, by the arms of both base
//! schemes, from a verifier built in the same deterministic world.

use dc_baselines::{BlsIndividual, Ed25519List};
use dc_bench::workload::{Layout, Profile, Setting, chains, p};
use dc_crypto::{Bls, BlsAggregate, ChainScheme, Ed25519};
use dc_verifier::{Verifier, VerifierConfig};

fn accepts<C: ChainScheme>(setting: &Setting<C::Base>, profile: Profile, n: usize) {
    let v = Verifier::<C, _, _, _>::new(
        p(profile.aud()),
        setting.roots(),
        setting.directory(),
        setting.store(),
        setting.clock(),
        VerifierConfig::default(),
    );
    v.pin("orga", setting.hash(profile));
    for layout in [Layout::Fresh, Layout::Prefixed { prefixes: 2 }] {
        // Sets verified by one verifier need distinct tags, or their nonce
        // streams coincide (the harness tags every set by all its parameters).
        let tag = format!("test-{layout:?}");
        for (i, c) in chains::<C>(setting, profile, n, layout, 4, &tag)
            .iter()
            .enumerate()
        {
            let r = v.verify(c);
            assert!(
                r.is_ok(),
                "{} N={n} {layout:?} chain {i}: {r:?}",
                profile.label()
            );
        }
    }
}

#[test]
fn every_profile_verifies_at_every_n() {
    let bls = Setting::<Bls>::new();
    let ed = Setting::<Ed25519>::new();
    for profile in Profile::ALL {
        for n in [1, 2, 3, 5, 10] {
            accepts::<BlsAggregate>(&bls, profile, n);
            accepts::<BlsIndividual>(&bls, profile, n);
            accepts::<Ed25519List>(&ed, profile, n);
        }
    }
}

#[test]
fn settings_are_deterministic() {
    let a = Setting::<Ed25519>::new();
    let b = Setting::<Ed25519>::new();
    let ca = chains::<Ed25519List>(&a, Profile::Large, 3, Layout::Fresh, 2, "det");
    let cb = chains::<Ed25519List>(&b, Profile::Large, 3, Layout::Fresh, 2, "det");
    assert_eq!(ca, cb);
    assert_eq!(a.hash(Profile::Medium), b.hash(Profile::Medium));
}

#[test]
fn large_profile_shape() {
    use dc_policy::ScopeForm;
    let scopes = dc_bench::workload::hop_scopes(Profile::Large);
    let count = |k: usize| match scopes[k].form() {
        ScopeForm::Rules(r) => r.len(),
        _ => 0,
    };
    // D-38: 16 rules, 2 dropped per hop, never below 4.
    let counts: Vec<usize> = (0..10).map(count).collect();
    assert_eq!(counts, vec![16, 14, 12, 10, 8, 6, 4, 4, 4, 4]);
    let approvals = |k: usize| match scopes[k].form() {
        ScopeForm::Rules(r) => r.iter().filter(|r| !r.approval.is_empty()).count(),
        _ => 0,
    };
    assert!((0..10).all(|k| approvals(k) == 2));
    // Every rule has 4 declared parameters and 3 atoms.
    let ScopeForm::Rules(r0) = scopes[0].form() else {
        panic!()
    };
    assert!(r0.iter().all(|r| r.params.len() == 4 && r.atoms.len() == 3));
}
