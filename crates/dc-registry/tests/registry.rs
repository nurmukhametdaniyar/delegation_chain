//! SPEC §11.1 `dc-registry`: PoP success and failure paths, revocation
//! ingestion; plus rotation, resolution (D-26), directory routing, the
//! policy store and injected latency. Registry tests run for both schemes:
//! arms C, C-batch and D use Ed25519 registries (SPEC §12).

use std::sync::Arc;
use std::time::{Duration, Instant};

use dc_crypto::{Bls, CryptoError, Dst, Ed25519, SigScheme};
use dc_registry::{
    Directory, MAX_CERT_LIFETIME, MemoryPolicyStore, POP_NONCE_TTL, PolicyStore, Registry,
    RegistryError, Resolver, RevocationError, RevocationSet, WithLatency, default_lifetime, enroll,
    enroll_with_validity,
};
use dc_types::digest::revocation_message;
use dc_types::digest::{TAG_SES, sha256};
use dc_types::{
    CertBody, Certificate, Clock, Identifier, Kind, ManualClock, ParsedCert, Principal,
    RevocationAssertion, RevocationBody,
};

const T0: u64 = 1_790_000_000;

fn p(s: &str) -> Principal {
    Principal::parse(s).unwrap()
}

fn key<S: SigScheme>(label: &str) -> S::SecretKey {
    S::keygen(&sha256(&[b"dc-registry-test", label.as_bytes()]))
}

fn pk<S: SigScheme>(sk: &S::SecretKey) -> Vec<u8> {
    S::pk_bytes(&S::public_key(sk))
}

struct Fixture<S: SigScheme> {
    clock: Arc<ManualClock>,
    reg: Registry<S, Arc<ManualClock>>,
}

fn fixture<S: SigScheme>(org: &str) -> Fixture<S> {
    let clock = Arc::new(ManualClock::new(T0));
    let root = sha256(&[b"root", org.as_bytes()]);
    let reg = Registry::new(Identifier::new(org).unwrap(), &root, clock.clone(), 42);
    Fixture { clock, reg }
}

fn parsed<S: SigScheme>(cert: &Certificate) -> ParsedCert<S> {
    ParsedCert::<S>::decode(cert).unwrap()
}

// ---- successful registration ----

fn issues_valid_certificates<S: SigScheme>() {
    let f = fixture::<S>("orga");
    let sk = key::<S>("payer");
    let cert = enroll(&f.reg, &p("orga:agent:payer"), &sk).unwrap();
    let c = parsed::<S>(&cert);
    assert!(S::verify(f.reg.root_pk(), &c.message(), Dst::Cert, &c.sig));
    assert_eq!(c.body.identifier, p("orga:agent:payer"));
    assert_eq!(c.body.pk, pk::<S>(&sk));
    assert_eq!(c.body.kind, Kind::Agent);
    assert_eq!(c.body.registry_id.as_str(), "orga");
    assert_eq!(c.body.registry_pk, S::pk_bytes(f.reg.root_pk()));
    assert_eq!(
        (c.body.iat, c.body.nbf, c.body.exp),
        (T0, T0, T0 + 24 * 3600)
    );
    assert_eq!(c.body.serial, 1);

    // Approvers get 7 days, issuers and signers 24 hours (D-10); serials
    // increase.
    for (id, days) in [
        ("orga:approver:finance", 7),
        ("orga:issuer:main", 1),
        ("orga:signer:hsm", 1),
    ] {
        let c = parsed::<S>(&enroll(&f.reg, &p(id), &key::<S>(id)).unwrap());
        assert_eq!(c.body.exp - c.body.iat, days * 24 * 3600, "{id}");
        assert_eq!(c.body.exp - c.body.iat, default_lifetime(c.body.kind));
    }
    let c = parsed::<S>(&enroll(&f.reg, &p("orga:agent:other"), &key::<S>("other")).unwrap());
    assert_eq!(c.body.serial, 5);
}

#[test]
fn issues_valid_certificates_bls() {
    issues_valid_certificates::<Bls>();
}

#[test]
fn issues_valid_certificates_ed25519() {
    issues_valid_certificates::<Ed25519>();
}

// ---- PoP failure paths (SPEC §6.4 step 3; T5a) ----

fn pop_failure_paths<S: SigScheme>() {
    let f = fixture::<S>("orga");
    let alice = key::<S>("alice");
    let alice_id = p("orga:agent:alice");
    let sign = |sk: &S::SecretKey, ch: &dc_types::PopChallenge| {
        S::sign(sk, &ch.message().unwrap(), Dst::Pop)
    };

    // A nonce this registry never issued.
    let other = fixture::<S>("orga");
    let foreign = other
        .reg
        .challenge(&alice_id, &pk::<S>(&alice), Kind::Agent)
        .unwrap();
    let mut foreign = foreign;
    foreign.nonce = [0xee; 16];
    assert_eq!(
        f.reg
            .register(&foreign, &sign(&alice, &foreign))
            .unwrap_err(),
        RegistryError::NonceUnknown
    );

    // Replay of a used nonce (T5a).
    let ch = f
        .reg
        .challenge(&alice_id, &pk::<S>(&alice), Kind::Agent)
        .unwrap();
    let pop = sign(&alice, &ch);
    f.reg.register(&ch, &pop).unwrap();
    assert_eq!(
        f.reg.register(&ch, &pop).unwrap_err(),
        RegistryError::NonceUsed
    );

    // A failed attempt consumes the nonce too.
    let ch = f
        .reg
        .challenge(&alice_id, &pk::<S>(&alice), Kind::Agent)
        .unwrap();
    let wrong = key::<S>("mallory");
    assert_eq!(
        f.reg.register(&ch, &sign(&wrong, &ch)).unwrap_err(),
        RegistryError::BadPop
    );
    assert_eq!(
        f.reg.register(&ch, &sign(&alice, &ch)).unwrap_err(),
        RegistryError::NonceUsed
    );

    // Expiry: 60 s is still valid, 61 s is not (D-11).
    let ch = f
        .reg
        .challenge(&alice_id, &pk::<S>(&alice), Kind::Agent)
        .unwrap();
    f.clock.advance(POP_NONCE_TTL);
    assert!(f.reg.register(&ch, &sign(&alice, &ch)).is_ok());
    let ch = f
        .reg
        .challenge(&alice_id, &pk::<S>(&alice), Kind::Agent)
        .unwrap();
    f.clock.advance(POP_NONCE_TTL + 1);
    assert_eq!(
        f.reg.register(&ch, &sign(&alice, &ch)).unwrap_err(),
        RegistryError::NonceExpired
    );

    // The registrant may not alter the challenge it was given.
    let ch = f
        .reg
        .challenge(&alice_id, &pk::<S>(&alice), Kind::Agent)
        .unwrap();
    let mut altered = ch.clone();
    altered.pk = pk::<S>(&key::<S>("someone-else"));
    assert_eq!(
        f.reg
            .register(&altered, &sign(&alice, &altered))
            .unwrap_err(),
        RegistryError::ChallengeMismatch
    );

    // T5a: Mallory asks to certify Alice's public key under Mallory's own
    // identifier, without Alice's secret key.
    let mallory_id = p("orga:agent:mallory");
    let ch = f
        .reg
        .challenge(&mallory_id, &pk::<S>(&alice), Kind::Agent)
        .unwrap();
    assert_eq!(
        f.reg.register(&ch, &sign(&wrong, &ch)).unwrap_err(),
        RegistryError::BadPop
    );

    // Namespace, kind and service rules.
    let bob = key::<S>("bob");
    let ch = f
        .reg
        .challenge(&p("orgb:agent:bob"), &pk::<S>(&bob), Kind::Agent)
        .unwrap();
    assert_eq!(
        f.reg.register(&ch, &sign(&bob, &ch)).unwrap_err(),
        RegistryError::WrongOrg("orgb:agent:bob".into())
    );
    let ch = f
        .reg
        .challenge(&p("orga:agent:bob"), &pk::<S>(&bob), Kind::Approver)
        .unwrap();
    assert_eq!(
        f.reg.register(&ch, &sign(&bob, &ch)).unwrap_err(),
        RegistryError::KindMismatch
    );
    assert_eq!(
        f.reg
            .challenge(&p("orga:service:payments"), &pk::<S>(&bob), Kind::Service)
            .unwrap_err(),
        RegistryError::ServiceKind
    );
}

#[test]
fn pop_failure_paths_bls() {
    pop_failure_paths::<Bls>();
}

#[test]
fn pop_failure_paths_ed25519() {
    pop_failure_paths::<Ed25519>();
}

#[test]
fn pop_under_the_chain_dst_is_rejected_bls() {
    // T5a, second row: a PoP signed under the CHAIN DST (D-04).
    let f = fixture::<Bls>("orga");
    let sk = key::<Bls>("alice");
    let ch = f
        .reg
        .challenge(&p("orga:agent:alice"), &pk::<Bls>(&sk), Kind::Agent)
        .unwrap();
    let pop = Bls::sign(&sk, &ch.message().unwrap(), Dst::Chain);
    assert_eq!(
        f.reg.register(&ch, &pop).unwrap_err(),
        RegistryError::BadPop
    );
}

#[test]
fn pop_over_a_chain_style_digest_is_rejected_ed25519() {
    // Ed25519 has no DSTs (SPEC §5.8): the analogue of the row above is a
    // signature over the challenge hashed under a chain tag instead of
    // TAG_POP (D-07).
    let f = fixture::<Ed25519>("orga");
    let sk = key::<Ed25519>("alice");
    let ch = f
        .reg
        .challenge(&p("orga:agent:alice"), &pk::<Ed25519>(&sk), Kind::Agent)
        .unwrap();
    let wrong_msg = sha256(&[TAG_SES, &ch.canonical_bytes().unwrap()]);
    let pop = Ed25519::sign(&sk, &wrong_msg, Dst::Chain);
    assert_eq!(
        f.reg.register(&ch, &pop).unwrap_err(),
        RegistryError::BadPop
    );
}

#[test]
fn rejects_invalid_public_keys() {
    let f = fixture::<Bls>("orga");
    let mut identity = vec![0u8; 48];
    identity[0] = 0xc0;
    let ch = f
        .reg
        .challenge(&p("orga:agent:zero"), &identity, Kind::Agent)
        .unwrap();
    let any_sig = Bls::sign(&key::<Bls>("x"), &ch.message().unwrap(), Dst::Pop);
    assert_eq!(
        f.reg.register(&ch, &any_sig).unwrap_err(),
        RegistryError::InvalidKey(CryptoError::Identity)
    );

    let f = fixture::<Ed25519>("orga");
    let mut weak = vec![0u8; 32];
    weak[0] = 1;
    let ch = f
        .reg
        .challenge(&p("orga:agent:weak"), &weak, Kind::Agent)
        .unwrap();
    let any_sig = Ed25519::sign(&key::<Ed25519>("x"), &ch.message().unwrap(), Dst::Pop);
    assert_eq!(
        f.reg.register(&ch, &any_sig).unwrap_err(),
        RegistryError::InvalidKey(CryptoError::WeakKey)
    );
}

#[test]
fn nonces_are_reproducible_from_the_seed() {
    let (a, b) = (fixture::<Bls>("orga"), fixture::<Bls>("orga"));
    let sk = key::<Bls>("alice");
    for _ in 0..3 {
        let x = a
            .reg
            .challenge(&p("orga:agent:alice"), &pk::<Bls>(&sk), Kind::Agent)
            .unwrap();
        let y = b
            .reg
            .challenge(&p("orga:agent:alice"), &pk::<Bls>(&sk), Kind::Agent)
            .unwrap();
        assert_eq!(x.nonce, y.nonce);
    }
}

// ---- rotation and resolution (paper §5.5; D-26) ----

#[test]
fn scheduled_rotation_yields_two_resolvable_certificates() {
    let f = fixture::<Bls>("orga");
    let id = p("orga:issuer:main");
    let (old, new) = (key::<Bls>("issuer-old"), key::<Bls>("issuer-new"));
    enroll_with_validity(&f.reg, &id, &old, T0, T0 + 100).unwrap();
    enroll_with_validity(&f.reg, &id, &new, T0 + 50, T0 + 200).unwrap();
    let c_old = parsed::<Bls>(&f.reg.resolve(&id, &pk::<Bls>(&old), T0 + 60).unwrap());
    let c_new = parsed::<Bls>(&f.reg.resolve(&id, &pk::<Bls>(&new), T0 + 60).unwrap());
    assert_eq!((c_old.body.nbf, c_old.body.exp), (T0, T0 + 100));
    assert_eq!((c_new.body.nbf, c_new.body.exp), (T0 + 50, T0 + 200));
    assert_eq!(c_old.body.pk, pk::<Bls>(&old));
    assert_eq!(c_new.body.pk, pk::<Bls>(&new));
}

#[test]
fn resolution_returns_the_latest_certificate_valid_or_not() {
    let f = fixture::<Bls>("orga");
    let id = p("orga:agent:payer");
    let sk = key::<Bls>("payer");
    let first = enroll_with_validity(&f.reg, &id, &sk, T0, T0 + 10).unwrap();
    // Expired: still returned (D-26); line 27 decides.
    f.clock.advance(3600);
    assert_eq!(
        f.reg.resolve(&id, &pk::<Bls>(&sk), f.clock.now() + 1),
        Some(first.clone())
    );
    // Renewing the same binding: the newer certificate wins.
    let second = enroll(&f.reg, &id, &sk).unwrap();
    assert_eq!(f.reg.resolve(&id, &pk::<Bls>(&sk), 0), Some(second.clone()));
    assert_eq!(parsed::<Bls>(&second).body.serial, 2);
    // Revoked: still returned; line 27 decides. (Re-certifying after the
    // revocation is refused, D-65, so this order replaces the pre-D-65 one.)
    f.reg.revoke(2).unwrap();
    assert_eq!(f.reg.resolve(&id, &pk::<Bls>(&sk), 0), Some(second));
    // Unknown identifier, or a key not bound to it.
    assert_eq!(
        f.reg.resolve(&p("orga:agent:nobody"), &pk::<Bls>(&sk), 0),
        None
    );
    assert_eq!(
        f.reg.resolve(&id, &pk::<Bls>(&key::<Bls>("other")), 0),
        None
    );
}

#[test]
fn directory_routes_by_organization() {
    let a = Arc::new(fixture::<Bls>("orga").reg);
    let b = Arc::new(fixture::<Bls>("orgb").reg);
    let sk = key::<Bls>("x");
    let ca = enroll(&*a, &p("orga:agent:x"), &sk).unwrap();
    let cb = enroll(&*b, &p("orgb:agent:x"), &sk).unwrap();
    let mut dir = Directory::new();
    dir.add("orga", a.clone());
    dir.add("orgb", b.clone());
    assert_eq!(
        dir.resolve(&p("orga:agent:x"), &pk::<Bls>(&sk), 0),
        Some(ca)
    );
    assert_eq!(
        dir.resolve(&p("orgb:agent:x"), &pk::<Bls>(&sk), 0),
        Some(cb)
    );
    assert_eq!(dir.resolve(&p("orgc:agent:x"), &pk::<Bls>(&sk), 0), None);
}

// ---- revocation (paper §5.6; SPEC §6.5) ----

#[test]
fn revocation_assertions_are_verified_and_ingested() {
    let fa = fixture::<Bls>("orga");
    let fb = fixture::<Bls>("orgb");
    enroll(&fa.reg, &p("orga:agent:payer"), &key::<Bls>("payer")).unwrap();
    let assertion = fa.reg.revoke(1).unwrap();
    assert_eq!(
        fa.reg.revoke(9).unwrap_err(),
        RegistryError::UnknownSerial(9)
    );

    let roots = |org: &str| match org {
        "orga" => Some(fa.reg.root_pk()),
        "orgb" => Some(fb.reg.root_pk()),
        _ => None,
    };
    let payer = p("orga:agent:payer");
    let payer_pk = pk::<Bls>(&key::<Bls>("payer"));
    let mut set = RevocationSet::new();
    assert!(!set.is_revoked("orga", &payer, &payer_pk));
    let b = set.ingest::<Bls>(&assertion, roots).unwrap();
    // The assertion names the binding, and keeps the serial for audit.
    assert_eq!(
        (b.registry.as_str(), &b.identifier, &b.pk, b.serial),
        ("orga", &payer, &payer_pk, 1)
    );
    assert!(set.is_revoked("orga", &payer, &payer_pk));
    assert!(!set.is_revoked("orgb", &payer, &payer_pk));
    assert!(!set.is_revoked("orga", &payer, &pk::<Bls>(&key::<Bls>("other"))));

    // Checked under the root of the organization it names.
    let wrong_root = |_: &str| Some(fb.reg.root_pk());
    assert_eq!(
        RevocationSet::new()
            .ingest::<Bls>(&assertion, wrong_root)
            .unwrap_err(),
        RevocationError::BadSignature
    );
    assert_eq!(
        RevocationSet::new()
            .ingest::<Bls>(&assertion, |_| None)
            .unwrap_err(),
        RevocationError::UnknownOrg("orga".into())
    );
    // Tampering with the serial breaks the signature or the encoding.
    let mut tampered = assertion.clone();
    let i = tampered.0.len() - 100;
    tampered.0[i] ^= 1;
    assert!(
        RevocationSet::new()
            .ingest::<Bls>(&tampered, roots)
            .is_err()
    );
}

// ---- policy store and latency (SPEC §6.6, §13.4) ----

#[test]
fn policy_store_is_content_addressed() {
    let store = MemoryPolicyStore::new();
    let h = store.put(vec![0xa1, 0x01, 0x00]);
    assert_eq!(h, sha256(&[&[0xa1, 0x01, 0x00]]));
    assert_eq!(store.load(&h), Some(vec![0xa1, 0x01, 0x00]));
    assert_eq!(store.load(&[0; 32]), None);
    // A store may serve the wrong bytes; the verifier checks (D-12).
    store.put_unchecked([7; 32], vec![1, 2, 3]);
    assert_eq!(store.load(&[7; 32]), Some(vec![1, 2, 3]));
}

#[test]
fn injected_latency_is_applied_and_counted() {
    let store = MemoryPolicyStore::new();
    let h = store.put(vec![0xa0]);
    let slow = WithLatency::new(store, Duration::from_millis(5));
    let start = Instant::now();
    for _ in 0..3 {
        assert!(slow.load(&h).is_some());
    }
    assert!(start.elapsed() >= Duration::from_millis(15));
    assert_eq!(slow.calls(), 3);

    let f = fixture::<Bls>("orga");
    let sk = key::<Bls>("payer");
    enroll(&f.reg, &p("orga:agent:payer"), &sk).unwrap();
    let r = WithLatency::new(f.reg, Duration::ZERO);
    assert!(
        r.resolve(&p("orga:agent:payer"), &pk::<Bls>(&sk), 0)
            .is_some()
    );
    assert!(
        r.resolve(&p("orga:agent:nobody"), &pk::<Bls>(&sk), 0)
            .is_none()
    );
    assert_eq!(r.calls(), 2);
}

// ---- test hooks: a compromised root (T5b) and a misbehaving registry (T5d) ----

#[test]
fn compromised_root_can_sign_anything() {
    let f = fixture::<Bls>("orga");
    let sk = key::<Bls>("forged");
    let body = CertBody {
        identifier: p("orgb:issuer:main"),
        pk: pk::<Bls>(&sk),
        kind: Kind::Issuer,
        registry_id: Identifier::new("orgb").unwrap(),
        registry_pk: Bls::pk_bytes(f.reg.root_pk()),
        iat: T0,
        nbf: T0,
        exp: T0 + 10,
        serial: 99,
    };
    let cert = f.reg.root_sign_arbitrary(&body);
    let c = parsed::<Bls>(&cert);
    assert_eq!(c.body, body);
    assert!(Bls::verify(
        f.reg.root_pk(),
        &c.message(),
        Dst::Cert,
        &c.sig
    ));
    f.reg
        .publish_arbitrary(&body.identifier, &body.pk, cert.clone());
    assert_eq!(f.reg.resolve(&body.identifier, &body.pk, 0), Some(cert));
}

// ---- binding revocation (D-65, P-29) ----

#[test]
fn a_revoked_binding_is_never_certified_again() {
    let f = fixture::<Bls>("orga");
    let id = p("orga:agent:payer");
    let sk = key::<Bls>("payer");
    enroll(&f.reg, &id, &sk).unwrap();
    // A renewal for the same key is fine while the binding stands.
    enroll(&f.reg, &id, &sk).unwrap();
    assert_eq!(f.reg.serials_of(&id, &pk::<Bls>(&sk)), vec![1, 2]);
    // Revoking either certificate revokes the binding.
    f.reg.revoke(1).unwrap();
    assert_eq!(
        enroll(&f.reg, &id, &sk).unwrap_err(),
        RegistryError::RevokedBinding
    );
    // The identifier with a new key is a different binding.
    assert!(enroll(&f.reg, &id, &key::<Bls>("payer-2")).is_ok());
}

#[test]
fn lifetimes_are_capped() {
    let f = fixture::<Bls>("orga");
    let sk = key::<Bls>("payer");
    let id = p("orga:agent:payer");
    assert!(enroll_with_validity(&f.reg, &id, &sk, T0, T0 + MAX_CERT_LIFETIME).is_ok());
    assert_eq!(
        enroll_with_validity(&f.reg, &id, &sk, T0, T0 + MAX_CERT_LIFETIME + 1).unwrap_err(),
        RegistryError::LifetimeTooLong
    );
}

#[test]
fn revocation_records_are_kept_for_the_maximum_lifetime() {
    let f = fixture::<Bls>("orga");
    let id = p("orga:agent:payer");
    let sk = key::<Bls>("payer");
    enroll(&f.reg, &id, &sk).unwrap();
    let a = f.reg.revoke(1).unwrap();
    let mut set = RevocationSet::new();
    set.ingest::<Bls>(&a, |_| Some(f.reg.root_pk())).unwrap();
    // A certificate issued at revocation time can be valid through
    // revoked_at + MAX_CERT_LIFETIME (closed interval), so the record stays.
    set.forget_before(T0 + MAX_CERT_LIFETIME);
    assert!(set.is_revoked("orga", &id, &pk::<Bls>(&sk)));
    set.forget_before(T0 + MAX_CERT_LIFETIME + 1);
    assert!(set.is_empty());
}

#[test]
fn a_root_cannot_revoke_a_binding_outside_its_namespace() {
    let fa = fixture::<Bls>("orga");
    // orga's root signs an assertion naming an orgb identifier.
    let root_sk = Bls::keygen(&sha256(&[b"root", b"orga"]));
    let body = RevocationBody {
        registry_id: Identifier::new("orga").unwrap(),
        serial: 1,
        revoked_at: T0,
        identifier: p("orgb:agent:payer"),
        pk: pk::<Bls>(&key::<Bls>("payer")),
    }
    .canonical_bytes();
    let sig = Bls::sign(&root_sk, &revocation_message(&body), Dst::Revoke);
    let a = RevocationAssertion::assemble::<Bls>(&body, &sig);
    assert_eq!(
        RevocationSet::new()
            .ingest::<Bls>(&a, |_| Some(fa.reg.root_pk()))
            .unwrap_err(),
        RevocationError::Namespace
    );
}
