//! The verifier: Algorithms 1–2 of the paper, line by line (SPEC §10).
//!
//! Generic over the arm's chain scheme, so arms A, A-ind, C and C-batch run
//! this same code and differ only where the signature scheme forces them to
//! (SPEC §12). Every rejection names its Algorithm line ([`Reject`]).
//!
//! Caches (paper §5.4; D-37): verified certificates, keyed by identifier and
//! key, live until the earlier of the certificate's expiry and a TTL (default
//! one hour), and are evicted on revocation; policies are immutable under
//! their hash. Both are filled during verification. Only line 50's nonce
//! insert changes a later decision.

mod nonce;
mod reject;

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

use dc_crypto::ops;
use dc_crypto::{ChainScheme, Dst, SigScheme};
use dc_policy::{Decision, Invocation, Scope, contains, evaluate};
use dc_registry::{PolicyStore, Resolver, RevocationError, verify_revocation};
use dc_types::digest::{Digest32, chain_digests, sha256};
use dc_types::{
    Body, BodyKind, CertBody, Clock, Envelope, Kind, ParsedCert, Principal, RevocationAssertion,
    decode_body,
};

pub use dc_crypto::ops::OpCounts;
pub use nonce::{NonceCache, nonce_key};
pub use reject::Reject;

type Pk<C> = <<C as ChainScheme>::Base as SigScheme>::PublicKey;

/// Verifier settings. The defaults are the paper's warm verifier.
#[derive(Clone, Debug)]
pub struct VerifierConfig {
    /// Cache verified certificates (paper §5.4). Off gives the uncached
    /// verifier of SPEC §11.3.
    pub cache_certificates: bool,
    /// Cache loaded policies (paper §5.4).
    pub cache_policies: bool,
    /// Upper bound on a cached certificate's life, in seconds (paper §5.4:
    /// "typically one hour").
    pub certificate_cache_ttl: u64,
    /// Clock-skew term of the nonce TTL, in seconds (D-25).
    pub nonce_skew: u64,
    /// Security-suite hooks (feature `test-hooks`).
    #[cfg(feature = "test-hooks")]
    pub hooks: TestHooks,
}

impl Default for VerifierConfig {
    fn default() -> Self {
        VerifierConfig {
            cache_certificates: true,
            cache_policies: true,
            certificate_cache_ttl: 3600,
            nonce_skew: 60,
            #[cfg(feature = "test-hooks")]
            hooks: TestHooks::default(),
        }
    }
}

impl VerifierConfig {
    /// No certificate or policy caching: every verification resolves and
    /// loads afresh (SPEC §11.3).
    pub fn uncached() -> Self {
        VerifierConfig {
            cache_certificates: false,
            cache_policies: false,
            ..Self::default()
        }
    }
}

/// Test-only hooks (SPEC §11.2 "Distinct messages"; D-31).
#[cfg(feature = "test-hooks")]
#[derive(Clone, Debug, Default)]
pub struct TestHooks {
    /// Skip line 5's check of recorded violations, so that the re-encoding
    /// comparison alone must catch non-canonical input (D-31).
    pub ignore_recorded_violations: bool,
    /// Before line 48, copy m_i over m_j. A real duplicate would need a
    /// SHA-256 collision.
    pub duplicate_digest: Option<(usize, usize)>,
}

/// An accepted chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Accepted {
    /// N: the number of bodies after the session body.
    pub n: usize,
    /// The decision of line 36 (`Allow` or `AllowWithApproval`).
    pub decision: Decision,
}

/// A certificate that has passed line 24 (decoded, bound to the identifier
/// and key it was resolved for, signed by the organization's root), with its
/// key parsed and validated (D-05).
pub struct VerifiedCert<P> {
    pub body: CertBody,
    pub pk: P,
    /// Cache lifetime: the earlier of the certificate's expiry and the TTL.
    valid_until: u64,
}

/// Why resolving a certificate failed: line 23 (41 for approvers) or line
/// 24 (42).
enum CertFailure {
    Unresolvable,
    Invalid,
}

type CertMap<P> = HashMap<String, Vec<(Vec<u8>, Arc<VerifiedCert<P>>)>>;

/// The verifier of SPEC §10.1.
pub struct Verifier<C: ChainScheme, R: Resolver, P: PolicyStore, K: Clock> {
    self_id: Principal,
    roots: HashMap<String, Pk<C>>,
    pinned: RwLock<HashMap<String, HashSet<Digest32>>>,
    resolver: R,
    policy_store: P,
    clock: K,
    cert_cache: RwLock<CertMap<Pk<C>>>,
    policy_cache: RwLock<HashMap<Digest32, Arc<Scope>>>,
    nonces: NonceCache,
    revoked: RwLock<HashSet<(String, u64)>>,
    config: VerifierConfig,
}

/// Algorithm 2, lines 47–49, on received body bytes: recompute the digests
/// with position tags, require them to be distinct, and check the chain
/// signature. Public so that the Theorem 3 tests can call phase 8 directly
/// on mutated body lists.
pub fn check_phase8<C: ChainScheme>(
    pks: &[&Pk<C>],
    bodies: &[&[u8]],
    sigs: &C::WireSigs,
) -> Result<(), Reject> {
    phase8::<C>(pks, bodies, sigs, None)
}

/// Phase 8, with the test hook that copies m_i over m_j before line 48.
fn phase8<C: ChainScheme>(
    pks: &[&Pk<C>],
    bodies: &[&[u8]],
    sigs: &C::WireSigs,
    duplicate: Option<(usize, usize)>,
) -> Result<(), Reject> {
    // Line 47.
    let mut m = chain_digests(bodies);
    if let Some((i, j)) = duplicate
        && i < m.len()
        && j < m.len()
    {
        m[j] = m[i];
    }
    // Line 48.
    let mut seen = HashSet::with_capacity(m.len());
    if !m.iter().all(|d| seen.insert(*d)) {
        return Err(Reject::L48DuplicateDigest);
    }
    // Line 49.
    if !C::verify_chain(pks, &m, sigs) {
        return Err(Reject::L49AggregateInvalid);
    }
    Ok(())
}

impl<C: ChainScheme, R: Resolver, P: PolicyStore, K: Clock> Verifier<C, R, P, K> {
    /// `self_id` is this verifier's service identifier ("self", line 8);
    /// `roots` is `Root[o]`.
    pub fn new(
        self_id: Principal,
        roots: HashMap<String, Pk<C>>,
        resolver: R,
        policy_store: P,
        clock: K,
        config: VerifierConfig,
    ) -> Self {
        Verifier {
            self_id,
            roots,
            pinned: RwLock::new(HashMap::new()),
            resolver,
            policy_store,
            clock,
            cert_cache: RwLock::new(HashMap::new()),
            policy_cache: RwLock::new(HashMap::new()),
            nonces: NonceCache::new(),
            revoked: RwLock::new(HashSet::new()),
            config,
        }
    }

    pub fn self_id(&self) -> &Principal {
        &self.self_id
    }

    /// Adds `hash` to `Pinned[org]`.
    pub fn pin(&self, org: &str, hash: Digest32) {
        self.pinned
            .write()
            .unwrap()
            .entry(org.to_owned())
            .or_default()
            .insert(hash);
    }

    /// Removes `hash` from `Pinned[org]`.
    pub fn unpin(&self, org: &str, hash: &Digest32) {
        if let Some(set) = self.pinned.write().unwrap().get_mut(org) {
            set.remove(hash);
        }
    }

    /// Push delivery of a revocation assertion (SPEC §6.5): verify it under
    /// `Root[registry_id]`, record the serial, and evict the cache entries
    /// that depend on it.
    pub fn ingest_revocation(
        &self,
        a: &RevocationAssertion,
    ) -> Result<(String, u64), RevocationError> {
        let (org, serial) = verify_revocation::<C::Base>(a, |o| self.roots.get(o))?;
        self.revoked.write().unwrap().insert((org.clone(), serial));
        let mut cache = self.cert_cache.write().unwrap();
        for entries in cache.values_mut() {
            entries
                .retain(|(_, c)| !(c.body.registry_id.as_str() == org && c.body.serial == serial));
        }
        cache.retain(|_, v| !v.is_empty());
        Ok((org, serial))
    }

    pub fn nonce_cache(&self) -> &NonceCache {
        &self.nonces
    }

    /// Number of cached certificates (for tests and Q10).
    pub fn cached_certificates(&self) -> usize {
        self.cert_cache.read().unwrap().values().map(Vec::len).sum()
    }

    /// Number of cached policies.
    pub fn cached_policies(&self) -> usize {
        self.policy_cache.read().unwrap().len()
    }

    /// Verifies a chain at the clock's current time.
    pub fn verify(&self, chain: &[u8]) -> Result<Accepted, Reject> {
        self.verify_at(chain, self.clock.now())
    }

    /// Verifies and returns this call's operation counts (feature
    /// `count-ops`; zeros otherwise).
    pub fn verify_counted(&self, chain: &[u8]) -> (Result<Accepted, Reject>, OpCounts) {
        ops::reset();
        let r = self.verify(chain);
        (r, ops::snapshot())
    }

    /// Resolves `(id, pk)` and runs line 24: decode, check the binding,
    /// verify under `Root[org(id)]`, validate the key. Uses the cache when
    /// configured. Lines 25–27 are left to the caller, on every use.
    fn certificate(
        &self,
        id: &Principal,
        pk: &[u8],
        t: u64,
    ) -> Result<Arc<VerifiedCert<Pk<C>>>, CertFailure> {
        if self.config.cache_certificates
            && let Some(entries) = self.cert_cache.read().unwrap().get(id.as_str())
            && let Some((_, c)) = entries.iter().find(|(k, _)| k.as_slice() == pk)
            && t <= c.valid_until
        {
            return Ok(c.clone());
        }
        ops::add(|c| c.resolver_calls += 1);
        let cert = self
            .resolver
            .resolve(id, pk, t)
            .ok_or(CertFailure::Unresolvable)?;
        let parsed = ParsedCert::<C::Base>::decode(&cert).map_err(|_| CertFailure::Invalid)?;
        // A certificate for another binding does not resolve (id, pk) (D-60).
        if &parsed.body.identifier != id || parsed.body.pk != pk {
            return Err(CertFailure::Unresolvable);
        }
        let root = self.roots.get(id.org()).ok_or(CertFailure::Invalid)?;
        if !C::Base::verify(root, &parsed.message(), Dst::Cert, &parsed.sig) {
            return Err(CertFailure::Invalid);
        }
        let key = C::Base::pk_from_bytes(&parsed.body.pk).map_err(|_| CertFailure::Invalid)?;
        let valid_until = parsed
            .body
            .exp
            .min(t.saturating_add(self.config.certificate_cache_ttl));
        let verified = Arc::new(VerifiedCert {
            body: parsed.body,
            pk: key,
            valid_until,
        });
        if self.config.cache_certificates && valid_until >= t {
            let mut cache = self.cert_cache.write().unwrap();
            let entries = cache.entry(id.as_str().to_owned()).or_default();
            entries.retain(|(k, _)| k.as_slice() != pk);
            entries.push((pk.to_vec(), verified.clone()));
        }
        Ok(verified)
    }

    /// Lines 25–27 on a certificate that passed line 24.
    fn phase5_checks(
        &self,
        c: &VerifiedCert<Pk<C>>,
        id: &Principal,
        kind: Kind,
        t: u64,
    ) -> Result<(), u8> {
        if c.body.registry_id.as_str() != id.org() {
            return Err(25);
        }
        if c.body.kind != kind {
            return Err(26);
        }
        let revoked = self
            .revoked
            .read()
            .unwrap()
            .contains(&(c.body.registry_id.as_str().to_owned(), c.body.serial));
        // Closed interval, as lines 13 and 44 (D-35, P-26).
        if t < c.body.nbf || t > c.body.exp || revoked {
            return Err(27);
        }
        Ok(())
    }

    /// Line 31: `LoadPolicy`, content-addressed (D-12).
    fn load_policy(&self, hash: &Digest32) -> Option<Arc<Scope>> {
        if self.config.cache_policies
            && let Some(s) = self.policy_cache.read().unwrap().get(hash)
        {
            return Some(s.clone());
        }
        ops::add(|c| c.policy_store_calls += 1);
        let bytes = self.policy_store.load(hash)?;
        if &sha256(&[&bytes]) != hash {
            return None;
        }
        let scope = Arc::new(Scope::decode_policy(&bytes).ok()?);
        if self.config.cache_policies {
            self.policy_cache
                .write()
                .unwrap()
                .insert(*hash, scope.clone());
        }
        Some(scope)
    }

    fn contains(&self, parent: &Scope, child: &Scope) -> bool {
        ops::add(|c| c.contains_calls += 1);
        contains(parent, child)
    }

    /// Algorithms 1 and 2, in order.
    pub fn verify_at(&self, chain: &[u8], t: u64) -> Result<Accepted, Reject> {
        // ---- Phase 1: structure and encoding ----
        // Line 2. Each body is decoded under its own kind (D-32); scopes and
        // signature points are validated here (D-28, D-30); canonical-form
        // violations are recorded for line 5 (D-31).
        let env = Envelope::from_bytes(chain).map_err(|e| Reject::L02Decode(e.to_string()))?;
        let decoded = env
            .bodies
            .iter()
            .map(|b| decode_body::<C::Base>(b))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| Reject::L02Decode(e.to_string()))?;
        let scopes = decoded
            .iter()
            .map(|d| d.body.scope().map(Scope::from_raw).transpose())
            .collect::<Result<Vec<Option<Scope>>, _>>()
            .map_err(|e| Reject::L02Decode(e.to_string()))?;
        let sigs = C::from_wire(&env.sigs, env.bodies.len())
            .map_err(|e| Reject::L02Decode(e.to_string()))?;

        // Line 3.
        if env.bodies.len() < 2 {
            return Err(Reject::L03TooShort);
        }
        let n = env.bodies.len() - 1;

        // Lines 4–6.
        #[cfg(feature = "test-hooks")]
        let check_recorded = !self.config.hooks.ignore_recorded_violations;
        #[cfg(not(feature = "test-hooks"))]
        let check_recorded = true;
        for (k, d) in decoded.iter().enumerate() {
            if check_recorded && d.violation.is_some() {
                return Err(Reject::L05NonCanonical { k });
            }
            match d.body.canonical_bytes() {
                Ok(b) if b == env.bodies[k] => {}
                _ => return Err(Reject::L05NonCanonical { k }),
            }
        }

        // Line 7.
        for (k, d) in decoded.iter().enumerate() {
            let expected = match k {
                0 => BodyKind::Session,
                k if k == n => BodyKind::Invocation,
                _ => BodyKind::Delegation,
            };
            if d.body.kind() != expected {
                return Err(Reject::L07KindMismatch { k });
            }
        }
        let bodies: Vec<&Body<C::Base>> = decoded.iter().map(|d| &d.body).collect();
        let Body::Session(session) = bodies[0] else {
            unreachable!("line 7")
        };
        let Body::Invocation(inv) = bodies[n] else {
            unreachable!("line 7")
        };

        // Line 8.
        if inv.aud != self.self_id {
            return Err(Reject::L08WrongAudience);
        }
        // Line 9.
        match inv.params.hash() {
            Ok(h) if h == inv.params_hash => {}
            _ => return Err(Reject::L09ParamsHash),
        }
        // Lines 10–12.
        for (k, b) in bodies.iter().enumerate().take(n).skip(1) {
            let Body::Delegation(d) = b else {
                unreachable!("line 7")
            };
            if d.hop_index != k as u64 || d.session_id != session.session_id {
                return Err(Reject::L11HopOrSession { k });
            }
        }

        // ---- Phase 2: temporal ----
        // Line 13, with no skew tolerance (P-07, resolved in 2026-09-29).
        if t < inv.nbf || t > inv.exp {
            return Err(Reject::L13TimeWindow);
        }
        // Lines 14–16.
        for k in 1..=n {
            if bodies[k].exp() > bodies[k - 1].exp() {
                return Err(Reject::L15ExpiryGrows { k });
            }
        }

        // ---- Phase 3: replay ----
        // Line 17: a lookup only.
        let nonce_key = nonce_key(&inv.invoker_pk, &inv.nonce);
        if self.nonces.contains(&nonce_key, t) {
            return Err(Reject::L17Replay);
        }

        // ---- Phase 4: key chain consistency ----
        // Line 18: identifier and key (D-36).
        if &session.subject_id != bodies[1].signer_id()
            || session.subject_pk.as_slice() != bodies[1].signer_pk()
        {
            return Err(Reject::L18SubjectMismatch);
        }
        // Lines 19–21.
        for k in 1..n {
            let Body::Delegation(d) = bodies[k] else {
                unreachable!("line 7")
            };
            if &d.delegatee_id != bodies[k + 1].signer_id()
                || d.delegatee_pk.as_slice() != bodies[k + 1].signer_pk()
            {
                return Err(Reject::L20DelegateeMismatch { k });
            }
        }

        // ---- Phase 5: identity resolution ----
        let mut certs = Vec::with_capacity(n + 1);
        for (k, b) in bodies.iter().enumerate() {
            let role = if k == 0 { Kind::Issuer } else { Kind::Agent };
            // Lines 23–24.
            let c = self
                .certificate(b.signer_id(), b.signer_pk(), t)
                .map_err(|f| match f {
                    CertFailure::Unresolvable => Reject::L23Unresolvable { k },
                    CertFailure::Invalid => Reject::L24CertificateInvalid { k },
                })?;
            // Lines 25–27.
            self.phase5_checks(&c, b.signer_id(), role, t)
                .map_err(|line| match line {
                    25 => Reject::L25RegistryNamespace { k },
                    26 => Reject::L26WrongKind { k },
                    _ => Reject::L27CertificateNotValid { k },
                })?;
            // Line 28: pk_k is the certified key, equal to spk(B_k) by
            // resolution.
            certs.push(c);
        }

        // ---- Phase 6: policy ----
        // Line 30.
        let pinned = self
            .pinned
            .read()
            .unwrap()
            .get(session.issuer_id.org())
            .is_some_and(|set| set.contains(&session.policy_hash));
        if !pinned {
            return Err(Reject::L30NotPinned);
        }
        // Line 31.
        let policy = self
            .load_policy(&session.policy_hash)
            .ok_or(Reject::L31PolicyUnavailable)?;
        let scope = |k: usize| {
            scopes[k]
                .as_ref()
                .expect("session and delegation bodies carry scopes")
        };
        // Line 32.
        if !self.contains(&policy, scope(0)) {
            return Err(Reject::L32SessionScopeExceedsPolicy);
        }
        // Lines 33–35.
        for k in 1..n {
            if !self.contains(scope(k - 1), scope(k)) {
                return Err(Reject::L34ScopeEscalation { k });
            }
        }
        // Line 36.
        ops::add(|c| c.evaluate_calls += 1);
        let d = evaluate(
            scope(n - 1),
            &Invocation {
                aud: &inv.aud,
                tool: &inv.tool,
                action: &inv.action,
                params: inv.params.value(),
            },
        );
        // Line 37.
        if d == Decision::Deny {
            return Err(Reject::L37Denied);
        }

        // ---- Phase 7: approvals ----
        if let Decision::AllowWithApproval(svcs) = &d {
            let digest = inv
                .invocation_digest()
                .map_err(|_| Reject::L43ReceiptSignature)?;
            for s in svcs {
                // Line 40. Receipts are sorted by approver (D-15); others
                // are ignored (D-34).
                let r = inv
                    .receipts
                    .binary_search_by(|r| r.approval.approver_id.cmp(s))
                    .map(|i| &inv.receipts[i])
                    .map_err(|_| Reject::L40MissingReceipt)?;
                // Line 41, with its reject clause (D-27).
                let c = self
                    .certificate(s, &r.approval.approver_pk, t)
                    .map_err(|f| match f {
                        CertFailure::Unresolvable => Reject::L41ApproverUnresolvable,
                        CertFailure::Invalid => Reject::L42ApproverCertificate,
                    })?;
                // Line 42.
                self.phase5_checks(&c, s, Kind::Approver, t)
                    .map_err(|_| Reject::L42ApproverCertificate)?;
                // Line 43.
                if r.approval.invocation_digest != digest
                    || !C::Base::verify(&c.pk, &r.message(), Dst::Receipt, &r.sig)
                {
                    return Err(Reject::L43ReceiptSignature);
                }
                // Line 44.
                if t < r.approval.iat || t > r.approval.exp {
                    return Err(Reject::L44ReceiptWindow);
                }
            }
        }

        // ---- Phase 8: aggregate signature ----
        let pks: Vec<&Pk<C>> = certs.iter().map(|c| &c.pk).collect();
        let refs: Vec<&[u8]> = env.bodies.iter().map(Vec::as_slice).collect();
        #[cfg(feature = "test-hooks")]
        let duplicate = self.config.hooks.duplicate_digest;
        #[cfg(not(feature = "test-hooks"))]
        let duplicate = None;
        phase8::<C>(&pks, &refs, &sigs, duplicate)?;

        // ---- Commit ----
        // Line 50: atomic insert-if-absent, TTL = (B_N.exp − t) + skew (D-25).
        let expires_at = inv.exp.saturating_add(self.config.nonce_skew);
        if !self.nonces.insert_if_absent(nonce_key, expires_at, t) {
            return Err(Reject::L50Replay);
        }
        // Line 51.
        Ok(Accepted { n, decision: d })
    }
}
