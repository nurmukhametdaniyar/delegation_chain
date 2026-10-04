//! Arms B and D: the verifier with a prefix cache (SPEC §12.1; VARIANT).
//!
//! An entry stands for the first N bodies of an accepted chain, keyed by
//! m_{N−1}. m_{N−1} commits to every prefix body's canonical bytes and to
//! the prefix's length, so a hit means the received prefix is byte-identical
//! to one the full algorithm accepted. The hit path then runs only the lines
//! that involve the last body, in Algorithm order, calling the same line
//! functions as the full path, so that both return the same decision and
//! the same reject variant (SPEC §11.3).
//!
//! Entries are filled only when the full path accepts (D-67). They are
//! evicted when a listed binding is revoked (D-65) and cleared on any pin
//! change. An entry is used only inside its validity window: from the latest
//! prefix certificate's `nbf` to the earliest of every prefix body's and
//! prefix certificate's `exp`, capped at the certificate cache's TTL from
//! the time it was filled (D-67).

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use dc_crypto::{PrefixScheme, ops};
use dc_policy::Scope;
use dc_registry::{PolicyStore, Resolver, RevocationError, RevokedBinding};
use dc_types::digest::{Digest32, m_delegation, m_invocation, m_session};
use dc_types::{Body, BodyKind, Clock, Envelope, Principal, RevocationAssertion, decode_body};

use crate::{
    AcceptHook, Accepted, AcceptedParts, OpCounts, Pk, Reject, Verifier, body_scope,
    decode_envelope, decode_sigs, line13,
};

/// Which path a verification took.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Path {
    Hit,
    Miss,
}

struct Entry<C: PrefixScheme> {
    /// m_0 … m_{N−1}.
    digests: Vec<Digest32>,
    /// (registry, identifier, key) of every prefix signer (D-65).
    bindings: Vec<(String, Principal, Vec<u8>)>,
    /// The identifier and key the last prefix body hands on (D-36).
    handoff: (Principal, Vec<u8>),
    /// The session's issuer organization and policy hash (line 30).
    pinned: (String, Digest32),
    /// B_{N−1}'s scope and expiry.
    scope: Scope,
    exp_last: u64,
    valid_from: u64,
    valid_until: u64,
    state: C::PrefixState,
}

impl<C: PrefixScheme> Entry<C> {
    fn lists(&self, b: &RevokedBinding) -> bool {
        self.bindings
            .iter()
            .any(|(reg, id, pk)| *reg == b.registry && *id == b.identifier && *pk == b.pk)
    }
}

/// The verifier of arm B (`C` = `BlsAggregate`) or arm D (`C` = the
/// Ed25519 list scheme): the default verifier plus a prefix cache.
pub struct PrefixVerifier<C: PrefixScheme, R: Resolver, P: PolicyStore, K: Clock> {
    inner: Verifier<C, R, P, K>,
    entries: RwLock<HashMap<Digest32, Arc<Entry<C>>>>,
}

/// m_{N−1} of a prefix: the session, then delegations (eqs. 1–2).
fn prefix_key(prefix: &[Vec<u8>]) -> Digest32 {
    let mut m = m_session(&prefix[0]);
    for b in &prefix[1..] {
        m = m_delegation(&m, b);
    }
    m
}

impl<C: PrefixScheme, R: Resolver, P: PolicyStore, K: Clock> PrefixVerifier<C, R, P, K> {
    pub fn new(inner: Verifier<C, R, P, K>) -> Self {
        PrefixVerifier {
            inner,
            entries: RwLock::new(HashMap::new()),
        }
    }

    /// The wrapped verifier. Its own `verify` never uses the prefix cache.
    pub fn inner(&self) -> &Verifier<C, R, P, K> {
        &self.inner
    }

    pub fn pin(&self, org: &str, hash: Digest32) {
        self.inner.pin(org, hash);
        self.entries.write().unwrap().clear();
    }

    pub fn unpin(&self, org: &str, hash: &Digest32) {
        self.inner.unpin(org, hash);
        self.entries.write().unwrap().clear();
    }

    /// Records the revocation, then evicts every entry listing the binding.
    /// The revocation set is updated first, and an entry is inserted only
    /// after checking that set under the entries' lock, so a verification
    /// that began before the revocation cannot leave a stale entry behind.
    pub fn ingest_revocation(
        &self,
        a: &RevocationAssertion,
    ) -> Result<RevokedBinding, RevocationError> {
        let b = self.inner.ingest_revocation(a)?;
        self.entries.write().unwrap().retain(|_, e| !e.lists(&b));
        Ok(b)
    }

    pub fn forget_revocations(&self, t: u64) {
        self.inner.forget_revocations(t);
    }

    /// Number of cached prefixes.
    pub fn cached_prefixes(&self) -> usize {
        self.entries.read().unwrap().len()
    }

    pub fn verify(&self, chain: &[u8]) -> Result<Accepted, Reject> {
        self.verify_at(chain, self.inner.now())
    }

    pub fn verify_at(&self, chain: &[u8], t: u64) -> Result<Accepted, Reject> {
        self.verify_traced(chain, t).0
    }

    /// Verifies and returns this call's operation counts (feature
    /// `count-ops`; zeros otherwise).
    pub fn verify_counted(&self, chain: &[u8]) -> (Result<Accepted, Reject>, OpCounts) {
        ops::reset();
        let r = self.verify(chain);
        (r, ops::snapshot())
    }

    /// Verifies, and says whether the prefix cache was used.
    pub fn verify_traced(&self, chain: &[u8], t: u64) -> (Result<Accepted, Reject>, Path) {
        let env = match decode_envelope(chain) {
            Ok(env) => env,
            Err(r) => return (Err(r), Path::Miss),
        };
        if env.bodies.len() < 2 {
            return (self.inner.verify_envelope(env, t, &mut ()), Path::Miss);
        }
        let n = env.bodies.len() - 1;
        // Step 1: m_{N−1}, and the lookup.
        let key = prefix_key(&env.bodies[..n]);
        let entry = self.entries.read().unwrap().get(&key).cloned();
        match entry {
            Some(e)
                if e.valid_from <= t
                    && t <= e.valid_until
                    && C::prefix_matches(&e.state, &env.sigs) =>
            {
                (self.hit(&env, n, &e, t), Path::Hit)
            }
            stale => {
                if stale.is_some_and(|e| t > e.valid_until) {
                    self.entries.write().unwrap().remove(&key);
                }
                let mut fill = Fill::<C>::default();
                let r = self.inner.verify_envelope(env, t, &mut fill);
                if let Some((key, e)) = fill.entry {
                    self.insert(key, e);
                }
                (r, Path::Miss)
            }
        }
    }

    /// Inserts an entry unless one of its bindings was revoked, or its
    /// policy unpinned, while the full path ran. Both are checked under the
    /// entries' lock, which revocation and pin changes take after updating
    /// their own state.
    fn insert(&self, key: Digest32, e: Entry<C>) {
        let mut entries = self.entries.write().unwrap();
        if e.bindings
            .iter()
            .any(|(reg, id, pk)| self.inner.is_revoked(reg, id, pk))
            || !self.inner.is_pinned(&e.pinned.0, &e.pinned.1)
        {
            return;
        }
        entries.insert(key, Arc::new(e));
    }

    /// The hit path of SPEC §12.1, in Algorithm order. Every line that
    /// involves only the prefix passed when the entry was filled.
    fn hit(&self, env: &Envelope, n: usize, e: &Entry<C>, t: u64) -> Result<Accepted, Reject> {
        let v = &self.inner;
        // Step 2. Line 2 for B_N, its scope if it has one, and the
        // signature container, in the full path's order.
        let d = decode_body::<C::Base>(&env.bodies[n])
            .map_err(|err| Reject::L02Decode(err.to_string()))?;
        body_scope(&d.body)?;
        let sigs = decode_sigs::<C>(env)?;
        // Line 5 for B_N.
        v.line5(n, &d, &env.bodies[n])?;
        // Line 7 for B_N.
        if d.body.kind() != BodyKind::Invocation {
            return Err(Reject::L07KindMismatch { k: n });
        }
        let Body::Invocation(inv) = &d.body else {
            unreachable!("line 7")
        };
        // Lines 8–9.
        v.lines_8_9(inv)?;
        // Step 3. Line 13; line 15 for k = N; line 17.
        line13(inv, t)?;
        if inv.exp > e.exp_last {
            return Err(Reject::L15ExpiryGrows { k: n });
        }
        let nonce_key = v.line17(inv, t)?;
        // Step 4. The last key link, identifier and key (D-36): line 18 if
        // N = 1, else line 20 for k = N − 1.
        if *d.body.signer_id() != e.handoff.0 || d.body.signer_pk() != e.handoff.1.as_slice() {
            return Err(if n == 1 {
                Reject::L18SubjectMismatch
            } else {
                Reject::L20DelegateeMismatch { k: n - 1 }
            });
        }
        // Step 5. Lines 23–28 for k = N.
        let c = v.signer_certificate(n, &d.body, t)?;
        // Step 6. Lines 36–46.
        let decision = v.lines_36_37(&e.scope, inv)?;
        v.phase7(inv, &decision, t)?;
        // Step 7. Line 47 for m_N; line 48 against the cached digests.
        let m_n = m_invocation(e.digests.last().expect("N ≥ 1"), &env.bodies[n]);
        if e.digests.contains(&m_n) {
            return Err(Reject::L48DuplicateDigest);
        }
        // Step 8. Line 49.
        if !C::verify_last(&e.state, &c.pk, &m_n, &sigs) {
            return Err(Reject::L49ChainSignaturesInvalid);
        }
        // Step 9. Line 50.
        v.line50(nonce_key, inv, t)?;
        Ok(Accepted { n, decision })
    }
}

/// The full path's hook: builds an entry from an accepted chain.
struct Fill<C: PrefixScheme> {
    entry: Option<(Digest32, Entry<C>)>,
}

impl<C: PrefixScheme> Default for Fill<C> {
    fn default() -> Self {
        Fill { entry: None }
    }
}

impl<C: PrefixScheme> AcceptHook<C> for Fill<C> {
    fn accepted(&mut self, parts: &AcceptedParts<'_, C>) {
        let n = parts.bodies.len() - 1;
        let prefix_certs = &parts.certs[..n];
        let pks: Vec<&Pk<C>> = prefix_certs.iter().map(|c| &c.pk).collect();
        let state = C::prefix_state(&pks, &parts.digests[..n], &parts.env.sigs);
        let Body::Session(session) = parts.bodies[0] else {
            unreachable!("line 7")
        };
        let handoff = match parts.bodies[n - 1] {
            Body::Session(s) => (s.subject_id.clone(), s.subject_pk.clone()),
            Body::Delegation(d) => (d.delegatee_id.clone(), d.delegatee_pk.clone()),
            Body::Invocation(_) => unreachable!("line 7"),
        };
        let valid_from = prefix_certs.iter().map(|c| c.body.nbf).max().unwrap_or(0);
        // A certificate's `valid_until` is already the earlier of its expiry
        // and the certificate cache's TTL from when it was resolved.
        let valid_until = prefix_certs
            .iter()
            .map(|c| c.valid_until)
            .chain(parts.bodies[..n].iter().map(|b| b.exp()))
            .min()
            .unwrap_or(0);
        let entry = Entry {
            digests: parts.digests[..n].to_vec(),
            bindings: prefix_certs
                .iter()
                .map(|c| {
                    (
                        c.body.registry_id.as_str().to_owned(),
                        c.body.identifier.clone(),
                        c.body.pk.clone(),
                    )
                })
                .collect(),
            handoff,
            pinned: (session.issuer_id.org().to_owned(), session.policy_hash),
            scope: parts.scopes[n - 1]
                .clone()
                .expect("session and delegation bodies carry scopes"),
            exp_last: parts.bodies[n - 1].exp(),
            valid_from,
            valid_until,
            state,
        };
        self.entry = Some((parts.digests[n - 1], entry));
    }
}
