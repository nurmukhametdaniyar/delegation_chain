//! Digests (paper §4.3; SPEC §5.4). Every tag is seven ASCII characters and
//! a NUL.

use sha2::{Digest, Sha256};

pub const TAG_SES: &[u8; 8] = b"TAG_SES\0";
pub const TAG_DEL: &[u8; 8] = b"TAG_DEL\0";
pub const TAG_INV: &[u8; 8] = b"TAG_INV\0";
/// InvocationDigest (D-06).
pub const TAG_IVD: &[u8; 8] = b"TAG_IVD\0";
/// Approval, certificate, revocation and PoP messages (D-07).
pub const TAG_APR: &[u8; 8] = b"TAG_APR\0";
pub const TAG_CRT: &[u8; 8] = b"TAG_CRT\0";
pub const TAG_REV: &[u8; 8] = b"TAG_REV\0";
pub const TAG_POP: &[u8; 8] = b"TAG_POP\0";

pub type Digest32 = [u8; 32];

pub fn sha256(parts: &[&[u8]]) -> Digest32 {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// m_0 = H(TAG_SES ‖ Canon(B_0)), eq. (1).
pub fn m_session(body: &[u8]) -> Digest32 {
    sha256(&[TAG_SES, body])
}

/// m_k = H(TAG_DEL ‖ m_{k−1} ‖ Canon(B_k)), eq. (2).
pub fn m_delegation(prev: &Digest32, body: &[u8]) -> Digest32 {
    sha256(&[TAG_DEL, prev, body])
}

/// m_N = H(TAG_INV ‖ m_{N−1} ‖ Canon(B_N)), eq. (3).
pub fn m_invocation(prev: &Digest32, body: &[u8]) -> Digest32 {
    sha256(&[TAG_INV, prev, body])
}

/// Algorithm 2 line 47: m_0 … m_N from the received canonical body bytes,
/// with the tag each position implies. Position 0 is the session, the last
/// position (if N ≥ 1) the invocation, and everything between a delegation.
pub fn chain_digests(bodies: &[&[u8]]) -> Vec<Digest32> {
    let mut out: Vec<Digest32> = Vec::with_capacity(bodies.len());
    for (k, b) in bodies.iter().enumerate() {
        let m = match (k, out.last()) {
            (0, _) | (_, None) => m_session(b),
            (k, Some(prev)) if k + 1 == bodies.len() => m_invocation(prev, b),
            (_, Some(prev)) => m_delegation(prev, b),
        };
        out.push(m);
    }
    out
}

/// `params_hash` = SHA256(Canon(params)), untagged as in the paper (P-05).
pub fn params_hash(canon_params: &[u8]) -> Digest32 {
    sha256(&[canon_params])
}

/// `policy_hash` = SHA256(Canon(policy)), untagged as in the paper (P-05).
pub fn policy_hash(canon_policy: &[u8]) -> Digest32 {
    sha256(&[canon_policy])
}

/// InvocationDigest over the invocation body with key 9 removed (D-06).
pub fn invocation_digest(canon_body_without_receipts: &[u8]) -> Digest32 {
    sha256(&[TAG_IVD, canon_body_without_receipts])
}

pub fn approval_message(canon_approval_body: &[u8]) -> Digest32 {
    sha256(&[TAG_APR, canon_approval_body])
}

pub fn cert_message(canon_cert_body: &[u8]) -> Digest32 {
    sha256(&[TAG_CRT, canon_cert_body])
}

pub fn revocation_message(canon_revocation_body: &[u8]) -> Digest32 {
    sha256(&[TAG_REV, canon_revocation_body])
}

pub fn pop_message(canon_challenge: &[u8]) -> Digest32 {
    sha256(&[TAG_POP, canon_challenge])
}
