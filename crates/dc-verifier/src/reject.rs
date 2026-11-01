use thiserror::Error;

/// Why a chain was rejected: one variant per rejecting line of Algorithms
/// 1–2 (SPEC §10.2, Appendix A; D-94's numbering). `k` is the body position.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum Reject {
    #[error("line 2: decoding failed: {0}")]
    L02Decode(String),
    #[error("line 3: N < 1")]
    L03TooShort,
    #[error("line 5: body {k} is not canonically encoded")]
    L05NonCanonical { k: usize },
    #[error("line 7: body {k}'s kind disagrees with its position")]
    L07KindMismatch { k: usize },
    #[error("line 8: the invocation is not addressed to this verifier")]
    L08WrongAudience,
    #[error("line 9: params_hash does not match the parameters")]
    L09ParamsHash,
    #[error("line 11: delegation {k} has the wrong hop index or session id")]
    L11HopOrSession { k: usize },
    #[error("line 13: t is outside [nbf, exp] of the invocation")]
    L13TimeWindow,
    #[error("line 15: body {k} expires after its parent")]
    L15ExpiryGrows { k: usize },
    #[error("line 17: replayed invoker key and nonce")]
    L17Replay,
    #[error("line 18: the session's subject is not the signer of body 1")]
    L18SubjectMismatch,
    #[error("line 20: delegation {k}'s delegatee is not the signer of body {}", k + 1)]
    L20DelegateeMismatch { k: usize },
    #[error("line 23: no certificate binds body {k}'s signer identifier to its key")]
    L23Unresolvable { k: usize },
    #[error("line 24: body {k}'s certificate does not verify under its organization's root")]
    L24CertificateInvalid { k: usize },
    #[error("line 25: body {k}'s certificate is from a registry outside its namespace")]
    L25RegistryNamespace { k: usize },
    #[error("line 26: body {k}'s certificate has the wrong kind for its position")]
    L26WrongKind { k: usize },
    #[error("line 27: body {k}'s certificate is not yet valid, expired, or revoked")]
    L27CertificateNotValid { k: usize },
    #[error("line 31: two chain digests are equal")]
    L31DuplicateDigest,
    #[error("line 32: the chain signatures do not verify")]
    L32ChainSignaturesInvalid,
    #[error("line 33: the session's policy is not pinned for its organization")]
    L33NotPinned,
    #[error("line 34: the policy is unavailable")]
    L34PolicyUnavailable,
    #[error("line 35: the session scope is not contained in the policy")]
    L35SessionScopeExceedsPolicy,
    #[error("line 37: delegation {k}'s scope is not contained in its parent's")]
    L37ScopeEscalation { k: usize },
    #[error("line 40: the innermost scope denies the invocation")]
    L40Denied,
    #[error("line 43: no receipt from a required approval service")]
    L43MissingReceipt,
    #[error("line 44: the approver's certificate cannot be resolved")]
    L44ApproverUnresolvable,
    #[error("line 45: the approver's certificate fails the phase-5 checks")]
    L45ApproverCertificate,
    #[error("line 46: the receipt does not verify over InvocationDigest(B_N)")]
    L46ReceiptSignature,
    #[error("line 47: t is outside the receipt's validity window")]
    L47ReceiptWindow,
    #[error("line 50: invoker key and nonce already recorded")]
    L50Replay,
}

impl Reject {
    /// The Algorithm line that rejected.
    pub fn line(&self) -> u8 {
        use Reject::*;
        match self {
            L02Decode(_) => 2,
            L03TooShort => 3,
            L05NonCanonical { .. } => 5,
            L07KindMismatch { .. } => 7,
            L08WrongAudience => 8,
            L09ParamsHash => 9,
            L11HopOrSession { .. } => 11,
            L13TimeWindow => 13,
            L15ExpiryGrows { .. } => 15,
            L17Replay => 17,
            L18SubjectMismatch => 18,
            L20DelegateeMismatch { .. } => 20,
            L23Unresolvable { .. } => 23,
            L24CertificateInvalid { .. } => 24,
            L25RegistryNamespace { .. } => 25,
            L26WrongKind { .. } => 26,
            L27CertificateNotValid { .. } => 27,
            L31DuplicateDigest => 31,
            L32ChainSignaturesInvalid => 32,
            L33NotPinned => 33,
            L34PolicyUnavailable => 34,
            L35SessionScopeExceedsPolicy => 35,
            L37ScopeEscalation { .. } => 37,
            L40Denied => 40,
            L43MissingReceipt => 43,
            L44ApproverUnresolvable => 44,
            L45ApproverCertificate => 45,
            L46ReceiptSignature => 46,
            L47ReceiptWindow => 47,
            L50Replay => 50,
        }
    }
}
