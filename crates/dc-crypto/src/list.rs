//! Chain signatures carried as a list of N+1 separate signatures: the
//! default instantiation's wire form (paper §4.3, §4.6), shared by the
//! list-carrying benchmark arms in `dc-baselines`.

use crate::{CryptoError, Dst, SigScheme, WireForm};

/// Parses a list of exactly `n` signatures of scheme `S`, each validated by
/// `S::sig_from_bytes`.
pub fn from_wire<S: SigScheme>(
    form: &WireForm,
    n: usize,
) -> Result<Vec<S::Signature>, CryptoError> {
    let WireForm::List(list) = form else {
        return Err(CryptoError::WireShape);
    };
    if list.len() != n {
        return Err(CryptoError::SignatureCount {
            expected: n,
            got: list.len(),
        });
    }
    list.iter().map(|b| S::sig_from_bytes(b)).collect()
}

pub fn to_wire<S: SigScheme>(sigs: &[S::Signature]) -> WireForm {
    WireForm::List(sigs.iter().map(S::sig_bytes).collect())
}

/// Checks each (key, digest, signature) triple with the scheme's single
/// verification, stopping at the first failure: line 49 for a list.
pub fn verify_each<S: SigScheme>(
    pks: &[&S::PublicKey],
    msgs: &[[u8; 32]],
    sigs: &[S::Signature],
) -> bool {
    !pks.is_empty()
        && pks.len() == msgs.len()
        && sigs.len() == msgs.len()
        && pks
            .iter()
            .zip(msgs)
            .zip(sigs)
            .all(|((pk, m), s)| S::verify(pk, m, Dst::Chain, s))
}
