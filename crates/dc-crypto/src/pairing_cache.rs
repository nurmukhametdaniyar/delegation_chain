//! Arm B's pairing cache (SPEC §5.7; VARIANT).
//!
//! Line 49 checks `Π_{k=0}^{N} e(pk_k, H(m_k)) = e(g1, σ_agg)`. For a known
//! prefix this module keeps `P = Π_{k<N} ML(H(m_k), pk_k)`, the Miller-loop
//! product before the final exponentiation, and per invocation checks
//! `FE(conj(ML(σ_agg, g1)) · P · ML(H(m_N), pk_N)) = 1`.
//!
//! That is the full equation, as `aggregate_verify` evaluates it, not a
//! weaker check. `blst`'s `finalverify` conjugates its first argument, and
//! after the final exponentiation conjugation is inversion. So this is the
//! SPEC's `FE(P · ML(H(m_N), pk_N) · ML(σ_agg, −g1)) = 1`.
//!
//! Only safe `blst` APIs are used: `Pairing::aggregate` with no signature
//! (hash to G2, then queue the pair), `Pairing::as_fp12` (commit the Miller
//! loops), `Pairing::aggregated` (the Miller loop of σ against g1), `Mul` on
//! `blst_fp12` and `blst_fp12::finalverify`. The hashing uses the chain DST
//! and no augmentation, exactly as `aggregate_verify` does. Keys and
//! signatures were validated when they were parsed (D-05, D-30), so neither
//! is re-checked here, again as on the full path.

use blst::min_pk::{PublicKey, Signature};
use blst::{BLST_ERROR, Pairing, blst_fp12, blst_p1_affine, blst_p2_affine};

use crate::prefix::PrefixScheme;
use crate::{BlsAggregate, Dst, WireForm, ops};

/// `P = Π_{k<N} ML(H(m_k), pk_k)`, before the final exponentiation.
#[derive(Clone, Copy, Debug)]
pub struct MillerProduct(blst_fp12);

/// Queues `ML(H(m), pk)` for each pair and returns the product. `None` if
/// `blst` refuses a pair, in which case `aggregate_verify` fails too.
pub fn prefix_product(pks: &[&PublicKey], msgs: &[[u8; 32]]) -> Option<MillerProduct> {
    if pks.is_empty() || pks.len() != msgs.len() {
        return None;
    }
    ops::add(|c| {
        c.hash_to_curve += msgs.len() as u64;
        c.miller_loops += msgs.len() as u64;
    });
    let mut ctx = Pairing::new(true, Dst::Chain.bls());
    for (pk, m) in pks.iter().zip(msgs) {
        let pk: &blst_p1_affine = (*pk).into();
        if ctx.aggregate(pk, false, &(), false, m, &[]) != BLST_ERROR::BLST_SUCCESS {
            return None;
        }
    }
    Some(MillerProduct(ctx.as_fp12()))
}

/// Line 49 given the prefix product: one hash to G2, two Miller loops and
/// one final exponentiation, whatever N is.
pub fn verify_with_prefix(
    p: &MillerProduct,
    pk_n: &PublicKey,
    m_n: &[u8; 32],
    sig: &Signature,
) -> bool {
    ops::add(|c| {
        c.sig_verifications += 1;
        c.hash_to_curve += 1;
        c.miller_loops += 2;
        c.final_exps += 1;
    });
    let mut ctx = Pairing::new(true, Dst::Chain.bls());
    let pk: &blst_p1_affine = pk_n.into();
    if ctx.aggregate(pk, false, &(), false, m_n, &[]) != BLST_ERROR::BLST_SUCCESS {
        return false;
    }
    let gt = p.0 * ctx.as_fp12();
    let sig: &blst_p2_affine = sig.into();
    let mut gt_sig = blst_fp12::default();
    Pairing::aggregated(&mut gt_sig, sig);
    blst_fp12::finalverify(&gt_sig, &gt)
}

/// Arm B: arm A's wire format and full path, with the pairing cache on a
/// prefix hit.
impl PrefixScheme for BlsAggregate {
    type PrefixState = Option<MillerProduct>;

    fn prefix_state(
        pks: &[&PublicKey],
        msgs: &[[u8; 32]],
        _wire: &WireForm,
    ) -> Option<MillerProduct> {
        prefix_product(pks, msgs)
    }

    /// The full equation covers every signature in σ_agg, so any aggregate
    /// may use the entry (SPEC §12.1).
    fn prefix_matches(_state: &Option<MillerProduct>, _wire: &WireForm) -> bool {
        true
    }

    fn verify_last(
        state: &Option<MillerProduct>,
        pk_n: &PublicKey,
        m_n: &[u8; 32],
        sig: &Signature,
    ) -> bool {
        state
            .as_ref()
            .is_some_and(|p| verify_with_prefix(p, pk_n, m_n, sig))
    }
}
