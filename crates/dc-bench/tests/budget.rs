//! D-100's inputs are what they claim to be: the new paddings keep the
//! alternating family's answers (both directions contained), and every
//! body built to fill 64 KiB passes lines 2 and 5 with its scope intact.

use dc_bench::bounds::{Pad, padded, search_pads};
use dc_bench::budget::{body_scopes, delegation_body, line2, line5, pads};
use dc_bench::workload::Setting;
use dc_crypto::Ed25519;
use dc_policy::contains;

#[test]
fn new_paddings_keep_the_alternating_answers() {
    let old = search_pads();
    let new: Vec<Pad> = pads().into_iter().filter(|p| !old.contains(p)).collect();
    assert!(!new.is_empty());
    for pad in new {
        for atoms in [4, 8] {
            let (x, y) = (padded(pad, 3, atoms, true), padded(pad, 3, atoms, false));
            assert!(
                contains(&y, &x) && contains(&x, &y),
                "{} at {atoms} atoms",
                pad.label()
            );
        }
    }
}

#[test]
fn every_body_passes_lines_2_and_5() {
    let setting = Setting::<Ed25519>::new();
    for (label, scope) in body_scopes() {
        let bytes = delegation_body(&setting, &scope);
        assert_eq!(line2(&bytes).as_ref(), Some(&scope), "{label}");
        let d = dc_types::decode_body::<Ed25519>(&bytes).unwrap();
        assert!(line5(&d, &bytes), "{label}");
        println!("{label}: {} bytes", bytes.len());
    }
}
