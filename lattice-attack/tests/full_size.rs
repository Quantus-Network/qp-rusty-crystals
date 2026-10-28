//! Opt-in end-to-end checks at the full ML-DSA-44 dimension (d = 2049).
//! Verification alone takes tens of seconds in release; run with
//! `cargo test --release -p qp-rusty-crystals-lattice-attack --test full_size -- --ignored`.

use std::time::Duration;

use qp_rusty_crystals_lattice_attack::{
	harness::{run, Budget, NullObserver},
	reducers::ProgressiveBkz,
	verify::verify,
	Instance, Variant,
};

#[test]
#[ignore]
fn full_ml_dsa_44_start_basis_verifies_with_score_zero() {
	let inst = Instance::full(Variant::MlDsa44, [0xA5u8; 32]);
	assert_eq!(inst.dim(), 2049);
	let score = verify(&inst, &inst.start_basis()).unwrap();
	assert!(score.score_bits.abs() < 1e-3, "{}", score.score_bits);
	assert!((score.log_volume - inst.log_volume()).abs() < 1e-6);
}

#[test]
#[ignore]
fn full_ml_dsa_44_timed_run_produces_a_verified_report() {
	let inst = Instance::full(Variant::MlDsa44, [0x5Au8; 32]);
	let mut budget = Budget::new(Duration::from_secs(20));
	budget.trace = false;
	budget.include_basis = false;
	let report = run(&inst, ProgressiveBkz::new(10, 40), &budget, &mut NullObserver);
	assert!(report.result.is_ok(), "{:?}", report.result);
	assert!(report.score_bits().unwrap() >= 0.0);
}
