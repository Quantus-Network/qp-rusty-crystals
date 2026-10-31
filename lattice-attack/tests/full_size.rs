//! Opt-in end-to-end checks at larger dimensions, up to the full ML-DSA-44
//! lattice (d = 2049). They take a few minutes in release; run with
//! `cargo test --release -p qp-rusty-crystals-lattice-attack --test full_size -- --ignored`.

use std::time::Duration;

use qp_rusty_crystals_lattice_attack::{
	harness::{run, Budget, NullObserver, Termination},
	reducers::{Lll, ProgressiveBkz},
	verify::verify,
	Instance, Variant,
};

/// LLL at d = 401 needs size-reduction coefficients far beyond `i64`; this
/// checks the `BigInt` fallback end to end and that LLL terminates.
#[test]
#[ignore]
fn lll_completes_and_verifies_at_d_401() {
	let inst = Instance::generate(Variant::MlDsa44, [0x2Au8; 32], 200, 200).unwrap();
	let mut budget = Budget::new(Duration::from_secs(900));
	budget.trace = false;
	let report = run(&inst, Lll::default(), &budget, &mut NullObserver);
	assert_eq!(report.termination, Termination::Done, "{:?}", report.termination);
	let score = report.result.unwrap();
	eprintln!("d=401 LLL: {:.1} bits in {:.1}s", score.score_bits, report.elapsed_secs);
	assert!(score.score_bits > 50_000.0, "{}", score.score_bits);
	// LLL cannot beat the q-vectors at this dimension, so the first row stays
	// at length q; that is expected, not a failure.
	assert!(score.first_norm <= 8_380_417.0, "{}", score.first_norm);
}

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
