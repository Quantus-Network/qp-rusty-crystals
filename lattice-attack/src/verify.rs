//! The verification criteria: is a submitted basis a basis of the instance's
//! lattice, and if so, what is its score?
//!
//! Acceptance requires, in order:
//!
//! 1. a square `d × d` matrix with entries below `2^MAX_ENTRY_BITS`;
//! 2. every row satisfies the lattice congruence (exact integer check);
//! 3. the exact-Gram Gram–Schmidt factorisation succeeds;
//! 4. the log-volume equals `m · ln q` within [`VOLUME_TOLERANCE`]. A proper sublattice has index
//!    at least 2, i.e. log-volume off by at least `ln 2`, so together with (2) this proves the rows
//!    generate the whole lattice.

use core::fmt;

use serde::{Deserialize, Serialize};

use crate::{
	basis::Basis,
	gso::{profile_exact, profile_f64, Profile},
	instance::Instance,
};

/// Entries of magnitude `2^40` or more are rejected. The starting basis has
/// entries of size `q < 2^23`; this bound exists only to keep the exact
/// arithmetic exact.
pub const MAX_ENTRY_BITS: u32 = 40;

/// Allowed deviation of the log-volume from `m · ln q`, in nats. A sublattice
/// deviates by at least `ln 2 ≈ 0.69`.
pub const VOLUME_TOLERANCE: f64 = 0.25;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Rejection {
	NotSquare {
		rows: usize,
		expected: usize,
	},
	EntryTooLarge {
		row: usize,
		col: usize,
		value: i64,
	},
	NotInLattice {
		row: usize,
	},
	/// The Gram–Schmidt factorisation could not vouch for the basis.
	Unverifiable {
		reason: String,
	},
	/// Rows lie in the lattice but generate a proper sublattice.
	WrongVolume {
		log_volume: f64,
		expected: f64,
	},
}

impl fmt::Display for Rejection {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Rejection::NotSquare { rows, expected } =>
				write!(f, "basis must be {expected}×{expected}, got {rows} rows"),
			Rejection::EntryTooLarge { row, col, value } =>
				write!(f, "entry ({row}, {col}) = {value} exceeds 2^{MAX_ENTRY_BITS}"),
			Rejection::NotInLattice { row } => write!(f, "row {row} is not a lattice vector"),
			Rejection::Unverifiable { reason } => write!(f, "unverifiable: {reason}"),
			Rejection::WrongVolume { log_volume, expected } => write!(
				f,
				"rows generate a sublattice (log-volume {log_volume:.4}, expected {expected:.4})"
			),
		}
	}
}

impl std::error::Error for Rejection {}

/// Verified score and the human-facing metrics derived from the same profile.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Score {
	/// `(P(B₀) − P(B)) / ln 2`: the ranking metric.
	pub score_bits: f64,
	/// Log-potential of the submitted basis, nats.
	pub potential: f64,
	/// Log-potential of the starting basis, nats.
	pub start_potential: f64,
	pub log_volume: f64,
	/// `‖b_1‖`, the first basis vector. Unaffected by size reduction.
	pub first_norm: f64,
	/// `min_i ‖b_i‖` over the submitted rows.
	pub shortest_row_norm: f64,
	/// `‖b_1‖` divided by the Gaussian heuristic for the lattice.
	pub first_over_gh: f64,
	/// Least-squares slope of the log Gram–Schmidt profile.
	pub slope: f64,
	/// `ln ‖b*_i‖` for every row.
	pub log_profile: Vec<f64>,
}

impl Score {
	fn from_profile(instance: &Instance, basis: &Basis, profile: Profile) -> Score {
		let potential = profile.potential();
		let start_potential = instance.start_potential();
		let first_norm = (basis.row_norm_sq(0) as f64).sqrt();
		let shortest_row_norm = (0..basis.len())
			.map(|i| basis.row_norm_sq(i) as f64)
			.fold(f64::INFINITY, f64::min)
			.sqrt();
		Score {
			score_bits: (start_potential - potential) / core::f64::consts::LN_2,
			potential,
			start_potential,
			log_volume: profile.log_volume(),
			first_norm,
			shortest_row_norm,
			first_over_gh: (first_norm.ln() - profile.log_gaussian_heuristic()).exp(),
			slope: profile.slope(),
			log_profile: profile.log_norms,
		}
	}
}

/// Full verification.
pub fn verify(instance: &Instance, basis: &Basis) -> Result<Score, Rejection> {
	let d = instance.dim();
	if basis.len() != d || !basis.is_square() {
		return Err(Rejection::NotSquare { rows: basis.len(), expected: d });
	}
	let limit = 1u64 << MAX_ENTRY_BITS;
	for (i, row) in basis.rows.iter().enumerate() {
		if let Some((j, &value)) = row.iter().enumerate().find(|(_, x)| x.unsigned_abs() >= limit) {
			return Err(Rejection::EntryTooLarge { row: i, col: j, value });
		}
	}
	for (i, row) in basis.rows.iter().enumerate() {
		if !instance.contains(row) {
			return Err(Rejection::NotInLattice { row: i });
		}
	}
	let profile =
		profile_exact(basis).map_err(|e| Rejection::Unverifiable { reason: e.to_string() })?;
	let log_volume = profile.log_volume();
	let expected = instance.log_volume();
	if (log_volume - expected).abs() > VOLUME_TOLERANCE {
		return Err(Rejection::WrongVolume { log_volume, expected });
	}
	Ok(Score::from_profile(instance, basis, profile))
}

/// How far the `f64` profile's log-volume may stray from the instance's
/// before the profile is deemed unreliable (at d = 2049 an unreliable one is
/// off by thousands of nats).
const FAST_VOLUME_TOLERANCE: f64 = 1.0;

/// Approximate score in bits from the `f64` profile, without any lattice
/// checks. For progress traces only. Returns `None` when `f64` could not
/// resolve the profile, detected by its log-volume disagreeing with the
/// instance's.
pub fn score_fast(instance: &Instance, basis: &Basis) -> Option<f64> {
	let p = profile_f64(basis)?;
	if (p.log_volume() - instance.log_volume()).abs() > FAST_VOLUME_TOLERANCE {
		return None;
	}
	Some((instance.start_potential() - p.potential()) / core::f64::consts::LN_2)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::instance::{Variant, Q};

	fn instance() -> Instance {
		Instance::generate(Variant::MlDsa44, [42u8; 32], 14, 10).unwrap()
	}

	#[test]
	fn start_basis_scores_zero() {
		let inst = instance();
		let s = verify(&inst, &inst.start_basis()).unwrap();
		assert!(s.score_bits.abs() < 1e-6, "{}", s.score_bits);
		assert_eq!(s.first_norm, Q as f64);
		// Identity rows carry a column of A, so the q-rows are the shortest.
		assert_eq!(s.shortest_row_norm, Q as f64);
		assert_eq!(s.log_profile.len(), inst.dim());
		assert!((s.log_volume - inst.log_volume()).abs() < 1e-9);
		assert!(s.first_over_gh > 1.0);
		assert!(s.slope < 0.0);
		assert!((score_fast(&inst, &inst.start_basis()).unwrap()).abs() < 1e-6);
	}

	#[test]
	fn unimodular_transforms_are_accepted() {
		let inst = instance();
		let start = inst.start_basis();
		let d = start.len();

		// Reversing the order is a permutation: same lattice, different score.
		let mut reversed = start.clone();
		reversed.rows.reverse();
		let s = verify(&inst, &reversed).unwrap();
		assert!(s.score_bits.abs() > 1.0);

		// Negating a row.
		let mut negated = start.clone();
		for x in negated.rows[3].iter_mut() {
			*x = -*x;
		}
		assert!(verify(&inst, &negated).is_ok());

		// Adding earlier rows to later rows leaves every b*_i unchanged, so
		// the score is exactly that of the start basis.
		let mut mixed = start.clone();
		for i in 1..d {
			for k in 0..d {
				mixed.rows[i][k] += 2 * start.rows[i - 1][k] - start.rows[i / 2][k];
			}
		}
		let s = verify(&inst, &mixed).unwrap();
		assert!(s.score_bits.abs() < 1e-6, "{}", s.score_bits);
	}

	#[test]
	fn rejects_scaled_row_as_sublattice() {
		let inst = instance();
		let mut b = inst.start_basis();
		for x in b.rows[0].iter_mut() {
			*x *= 2;
		}
		match verify(&inst, &b) {
			Err(Rejection::WrongVolume { log_volume, expected }) => {
				assert!((log_volume - expected - core::f64::consts::LN_2).abs() < 1e-9);
			},
			other => panic!("expected WrongVolume, got {other:?}"),
		}
	}

	#[test]
	fn rejects_dependent_rows() {
		let inst = instance();
		let mut b = inst.start_basis();
		let combo: Vec<i64> = (0..b.len()).map(|k| b.rows[1][k] + b.rows[2][k]).collect();
		b.rows[5] = combo;
		assert!(matches!(verify(&inst, &b), Err(Rejection::Unverifiable { .. })));
	}

	#[test]
	fn rejects_foreign_lattice() {
		let inst = instance();
		let other = Instance::generate(Variant::MlDsa44, [43u8; 32], 14, 10).unwrap();
		match verify(&inst, &other.start_basis()) {
			Err(Rejection::NotInLattice { row }) => assert!(row >= inst.m()),
			other => panic!("expected NotInLattice, got {other:?}"),
		}
	}

	#[test]
	fn rejects_malformed_input() {
		let inst = instance();
		let mut b = inst.start_basis();
		b.rows.pop();
		assert!(matches!(verify(&inst, &b), Err(Rejection::NotSquare { .. })));

		let mut b = inst.start_basis();
		b.rows[0].push(0);
		assert!(matches!(verify(&inst, &b), Err(Rejection::NotSquare { .. })));

		let mut b = inst.start_basis();
		b.rows[2][1] = 1 << MAX_ENTRY_BITS;
		assert!(matches!(verify(&inst, &b), Err(Rejection::EntryTooLarge { row: 2, col: 1, .. })));

		let mut b = inst.start_basis();
		b.rows[2][1] = -(1 << MAX_ENTRY_BITS) + 1;
		assert!(matches!(verify(&inst, &b), Err(Rejection::NotInLattice { row: 2 })));
	}

	#[test]
	fn rejection_and_score_round_trip_through_json() {
		let inst = instance();
		let s = verify(&inst, &inst.start_basis()).unwrap();
		let json = serde_json::to_string(&s).unwrap();
		let back: Score = serde_json::from_str(&json).unwrap();
		assert_eq!(back, s);
		let r = Rejection::NotInLattice { row: 3 };
		let back: Rejection = serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
		assert_eq!(back, r);
		assert_eq!(r.to_string(), "row 3 is not a lattice vector");
	}
}
