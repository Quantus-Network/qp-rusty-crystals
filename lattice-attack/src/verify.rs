//! The verification criteria: is a submitted basis a basis of the instance's
//! lattice, and if so, what is its score?
//!
//! Acceptance requires, in order:
//!
//! 1. a square `d × d` matrix with entries below `2^MAX_ENTRY_BITS`;
//! 2. every row satisfies the lattice congruence (exact integer check);
//! 3. the rows generate the whole lattice, not a sublattice: `det B ≡ ±qᵐ` modulo [`INDEX_PRIMES`]
//!    62-bit primes derived by hashing the instance and the basis (see [`crate::modp`]);
//! 4. the certified Gram–Schmidt profile ([`profile_exact`]) can be computed; its log-volume is
//!    then checked against `m · ln q` as a consistency check on the arithmetic.

use core::fmt;

use qp_rusty_crystals_dilithium::fips202::{
	shake256_absorb, shake256_finalize, shake256_squeeze, Shake256State,
};
use serde::{Deserialize, Serialize};

use crate::{
	basis::Basis,
	gso::{profile_exact, profile_f64, Profile, CERTIFIED_TOLERANCE},
	instance::{Instance, Q},
	modp::{determinant, next_prime, Mont},
};

/// Entries of magnitude `2^40` or more are rejected. The starting basis has
/// entries of size `q < 2^23`; this bound exists only to keep the exact
/// arithmetic exact.
pub const MAX_ENTRY_BITS: u32 = 40;

/// Number of hash-derived primes the determinant is checked against.
pub const INDEX_PRIMES: usize = 3;

const PRIME_DOMAIN: &[u8] = b"qp-lattice-attack/index-primes/v1";

/// Allowed deviation of the certified log-volume from `m · ln q`, in nats.
/// The certificate bounds the error by far less; a larger deviation would
/// mean a bug, not a sublattice (those are caught exactly before).
const VOLUME_CONSISTENCY: f64 = 1e-6 + CERTIFIED_TOLERANCE;

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
	/// Rows lie in the lattice but generate a proper sublattice (or are
	/// linearly dependent).
	Sublattice,
	/// The certified Gram–Schmidt profile could not be computed.
	Unverifiable {
		reason: String,
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
			Rejection::Sublattice =>
				write!(f, "rows lie in the lattice but do not generate it (determinant ≠ ±q^m)"),
			Rejection::Unverifiable { reason } => write!(f, "unverifiable: {reason}"),
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
	if !generates_lattice(instance, basis) {
		return Err(Rejection::Sublattice);
	}
	let profile =
		profile_exact(basis).map_err(|e| Rejection::Unverifiable { reason: e.to_string() })?;
	let log_volume = profile.log_volume();
	let expected = instance.log_volume();
	if (log_volume - expected).abs() > VOLUME_CONSISTENCY {
		return Err(Rejection::Unverifiable {
			reason: format!("certified log-volume {log_volume} disagrees with {expected}"),
		});
	}
	Ok(Score::from_profile(instance, basis, profile))
}

/// Whether rows already known to lie in the lattice generate all of it:
/// `det B ≡ ±qᵐ` modulo each of [`INDEX_PRIMES`] primes derived from the
/// instance and the basis, with the same sign for every prime.
pub fn generates_lattice(instance: &Instance, basis: &Basis) -> bool {
	let mut sign = None;
	for p in index_primes(instance, basis) {
		let mont = Mont::new(p);
		let det = determinant(&basis.rows, &mont);
		let qm = mont.pow(mont.from_i64(Q), instance.m() as u64);
		let s = if det == qm {
			true
		} else if det == mont.neg(qm) {
			false
		} else {
			return false;
		};
		if sign.is_some_and(|prev| prev != s) {
			return false;
		}
		sign = Some(s);
	}
	true
}

/// Distinct primes in `[2^62, 2^63)`, other than `q`, from a SHAKE256 stream
/// over the instance id and every basis entry.
fn index_primes(instance: &Instance, basis: &Basis) -> [u64; INDEX_PRIMES] {
	let mut state = Shake256State::default();
	shake256_absorb(&mut state, PRIME_DOMAIN);
	shake256_absorb(&mut state, instance.id());
	shake256_absorb(&mut state, &(basis.len() as u64).to_le_bytes());
	let mut buf = Vec::with_capacity(8 * basis.len());
	for row in &basis.rows {
		buf.clear();
		buf.extend(row.iter().flat_map(|x| x.to_le_bytes()));
		shake256_absorb(&mut state, &buf);
	}
	shake256_finalize(&mut state);

	let mut primes = [0u64; INDEX_PRIMES];
	let mut word = [0u8; 8];
	for i in 0..INDEX_PRIMES {
		loop {
			shake256_squeeze(&mut word, &mut state);
			let candidate = (u64::from_le_bytes(word) >> 1) | (1 << 62) | 1;
			let p = next_prime(candidate);
			if p < (1 << 63) && p != Q as u64 && !primes[..i].contains(&p) {
				primes[i] = p;
				break;
			}
		}
	}
	primes
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
	use crate::{
		instance::Variant,
		reducers::{
			lll::{lll, DEFAULT_DELTA, DEFAULT_ETA},
			workspace::Workspace,
		},
	};

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
		for row in [0, inst.dim() - 1] {
			let mut b = inst.start_basis();
			for x in b.rows[row].iter_mut() {
				*x *= 2;
			}
			assert_eq!(verify(&inst, &b), Err(Rejection::Sublattice));
			for x in b.rows[row].iter_mut() {
				*x = -*x;
			}
			assert_eq!(verify(&inst, &b), Err(Rejection::Sublattice));
		}
	}

	#[test]
	fn rejects_dependent_rows() {
		let inst = instance();
		let mut b = inst.start_basis();
		let combo: Vec<i64> = (0..b.len()).map(|k| b.rows[1][k] + b.rows[2][k]).collect();
		b.rows[5] = combo;
		assert_eq!(verify(&inst, &b), Err(Rejection::Sublattice));
	}

	fn lll_reduced(inst: &Instance) -> Basis {
		let d = inst.dim();
		let mut ws = Workspace::new(inst.start_basis().rows);
		assert!(lll(&mut ws, 0, d, DEFAULT_DELTA, DEFAULT_ETA, &mut || false));
		Basis::new(ws.into_rows())
	}

	/// An index-2 sublattice disguised by row additions that make the Gram
	/// matrix badly conditioned: the volume check of an uncertified
	/// floating-point profile accepted this, the determinant check must not.
	#[test]
	fn rejects_disguised_index_two_sublattice() {
		let inst = Instance::generate(Variant::MlDsa44, [42u8; 32], 20, 20).unwrap();
		let d = inst.dim();
		let mut b = lll_reduced(&inst);
		for x in &mut b.rows[d - 1] {
			*x *= 2;
		}
		let orig = b.clone();
		let coefficients = [
			17i64, 3, 17, 18, 4, 13, 1, 10, 1, 9, 10, 14, 11, 2, 5, 16, 12, 10, 8, 11, 12, 11, 17,
			4, 3, 2,
		];
		for (i, c) in (15..d).zip(coefficients) {
			for j in 0..d {
				b.rows[i][j] += c * orig.rows[i - 1][j];
			}
		}
		assert!(b.rows.iter().all(|r| inst.contains(r)));
		assert_eq!(verify(&inst, &b), Err(Rejection::Sublattice));
	}

	/// Row additions that keep the lattice must not move the score: the
	/// certified profile is representation-independent.
	#[test]
	fn score_is_invariant_under_lower_triangular_rewrites() {
		let inst = Instance::generate(Variant::MlDsa44, [42u8; 32], 20, 20).unwrap();
		let d = inst.dim();
		let reduced = lll_reduced(&inst);
		let reference = verify(&inst, &reduced).unwrap();
		let mut b = reduced.clone();
		for i in 1..d {
			for j in 0..d {
				b.rows[i][j] +=
					(4096 - 7 * i as i64) * reduced.rows[i - 1][j] - 3 * reduced.rows[i / 2][j];
			}
		}
		let s = verify(&inst, &b).unwrap();
		assert!(
			(s.score_bits - reference.score_bits).abs() < 1e-6,
			"{} vs {}",
			s.score_bits,
			reference.score_bits
		);
		assert_eq!(s.first_norm, reference.first_norm);
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
