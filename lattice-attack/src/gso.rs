//! Gram–Schmidt profiles and the quantities derived from them.
//!
//! Two implementations of the same computation:
//!
//! - [`profile_f64`]: modified Gram–Schmidt on `f64` copies of the rows. Cheap; used by the harness
//!   for progress traces. Not trusted by the verifier.
//! - [`profile_dd`]: Cholesky factorisation of the exact integer Gram matrix in double-double
//!   arithmetic. Used by the verifier for the score and the volume check, and fails loudly instead
//!   of returning a questionable number.

use core::fmt;

use crate::{basis::Basis, dd::Dd};

/// Natural logs of the Gram–Schmidt lengths `ln ‖b*_i‖`, in basis order.
#[derive(Clone, Debug, PartialEq)]
pub struct Profile {
	pub log_norms: Vec<f64>,
}

impl Profile {
	pub fn dim(&self) -> usize {
		self.log_norms.len()
	}

	/// Log-potential `Σ_i (d − 1 − i) · ln ‖b*_i‖` (0-indexed), in nats.
	pub fn potential(&self) -> f64 {
		let d = self.log_norms.len();
		self.log_norms.iter().enumerate().map(|(i, &l)| (d - 1 - i) as f64 * l).sum()
	}

	/// `ln vol(L) = Σ_i ln ‖b*_i‖`.
	pub fn log_volume(&self) -> f64 {
		self.log_norms.iter().sum()
	}

	/// Least-squares slope of `ln ‖b*_i‖` against `i`. Zero for a flat
	/// profile; negative for a reduced basis.
	pub fn slope(&self) -> f64 {
		let d = self.log_norms.len();
		if d < 2 {
			return 0.0;
		}
		let n = d as f64;
		let mean_i = (n - 1.0) / 2.0;
		let mean_l = self.log_volume() / n;
		let (mut num, mut den) = (0.0, 0.0);
		for (i, &l) in self.log_norms.iter().enumerate() {
			let di = i as f64 - mean_i;
			num += di * (l - mean_l);
			den += di * di;
		}
		num / den
	}

	/// `ln` of the Gaussian heuristic `sqrt(d / 2πe) · vol^{1/d}`: the
	/// expected length of the shortest vector of a random lattice with this
	/// volume.
	pub fn log_gaussian_heuristic(&self) -> f64 {
		let d = self.log_norms.len() as f64;
		0.5 * (d / (2.0 * core::f64::consts::PI * core::f64::consts::E)).ln() +
			self.log_volume() / d
	}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GsoError {
	NotSquare,
	/// Row `index` is (numerically) a combination of the previous rows.
	NonPositivePivot {
		index: usize,
	},
	/// The Gram–Schmidt length of row `index` is so small relative to the row
	/// itself that double-double arithmetic cannot vouch for it.
	IllConditioned {
		index: usize,
	},
}

impl fmt::Display for GsoError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			GsoError::NotSquare => write!(f, "basis is not square"),
			GsoError::NonPositivePivot { index } =>
				write!(f, "row {index} is linearly dependent on earlier rows"),
			GsoError::IllConditioned { index } =>
				write!(f, "row {index} is too ill-conditioned to verify"),
		}
	}
}

impl std::error::Error for GsoError {}

/// Fast approximate profile. Returns `None` if a row is numerically dependent
/// on its predecessors.
pub fn profile_f64(basis: &Basis) -> Option<Profile> {
	if !basis.is_square() {
		return None;
	}
	let d = basis.len();
	let mut bstar: Vec<Vec<f64>> = Vec::with_capacity(d);
	let mut r = Vec::with_capacity(d);
	let mut log_norms = Vec::with_capacity(d);
	for row in &basis.rows {
		let mut v: Vec<f64> = row.iter().map(|&x| x as f64).collect();
		for (bj, &rj) in bstar.iter().zip(&r) {
			let mu = dot_f64(&v, bj) / rj;
			for (vi, bji) in v.iter_mut().zip(bj) {
				*vi -= mu * bji;
			}
		}
		let ri = dot_f64(&v, &v);
		if ri <= 0.0 || !ri.is_finite() {
			return None;
		}
		log_norms.push(0.5 * ri.ln());
		r.push(ri);
		bstar.push(v);
	}
	Some(Profile { log_norms })
}

fn dot_f64(a: &[f64], b: &[f64]) -> f64 {
	a.iter().zip(b).map(|(x, y)| x * y).sum()
}

/// Pivots smaller than `2^-ILL_CONDITIONED_BITS` times the row's squared norm
/// are rejected: double-double carries ~104 bits, so this leaves at least 24
/// bits of relative accuracy in every pivot.
const ILL_CONDITIONED_BITS: i32 = 80;

/// Verifier-grade profile from the exact Gram matrix.
///
/// Entries must be below `2^62 / sqrt(d)` in magnitude for the exact `i128`
/// inner products; the verifier enforces `2^40`.
pub fn profile_dd(basis: &Basis) -> Result<Profile, GsoError> {
	if !basis.is_square() {
		return Err(GsoError::NotSquare);
	}
	let d = basis.len();
	let max_abs = basis.max_abs_entry() as u128;
	let i64_ok = max_abs * max_abs * (d as u128) <= i64::MAX as u128;

	let mut chol: Vec<Vec<Dd>> = Vec::with_capacity(d);
	let mut log_norms = Vec::with_capacity(d);
	let mut gram_row = vec![Dd::ZERO; d];
	for i in 0..d {
		let bi = &basis.rows[i];
		for (g, bj) in gram_row.iter_mut().zip(&basis.rows).take(i + 1) {
			*g = if i64_ok {
				Dd::from_i64(dot_i64(bi, bj))
			} else {
				Dd::from_i128(dot_i128(bi, bj))
			};
		}

		let mut row: Vec<Dd> = Vec::with_capacity(i + 1);
		for j in 0..i {
			let mut acc = gram_row[j];
			for k in 0..j {
				acc = acc - row[k] * chol[j][k];
			}
			row.push(acc / chol[j][j]);
		}
		let mut pivot = gram_row[i];
		for rik in &row {
			pivot = pivot - *rik * *rik;
		}
		if !pivot.is_positive() {
			return Err(GsoError::NonPositivePivot { index: i });
		}
		let floor = gram_row[i] * Dd::from_f64(2f64.powi(-ILL_CONDITIONED_BITS));
		if pivot.lt(floor) {
			return Err(GsoError::IllConditioned { index: i });
		}
		log_norms.push(0.5 * pivot.ln());
		row.push(pivot.sqrt());
		chol.push(row);
	}
	Ok(Profile { log_norms })
}

fn dot_i64(a: &[i64], b: &[i64]) -> i64 {
	a.iter().zip(b).map(|(x, y)| x * y).sum()
}

fn dot_i128(a: &[i64], b: &[i64]) -> i128 {
	a.iter().zip(b).map(|(&x, &y)| x as i128 * y as i128).sum()
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::instance::{Instance, Variant, Q};

	fn basis(rows: &[&[i64]]) -> Basis {
		Basis::new(rows.iter().map(|r| r.to_vec()).collect())
	}

	#[test]
	fn identity_has_flat_zero_profile() {
		let b = basis(&[&[1, 0, 0], &[0, 1, 0], &[0, 0, 1]]);
		for p in [profile_f64(&b).unwrap(), profile_dd(&b).unwrap()] {
			assert_eq!(p.log_norms, vec![0.0, 0.0, 0.0]);
			assert_eq!(p.potential(), 0.0);
			assert_eq!(p.log_volume(), 0.0);
			assert_eq!(p.slope(), 0.0);
		}
	}

	#[test]
	fn triangular_basis_profile_is_its_diagonal() {
		let b = basis(&[&[3, 0], &[4, 5]]);
		for p in [profile_f64(&b).unwrap(), profile_dd(&b).unwrap()] {
			assert!((p.log_norms[0] - 3f64.ln()).abs() < 1e-12);
			assert!((p.log_norms[1] - 5f64.ln()).abs() < 1e-12);
			assert!((p.log_volume() - 15f64.ln()).abs() < 1e-12);
			assert!((p.potential() - 3f64.ln()).abs() < 1e-12);
		}
		// Swapping the rows moves the mass: b*_1 = (4,5), b*_2 has length 15/sqrt(41).
		let swapped = basis(&[&[4, 5], &[3, 0]]);
		let p = profile_dd(&swapped).unwrap();
		assert!((p.log_norms[0] - 41f64.sqrt().ln()).abs() < 1e-12);
		assert!((p.log_volume() - 15f64.ln()).abs() < 1e-12);
		assert!(p.potential() > profile_dd(&b).unwrap().potential());
	}

	#[test]
	fn dependent_rows_are_detected() {
		let b = basis(&[&[1, 2, 3], &[2, 4, 6], &[0, 0, 1]]);
		assert_eq!(profile_dd(&b), Err(GsoError::NonPositivePivot { index: 1 }));
		assert!(profile_f64(&b).is_none());
		assert_eq!(profile_dd(&basis(&[&[1, 2], &[3, 4], &[5, 6]])), Err(GsoError::NotSquare));
	}

	#[test]
	fn start_basis_profile_matches_closed_form() {
		let inst = Instance::generate(Variant::MlDsa44, [5u8; 32], 12, 7).unwrap();
		let p = profile_dd(&inst.start_basis()).unwrap();
		for (i, &l) in p.log_norms.iter().enumerate() {
			let expected = if i < inst.m() { (Q as f64).ln() } else { 0.0 };
			assert!((l - expected).abs() < 1e-9, "row {i}: {l} vs {expected}");
		}
		assert!((p.potential() - inst.start_potential()).abs() < 1e-6);
		assert!((p.log_volume() - inst.log_volume()).abs() < 1e-9);
		assert!(p.slope() < 0.0);
	}

	#[test]
	fn f64_and_dd_agree_on_moderate_bases() {
		let inst = Instance::generate(Variant::MlDsa65, [8u8; 32], 9, 9).unwrap();
		let mut b = inst.start_basis();
		// Unit lower-triangular mix (only earlier rows are added), so the
		// lattice is unchanged but the basis is no longer triangular-ish.
		let orig = b.clone();
		let d = b.len();
		for i in 1..d {
			for k in 0..d {
				b.rows[i][k] += 3 * orig.rows[i - 1][k] - orig.rows[i / 2][k];
			}
		}
		let fast = profile_f64(&b).unwrap();
		let exact = profile_dd(&b).unwrap();
		for (a, e) in fast.log_norms.iter().zip(&exact.log_norms) {
			assert!((a - e).abs() < 1e-6, "{a} vs {e}");
		}
		assert!((exact.log_volume() - inst.log_volume()).abs() < 1e-9);
	}

	#[test]
	fn large_entries_fall_back_to_i128_products() {
		let big = 1i64 << 40;
		let b = basis(&[&[big, 1], &[1, big]]);
		let p = profile_dd(&b).unwrap();
		let expected_vol = ((big as f64).powi(2) - 1.0).ln();
		assert!((p.log_volume() - expected_vol).abs() < 1e-9);
	}

	#[test]
	fn gaussian_heuristic_scales_with_volume() {
		let p = Profile { log_norms: vec![0.0; 100] };
		assert!(
			(p.log_gaussian_heuristic() -
				0.5 * (100.0 / (2.0 * core::f64::consts::PI * core::f64::consts::E)).ln())
			.abs() < 1e-12
		);
	}
}
