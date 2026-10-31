//! Gram–Schmidt profiles and the quantities derived from them.
//!
//! Two implementations of the same computation:
//!
//! - [`profile_f64`]: Householder QR on `f64` copies of the rows. Cheap; used by the harness for
//!   progress traces. Not trusted by the verifier, and returns `None` once the dimension outgrows
//!   `f64` (around d ≈ 700 for ML-DSA bases).
//! - [`profile_exact`]: Cholesky factorisation of the exact integer Gram matrix in fixed-point
//!   `BigInt` arithmetic, with the number of fractional bits chosen from the dimension and raised
//!   on failure. Used by the verifier for the score and the volume check, and fails loudly instead
//!   of returning a questionable number.
//!
//! Why so much precision: the Gram matrix of a reduced basis is extremely ill-conditioned even
//! when every Gram–Schmidt length is around 1, because the coordinates of a row with respect to
//! the rows before it grow exponentially with the dimension. Fixed-precision Cholesky (including
//! double-double) loses the small pivots entirely once the dimension passes a few hundred.

use core::fmt;

use num_bigint::{BigInt, Sign};
use num_traits::{ToPrimitive, Zero};

use crate::basis::Basis;

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
	/// itself that the arithmetic cannot vouch for it.
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

/// A Gram–Schmidt length below this fraction of the row's length is treated
/// as zero: `f64` Householder QR leaves noise of about `2^-47` times the row
/// length in the tail of a dependent row, while a genuine Gram–Schmidt length
/// of a size-reduced ML-DSA row is at least about `2^-32` of its length.
pub const F64_DEPENDENCE_RATIO: f64 = 1e-12;

/// Fast approximate profile by Householder QR. Returns `None` if a row is
/// numerically dependent on its predecessors.
pub fn profile_f64(basis: &Basis) -> Option<Profile> {
	if !basis.is_square() {
		return None;
	}
	let d = basis.len();
	let mut refl: Vec<Vec<f64>> = Vec::with_capacity(d);
	let mut tau = Vec::with_capacity(d);
	let mut log_norms = Vec::with_capacity(d);
	for (k, row) in basis.rows.iter().enumerate() {
		let mut x: Vec<f64> = row.iter().map(|&x| x as f64).collect();
		let row_norm = dot_f64(&x, &x).sqrt();
		for (j, (v, &t)) in refl.iter().zip(&tau).enumerate() {
			let s = t * dot_f64(&x[j..], &v[j..]);
			if s != 0.0 {
				for (xi, vi) in x[j..].iter_mut().zip(&v[j..]) {
					*xi -= s * vi;
				}
			}
		}
		let norm = dot_f64(&x[k..], &x[k..]).sqrt();
		if norm.is_nan() || norm <= row_norm * F64_DEPENDENCE_RATIO {
			return None;
		}
		let alpha = if x[k] > 0.0 { -norm } else { norm };
		let mut v = vec![0.0; d];
		v[k..].copy_from_slice(&x[k..]);
		v[k] -= alpha;
		tau.push(2.0 / dot_f64(&v[k..], &v[k..]));
		refl.push(v);
		log_norms.push(norm.ln());
	}
	Some(Profile { log_norms })
}

fn dot_f64(a: &[f64], b: &[f64]) -> f64 {
	a.iter().zip(b).map(|(x, y)| x * y).sum()
}

/// Pivots smaller than `2^-ILL_CONDITIONED_BITS` times the row's squared norm
/// are rejected rather than trusted.
const ILL_CONDITIONED_BITS: u32 = 80;

/// Fractional bits for the first attempt at dimension `d`. On reduced ML-DSA
/// bases the pivots need about 54 bits for the magnitude of the Gram entries
/// plus one bit per 20 rows (a d = 801 basis is exact to 1e-7 nats at 104
/// bits and off by nats at 80). This leaves a margin of 74 bits plus a fifth
/// of a bit per row, and [`profile_exact`] doubles it if the attempt fails.
pub fn frac_bits_for(d: usize) -> u32 {
	128 + (d as u32) / 4
}

const MAX_FRAC_BITS: u32 = 8192;

/// Verifier-grade profile from the exact Gram matrix, retrying with more
/// precision while the factorisation fails and the cap allows.
pub fn profile_exact(basis: &Basis) -> Result<Profile, GsoError> {
	let mut bits = frac_bits_for(basis.len());
	loop {
		match profile_fixed(basis, bits) {
			Err(GsoError::NonPositivePivot { .. } | GsoError::IllConditioned { .. })
				if bits < MAX_FRAC_BITS =>
				bits = (2 * bits).min(MAX_FRAC_BITS),
			other => return other,
		}
	}
}

/// Cholesky factorisation of the exact Gram matrix in fixed-point arithmetic
/// with `frac_bits` fractional bits. Entries must be below `2^62 / sqrt(d)`
/// in magnitude for the exact inner products; the verifier enforces `2^40`.
pub fn profile_fixed(basis: &Basis, frac_bits: u32) -> Result<Profile, GsoError> {
	if !basis.is_square() {
		return Err(GsoError::NotSquare);
	}
	let d = basis.len();
	let max_abs = basis.max_abs_entry() as u128;
	let i64_ok = max_abs * max_abs * (d as u128) <= i64::MAX as u128;
	let shift = frac_bits as usize;

	let mut chol: Vec<Vec<BigInt>> = Vec::with_capacity(d);
	let mut log_norms = Vec::with_capacity(d);
	for i in 0..d {
		let bi = &basis.rows[i];
		let gram: Vec<BigInt> = basis.rows[..=i]
			.iter()
			.map(|bj| {
				let g = if i64_ok { dot_i64(bi, bj) as i128 } else { dot_i128(bi, bj) };
				BigInt::from(g) << shift
			})
			.collect();

		let mut row: Vec<BigInt> = Vec::with_capacity(i + 1);
		for j in 0..i {
			let mut acc = gram[j].clone();
			for (rik, cjk) in row.iter().zip(&chol[j]) {
				acc -= (rik * cjk) >> shift;
			}
			row.push((acc << shift) / &chol[j][j]);
		}
		let mut pivot = gram[i].clone();
		for rik in &row {
			pivot -= (rik * rik) >> shift;
		}
		if pivot.sign() != Sign::Plus {
			return Err(GsoError::NonPositivePivot { index: i });
		}
		if pivot < (&gram[i] >> ILL_CONDITIONED_BITS) {
			return Err(GsoError::IllConditioned { index: i });
		}
		log_norms.push(0.5 * (ln_big(&pivot) - frac_bits as f64 * core::f64::consts::LN_2));
		row.push(isqrt(&(pivot << shift)));
		chol.push(row);
	}
	Ok(Profile { log_norms })
}

/// Natural log of a positive `BigInt`, to `f64` relative precision.
fn ln_big(x: &BigInt) -> f64 {
	let bits = x.bits();
	let drop = bits.saturating_sub(62);
	let mantissa = (x >> drop).to_f64().expect("at most 62 bits");
	mantissa.ln() + drop as f64 * core::f64::consts::LN_2
}

/// Floor of the square root of a non-negative `BigInt`.
fn isqrt(n: &BigInt) -> BigInt {
	if n.is_zero() {
		return BigInt::zero();
	}
	let mut x: BigInt = BigInt::from(1) << n.bits().div_ceil(2);
	loop {
		let y: BigInt = (&x + n / &x) >> 1;
		if y >= x {
			return x;
		}
		x = y;
	}
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
		for p in [profile_f64(&b).unwrap(), profile_exact(&b).unwrap()] {
			assert_eq!(p.log_norms, vec![0.0, 0.0, 0.0]);
			assert_eq!(p.potential(), 0.0);
			assert_eq!(p.log_volume(), 0.0);
			assert_eq!(p.slope(), 0.0);
		}
	}

	#[test]
	fn triangular_basis_profile_is_its_diagonal() {
		let b = basis(&[&[3, 0], &[4, 5]]);
		for p in [profile_f64(&b).unwrap(), profile_exact(&b).unwrap()] {
			assert!((p.log_norms[0] - 3f64.ln()).abs() < 1e-12);
			assert!((p.log_norms[1] - 5f64.ln()).abs() < 1e-12);
			assert!((p.log_volume() - 15f64.ln()).abs() < 1e-12);
			assert!((p.potential() - 3f64.ln()).abs() < 1e-12);
		}
		// Swapping the rows moves the mass: b*_1 = (4,5), b*_2 has length 15/sqrt(41).
		let swapped = basis(&[&[4, 5], &[3, 0]]);
		let p = profile_exact(&swapped).unwrap();
		assert!((p.log_norms[0] - 41f64.sqrt().ln()).abs() < 1e-12);
		assert!((p.log_volume() - 15f64.ln()).abs() < 1e-12);
		assert!(p.potential() > profile_exact(&b).unwrap().potential());
	}

	#[test]
	fn dependent_rows_are_detected() {
		let b = basis(&[&[1, 2, 3], &[2, 4, 6], &[0, 0, 1]]);
		assert_eq!(profile_exact(&b), Err(GsoError::NonPositivePivot { index: 1 }));
		assert!(profile_f64(&b).is_none());
		assert_eq!(profile_exact(&basis(&[&[1, 2], &[3, 4], &[5, 6]])), Err(GsoError::NotSquare));
	}

	#[test]
	fn start_basis_profile_matches_closed_form() {
		let inst = Instance::generate(Variant::MlDsa44, [5u8; 32], 12, 7).unwrap();
		let p = profile_exact(&inst.start_basis()).unwrap();
		for (i, &l) in p.log_norms.iter().enumerate() {
			let expected = if i < inst.m() { (Q as f64).ln() } else { 0.0 };
			assert!((l - expected).abs() < 1e-9, "row {i}: {l} vs {expected}");
		}
		assert!((p.potential() - inst.start_potential()).abs() < 1e-6);
		assert!((p.log_volume() - inst.log_volume()).abs() < 1e-9);
		assert!(p.slope() < 0.0);
	}

	#[test]
	fn f64_and_exact_agree_on_moderate_bases() {
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
		let exact = profile_exact(&b).unwrap();
		// Householder errors are relative to the largest row, not to each
		// Gram–Schmidt length, so the fast path is only good to ~1e-4 here.
		for (a, e) in fast.log_norms.iter().zip(&exact.log_norms) {
			assert!((a - e).abs() < 1e-4, "{a} vs {e}");
		}
		assert!((exact.log_volume() - inst.log_volume()).abs() < 1e-9);
	}

	#[test]
	fn large_entries_fall_back_to_i128_products() {
		let big = 1i64 << 40;
		let b = basis(&[&[big, 1], &[1, big]]);
		let p = profile_exact(&b).unwrap();
		let expected_vol = ((big as f64).powi(2) - 1.0).ln();
		assert!((p.log_volume() - expected_vol).abs() < 1e-9);
	}

	#[test]
	fn isqrt_is_floor_sqrt() {
		for n in [0u64, 1, 2, 3, 4, 15, 16, 17, 1 << 40, (1 << 40) + 1, u64::MAX] {
			let r = isqrt(&BigInt::from(n));
			assert!(&r * &r <= BigInt::from(n));
			assert!((&r + 1) * (&r + 1) > BigInt::from(n));
		}
		let big = BigInt::from(1) << 200;
		assert_eq!(isqrt(&big), BigInt::from(1) << 100);
	}

	#[test]
	fn ln_big_matches_f64_and_handles_huge_values() {
		assert!((ln_big(&BigInt::from(1_000_000)) - 1e6f64.ln()).abs() < 1e-12);
		let huge = BigInt::from(3) << 2000;
		assert!((ln_big(&huge) - (3f64.ln() + 2000.0 * core::f64::consts::LN_2)).abs() < 1e-9);
	}

	#[test]
	fn more_fractional_bits_do_not_change_a_well_conditioned_profile() {
		let inst = Instance::generate(Variant::MlDsa44, [9u8; 32], 20, 20).unwrap();
		let b = inst.start_basis();
		let a = profile_fixed(&b, 64).unwrap();
		let c = profile_fixed(&b, 512).unwrap();
		for (x, y) in a.log_norms.iter().zip(&c.log_norms) {
			assert!((x - y).abs() < 1e-9);
		}
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
