//! Gram–Schmidt profiles and the quantities derived from them.
//!
//! Two implementations of the same computation:
//!
//! - [`profile_f64`]: the reducers' `f64` Householder QR. Cheap; used by the harness for progress
//!   traces. Not trusted by the verifier.
//! - [`profile_exact`]: the verifier's profile, with a certified error bound. The basis is
//!   size-reduced with exact integer row operations (which leaves every Gram–Schmidt length
//!   unchanged), its exact integer Gram matrix is Cholesky-factored in fixed-point `BigInt`
//!   arithmetic, and an a posteriori bound shows that the factorisation determines the
//!   log-potential to within [`CERTIFIED_TOLERANCE`]. If the bound does not hold at the precision
//!   used, the precision is raised and the factorisation repeated.
//!
//! # The certificate
//!
//! Write `G` for the exact Gram matrix and `L` for the computed lower-triangular factor, an exact
//! rational matrix with `F` fractional bits, so `G ≈ L·Lᵀ`. The algorithm truncates once per entry,
//! which bounds every entry of `E = G − L·Lᵀ` by `(2·max_j L_jj + 1)·2^{-F}` in magnitude. For
//! every leading `i × i` block, `det G_i / det (L·Lᵀ)_i = det(I + S_i)` with
//! `‖S_i‖₂ ≤ ‖L⁻¹‖₂² · ‖E‖₂`, and `‖L⁻¹‖₂ ≤ ‖U⁻¹‖_F / min_j L_jj` where `U = diag(L)⁻¹·L` is unit
//! triangular with off-diagonal entries of magnitude at most `η`, so `‖U⁻¹‖_F² ≤ d·(1+η)^{2(d−1)}`.
//! The log-potential is half the sum of the log leading minors, which turns a bound `s` on every
//! `‖S_i‖₂` into a bound `s·d²/2` on the potential and `d·s` on the log-volume.
//!
//! The required precision is therefore about `2·d·log₂(1+η)` bits plus the magnitude of the
//! entries. Size reduction comes first because it bounds `η` by about `1/2`: without it `η` is
//! whatever the submitter chose, and so is the precision.

use core::{f64::consts::LN_2, fmt};
use std::thread;

use num_bigint::{BigInt, Sign};
use num_traits::{FromPrimitive, Signed, ToPrimitive, Zero};

use crate::{
	basis::{sub_multiple_big, sub_multiple_i64, Basis, MAX_COEFFICIENT},
	reducers::workspace::Workspace,
};

/// Natural logs of the Gram–Schmidt lengths `ln ‖b*_i‖`, in basis order.
#[derive(Clone, Debug, PartialEq)]
pub struct Profile {
	pub log_norms: Vec<f64>,
}

impl Profile {
	/// From squared Gram–Schmidt norms `‖b*_i‖²`.
	pub fn from_squared_norms(r: &[f64]) -> Profile {
		Profile { log_norms: r.iter().map(|x| 0.5 * x.ln()).collect() }
	}

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

	/// `ln` of the Gaussian heuristic for this lattice; see
	/// [`log_gaussian_heuristic`].
	pub fn log_gaussian_heuristic(&self) -> f64 {
		log_gaussian_heuristic(self.log_norms.len(), self.log_volume())
	}
}

/// `ln` of the Gaussian heuristic for a lattice of dimension `d` with the
/// given log-volume: the radius of the `d`-ball whose volume equals the
/// lattice volume, `(vol · Γ(d/2 + 1) / π^{d/2})^{1/d}`, which is the expected
/// length of the shortest vector of a random lattice. Exact in `d`, not the
/// `sqrt(d / 2πe)` asymptotic (8 % off at `d = 30`).
pub fn log_gaussian_heuristic(d: usize, log_volume: f64) -> f64 {
	if d == 0 {
		return 0.0;
	}
	let n = d as f64;
	(log_volume + ln_gamma_half(d) - 0.5 * n * core::f64::consts::PI.ln()) / n
}

/// `ln Γ(n/2 + 1)`.
fn ln_gamma_half(n: usize) -> f64 {
	if n.is_multiple_of(2) {
		(1..=n / 2).map(|k| (k as f64).ln()).sum()
	} else {
		0.5 * core::f64::consts::PI.ln() +
			(1..=n.div_ceil(2)).map(|j| (j as f64 - 0.5).ln()).sum::<f64>()
	}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GsoError {
	NotSquare,
	/// An entry reaches `2^MAX_PROFILE_ENTRY_BITS` in magnitude.
	EntryTooLarge {
		row: usize,
		col: usize,
	},
	/// Row `index` is a combination of the previous rows (or indistinguishable
	/// from one at the highest precision tried).
	NonPositivePivot {
		index: usize,
	},
	/// The certificate would need more than the maximum precision.
	Uncertified {
		bits: u32,
	},
	/// Size reduction did not finish within `MAX_REDUCTION_PASSES`: the input
	/// is very far from size-reduced.
	Unreduced,
}

impl fmt::Display for GsoError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			GsoError::NotSquare => write!(f, "basis is not square"),
			GsoError::EntryTooLarge { row, col } =>
				write!(f, "entry ({row}, {col}) exceeds 2^{MAX_PROFILE_ENTRY_BITS}"),
			GsoError::NonPositivePivot { index } =>
				write!(f, "row {index} is linearly dependent on earlier rows"),
			GsoError::Uncertified { bits } =>
				write!(f, "profile would need {bits} fractional bits to certify"),
			GsoError::Unreduced =>
				write!(f, "basis not size-reduced after {MAX_REDUCTION_PASSES} passes"),
		}
	}
}

impl std::error::Error for GsoError {}

/// Fast approximate profile by `f64` Householder QR. Returns `None` if a row
/// is numerically dependent on its predecessors.
pub fn profile_f64(basis: &Basis) -> Option<Profile> {
	if !basis.is_square() {
		return None;
	}
	let mut ws = Workspace::new(basis.rows.clone());
	ws.ensure(basis.len());
	if !ws.r.iter().all(|&r| r > 0.0) {
		return None;
	}
	Some(Profile::from_squared_norms(&ws.r))
}

/// Entries must stay below this for the exact `i128` Gram matrix; the
/// verifier's own input bound is tighter, and size reduction of a basis within
/// that bound cannot reach this one.
pub const MAX_PROFILE_ENTRY_BITS: u32 = 52;

/// Bound on the error of the certified log-potential, in nats (the `f64`
/// summation of the profile adds about `d² · 10⁻¹⁴` on top).
pub const CERTIFIED_TOLERANCE: f64 = 1e-6;

/// Size reduction in the verifier rounds coefficients whose `|μ|` exceeds
/// this. It matches the reducers' default `η`, so their output is left alone.
const REDUCE_ABOVE: f64 = 0.51;

const SAFETY_BITS: f64 = 16.0;
const MAX_FRAC_BITS: u32 = 1 << 14;
/// Each pass costs a factorisation. Reducer output needs at most two (the
/// second confirms), and every pass reduces at least one more row.
const MAX_REDUCTION_PASSES: u32 = 8;
/// Products per column below which the Cholesky column is computed serially.
const PARALLEL_THRESHOLD: usize = 1 << 15;

/// Fractional bits the certificate needs for dimension `d`, observed maximum
/// `|μ|` of `η`, and Gram–Schmidt lengths between `2^log2_rmin` and
/// `2^log2_rmax`.
fn required_bits(d: usize, eta: f64, log2_rmax: f64, log2_rmin: f64) -> u32 {
	let n = d as f64;
	let need = 4.0 * n.log2() + (2.0 + log2_rmax.max(0.0)) + 2.0 * (n - 1.0) * (1.0 + eta).log2() -
		2.0 * log2_rmin -
		CERTIFIED_TOLERANCE.log2() +
		SAFETY_BITS;
	if need.is_nan() {
		u32::MAX
	} else {
		need.max(0.0).ceil() as u32
	}
}

/// Fractional bits for the first attempt at dimension `d`: enough to certify
/// a size-reduced basis whose Gram–Schmidt lengths lie between `1/4` and
/// `2^47` (the largest possible under the verifier's entry bound).
pub fn frac_bits_for(d: usize) -> u32 {
	required_bits(d, REDUCE_ABOVE, 47.0, -2.0)
}

/// Verifier-grade profile with a certified error bound; see the module
/// documentation. Fails only for non-square input, oversized entries,
/// dependent rows, input that would need more than `2^14` fractional bits, or
/// input so far from size-reduced that eight reduction passes do not finish.
pub fn profile_exact(basis: &Basis) -> Result<Profile, GsoError> {
	if !basis.is_square() {
		return Err(GsoError::NotSquare);
	}
	let limit = 1u64 << MAX_PROFILE_ENTRY_BITS;
	for (row, r) in basis.rows.iter().enumerate() {
		if let Some(col) = r.iter().position(|x| x.unsigned_abs() >= limit) {
			return Err(GsoError::EntryTooLarge { row, col });
		}
	}
	let d = basis.len();
	if d == 0 {
		return Ok(Profile { log_norms: Vec::new() });
	}

	let mut rows = basis.rows.clone();
	let mut bits = frac_bits_for(d);
	let mut passes = 0;
	loop {
		let mut fac = match cholesky(&gram_matrix(&rows), bits) {
			Ok(fac) => fac,
			Err(index) => {
				if bits >= MAX_FRAC_BITS {
					return Err(GsoError::NonPositivePivot { index });
				}
				bits = (2 * bits).min(MAX_FRAC_BITS);
				continue;
			},
		};
		if size_reduce(&mut rows, &mut fac) {
			passes += 1;
			if passes > MAX_REDUCTION_PASSES {
				return Err(GsoError::Unreduced);
			}
			continue;
		}
		match fac.required_bits() {
			need if need <= bits => return Ok(fac.profile()),
			need if need > MAX_FRAC_BITS => return Err(GsoError::Uncertified { bits: need }),
			need => bits = need.max(bits + 1),
		}
	}
}

/// Uncertified fixed-point Cholesky profile at a given precision, without
/// size reduction. For experiments and tests; the verifier uses
/// [`profile_exact`].
pub fn profile_fixed(basis: &Basis, frac_bits: u32) -> Result<Profile, GsoError> {
	if !basis.is_square() {
		return Err(GsoError::NotSquare);
	}
	cholesky(&gram_matrix(&basis.rows), frac_bits)
		.map(|fac| fac.profile())
		.map_err(|index| GsoError::NonPositivePivot { index })
}

fn parallelism() -> usize {
	thread::available_parallelism().map_or(1, |n| n.get().min(32))
}

/// Lower triangle of the exact Gram matrix. Entries below
/// `2^MAX_PROFILE_ENTRY_BITS` keep every inner product inside `i128`.
fn gram_matrix(rows: &[Vec<i64>]) -> Vec<Vec<i128>> {
	let d = rows.len();
	let mut gram: Vec<Vec<i128>> = (0..d).map(|i| vec![0; i + 1]).collect();
	let fill = |i: usize, out: &mut Vec<i128>| {
		for (j, g) in out.iter_mut().enumerate() {
			*g = rows[i].iter().zip(&rows[j]).map(|(&x, &y)| x as i128 * y as i128).sum();
		}
	};
	let threads = parallelism();
	if threads > 1 && d * d * d / 2 >= PARALLEL_THRESHOLD {
		let chunk = d.div_ceil(threads);
		thread::scope(|s| {
			for (c, part) in gram.chunks_mut(chunk).enumerate() {
				let fill = &fill;
				s.spawn(move || {
					for (t, out) in part.iter_mut().enumerate() {
						fill(c * chunk + t, out);
					}
				});
			}
		});
	} else {
		for (i, out) in gram.iter_mut().enumerate() {
			fill(i, out);
		}
	}
	gram
}

/// Fixed-point Cholesky factor: `r[i][j]` for `j <= i` is `L_ij · 2^bits`,
/// where `L_ij = μ_ij · ‖b*_j‖` and `L_ii = ‖b*_i‖`.
struct Factor {
	r: Vec<Vec<BigInt>>,
	bits: u32,
}

/// Cholesky factorisation of the Gram matrix in fixed-point arithmetic,
/// column by column, with the rows of each column computed in parallel. On a
/// non-positive pivot returns the row index.
fn cholesky(gram: &[Vec<i128>], bits: u32) -> Result<Factor, usize> {
	let d = gram.len();
	let shift = bits as usize;
	let mut r: Vec<Vec<BigInt>> = (0..d).map(|i| vec![BigInt::zero(); i + 1]).collect();
	let threads = parallelism();
	for j in 0..d {
		let (head, tail) = r.split_at_mut(j + 1);
		let rj = &mut head[j];
		let sum = dot_big(&rj[..j], &rj[..j]);
		let pivot = (BigInt::from(gram[j][j]) << shift) - (sum >> shift);
		if pivot.sign() != Sign::Plus {
			return Err(j);
		}
		rj[j] = isqrt(&(pivot << shift));
		let rj: &Vec<BigInt> = rj;

		let column = |i: usize, row: &mut Vec<BigInt>| {
			let sum = dot_big(&row[..j], &rj[..j]);
			let acc = (BigInt::from(gram[i][j]) << shift) - (sum >> shift);
			row[j] = (acc << shift) / &rj[j];
		};
		if threads > 1 && tail.len() * j >= PARALLEL_THRESHOLD {
			let chunk = tail.len().div_ceil(threads);
			thread::scope(|s| {
				for (c, part) in tail.chunks_mut(chunk).enumerate() {
					let column = &column;
					s.spawn(move || {
						for (t, row) in part.iter_mut().enumerate() {
							column(j + 1 + c * chunk + t, row);
						}
					});
				}
			});
		} else {
			for (t, row) in tail.iter_mut().enumerate() {
				column(j + 1 + t, row);
			}
		}
	}
	Ok(Factor { r, bits })
}

fn dot_big(a: &[BigInt], b: &[BigInt]) -> BigInt {
	let mut sum = BigInt::zero();
	for (x, y) in a.iter().zip(b) {
		if !x.is_zero() && !y.is_zero() {
			sum += x * y;
		}
	}
	sum
}

impl Factor {
	fn profile(&self) -> Profile {
		Profile {
			log_norms: self
				.r
				.iter()
				.enumerate()
				.map(|(i, row)| ln_scaled(&row[i], self.bits))
				.collect(),
		}
	}

	/// Fractional bits at which the certificate holds for the observed
	/// `η`, largest and smallest Gram–Schmidt length.
	fn required_bits(&self) -> u32 {
		let f = self.bits as f64;
		let (mut log2_rmax, mut log2_rmin, mut log2_eta) =
			(f64::NEG_INFINITY, f64::INFINITY, f64::NEG_INFINITY);
		for (i, row) in self.r.iter().enumerate() {
			let diag = log2_big(&row[i]);
			log2_rmax = log2_rmax.max(diag);
			log2_rmin = log2_rmin.min(diag);
			for (j, x) in row[..i].iter().enumerate() {
				if !x.is_zero() {
					log2_eta = log2_eta.max(log2_big(&x.abs()) - log2_big(&self.r[j][j]));
				}
			}
		}
		required_bits(self.r.len(), log2_eta.exp2(), log2_rmax - f, log2_rmin - f)
	}
}

/// Size-reduce `rows` with the coefficients implied by `fac`, using exact
/// integer row operations (rows of the result are the same lattice basis with
/// the same Gram–Schmidt lengths). Returns whether anything changed.
///
/// The factor rows are updated along with the basis rows, `r_k -= c·r_j`, in
/// the fixed-point arithmetic of the factor. The error of a reduced row's
/// factor row grows with the product of the coefficients applied along the
/// chain of rows it depends on, so a reduced row is kept only if it is at most
/// as long as a row with every `|μ| ≤ ACCEPT_MU` could be; otherwise it is
/// left alone for this pass. The earliest row still needing reduction always
/// has exact coefficients, so every pass makes progress.
fn size_reduce(rows: &mut [Vec<i64>], fac: &mut Factor) -> bool {
	const ACCEPT_MU: f64 = 2.0;
	let d = rows.len();
	let gs_norm_sq: Vec<f64> =
		(0..d).map(|i| (2.0 * ln_scaled(&fac.r[i][i], fac.bits)).exp()).collect();
	let mut earlier_sum = gs_norm_sq[0];
	let mut changed = false;
	for k in 1..d {
		let bound = (gs_norm_sq[k] + ACCEPT_MU * ACCEPT_MU * earlier_sum) * (1.0 + 1e-9);
		earlier_sum += gs_norm_sq[k];
		let (r_earlier, r_rest) = fac.r.split_at_mut(k);
		let r_k = &mut r_rest[0];
		let mu = |r_k: &[BigInt], j: usize| ratio_f64(&r_k[j], &r_earlier[j][j]);
		if !(0..k).any(|j| mu(r_k, j).abs() > REDUCE_ABOVE) {
			continue;
		}
		let (earlier, rest) = rows.split_at_mut(k);
		let mut row_k = rest[0].clone();
		let saved_r_k = r_k[..k].to_vec();
		let mut big: Option<Vec<BigInt>> = None;
		for j in (0..k).rev() {
			let m = mu(r_k, j);
			if m.abs() <= REDUCE_ABOVE || m.is_nan() {
				continue;
			}
			let c = m.round().clamp(-MAX_COEFFICIENT, MAX_COEFFICIENT);
			match &mut big {
				Some(b) => sub_multiple_big(b, &earlier[j], c, 0),
				None =>
					if let Err(done) = sub_multiple_i64(&mut row_k, &earlier[j], c) {
						let mut b: Vec<BigInt> = row_k.iter().map(|&x| BigInt::from(x)).collect();
						sub_multiple_big(&mut b, &earlier[j], c, done);
						big = Some(b);
					},
			}
			let cb = BigInt::from_f64(c).expect("finite integer coefficient");
			for (x, y) in r_k[..=j].iter_mut().zip(&r_earlier[j]) {
				if !y.is_zero() {
					*x -= &cb * y;
				}
			}
		}
		let accepted = big
			.map_or(Some(row_k), |b| {
				b.iter().map(ToPrimitive::to_i64).collect::<Option<Vec<i64>>>()
			})
			.filter(|row| row.iter().map(|&x| (x as f64) * (x as f64)).sum::<f64>() <= bound);
		match accepted {
			Some(row) => {
				rest[0] = row;
				changed = true;
			},
			None => r_k[..k].clone_from_slice(&saved_r_k),
		}
	}
	changed
}

/// `a / b` as `f64` for `b > 0`, `±inf` when out of range.
fn ratio_f64(a: &BigInt, b: &BigInt) -> f64 {
	let drop = b.bits().saturating_sub(60);
	let bf = (b >> drop).to_f64().expect("at most 60 bits");
	match (a >> drop).to_f64() {
		Some(af) => af / bf,
		None if a.sign() == Sign::Minus => f64::NEG_INFINITY,
		None => f64::INFINITY,
	}
}

/// `log2` of a positive `BigInt`, to `f64` relative precision.
fn log2_big(x: &BigInt) -> f64 {
	let drop = x.bits().saturating_sub(62);
	(x >> drop).to_f64().expect("at most 62 bits").log2() + drop as f64
}

/// `ln(x / 2^frac_bits)` for positive `x`, accurate to about `1e-14` absolute
/// even when `x` is thousands of bits long.
fn ln_scaled(x: &BigInt, frac_bits: u32) -> f64 {
	let drop = x.bits().saturating_sub(62);
	let mantissa = (x >> drop).to_f64().expect("at most 62 bits");
	mantissa.ln() + (drop as f64 - frac_bits as f64) * LN_2
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

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{
		instance::{Instance, Variant, Q},
		reducers::lll::{lll, DEFAULT_DELTA, DEFAULT_ETA},
	};

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
		let big = 1i64 << MAX_PROFILE_ENTRY_BITS;
		assert_eq!(
			profile_exact(&basis(&[&[1, 0], &[0, big]])),
			Err(GsoError::EntryTooLarge { row: 1, col: 1 })
		);
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

	/// Adding large multiples of earlier rows makes the Gram matrix as
	/// ill-conditioned as the submitter likes; the certified profile must
	/// come out the same as for the reduced basis it was made from.
	#[test]
	fn profile_is_invariant_under_badly_conditioned_rewrites() {
		let inst = Instance::generate(Variant::MlDsa44, [42u8; 32], 20, 20).unwrap();
		let d = inst.dim();
		let mut ws = Workspace::new(inst.start_basis().rows);
		assert!(lll(&mut ws, 0, d, DEFAULT_DELTA, DEFAULT_ETA, &mut || false));
		let reduced = Basis::new(ws.into_rows());
		let reference = profile_exact(&reduced).unwrap();

		let mut b = reduced.clone();
		let coefficients = [
			17i64, 3, 17, 18, 4, 13, 1, 10, 1, 9, 10, 14, 11, 2, 5, 16, 12, 10, 8, 11, 12, 11, 17,
			4, 3, 2,
		];
		for (i, c) in (15..d).zip(coefficients) {
			for j in 0..d {
				b.rows[i][j] += c * reduced.rows[i - 1][j];
			}
		}
		let mut all_rows = reduced.clone();
		for i in 1..d {
			for j in 0..d {
				all_rows.rows[i][j] += 4096 * reduced.rows[i - 1][j];
			}
		}
		for rewritten in [b, all_rows] {
			let p = profile_exact(&rewritten).unwrap();
			for (x, y) in p.log_norms.iter().zip(&reference.log_norms) {
				assert!((x - y).abs() < 1e-9, "{x} vs {y}");
			}
			assert!((p.potential() - reference.potential()).abs() < 1e-6);
		}
	}

	/// Row 1 reduced against row 0 keeps a residual projection onto it, so
	/// the acceptance bound at `k = 1` must include `‖b*_0‖²`.
	#[test]
	fn residual_projection_onto_the_first_row_is_accepted() {
		let inst = Instance::generate(Variant::MlDsa44, [42u8; 32], 600, 1).unwrap();
		let start = inst.start_basis();
		let reference = profile_exact(&start).unwrap();
		let mut b = start.clone();
		for j in 0..inst.dim() {
			b.rows[1][j] += 65536 * start.rows[0][j];
		}
		let p = profile_exact(&b).unwrap();
		for (x, y) in p.log_norms.iter().zip(&reference.log_norms) {
			assert!((x - y).abs() < 1e-9, "{x} vs {y}");
		}
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
	fn logs_of_big_integers() {
		assert!((ln_scaled(&BigInt::from(1_000_000), 0) - 1e6f64.ln()).abs() < 1e-12);
		let huge = BigInt::from(3) << 2000;
		assert!((ln_scaled(&huge, 2000) - 3f64.ln()).abs() < 1e-13);
		assert!((log2_big(&huge) - (2000.0 + 3f64.log2())).abs() < 1e-9);
		assert!(
			(ratio_f64(&(BigInt::from(-5) << 3000), &(BigInt::from(2) << 3000)) + 2.5).abs() <
				1e-12
		);
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
	fn required_bits_grow_linearly_with_dimension_and_eta() {
		let small = required_bits(100, 0.5, 23.0, 0.0);
		let large = required_bits(2049, 0.5, 23.0, 0.0);
		assert!(large > small + 2200 && large < small + 2400, "{small} {large}");
		assert!(required_bits(100, 17.0, 23.0, 0.0) > required_bits(100, 0.5, 23.0, 0.0) + 600);
		assert_eq!(required_bits(100, f64::INFINITY, 0.0, 0.0), u32::MAX);
	}

	#[test]
	fn gaussian_heuristic_is_exact_in_small_dimension() {
		// Unit volume in dimension 2: the disc of area 1 has radius 1/sqrt(pi).
		assert!((log_gaussian_heuristic(2, 0.0) + 0.5 * core::f64::consts::PI.ln()).abs() < 1e-12);
		// Dimension 1: the "ball" of length 1 has radius 1/2.
		assert!((log_gaussian_heuristic(1, 0.0) - 0.5f64.ln()).abs() < 1e-12);
		// Large d approaches sqrt(d / 2πe), with Stirling's (πd)^(1/2d) correction.
		let d = 2000.0;
		let p = Profile { log_norms: vec![0.0; 2000] };
		let asymptotic = 0.5 * (d / (2.0 * core::f64::consts::PI * core::f64::consts::E)).ln() +
			(core::f64::consts::PI * d).ln() / (2.0 * d);
		assert!((p.log_gaussian_heuristic() - asymptotic).abs() < 1e-5);
	}
}
