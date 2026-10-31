//! Integer rows plus an incrementally maintained `f64` Gram–Schmidt
//! decomposition, shared by the reference LLL and BKZ implementations.
//!
//! Gram–Schmidt data is computed row by row by Householder QR and cached;
//! mutating row `k` invalidates rows `k..`. Rows below the invalidated point
//! keep their data because the span of a prefix is unchanged by unimodular
//! operations inside it. Householder rather than Gram–Schmidt because its
//! errors scale with the row norm instead of with the condition number of
//! the basis: q-ary bases at ML-DSA size have rows around `2^27` with
//! Gram–Schmidt norms around 1, which modified Gram–Schmidt in `f64` cannot
//! resolve.
//!
//! Rows at rest fit comfortably in `i64`, but the intermediate values of a
//! size reduction do not: the nearest-plane coordinates of a fresh row with
//! respect to a reduced prefix grow exponentially with the prefix length
//! (hundreds of bits at d ≈ 2000). A row is therefore moved to `BigInt` for
//! the duration of its size reduction as soon as an `i64` operation would
//! overflow, and moved back once it is reduced.

use std::cmp::min;

use num_bigint::BigInt;
use num_traits::{FromPrimitive, ToPrimitive};

use crate::gso::F64_DEPENDENCE_RATIO;

pub struct Workspace {
	pub rows: Vec<Vec<i64>>,
	/// `mu[i][j]` for `j < i`; entries `j >= i` are unused.
	pub mu: Vec<Vec<f64>>,
	/// Squared Gram–Schmidt norms `‖b*_i‖²`.
	pub r: Vec<f64>,
	/// Householder reflector of row `j` (zero before index `j`). Applying
	/// the reflectors of rows `0..k` to row `k` gives its coordinates in the
	/// Gram–Schmidt frame: entry `j < k` is `mu[k][j] * diag[j]`, and the
	/// norm of entries `k..` is `‖b*_k‖`.
	refl: Vec<Vec<f64>>,
	/// `2 / ‖refl[j]‖²`, or 0 for an identity reflector.
	tau: Vec<f64>,
	/// Signed `‖b*_j‖` as produced by the reflector; `r[j] = diag[j]²`.
	diag: Vec<f64>,
	/// Rows `0..valid` have up-to-date Gram–Schmidt data.
	valid: usize,
}

impl Workspace {
	pub fn new(rows: Vec<Vec<i64>>) -> Self {
		let d = rows.len();
		let width = rows.first().map_or(0, Vec::len);
		Workspace {
			rows,
			mu: vec![vec![0.0; d]; d],
			r: vec![0.0; d],
			refl: vec![vec![0.0; width]; d],
			tau: vec![0.0; d],
			diag: vec![0.0; d],
			valid: 0,
		}
	}

	pub fn dim(&self) -> usize {
		self.rows.len()
	}

	pub fn into_rows(self) -> Vec<Vec<i64>> {
		self.rows
	}

	/// Mark rows `k..` as needing recomputation.
	pub fn invalidate_from(&mut self, k: usize) {
		self.valid = min(self.valid, k);
	}

	/// Make rows `0..upto` valid.
	pub fn ensure(&mut self, upto: usize) {
		while self.valid < upto {
			self.compute_row(self.valid);
			self.valid += 1;
		}
	}

	fn compute_row(&mut self, k: usize) {
		let v = self.rows[k].iter().map(|&x| x as f64).collect();
		self.compute_row_from(k, v);
	}

	/// Gram–Schmidt data for row `k` given its entries as `f64`, which may
	/// come from a `BigInt` scratch row during size reduction.
	fn compute_row_from(&mut self, k: usize, mut x: Vec<f64>) {
		let row_norm = dot(&x, &x).sqrt();
		for j in 0..k {
			let v = &self.refl[j][j..];
			let s = self.tau[j] * dot(&x[j..], v);
			if s != 0.0 {
				for (xi, vi) in x[j..].iter_mut().zip(v) {
					*xi -= s * vi;
				}
			}
			self.mu[k][j] = if self.diag[j] != 0.0 { x[j] / self.diag[j] } else { 0.0 };
		}
		// A row whose remaining length is below what `f64` can distinguish
		// from zero (including the extra row of a generating set) is treated
		// as dependent: identity reflector, `r = 0`, and later rows get
		// `mu = 0` against it so nothing is reduced against noise.
		let tail = x.get(k..).unwrap_or(&[]);
		let norm = dot(tail, tail).sqrt();
		let mut v = vec![0.0; x.len()];
		if norm > row_norm * F64_DEPENDENCE_RATIO {
			let alpha = if tail[0] > 0.0 { -norm } else { norm };
			v[k..].copy_from_slice(tail);
			v[k] -= alpha;
			self.tau[k] = 2.0 / dot(&v[k..], &v[k..]);
			self.diag[k] = alpha;
			self.r[k] = norm * norm;
		} else {
			self.tau[k] = 0.0;
			self.diag[k] = 0.0;
			self.r[k] = 0.0;
		}
		self.refl[k] = v;
	}

	/// Size-reduce row `k` against rows `0..k` (`|mu[k][j]| <= eta`
	/// afterwards, up to floating-point error). Returns whether the row
	/// changed. Leaves rows `0..=k` valid.
	///
	/// Each pass subtracts the rounded coefficients computed from the current
	/// floating-point data and then recomputes row `k` exactly, so inaccurate
	/// coefficients only cost extra passes. Coefficients beyond the range of
	/// `f64` are clamped; the next pass picks up the remainder.
	pub fn size_reduce_row(&mut self, k: usize, eta: f64) -> bool {
		self.ensure(k);
		let mut changed = false;
		let mut big: Option<Vec<BigInt>> = None;
		loop {
			self.invalidate_from(k);
			match &big {
				Some(b) => {
					let v = b.iter().map(|x| x.to_f64().unwrap_or(f64::INFINITY)).collect();
					self.compute_row_from(k, v);
					self.valid = k + 1;
				},
				None => self.ensure(k + 1),
			}
			let mut pass_changed = false;
			for j in (0..k).rev() {
				let m = self.mu[k][j];
				if m.abs() > eta {
					let c = m.round().clamp(-MAX_COEFFICIENT, MAX_COEFFICIENT);
					match &mut big {
						Some(b) => sub_multiple_big(b, &self.rows[j], c, 0),
						None => {
							let (row_k, row_j) = split_rows(&mut self.rows, k, j);
							if let Err(done) = sub_multiple_i64(row_k, row_j, c) {
								let mut b: Vec<BigInt> =
									row_k.iter().map(|&x| BigInt::from(x)).collect();
								sub_multiple_big(&mut b, row_j, c, done);
								big = Some(b);
							}
						},
					}
					for i in 0..j {
						self.mu[k][i] -= c * self.mu[j][i];
					}
					self.mu[k][j] -= c;
					pass_changed = true;
				}
			}
			if !pass_changed {
				if let Some(b) = big.take() {
					match b.iter().map(ToPrimitive::to_i64).collect() {
						Some(row) => self.rows[k] = row,
						None => {
							// Reduced per the floating-point data yet still
							// too large: the data was inaccurate, refine again.
							big = Some(b);
							continue;
						},
					}
				}
				break;
			}
			changed = true;
		}
		changed
	}

	/// Swap rows `k-1` and `k`.
	pub fn swap(&mut self, k: usize) {
		self.rows.swap(k - 1, k);
		self.invalidate_from(k - 1);
	}

	/// `row_dst += c * row_src` (`dst != src`). Invalidates from `dst`.
	pub fn add_multiple(&mut self, dst: usize, src: usize, c: i64) {
		let (d, s) = split_rows(&mut self.rows, dst, src);
		for (x, y) in d.iter_mut().zip(s.iter()) {
			*x = x.checked_add(c.checked_mul(*y).expect("overflow")).expect("overflow");
		}
		self.invalidate_from(dst);
	}

	/// Move row `from` to position `to <= from`, shifting the rows between
	/// down by one. Invalidates from `to`.
	pub fn rotate_up(&mut self, from: usize, to: usize) {
		self.rows[to..=from].rotate_right(1);
		self.invalidate_from(to);
	}

	/// Insert an extra row at position `k`. The rows then form a generating
	/// set rather than a basis until one row is removed again.
	pub fn insert_row(&mut self, k: usize, row: Vec<i64>) {
		let width = row.len();
		self.rows.insert(k, row);
		let d = self.rows.len();
		self.mu.push(vec![0.0; d]);
		for m in &mut self.mu {
			m.push(0.0);
		}
		self.r.push(0.0);
		self.refl.push(vec![0.0; width]);
		self.tau.push(0.0);
		self.diag.push(0.0);
		self.invalidate_from(k);
	}

	/// Remove row `k`. Invalidates from `k`.
	pub fn remove_row(&mut self, k: usize) {
		self.rows.remove(k);
		self.mu.pop();
		self.r.pop();
		self.refl.pop();
		self.tau.pop();
		self.diag.pop();
		self.invalidate_from(k);
	}

	pub fn row_is_zero(&self, k: usize) -> bool {
		self.rows[k].iter().all(|&x| x == 0)
	}

	/// Recompute everything from scratch and check the LLL conditions with
	/// parameters `(delta, eta)`, allowing a small floating-point slack.
	pub fn is_lll_reduced(&mut self, delta: f64, eta: f64) -> bool {
		self.valid = 0;
		self.ensure(self.dim());
		for k in 1..self.dim() {
			for j in 0..k {
				if self.mu[k][j].abs() > eta + 1e-9 {
					return false;
				}
			}
			let m = self.mu[k][k - 1];
			if self.r[k] < (delta - m * m) * self.r[k - 1] * (1.0 - 1e-9) {
				return false;
			}
		}
		true
	}
}

/// Largest size-reduction coefficient applied in one pass. Keeps `c * x`
/// finite in `f64` for the Gram–Schmidt updates and leaves room for the
/// exponent range when a row has grown large.
const MAX_COEFFICIENT: f64 = 1e300;

/// `row_k -= c * row_j` in `i64`, stopping at the first entry whose result
/// does not fit. Entries before it are updated; returns their count as the
/// error so the caller can finish in wider arithmetic.
fn sub_multiple_i64(row_k: &mut [i64], row_j: &[i64], c: f64) -> Result<(), usize> {
	if c.abs() >= 9.2e18 {
		return Err(0);
	}
	let ci = c as i64;
	for (i, (xk, xj)) in row_k.iter_mut().zip(row_j).enumerate() {
		match ci.checked_mul(*xj).and_then(|p| xk.checked_sub(p)) {
			Some(v) => *xk = v,
			None => return Err(i),
		}
	}
	Ok(())
}

/// `row_k[from..] -= c * row_j[from..]` exactly, `c` being an integer-valued
/// `f64`.
fn sub_multiple_big(row_k: &mut [BigInt], row_j: &[i64], c: f64, from: usize) {
	let c = BigInt::from_f64(c).expect("finite integer coefficient");
	for (xk, &xj) in row_k[from..].iter_mut().zip(&row_j[from..]) {
		if xj != 0 {
			*xk -= &c * xj;
		}
	}
}

fn split_rows(rows: &mut [Vec<i64>], a: usize, b: usize) -> (&mut Vec<i64>, &mut Vec<i64>) {
	debug_assert_ne!(a, b);
	if a < b {
		let (lo, hi) = rows.split_at_mut(b);
		(&mut lo[a], &mut hi[0])
	} else {
		let (lo, hi) = rows.split_at_mut(a);
		(&mut hi[0], &mut lo[b])
	}
}

pub(crate) fn dot(a: &[f64], b: &[f64]) -> f64 {
	a.iter().zip(b).map(|(x, y)| x * y).sum()
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn size_reduction_survives_coefficients_beyond_i64() {
		// b1* = (0, 1, 0), so reducing b2 needs c = 2^36 against b1 and then
		// c = -2^72 against b0; the intermediate row is (-2^72, 0, 1).
		let a = 1i64 << 36;
		let mut ws = Workspace::new(vec![vec![1, 0, 0], vec![a, 1, 0], vec![0, a, 1]]);
		assert!(ws.size_reduce_row(2, DEFAULT_ETA));
		assert_eq!(ws.rows[2], vec![0, 0, 1]);
		assert_eq!(ws.rows[1], vec![a, 1, 0]);
		assert!(ws.mu[2][0].abs() <= DEFAULT_ETA && ws.mu[2][1].abs() <= DEFAULT_ETA);
		assert!((ws.r[2] - 1.0).abs() < 1e-9);
	}

	#[test]
	fn size_reduction_of_a_reduced_row_is_a_no_op() {
		let mut ws = Workspace::new(vec![vec![5, 0], vec![2, 7]]);
		assert!(!ws.size_reduce_row(1, DEFAULT_ETA));
		assert_eq!(ws.rows[1], vec![2, 7]);
	}

	const DEFAULT_ETA: f64 = crate::reducers::lll::DEFAULT_ETA;
}
