//! Integer rows plus an incrementally maintained `f64` Gram–Schmidt
//! decomposition, shared by the reference LLL and BKZ implementations.
//!
//! Gram–Schmidt data is computed row by row with modified Gram–Schmidt and
//! cached; mutating row `k` invalidates rows `k..`. Rows below the invalidated
//! point keep their data because the span of a prefix is unchanged by
//! unimodular operations inside it.

use std::cmp::min;

pub struct Workspace {
	pub rows: Vec<Vec<i64>>,
	/// `mu[i][j]` for `j < i`; entries `j >= i` are unused.
	pub mu: Vec<Vec<f64>>,
	/// Squared Gram–Schmidt norms `‖b*_i‖²`.
	pub r: Vec<f64>,
	bstar: Vec<Vec<f64>>,
	/// Rows `0..valid` have up-to-date `mu`, `r`, `bstar`.
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
			bstar: vec![vec![0.0; width]; d],
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
		let mut v: Vec<f64> = self.rows[k].iter().map(|&x| x as f64).collect();
		for j in 0..k {
			let m = dot(&v, &self.bstar[j]) / self.r[j];
			self.mu[k][j] = m;
			for (vi, bj) in v.iter_mut().zip(&self.bstar[j]) {
				*vi -= m * bj;
			}
		}
		self.r[k] = dot(&v, &v);
		self.bstar[k] = v;
	}

	/// Size-reduce row `k` against rows `0..k` (`|mu[k][j]| <= eta`
	/// afterwards, up to floating-point error). Returns whether the row
	/// changed. Leaves rows `0..=k` valid.
	pub fn size_reduce_row(&mut self, k: usize, eta: f64) -> bool {
		self.ensure(k);
		let mut changed = false;
		loop {
			self.invalidate_from(k);
			self.ensure(k + 1);
			let mut pass_changed = false;
			for j in (0..k).rev() {
				let m = self.mu[k][j];
				if m.abs() > eta {
					let c = m.round();
					let ci = c as i64;
					let (row_k, row_j) = split_rows(&mut self.rows, k, j);
					for (xk, xj) in row_k.iter_mut().zip(row_j.iter()) {
						*xk = xk
							.checked_sub(ci.checked_mul(*xj).expect("overflow"))
							.expect("overflow");
					}
					for i in 0..j {
						self.mu[k][i] -= c * self.mu[j][i];
					}
					self.mu[k][j] -= c;
					pass_changed = true;
				}
			}
			if !pass_changed {
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
		self.bstar.push(vec![0.0; width]);
		self.invalidate_from(k);
	}

	/// Remove row `k`. Invalidates from `k`.
	pub fn remove_row(&mut self, k: usize) {
		self.rows.remove(k);
		self.mu.pop();
		self.r.pop();
		self.bstar.pop();
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
