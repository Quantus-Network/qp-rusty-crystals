//! Integer lattice basis: the type exchanged between the harness, reducers and
//! the verifier.

use num_bigint::BigInt;
use num_traits::FromPrimitive;
use serde::{Deserialize, Serialize};

/// A list of integer row vectors generating a lattice.
///
/// Reducers may hold any internal representation they like; this is only the
/// boundary type. The verifier never trusts anything beyond the integers
/// stored here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Basis {
	pub rows: Vec<Vec<i64>>,
}

impl Basis {
	pub fn new(rows: Vec<Vec<i64>>) -> Self {
		Basis { rows }
	}

	/// Number of rows (basis vectors).
	pub fn len(&self) -> usize {
		self.rows.len()
	}

	pub fn is_empty(&self) -> bool {
		self.rows.is_empty()
	}

	/// True when every row has exactly `len()` entries.
	pub fn is_square(&self) -> bool {
		let d = self.rows.len();
		self.rows.iter().all(|r| r.len() == d)
	}

	/// Largest absolute entry, or 0 for an empty basis.
	pub fn max_abs_entry(&self) -> u64 {
		self.rows.iter().flatten().map(|x| x.unsigned_abs()).max().unwrap_or(0)
	}

	/// Squared Euclidean norm of row `i`, exact.
	pub fn row_norm_sq(&self, i: usize) -> i128 {
		self.rows[i].iter().map(|&x| (x as i128) * (x as i128)).sum()
	}
}

/// Largest size-reduction coefficient applied in one pass. Keeps `c * x`
/// finite in `f64` and leaves room for the exponent range when a row has
/// grown large.
pub(crate) const MAX_COEFFICIENT: f64 = 1e300;

/// `row_k -= c * row_j` in `i64`, stopping at the first entry whose result
/// does not fit. Entries before it are updated; returns their count as the
/// error so the caller can finish in wider arithmetic.
pub(crate) fn sub_multiple_i64(row_k: &mut [i64], row_j: &[i64], c: f64) -> Result<(), usize> {
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
pub(crate) fn sub_multiple_big(row_k: &mut [BigInt], row_j: &[i64], c: f64, from: usize) {
	let c = BigInt::from_f64(c).expect("finite integer coefficient");
	for (xk, &xj) in row_k[from..].iter_mut().zip(&row_j[from..]) {
		if xj != 0 {
			*xk -= &c * xj;
		}
	}
}
