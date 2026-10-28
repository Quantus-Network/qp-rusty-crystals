//! Integer lattice basis: the type exchanged between the harness, reducers and
//! the verifier.

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
