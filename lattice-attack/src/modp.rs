//! Determinants modulo word-sized primes, used to decide exactly whether a
//! set of lattice vectors generates the whole lattice.
//!
//! If every row of `B` lies in the lattice, `det B = ±k · qᵐ` with `k ≥ 1` the
//! index of the sublattice they generate, and `k = 1` iff `det B ≡ ±qᵐ` modulo
//! every prime. The verifier checks this for a few 62-bit primes derived by
//! hashing the instance and the submitted basis, so the submitter cannot
//! choose a sublattice whose index happens to be `≡ 1` modulo known primes.
//! A fixed nonzero integer of `N` bits has at most `N/62` such prime factors,
//! so each prime catches a proper sublattice except with probability about
//! `2^-40`; the primes are independent, and changing the basis changes them.

use std::thread;

/// Montgomery arithmetic modulo an odd prime below `2^63`.
#[derive(Clone, Copy)]
pub struct Mont {
	p: u64,
	/// `-p^{-1} mod 2^64`.
	ninv: u64,
	/// `2^128 mod p`.
	r2: u64,
	/// `2^64 mod p`: the Montgomery form of 1.
	one: u64,
}

impl Mont {
	pub fn new(p: u64) -> Self {
		assert!(p % 2 == 1 && p < (1 << 63), "modulus must be odd and below 2^63");
		let mut inv = p;
		for _ in 0..6 {
			inv = inv.wrapping_mul(2u64.wrapping_sub(p.wrapping_mul(inv)));
		}
		let r = ((1u128 << 64) % p as u128) as u64;
		let r2 = ((r as u128 * r as u128) % p as u128) as u64;
		Mont { p, ninv: inv.wrapping_neg(), r2, one: r }
	}

	fn redc(&self, t: u128) -> u64 {
		let m = (t as u64).wrapping_mul(self.ninv);
		let u = ((t + m as u128 * self.p as u128) >> 64) as u64;
		if u >= self.p {
			u - self.p
		} else {
			u
		}
	}

	/// Montgomery form of `x mod p`.
	pub fn from_i64(&self, x: i64) -> u64 {
		self.mul(x.rem_euclid(self.p as i64) as u64, self.r2)
	}

	pub fn from_u64(&self, x: u64) -> u64 {
		self.mul(x % self.p, self.r2)
	}

	pub fn mul(&self, a: u64, b: u64) -> u64 {
		self.redc(a as u128 * b as u128)
	}

	pub fn sub(&self, a: u64, b: u64) -> u64 {
		if a >= b {
			a - b
		} else {
			a + self.p - b
		}
	}

	pub fn neg(&self, a: u64) -> u64 {
		if a == 0 {
			0
		} else {
			self.p - a
		}
	}

	pub fn pow(&self, mut base: u64, mut exp: u64) -> u64 {
		let mut acc = self.one;
		while exp > 0 {
			if exp & 1 == 1 {
				acc = self.mul(acc, base);
			}
			base = self.mul(base, base);
			exp >>= 1;
		}
		acc
	}

	pub fn inv(&self, a: u64) -> u64 {
		self.pow(a, self.p - 2)
	}
}

/// Determinant of the square matrix `rows` modulo `p`, in Montgomery form
/// (compare with values produced by the same [`Mont`]).
pub fn determinant(rows: &[Vec<i64>], mont: &Mont) -> u64 {
	let d = rows.len();
	let mut a: Vec<Vec<u64>> =
		rows.iter().map(|r| r.iter().map(|&x| mont.from_i64(x)).collect()).collect();
	let threads = thread::available_parallelism().map_or(1, |n| n.get().min(32));
	let mut det = mont.one;
	for j in 0..d {
		let Some(pivot) = (j..d).find(|&i| a[i][j] != 0) else {
			return 0;
		};
		if pivot != j {
			a.swap(pivot, j);
			det = mont.neg(det);
		}
		det = mont.mul(det, a[j][j]);
		let inv = mont.inv(a[j][j]);
		let (head, tail) = a.split_at_mut(j + 1);
		let row_j = &head[j];
		let eliminate = |row: &mut Vec<u64>| {
			let f = mont.mul(row[j], inv);
			if f != 0 {
				for (x, &y) in row[j + 1..].iter_mut().zip(&row_j[j + 1..]) {
					*x = mont.sub(*x, mont.mul(f, y));
				}
			}
		};
		if threads > 1 && tail.len() * (d - j) >= 1 << 15 {
			let chunk = tail.len().div_ceil(threads);
			thread::scope(|s| {
				for part in tail.chunks_mut(chunk) {
					let eliminate = &eliminate;
					s.spawn(move || part.iter_mut().for_each(eliminate));
				}
			});
		} else {
			tail.iter_mut().for_each(eliminate);
		}
	}
	det
}

/// Deterministic Miller–Rabin, exact for all `u64`.
pub fn is_prime(n: u64) -> bool {
	if n < 2 {
		return false;
	}
	for p in [2u64, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37] {
		if n.is_multiple_of(p) {
			return n == p;
		}
	}
	let mulmod = |a: u64, b: u64| ((a as u128 * b as u128) % n as u128) as u64;
	let powmod = |mut b: u64, mut e: u64| {
		let mut acc = 1u64;
		while e > 0 {
			if e & 1 == 1 {
				acc = mulmod(acc, b);
			}
			b = mulmod(b, b);
			e >>= 1;
		}
		acc
	};
	let s = (n - 1).trailing_zeros();
	let d = (n - 1) >> s;
	'witness: for a in [2u64, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37] {
		let mut x = powmod(a, d);
		if x == 1 || x == n - 1 {
			continue;
		}
		for _ in 1..s {
			x = mulmod(x, x);
			if x == n - 1 {
				continue 'witness;
			}
		}
		return false;
	}
	true
}

/// Smallest prime `>= n`.
pub fn next_prime(mut n: u64) -> u64 {
	if n <= 2 {
		return 2;
	}
	n |= 1;
	while !is_prime(n) {
		n += 2;
	}
	n
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn primality_and_next_prime() {
		assert!(is_prime(2) && is_prime(3) && is_prime(8_380_417) && is_prime((1 << 61) - 1));
		assert!(!is_prime(1) && !is_prime(4) && !is_prime(8_380_419) && !is_prime(3_215_031_751));
		assert_eq!(next_prime(90), 97);
		assert_eq!(next_prime(97), 97);
		assert!(is_prime(next_prime(1 << 62)));
	}

	#[test]
	fn montgomery_matches_plain_arithmetic() {
		let p = next_prime((1 << 62) + 12345);
		let m = Mont::new(p);
		let (a, b) = (123_456_789_012_345u64, (1u64 << 62) - 7);
		let expected = ((a as u128 * b as u128) % p as u128) as u64;
		assert_eq!(m.mul(m.from_u64(a), m.from_u64(b)), m.from_u64(expected));
		assert_eq!(m.mul(m.from_u64(a), m.inv(m.from_u64(a))), m.one);
		assert_eq!(m.from_i64(-1), m.from_u64(p - 1));
		assert_eq!(m.sub(m.from_u64(3), m.from_u64(5)), m.from_i64(-2));
		assert_eq!(m.pow(m.from_u64(2), 10), m.from_u64(1024));
	}

	#[test]
	fn determinants_of_small_matrices() {
		let m = Mont::new(next_prime(1 << 62));
		let det = |rows: &[&[i64]]| {
			let rows: Vec<Vec<i64>> = rows.iter().map(|r| r.to_vec()).collect();
			determinant(&rows, &m)
		};
		assert_eq!(det(&[&[1, 2], &[3, 4]]), m.from_i64(-2));
		assert_eq!(det(&[&[0, 1], &[1, 0]]), m.from_i64(-1));
		assert_eq!(det(&[&[2, 0, 0], &[0, 3, 0], &[0, 0, 5]]), m.from_i64(30));
		assert_eq!(det(&[&[1, 2, 3], &[2, 4, 6], &[0, 0, 1]]), 0);
		assert_eq!(det(&[&[0, 0], &[0, 1]]), 0);
		assert_eq!(det(&[]), m.one);
	}

	#[test]
	fn large_determinant_uses_the_parallel_path() {
		// Lower-triangular with a dense fill; the determinant is the diagonal product.
		let d = 300;
		let rows: Vec<Vec<i64>> = (0..d)
			.map(|i| {
				(0..d)
					.map(|j| {
						if j < i {
							((i * 7 + j * 13) % 11) as i64 - 5
						} else if j == i {
							(i % 3) as i64 + 1
						} else {
							0
						}
					})
					.collect()
			})
			.collect();
		let m = Mont::new(next_prime((1 << 62) + 999));
		let mut expected = m.one;
		for i in 0..d {
			expected = m.mul(expected, m.from_i64((i % 3) as i64 + 1));
		}
		// Row operations mixing earlier rows into later ones keep the determinant.
		let mut mixed = rows.clone();
		for i in 1..d {
			for j in 0..d {
				mixed[i][j] += 3 * rows[i - 1][j];
			}
		}
		assert_eq!(determinant(&rows, &m), expected);
		assert_eq!(determinant(&mixed, &m), expected);
	}
}
