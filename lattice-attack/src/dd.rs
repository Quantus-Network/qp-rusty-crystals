//! Double-double arithmetic: an unevaluated sum `hi + lo` of two `f64`s giving
//! roughly 106 bits of significand. Used by the verifier so that the
//! Gram–Schmidt lengths of a submitted basis are computed to far more
//! precision than the score tolerances require, independent of how badly
//! conditioned the basis is.
//!
//! Only the operations the verifier needs are implemented. All of them are
//! the standard error-free transformations (Dekker, Knuth, Bailey).

use core::ops::{Add, Div, Mul, Neg, Sub};

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Dd {
	pub hi: f64,
	pub lo: f64,
}

#[inline]
fn two_sum(a: f64, b: f64) -> (f64, f64) {
	let s = a + b;
	let bb = s - a;
	let err = (a - (s - bb)) + (b - bb);
	(s, err)
}

#[inline]
fn quick_two_sum(a: f64, b: f64) -> (f64, f64) {
	let s = a + b;
	let err = b - (s - a);
	(s, err)
}

#[inline]
fn two_prod(a: f64, b: f64) -> (f64, f64) {
	let p = a * b;
	let err = a.mul_add(b, -p);
	(p, err)
}

impl Dd {
	pub const ZERO: Dd = Dd { hi: 0.0, lo: 0.0 };
	pub const ONE: Dd = Dd { hi: 1.0, lo: 0.0 };

	#[inline]
	pub fn from_f64(x: f64) -> Dd {
		Dd { hi: x, lo: 0.0 }
	}

	/// Exact for `|x| < 2^106`.
	pub fn from_i128(x: i128) -> Dd {
		let hi = x as f64;
		let rem = x - hi as i128;
		let lo = rem as f64;
		let (hi, lo) = quick_two_sum(hi, lo);
		Dd { hi, lo }
	}

	#[inline]
	pub fn from_i64(x: i64) -> Dd {
		Dd::from_i128(x as i128)
	}

	#[inline]
	pub fn to_f64(self) -> f64 {
		self.hi + self.lo
	}

	/// Newton step on the `f64` square root. Requires `self > 0`.
	pub fn sqrt(self) -> Dd {
		if self.hi <= 0.0 {
			return Dd::ZERO;
		}
		let x = 1.0 / self.hi.sqrt();
		let ax = Dd::from_f64(self.hi * x);
		let diff = self - ax * ax;
		ax + Dd::from_f64(diff.hi * x * 0.5)
	}

	/// Natural log, accurate to about `f64` relative precision in the result,
	/// which is all the score needs once the argument itself is accurate.
	/// Requires `self > 0`.
	pub fn ln(self) -> f64 {
		self.hi.ln() + (self.lo / self.hi).ln_1p()
	}

	#[inline]
	pub fn is_positive(self) -> bool {
		self.hi > 0.0 || (self.hi == 0.0 && self.lo > 0.0)
	}

	#[inline]
	pub fn abs(self) -> Dd {
		if self.hi < 0.0 || (self.hi == 0.0 && self.lo < 0.0) {
			-self
		} else {
			self
		}
	}

	pub fn lt(self, o: Dd) -> bool {
		self.hi < o.hi || (self.hi == o.hi && self.lo < o.lo)
	}
}

impl Add for Dd {
	type Output = Dd;

	#[inline]
	fn add(self, o: Dd) -> Dd {
		let (s, e) = two_sum(self.hi, o.hi);
		let (t, f) = two_sum(self.lo, o.lo);
		let e = e + t;
		let (s, e) = quick_two_sum(s, e);
		let e = e + f;
		let (hi, lo) = quick_two_sum(s, e);
		Dd { hi, lo }
	}
}

impl Neg for Dd {
	type Output = Dd;

	#[inline]
	fn neg(self) -> Dd {
		Dd { hi: -self.hi, lo: -self.lo }
	}
}

impl Sub for Dd {
	type Output = Dd;

	#[inline]
	fn sub(self, o: Dd) -> Dd {
		self + (-o)
	}
}

impl Mul for Dd {
	type Output = Dd;

	#[inline]
	fn mul(self, o: Dd) -> Dd {
		let (p, e) = two_prod(self.hi, o.hi);
		let e = e + (self.hi * o.lo + self.lo * o.hi);
		let (hi, lo) = quick_two_sum(p, e);
		Dd { hi, lo }
	}
}

impl Div for Dd {
	type Output = Dd;

	#[inline]
	fn div(self, o: Dd) -> Dd {
		let q1 = self.hi / o.hi;
		let r = self - o * Dd::from_f64(q1);
		let q2 = r.hi / o.hi;
		let r = r - o * Dd::from_f64(q2);
		let q3 = r.hi / o.hi;
		let (hi, lo) = quick_two_sum(q1, q2);
		Dd { hi, lo } + Dd::from_f64(q3)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn keeps_bits_f64_would_lose() {
		let tiny = Dd::from_f64(2f64.powi(-60));
		let x = Dd::ONE + tiny - Dd::ONE;
		assert_eq!(x.to_f64(), 2f64.powi(-60));
		assert_eq!((Dd::ONE + tiny).hi, 1.0);
	}

	#[test]
	fn from_i128_is_exact() {
		let x: i128 = (1i128 << 100) + 12345;
		let d = Dd::from_i128(x);
		assert_eq!(d.hi as i128 + d.lo as i128, x);
		let y = Dd::from_i128(-x);
		assert_eq!(y.hi as i128 + y.lo as i128, -x);
	}

	#[test]
	fn mul_div_round_trip() {
		let a = Dd::from_i128((1i128 << 70) + 7);
		let b = Dd::from_i128((1i128 << 40) + 3);
		let c = a * b / b;
		let err = (c - a).abs();
		assert!(err.lt(Dd::from_f64(1e-12)), "err = {err:?}");
	}

	#[test]
	fn sqrt_and_ln() {
		let x = Dd::from_i128(1i128 << 90);
		let s = x.sqrt();
		assert!((s - Dd::from_i128(1i128 << 45)).abs().lt(Dd::from_f64(1e-9)));
		assert!((x.ln() - 90.0 * core::f64::consts::LN_2).abs() < 1e-12);
		let near_one = Dd::ONE + Dd::from_f64(1e-20);
		assert!((near_one.ln() - 1e-20).abs() < 1e-30);
	}

	#[test]
	fn exact_products_of_integers() {
		let a = Dd::from_i64(8380417 * 8380417 + 1);
		let b = Dd::from_i64(3 * 8380417);
		let p = a * b;
		let expected = (8380417i128 * 8380417 + 1) * (3 * 8380417);
		assert_eq!(p.hi as i128 + p.lo as i128, expected);
	}
}
