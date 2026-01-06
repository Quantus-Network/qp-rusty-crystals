//! Field arithmetic and vector operations for threshold ML-DSA
//!
//! This module implements arithmetic operations in the field Z_q where q = 8380417,
//! as well as vector and polynomial operations needed for the threshold protocol.

use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::params::common::{N, Q};

/// Element of Z_q where q = 8380417
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FieldElement(pub u32);

impl Zeroize for FieldElement {
	fn zeroize(&mut self) {
		self.0.zeroize();
	}
}

impl FieldElement {
	/// Zero element
	pub const ZERO: Self = Self(0);

	/// One element
	pub const ONE: Self = Self(1);

	/// Create a new field element, reducing modulo q if necessary
	pub fn new(val: u32) -> Self {
		Self(val % Q)
	}

	/// Create a field element from a signed integer
	pub fn from_i32(val: i32) -> Self {
		let reduced = if val >= 0 {
			(val as u32) % Q
		} else {
			// Handle negative values: convert to positive equivalent
			let pos_val = ((-val) as u32) % Q;
			if pos_val == 0 {
				0
			} else {
				Q - pos_val
			}
		};
		Self(reduced)
	}

	/// Get the value as u32
	pub fn value(&self) -> u32 {
		self.0
	}

	/// Get the centered representation (in range [-(q-1)/2, (q-1)/2])
	pub fn centered(&self) -> i32 {
		if self.0 <= Q / 2 {
			self.0 as i32
		} else {
			(self.0 as i32) - (Q as i32)
		}
	}

	/// Compute multiplicative inverse modulo q
	pub fn inverse(self) -> Option<Self> {
		if self.0 == 0 {
			return None;
		}
		Some(Self(mod_inverse(self.0, Q)))
	}

	/// Power operation: self^exp mod q
	pub fn pow(self, exp: u32) -> Self {
		if exp == 0 {
			return Self::ONE;
		}

		let mut base = self;
		let mut result = Self::ONE;
		let mut exp = exp;

		while exp > 0 {
			if exp & 1 == 1 {
				result = result * base;
			}
			base = base * base;
			exp >>= 1;
		}
		result
	}

	/// Check if the element is zero
	pub fn is_zero(&self) -> bool {
		self.0 == 0
	}
}

impl Add for FieldElement {
	type Output = Self;

	fn add(self, other: Self) -> Self {
		let sum = (self.0 + other.0) % Q;
		Self(sum)
	}
}

impl AddAssign for FieldElement {
	fn add_assign(&mut self, other: Self) {
		*self = *self + other;
	}
}

impl Sub for FieldElement {
	type Output = Self;

	fn sub(self, other: Self) -> Self {
		let diff = if self.0 >= other.0 { self.0 - other.0 } else { Q - (other.0 - self.0) };
		Self(diff)
	}
}

impl SubAssign for FieldElement {
	fn sub_assign(&mut self, other: Self) {
		*self = *self - other;
	}
}

impl Mul for FieldElement {
	type Output = Self;

	fn mul(self, other: Self) -> Self {
		let product = ((self.0 as u64) * (other.0 as u64)) % (Q as u64);
		Self(product as u32)
	}
}

impl MulAssign for FieldElement {
	fn mul_assign(&mut self, other: Self) {
		*self = *self * other;
	}
}

impl Neg for FieldElement {
	type Output = Self;

	fn neg(self) -> Self {
		if self.0 == 0 {
			Self::ZERO
		} else {
			Self(Q - self.0)
		}
	}
}

/// Polynomial with N coefficients in Z_q
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Polynomial([FieldElement; N]);

impl Default for Polynomial {
	fn default() -> Self {
		Self([FieldElement::ZERO; N])
	}
}

impl Polynomial {
	/// Create a new zero polynomial
	pub fn zero() -> Self {
		Self::default()
	}

	/// Create polynomial from coefficient array
	pub fn from_coefficients(coeffs: [FieldElement; N]) -> Self {
		Self(coeffs)
	}

	/// Get coefficient at index i
	pub fn get(&self, i: usize) -> FieldElement {
		self.0[i]
	}

	/// Set coefficient at index i
	pub fn set(&mut self, i: usize, val: FieldElement) {
		self.0[i] = val;
	}

	/// Get mutable reference to coefficients
	pub fn coeffs_mut(&mut self) -> &mut [FieldElement; N] {
		&mut self.0
	}

	/// Get reference to coefficients
	pub fn coeffs(&self) -> &[FieldElement; N] {
		&self.0
	}

	/// Add two polynomials
	pub fn add(&self, other: &Self) -> Self {
		let mut result = Self::zero();
		for i in 0..N {
			result.0[i] = self.0[i] + other.0[i];
		}
		result
	}

	/// Subtract two polynomials
	pub fn sub(&self, other: &Self) -> Self {
		let mut result = Self::zero();
		for i in 0..N {
			result.0[i] = self.0[i] - other.0[i];
		}
		result
	}

	/// Multiply polynomial by scalar
	pub fn scalar_mul(&self, scalar: FieldElement) -> Self {
		let mut result = Self::zero();
		for i in 0..N {
			result.0[i] = self.0[i] * scalar;
		}
		result
	}

	/// Negate polynomial
	pub fn negate(&self) -> Self {
		let mut result = Self::zero();
		for i in 0..N {
			result.0[i] = -self.0[i];
		}
		result
	}
}

/// Vector of L polynomials
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct VecL<const L: usize>([Polynomial; L]);

impl<const L: usize> Default for VecL<L> {
	fn default() -> Self {
		Self(core::array::from_fn(|_| Polynomial::zero()))
	}
}

impl<const L: usize> VecL<L> {
	/// Create new zero vector
	pub fn zero() -> Self {
		Self::default()
	}

	/// Get polynomial at index
	pub fn get(&self, i: usize) -> &Polynomial {
		&self.0[i]
	}

	/// Get mutable polynomial at index
	pub fn get_mut(&mut self, i: usize) -> &mut Polynomial {
		&mut self.0[i]
	}

	/// Set polynomial at index
	pub fn set(&mut self, i: usize, poly: Polynomial) {
		self.0[i] = poly;
	}

	/// Add two vectors
	pub fn add(&self, other: &Self) -> Self {
		let mut result = Self::zero();
		for i in 0..L {
			result.0[i] = self.0[i].add(&other.0[i]);
		}
		result
	}

	/// Subtract two vectors
	pub fn sub(&self, other: &Self) -> Self {
		let mut result = Self::zero();
		for i in 0..L {
			result.0[i] = self.0[i].sub(&other.0[i]);
		}
		result
	}

	/// Multiply vector by scalar
	pub fn scalar_mul(&self, scalar: FieldElement) -> Self {
		let mut result = Self::zero();
		for i in 0..L {
			result.0[i] = self.0[i].scalar_mul(scalar);
		}
		result
	}
}

/// Vector of K polynomials
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct VecK<const K: usize>([Polynomial; K]);

impl<const K: usize> Default for VecK<K> {
	fn default() -> Self {
		Self(core::array::from_fn(|_| Polynomial::zero()))
	}
}

impl<const K: usize> VecK<K> {
	/// Create new zero vector
	pub fn zero() -> Self {
		Self::default()
	}

	/// Get polynomial at index
	pub fn get(&self, i: usize) -> &Polynomial {
		&self.0[i]
	}

	/// Get mutable polynomial at index
	pub fn get_mut(&mut self, i: usize) -> &mut Polynomial {
		&mut self.0[i]
	}

	/// Set polynomial at index
	pub fn set(&mut self, i: usize, poly: Polynomial) {
		self.0[i] = poly;
	}

	/// Add two vectors
	pub fn add(&self, other: &Self) -> Self {
		let mut result = Self::zero();
		for i in 0..K {
			result.0[i] = self.0[i].add(&other.0[i]);
		}
		result
	}

	/// Subtract two vectors
	pub fn sub(&self, other: &Self) -> Self {
		let mut result = Self::zero();
		for i in 0..K {
			result.0[i] = self.0[i].sub(&other.0[i]);
		}
		result
	}

	/// Multiply vector by scalar
	pub fn scalar_mul(&self, scalar: FieldElement) -> Self {
		let mut result = Self::zero();
		for i in 0..K {
			result.0[i] = self.0[i].scalar_mul(scalar);
		}
		result
	}
}

/// Float vector for threshold computations (matches Go's FVec)
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct FloatVec<const SIZE: usize>([f64; SIZE]);

impl<const SIZE: usize> Default for FloatVec<SIZE> {
	fn default() -> Self {
		Self([0.0; SIZE])
	}
}

impl<const SIZE: usize> FloatVec<SIZE> {
	/// Create new zero vector
	pub fn zero() -> Self {
		Self::default()
	}

	/// Add two float vectors
	pub fn add(&self, other: &Self) -> Self {
		let mut result = Self::zero();
		for i in 0..SIZE {
			result.0[i] = self.0[i] + other.0[i];
		}
		result
	}

	/// Convert from VecL and VecK (matches Go's From method)
	pub fn from_vecs<const L: usize, const K: usize>(s1: &VecL<L>, s2: &VecK<K>) -> Self {
		let mut result = Self::zero();

		// Copy L polynomials from s1
		for i in 0..L {
			for j in 0..N {
				let coeff = s1.get(i).get(j).centered();
				result.0[i * N + j] = coeff as f64;
			}
		}

		// Copy K polynomials from s2
		for i in 0..K {
			for j in 0..N {
				let coeff = s2.get(i).get(j).centered();
				result.0[(L + i) * N + j] = coeff as f64;
			}
		}

		result
	}

	/// Round float values back to integer polynomials
	pub fn round_to_vecs<const L: usize, const K: usize>(&self) -> (VecL<L>, VecK<K>) {
		let mut s1 = VecL::<L>::zero();
		let mut s2 = VecK::<K>::zero();

		// Extract L polynomials to s1
		for i in 0..L {
			for j in 0..N {
				let rounded = self.0[i * N + j].round() as i32;
				s1.get_mut(i).set(j, FieldElement::from_i32(rounded));
			}
		}

		// Extract K polynomials to s2
		for i in 0..K {
			for j in 0..N {
				let rounded = self.0[(L + i) * N + j].round() as i32;
				s2.get_mut(i).set(j, FieldElement::from_i32(rounded));
			}
		}

		(s1, s2)
	}
}

/// Compute modular inverse using extended Euclidean algorithm
fn mod_inverse(a: u32, m: u32) -> u32 {
	if a == 0 {
		return 0;
	}

	let (mut old_r, mut r) = (a as i64, m as i64);
	let (mut old_s, mut s) = (1i64, 0i64);

	while r != 0 {
		let quotient = old_r / r;
		let temp_r = r;
		r = old_r - quotient * r;
		old_r = temp_r;

		let temp_s = s;
		s = old_s - quotient * s;
		old_s = temp_s;
	}

	if old_s < 0 {
		old_s += m as i64;
	}

	old_s as u32
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_field_element_basic_ops() {
		let a = FieldElement::new(100);
		let b = FieldElement::new(200);

		assert_eq!(a + b, FieldElement::new(300));
		assert_eq!(b - a, FieldElement::new(100));
		assert_eq!(a * b, FieldElement::new(20000));
	}

	#[test]
	fn test_field_element_modular_arithmetic() {
		let a = FieldElement::new(Q - 1);
		let b = FieldElement::new(2);

		// Test overflow
		assert_eq!(a + b, FieldElement::new(1));

		// Test underflow
		let c = FieldElement::new(1);
		let d = FieldElement::new(2);
		assert_eq!(c - d, FieldElement::new(Q - 1));
	}

	#[test]
	fn test_field_element_centered() {
		let a = FieldElement::new(100);
		assert_eq!(a.centered(), 100);

		let b = FieldElement::new(Q - 100);
		assert_eq!(b.centered(), -100);
	}

	#[test]
	fn test_polynomial_operations() {
		let mut p1 = Polynomial::zero();
		let mut p2 = Polynomial::zero();

		p1.set(0, FieldElement::new(5));
		p1.set(1, FieldElement::new(10));

		p2.set(0, FieldElement::new(3));
		p2.set(1, FieldElement::new(7));

		let sum = p1.add(&p2);
		assert_eq!(sum.get(0), FieldElement::new(8));
		assert_eq!(sum.get(1), FieldElement::new(17));

		let diff = p1.sub(&p2);
		assert_eq!(diff.get(0), FieldElement::new(2));
		assert_eq!(diff.get(1), FieldElement::new(3));
	}

	#[test]
	fn test_vector_operations() {
		let mut v1 = VecL::<2>::zero();
		let mut v2 = VecL::<2>::zero();

		v1.get_mut(0).set(0, FieldElement::new(5));
		v2.get_mut(0).set(0, FieldElement::new(3));

		let sum = v1.add(&v2);
		assert_eq!(sum.get(0).get(0), FieldElement::new(8));
	}

	#[test]
	fn test_mod_inverse() {
		// Test some known inverses
		assert_eq!(mod_inverse(2, Q), (Q + 1) / 2); // inverse of 2

		// Test that a * inv(a) ≡ 1 (mod q)
		let a = 1337u32;
		let inv_a = mod_inverse(a, Q);
		assert_eq!(((a as u64 * inv_a as u64) % Q as u64) as u32, 1);
	}
}
