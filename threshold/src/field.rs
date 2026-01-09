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

	/// Create a new field element, reducing modulo q if necessary
	pub fn new(val: u32) -> Self {
		Self(val % Q)
	}

	/// Get the value as u32
	pub fn value(&self) -> u32 {
		self.0
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

	/// Get coefficient at index i
	pub fn get(&self, i: usize) -> FieldElement {
		self.0[i]
	}

	/// Set coefficient at index i
	pub fn set(&mut self, i: usize, val: FieldElement) {
		self.0[i] = val;
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
}
