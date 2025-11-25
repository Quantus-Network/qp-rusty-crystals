#![no_std]
#![allow(clippy::identity_op)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::precedence)]
#![allow(clippy::unnecessary_cast)]
#![allow(clippy::enum_variant_names)]

extern crate alloc;

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Wrapper for sensitive 32-byte data that enforces move semantics and automatic zeroization
///
/// Both `new()` and `from()` take mutable references and zeroize the input data,
/// ensuring no copies of sensitive data remain in memory.
///
/// ```rust
/// use qp_rusty_crystals_dilithium::SensitiveBytes32;
/// let mut entropy = [42u8; 32];
/// let sensitive = SensitiveBytes32::new(&mut entropy); // entropy is now zeroed
/// // or
/// let sensitive = SensitiveBytes32::from(&mut entropy); // same behavior
/// ```
#[derive(Clone, ZeroizeOnDrop)]
pub struct SensitiveBytes32([u8; 32]);

impl SensitiveBytes32 {
	// Note this zeroizes the input bytes so that the struct takes practical ownership of the input.
	pub fn new(bytes: &mut [u8; 32]) -> Self {
		let result = Self(*bytes);
		bytes.zeroize();
		result
	}

	pub fn as_bytes(&self) -> &[u8; 32] {
		&self.0
	}

	pub fn into_bytes(self) -> [u8; 32] {
		self.0
	}
}

impl From<&mut [u8; 32]> for SensitiveBytes32 {
	fn from(bytes: &mut [u8; 32]) -> Self {
		let result = Self(*bytes);
		bytes.zeroize();
		result
	}
}

/// Wrapper for sensitive 64-byte data that enforces move semantics and automatic zeroization
///
/// Both `new()` and `from()` take mutable references and zeroize the input data,
/// ensuring no copies of sensitive data remain in memory.
#[derive(Clone, ZeroizeOnDrop)]
pub struct SensitiveBytes64([u8; 64]);

impl SensitiveBytes64 {
	// Note this zeroizes the input bytes so that the struct takes practical ownership of the input.
	pub fn new(bytes: &mut [u8; 64]) -> Self {
		let result = Self(*bytes);
		bytes.zeroize();
		result
	}

	pub fn as_bytes(&self) -> &[u8; 64] {
		&self.0
	}

	pub fn into_bytes(self) -> [u8; 64] {
		self.0
	}
}

impl From<&mut [u8; 64]> for SensitiveBytes64 {
	fn from(bytes: &mut [u8; 64]) -> Self {
		let result = Self(*bytes);
		bytes.zeroize();
		result
	}
}

pub mod drbg;
mod errors;
pub mod fips202;
pub mod ml_dsa_87;
pub mod ntt;
pub mod packing;
pub mod params;
pub mod poly;
pub mod polyvec;
pub mod reduce;
pub mod rounding;
pub mod sign;

#[cfg(test)]
mod tests {
	#[test]
	fn params() {
		assert_eq!(crate::params::Q, 8380417);
		assert_eq!(crate::params::N, 256);
		assert_eq!(crate::params::R, 1753);
		assert_eq!(crate::params::D, 13);
	}
	#[test]
	fn params_lvl5() {
		assert_eq!(crate::params::TAU, 60);
		assert_eq!(crate::params::CHALLENGE_ENTROPY, 257);
		assert_eq!(crate::params::GAMMA1, 524288);
		assert_eq!(crate::params::GAMMA2, 261888);
		assert_eq!(crate::params::K, 8);
		assert_eq!(crate::params::L, 7);
		assert_eq!(crate::params::ETA, 2);
		assert_eq!(crate::params::BETA, 120);
		assert_eq!(crate::params::OMEGA, 75);
	}
}
