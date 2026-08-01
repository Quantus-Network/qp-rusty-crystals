#![no_std]
#![allow(clippy::identity_op)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::precedence)]
#![allow(clippy::unnecessary_cast)]
#![allow(clippy::enum_variant_names)]
// Without an `ml-dsa-*` feature the public frontends are not compiled, so the
// const-generic signing core and the unused `define_ml_dsa!` macro become dead
// code. That configuration is intentional (hdwallet's wormhole/mnemonic
// surface depends on dilithium with no parameter set), so silence the
// featureless-build lints rather than feature-gating the entire core.
#![cfg_attr(
	not(any(feature = "ml-dsa-44", feature = "ml-dsa-65", feature = "ml-dsa-87")),
	allow(dead_code, unused_macros, unused_imports)
)]

extern crate alloc;

// `std` is pulled in only for the test build so the ACVP known-answer harness
// (`acvp`) can read the vendored NIST vector files from disk. Production builds
// remain `#![no_std]`.
#[cfg(test)]
extern crate std;

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Compares two 32-byte arrays in constant time.
///
/// `==` on byte arrays is *allowed* to short-circuit at the first differing
/// byte, making the comparison time depend on the length of the matching
/// prefix — a timing oracle that lets an attacker recover a secret
/// incrementally (security review). Whether the compiler actually emits an
/// early exit varies by target and optimization level, so secret material
/// must never rely on it. This routine unconditionally folds the XOR of every
/// byte pair into an accumulator; `black_box` denies the optimizer knowledge
/// of the accumulated value so it cannot reintroduce a value-dependent exit.
#[must_use]
pub fn ct_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
	let mut diff = 0u8;
	for (x, y) in a.iter().zip(b.iter()) {
		diff |= x ^ y;
	}
	core::hint::black_box(diff) == 0
}

/// Wrapper for sensitive 32-byte data that enforces move semantics and automatic zeroization
///
/// Both `new()` and `from()` take mutable references and zeroize the input data,
/// ensuring no copies of sensitive data remain in memory. `Clone` is intentionally
/// not derived: the type is move-only by construction, so the secret can exist in
/// at most one wrapper instance at a time.
///
/// ```rust
/// use qp_rusty_crystals_dilithium::SensitiveBytes32;
/// let mut entropy = [42u8; 32];
/// let sensitive = SensitiveBytes32::new(&mut entropy); // entropy is now zeroed
/// // or
/// let sensitive = SensitiveBytes32::from(&mut entropy); // same behavior
/// ```
#[derive(ZeroizeOnDrop)]
pub struct SensitiveBytes32([u8; 32]);

impl SensitiveBytes32 {
	// Note this zeroizes the input bytes so that the struct takes practical ownership of the input.
	pub fn new(bytes: &mut [u8; 32]) -> Self {
		let result = Self(*bytes);
		bytes.zeroize();
		result
	}

	/// All-zero value, intended to be filled in place via [`Self::as_mut_bytes`].
	///
	/// Writing the secret directly into the wrapper's interior avoids ever
	/// materializing it in a separate buffer that `new`/`from` would have to
	/// copy from (Rust moves and copies leave unwiped duplicates in dead
	/// stack slots).
	pub fn zeroed() -> Self {
		Self([0u8; 32])
	}

	/// Mutable access to the wrapped bytes, for in-place construction
	/// (see [`Self::zeroed`]). The value keeps sole ownership of the secret.
	pub fn as_mut_bytes(&mut self) -> &mut [u8; 32] {
		&mut self.0
	}

	pub fn as_bytes(&self) -> &[u8; 32] {
		&self.0
	}

	pub fn into_bytes(self) -> [u8; 32] {
		self.0
	}

	/// Constant-time equality with another secret.
	///
	/// `PartialEq` is intentionally not implemented for this type: a plain
	/// `==` on the wrapped bytes may short-circuit and leak the length of the
	/// matching prefix through timing. Callers that genuinely need to compare
	/// secrets must do so explicitly through this method (see [`ct_eq_32`]).
	#[must_use]
	pub fn ct_eq(&self, other: &Self) -> bool {
		ct_eq_32(&self.0, &other.0)
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
/// ensuring no copies of sensitive data remain in memory. `Clone` is intentionally
/// not derived: the type is move-only by construction, so the secret can exist in
/// at most one wrapper instance at a time.
#[derive(ZeroizeOnDrop)]
pub struct SensitiveBytes64([u8; 64]);

impl SensitiveBytes64 {
	// Note this zeroizes the input bytes so that the struct takes practical ownership of the input.
	pub fn new(bytes: &mut [u8; 64]) -> Self {
		let result = Self(*bytes);
		bytes.zeroize();
		result
	}

	/// All-zero value, intended to be filled in place via [`Self::as_mut_bytes`].
	///
	/// Writing the secret directly into the wrapper's interior avoids ever
	/// materializing it in a separate buffer that `new`/`from` would have to
	/// copy from (Rust moves and copies leave unwiped duplicates in dead
	/// stack slots).
	pub fn zeroed() -> Self {
		Self([0u8; 64])
	}

	/// Mutable access to the wrapped bytes, for in-place construction
	/// (see [`Self::zeroed`]). The value keeps sole ownership of the secret.
	pub fn as_mut_bytes(&mut self) -> &mut [u8; 64] {
		&mut self.0
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

mod errors;
pub use errors::{KeyParsingError, SignatureError};

pub mod fips202;
pub(crate) mod frontend;
pub(crate) mod ntt;
pub mod packing;
pub mod params;
pub mod poly;
pub mod polyvec;
pub(crate) mod reduce;
pub mod rounding;
pub(crate) mod sign;

#[cfg(feature = "ml-dsa-44")]
pub mod ml_dsa_44;
#[cfg(feature = "ml-dsa-65")]
pub mod ml_dsa_65;
#[cfg(feature = "ml-dsa-87")]
pub mod ml_dsa_87;

#[cfg(test)]
mod acvp;

#[cfg(test)]
mod tests {
	use crate::{ct_eq_32, SensitiveBytes32};

	#[test]
	fn ct_eq_32_semantics() {
		let a = [0xA5u8; 32];
		assert!(ct_eq_32(&a, &a));

		// Differences at the first, last, and a middle byte must all be
		// detected — the fold must cover the entire array.
		for idx in [0usize, 15, 31] {
			let mut b = a;
			b[idx] ^= 1;
			assert!(!ct_eq_32(&a, &b), "difference at byte {idx} not detected");
		}

		assert!(!ct_eq_32(&[0u8; 32], &[0xFFu8; 32]));
	}

	#[test]
	fn sensitive_bytes_ct_eq() {
		let mut raw1 = [7u8; 32];
		let mut raw2 = [7u8; 32];
		let mut raw3 = [8u8; 32];
		let a = SensitiveBytes32::new(&mut raw1);
		let b = SensitiveBytes32::new(&mut raw2);
		let c = SensitiveBytes32::new(&mut raw3);
		assert!(a.ct_eq(&b));
		assert!(!a.ct_eq(&c));
	}

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
