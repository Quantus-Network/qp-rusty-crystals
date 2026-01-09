//! Parameter definitions for threshold ML-DSA variants

use crate::common::{validate_threshold_params, ThresholdResult};

/// Common constants across all ML-DSA variants
pub mod common {
	/// Ring dimension (common to all ML-DSA variants)
	pub const N: usize = 256;

	/// Modulus q = 2^23 - 2^13 + 1
	pub const Q: u32 = 8380417;

	/// Number of bits in q
	pub const Q_BITS: usize = 23;

	/// Size of seed for key generation
	pub const SEED_SIZE: usize = 32;

	/// Size of TR (public key hash)
	pub const TR_SIZE: usize = 64;

	/// Size of challenge hash
	pub const C_TILDE_SIZE: usize = 64;

	/// Size of packed T1 polynomial
	pub const POLY_T1_SIZE: usize = 320;
}

/// Parameter trait for ML-DSA variants
pub trait MlDsaParams {
	/// Security level name
	const NAME: &'static str;

	/// Dimension k (rows in A)
	const K: usize;

	/// Dimension l (columns in A)
	const L: usize;

	/// Coefficient range parameter η
	const ETA: i32;

	/// Double eta bits for packing
	const DOUBLE_ETA_BITS: usize;

	/// Number of ±1's in c
	const OMEGA: usize;

	/// Parameter τ (tau)
	const TAU: usize;

	/// γ₁ bits
	const GAMMA1_BITS: usize;

	/// γ₂ parameter
	const GAMMA2: i32;

	/// NIST mode flag
	const NIST: bool;

	// Derived constants

	/// β = τη, maximum size of c·s₂
	const BETA: usize = Self::TAU * Self::ETA as usize;

	/// γ₁ = 2^(γ₁ bits)
	const GAMMA1: i32 = 1 << Self::GAMMA1_BITS;

	/// α = 2γ₂
	const ALPHA: i32 = 2 * Self::GAMMA2;

	/// Size of packed polynomial with coefficients ≤ η
	const POLY_LEQ_ETA_SIZE: usize = (common::N * Self::DOUBLE_ETA_BITS) / 8;

	/// Size of packed polynomial with coefficients < γ₁
	const POLY_LE_GAMMA1_SIZE: usize = (Self::GAMMA1_BITS + 1) * common::N / 8;

	/// Size of packed w₁ polynomial
	const POLY_W1_SIZE: usize = (common::N * (common::Q_BITS - Self::GAMMA1_BITS)) / 8;

	/// Size of packed w polynomial (full modulus)
	const POLY_Q_SIZE: usize = (common::N * common::Q_BITS) / 8;

	/// Size of packed public key
	const PUBLIC_KEY_SIZE: usize = 32 + common::POLY_T1_SIZE * Self::K;

	/// Size of packed signature
	const SIGNATURE_SIZE: usize =
		Self::L * Self::POLY_LE_GAMMA1_SIZE + Self::OMEGA + Self::K + common::C_TILDE_SIZE;

	/// Size of single commitment in threshold protocol
	const SINGLE_COMMITMENT_SIZE: usize = Self::K * Self::POLY_Q_SIZE;

	/// Size of single response in threshold protocol
	const SINGLE_RESPONSE_SIZE: usize = Self::L * Self::POLY_LE_GAMMA1_SIZE;
}

/// Parameters for ML-DSA-87 (256-bit security, NIST Level 5)
pub struct MlDsa87Params;

impl MlDsaParams for MlDsa87Params {
	const NAME: &'static str = "ML-DSA-87";
	const K: usize = 8;
	const L: usize = 7;
	const ETA: i32 = 2;
	const DOUBLE_ETA_BITS: usize = 3;
	const OMEGA: usize = 75;
	const TAU: usize = 60;
	const GAMMA1_BITS: usize = 19;
	const GAMMA2: i32 = 261888;
	const NIST: bool = true;
}

/// Threshold-specific parameters
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThresholdParams {
	/// Threshold value (minimum parties required to sign)
	pub t: u8,
	/// Total number of parties
	pub n: u8,
	/// Number of active parties participating in signing
	pub k: u8,
	/// Canonical K parameter (number of iterations per party)
	pub canonical_k: u16,
}

impl ThresholdParams {
	/// Create new threshold parameters with validation
	pub fn new(t: u8, n: u8) -> ThresholdResult<Self> {
		validate_threshold_params(t, n)?;
		// Get the canonical K parameter from ThresholdConfig
		let canonical_k = Self::get_canonical_k(t, n)?;
		Ok(Self { t, n, k: n, canonical_k })
	}

	/// Create threshold parameters for a signing session with specific active parties
	pub fn for_signing(t: u8, n: u8, active_parties: u8) -> ThresholdResult<Self> {
		validate_threshold_params(t, n)?;

		if active_parties < t {
			return Err(crate::common::ThresholdError::InsufficientParties {
				provided: active_parties as usize,
				required: t,
			});
		}

		if active_parties > n {
			return Err(crate::common::ThresholdError::InvalidParameters {
				threshold: t,
				parties: n,
				reason: "active parties cannot exceed total parties",
			});
		}

		// Get the canonical K parameter
		let canonical_k = Self::get_canonical_k(t, n)?;
		Ok(Self { t, n, k: active_parties, canonical_k })
	}

	/// Get response size for this threshold configuration
	pub fn response_size<P: MlDsaParams>(&self) -> usize {
		self.canonical_k as usize * P::SINGLE_RESPONSE_SIZE
	}

	/// Get commitment size for this threshold configuration
	pub fn commitment_size<P: MlDsaParams>(&self) -> usize {
		self.canonical_k as usize * P::SINGLE_COMMITMENT_SIZE
	}

	/// Check if enough parties are participating for threshold
	pub fn has_threshold(&self, num_parties: usize) -> bool {
		num_parties >= self.t as usize
	}

	/// Get the threshold value
	pub fn threshold(&self) -> u8 {
		self.t
	}

	/// Get the total number of parties
	pub fn total_parties(&self) -> u8 {
		self.n
	}

	/// Get the number of active parties
	pub fn active_parties(&self) -> u8 {
		self.k
	}

	/// Get the canonical K parameter (number of iterations per party)
	pub fn canonical_k(&self) -> u16 {
		self.canonical_k
	}

	/// Get the canonical K parameter for given threshold parameters
	fn get_canonical_k(t: u8, n: u8) -> ThresholdResult<u16> {
		// These values match the canonical Golang implementation
		// from Threshold-ML-DSA/implementation/sign/thmldsa/thmldsa87/internal/dilithium.go
		let k = match (t, n) {
			(2, 2) => 3,
			(2, 3) => 4,
			(3, 3) => 6,
			(2, 4) => 4,
			(3, 4) => 11,
			(4, 4) => 14,
			(2, 5) => 5,
			(3, 5) => 26,
			(4, 5) => 70,
			(5, 5) => 35,
			(2, 6) => 5,
			(3, 6) => 39,
			(4, 6) => 208,
			(5, 6) => 295,
			(6, 6) => 87,
			_ => {
				return Err(crate::common::ThresholdError::InvalidParameters {
					threshold: t,
					parties: n,
					reason: "unsupported threshold configuration",
				})
			},
		};
		Ok(k)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_mldsa87_constants() {
		assert_eq!(MlDsa87Params::NAME, "ML-DSA-87");
		assert_eq!(MlDsa87Params::K, 8);
		assert_eq!(MlDsa87Params::L, 7);
		assert_eq!(MlDsa87Params::ETA, 2);
		assert_eq!(MlDsa87Params::GAMMA1, 524288); // 2^19
	}

	#[test]
	fn test_threshold_params_creation() {
		let params = ThresholdParams::new(3, 5).unwrap();
		assert_eq!(params.threshold(), 3);
		assert_eq!(params.total_parties(), 5);
		assert_eq!(params.active_parties(), 5);
	}

	#[test]
	fn test_threshold_params_for_signing() {
		let params = ThresholdParams::for_signing(3, 5, 4).unwrap();
		assert_eq!(params.threshold(), 3);
		assert_eq!(params.total_parties(), 5);
		assert_eq!(params.active_parties(), 4);
	}

	#[test]
	fn test_threshold_validation() {
		// Should succeed
		assert!(ThresholdParams::new(2, 3).is_ok());
		assert!(ThresholdParams::new(3, 6).is_ok());

		// Should fail
		assert!(ThresholdParams::new(1, 3).is_err()); // threshold too small
		assert!(ThresholdParams::new(5, 3).is_err()); // threshold > parties
		assert!(ThresholdParams::new(3, 7).is_err()); // too many parties
	}

	#[test]
	fn test_has_threshold() {
		let params = ThresholdParams::new(3, 5).unwrap();
		assert!(!params.has_threshold(2));
		assert!(params.has_threshold(3));
		assert!(params.has_threshold(5));
	}

	#[test]
	fn test_size_calculations() {
		let params = ThresholdParams::new(3, 5).unwrap();

		// Test with ML-DSA-87 parameters
		let response_size = params.response_size::<MlDsa87Params>();
		let commitment_size = params.commitment_size::<MlDsa87Params>();

		// For (3, 5) threshold, canonical K = 26
		assert_eq!(response_size, 26 * MlDsa87Params::SINGLE_RESPONSE_SIZE);
		assert_eq!(commitment_size, 26 * MlDsa87Params::SINGLE_COMMITMENT_SIZE);
	}
}