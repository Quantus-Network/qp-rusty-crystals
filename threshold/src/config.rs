//! Threshold configuration for ML-DSA-87.
//!
//! This module contains the configuration parameters for threshold signing,
//! including the threshold value (t) and total parties (n).

use borsh::{BorshDeserialize, BorshSerialize};

use crate::error::{validate_threshold_params, ThresholdError, ThresholdResult};

/// Configuration for a threshold signing scheme.
///
/// A (t, n) threshold scheme requires at least t out of n parties to
/// cooperate in order to produce a valid signature.
///
/// # Example
///
/// ```
/// use qp_rusty_crystals_threshold::ThresholdConfig;
///
/// // Create a 2-of-3 threshold scheme
/// let config = ThresholdConfig::new(2, 3).expect("valid parameters");
/// assert_eq!(config.threshold(), 2);
/// assert_eq!(config.total_parties(), 3);
/// ```
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ThresholdConfig {
	/// Threshold value (minimum parties required to sign).
	t: u32,
	/// Total number of parties.
	n: u32,
	/// Number of iterations (K parameter from reference implementation).
	k_iterations: u32,
}

impl ThresholdConfig {
	/// Create a new threshold configuration.
	///
	/// # Arguments
	///
	/// * `t` - Threshold value (minimum parties required to sign)
	/// * `n` - Total number of parties
	///
	/// # Errors
	///
	/// Returns an error if:
	/// - `t < 2` (threshold must be at least 2)
	/// - `n > 6` (maximum 6 parties supported)
	/// - `t > n` (threshold cannot exceed total parties)
	/// - The (t, n) combination is not supported
	///
	/// # Note on k_iterations
	///
	/// The K parameter determines how many parallel signing attempts are made.
	/// Values come from the reference Threshold-ML-DSA implementation
	/// and are derived from security analysis of rejection sampling probability.
	pub fn new(t: u32, n: u32) -> ThresholdResult<Self> {
		validate_threshold_params(t, n)?;

		// K iterations determine parallel signing attempts. Values are tuned to
		// achieve low retry rates (~0.3-0.5 average retries per signing).
		// Values are from the reference Threshold-ML-DSA implementation.
		let k_iterations = match (t, n) {
			(2, 2) => 4,
			(2, 3) => 5,
			(3, 3) => 12,
			(2, 4) => 7,
			(3, 4) => 24,
			(4, 4) => 25,
			(2, 5) => 6,
			(3, 5) => 42,
			(4, 5) => 110,
			(5, 5) => 60,
			(2, 6) => 8,
			(3, 6) => 65,
			(4, 6) => 350,
			(5, 6) => 380,
			(6, 6) => 180,
			_ =>
				return Err(ThresholdError::InvalidParameters {
					threshold: t,
					parties: n,
					reason: "unsupported threshold configuration for ML-DSA-87",
				}),
		};

		Ok(Self { t, n, k_iterations })
	}

	/// Get the threshold value (minimum parties required to sign).
	#[inline]
	pub fn threshold(&self) -> u32 {
		self.t
	}

	/// Get the total number of parties.
	#[inline]
	pub fn total_parties(&self) -> u32 {
		self.n
	}

	/// Get the number of iterations (K parameter).
	#[inline]
	pub fn k_iterations(&self) -> u32 {
		self.k_iterations
	}
}

impl BorshSerialize for ThresholdConfig {
	fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
		// Only serialize t and n; k_iterations is derived
		self.t.serialize(writer)?;
		self.n.serialize(writer)?;
		Ok(())
	}
}

impl BorshDeserialize for ThresholdConfig {
	fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
		let t = u32::deserialize_reader(reader)?;
		let n = u32::deserialize_reader(reader)?;
		ThresholdConfig::new(t, n).map_err(|e| {
			borsh::io::Error::new(
				borsh::io::ErrorKind::InvalidData,
				alloc::string::ToString::to_string(&e),
			)
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_config_creation() {
		let config = ThresholdConfig::new(2, 3).unwrap();
		assert_eq!(config.threshold(), 2);
		assert_eq!(config.total_parties(), 3);
		assert_eq!(config.k_iterations(), 5); // Updated based on retry tuning
	}

	#[test]
	fn test_all_valid_configs() {
		let valid_configs = [
			(2, 2),
			(2, 3),
			(3, 3),
			(2, 4),
			(3, 4),
			(4, 4),
			(2, 5),
			(3, 5),
			(4, 5),
			(5, 5),
			(2, 6),
			(3, 6),
			(4, 6),
			(5, 6),
			(6, 6),
		];

		for (t, n) in valid_configs {
			let config = ThresholdConfig::new(t, n);
			assert!(config.is_ok(), "Config ({}, {}) should be valid", t, n);
		}
	}

	#[test]
	fn test_n7_not_supported() {
		// n=7 is not supported because hyperball parameters have not been computed
		// and the required K values would be impractically large (K > 3000)
		let result = ThresholdConfig::new(2, 7);
		assert!(result.is_err(), "Config (2, 7) should be rejected");
	}

	#[test]
	fn test_invalid_threshold_too_small() {
		let result = ThresholdConfig::new(1, 3);
		assert!(result.is_err());
	}

	#[test]
	fn test_invalid_too_many_parties() {
		let result = ThresholdConfig::new(3, 8);
		assert!(result.is_err());
	}

	#[test]
	fn test_invalid_threshold_exceeds_parties() {
		let result = ThresholdConfig::new(5, 3);
		assert!(result.is_err());
	}
}
