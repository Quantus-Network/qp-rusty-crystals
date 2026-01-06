//! Common types, constants, and error definitions for threshold ML-DSA

use core::fmt;

/// Result type for threshold operations
pub type ThresholdResult<T> = Result<T, ThresholdError>;

/// Error types for threshold operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThresholdError {
	/// Invalid threshold parameters (t, n)
	InvalidParameters {
		/// Threshold value
		threshold: u8,
		/// Total number of parties
		parties: u8,
		/// Description of the validation error
		reason: &'static str,
	},
	/// Invalid party ID
	InvalidPartyId {
		/// The invalid party ID
		party_id: u8,
		/// Maximum valid party ID
		max_id: u8,
	},
	/// Insufficient number of parties for threshold
	InsufficientParties {
		/// Number of parties provided
		provided: usize,
		/// Required threshold
		required: u8,
	},
	/// Invalid signature share
	InvalidSignatureShare {
		/// Party ID that provided the invalid share
		party_id: u8,
		/// Reason for invalidity
		reason: &'static str,
	},
	/// Invalid commitment
	InvalidCommitment {
		/// Party ID that provided the invalid commitment
		party_id: u8,
		/// Expected size
		expected_size: usize,
		/// Actual size
		actual_size: usize,
	},
	/// Invalid response size
	InvalidResponseSize {
		/// Expected size
		expected: usize,
		/// Actual size
		actual: usize,
	},
	/// Invalid commitment size
	InvalidCommitmentSize {
		/// Expected size
		expected: usize,
		/// Actual size
		actual: usize,
	},
	/// Commitment verification failed
	CommitmentVerificationFailed {
		/// Party ID
		party_id: u8,
	},
	/// Random number generation failed
	RandomnessError,
	/// Context too long (must be ≤ 255 bytes)
	ContextTooLong {
		/// Length provided
		length: usize,
	},
	/// Signature combination failed
	CombinationFailed,
	/// Invalid polynomial coefficient
	InvalidCoefficient,
	/// Buffer size mismatch
	BufferSizeMismatch {
		/// Expected size
		expected: usize,
		/// Actual size
		actual: usize,
	},
	/// Invalid configuration
	InvalidConfiguration(String),
}

impl fmt::Display for ThresholdError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			ThresholdError::InvalidParameters { threshold, parties, reason } => {
				write!(
					f,
					"Invalid threshold parameters: t={}, n={}, reason: {}",
					threshold, parties, reason
				)
			},
			ThresholdError::InvalidPartyId { party_id, max_id } => {
				write!(f, "Invalid party ID: {} (max: {})", party_id, max_id)
			},
			ThresholdError::InsufficientParties { provided, required } => {
				write!(f, "Insufficient parties: provided {}, required {}", provided, required)
			},
			ThresholdError::InvalidSignatureShare { party_id, reason } => {
				write!(f, "Invalid signature share from party {}: {}", party_id, reason)
			},
			ThresholdError::InvalidCommitment { party_id, expected_size, actual_size } => {
				write!(
					f,
					"Invalid commitment from party {}: expected {} bytes, got {}",
					party_id, expected_size, actual_size
				)
			},
			ThresholdError::InvalidResponseSize { expected, actual } => {
				write!(f, "Invalid response size: expected {}, got {}", expected, actual)
			},
			ThresholdError::InvalidCommitmentSize { expected, actual } => {
				write!(f, "Invalid commitment size: expected {}, got {}", expected, actual)
			},
			ThresholdError::CommitmentVerificationFailed { party_id } => {
				write!(f, "Commitment verification failed for party {}", party_id)
			},
			ThresholdError::RandomnessError => {
				write!(f, "Failed to generate random bytes")
			},
			ThresholdError::ContextTooLong { length } => {
				write!(f, "Context too long: {} bytes (max: 255)", length)
			},
			ThresholdError::CombinationFailed => {
				write!(f, "Signature combination failed")
			},
			ThresholdError::InvalidCoefficient => {
				write!(f, "Invalid polynomial coefficient")
			},
			ThresholdError::BufferSizeMismatch { expected, actual } => {
				write!(f, "Buffer size mismatch: expected {}, got {}", expected, actual)
			},
			ThresholdError::InvalidConfiguration(msg) => {
				write!(f, "Invalid configuration: {}", msg)
			},
		}
	}
}

#[cfg(feature = "std")]
impl std::error::Error for ThresholdError {}

/// Validate threshold parameters
pub fn validate_threshold_params(t: u8, n: u8) -> ThresholdResult<()> {
	use crate::{MAX_PARTIES, MIN_THRESHOLD};

	if t < MIN_THRESHOLD {
		return Err(ThresholdError::InvalidParameters {
			threshold: t,
			parties: n,
			reason: "threshold must be at least 2",
		});
	}

	if n > MAX_PARTIES {
		return Err(ThresholdError::InvalidParameters {
			threshold: t,
			parties: n,
			reason: "too many parties (max 6)",
		});
	}

	if t > n {
		return Err(ThresholdError::InvalidParameters {
			threshold: t,
			parties: n,
			reason: "threshold cannot exceed number of parties",
		});
	}

	Ok(())
}

/// Validate context length for ML-DSA
pub fn validate_context(ctx: &[u8]) -> ThresholdResult<()> {
	if ctx.len() > 255 {
		return Err(ThresholdError::ContextTooLong { length: ctx.len() });
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_valid_threshold_params() {
		assert!(validate_threshold_params(2, 3).is_ok());
		assert!(validate_threshold_params(3, 5).is_ok());
		assert!(validate_threshold_params(6, 6).is_ok());
	}

	#[test]
	fn test_invalid_threshold_params() {
		// Threshold too small
		assert!(validate_threshold_params(1, 3).is_err());

		// Too many parties
		assert!(validate_threshold_params(3, 7).is_err());

		// Threshold exceeds parties
		assert!(validate_threshold_params(5, 3).is_err());
	}

	#[test]
	fn test_valid_context() {
		assert!(validate_context(b"").is_ok());
		assert!(validate_context(b"test context").is_ok());
		assert!(validate_context(&vec![0u8; 255]).is_ok());
	}

	#[test]
	fn test_invalid_context() {
		assert!(validate_context(&vec![0u8; 256]).is_err());
	}
}
