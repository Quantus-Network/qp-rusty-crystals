//! Error types for threshold ML-DSA operations.

use alloc::{string::String, vec::Vec};
use core::fmt;

/// Result type for threshold operations.
pub type ThresholdResult<T> = Result<T, ThresholdError>;

/// Error types for threshold operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThresholdError {
	/// Invalid threshold parameters (t, n).
	InvalidParameters {
		/// Threshold value.
		threshold: u32,
		/// Total number of parties.
		parties: u32,
		/// Description of the validation error.
		reason: &'static str,
	},
	/// Invalid party ID.
	InvalidPartyId {
		/// The invalid party ID.
		party_id: u32,
		/// Maximum valid party ID.
		max_id: u32,
	},
	/// Insufficient number of parties for threshold.
	InsufficientParties {
		/// Number of parties provided.
		provided: usize,
		/// Required threshold.
		required: u32,
	},
	/// Invalid signature share.
	InvalidSignatureShare {
		/// Party ID that provided the invalid share.
		party_id: u32,
		/// Reason for invalidity.
		reason: &'static str,
	},
	/// Invalid commitment.
	InvalidCommitment {
		/// Party ID that provided the invalid commitment.
		party_id: u32,
		/// Expected size.
		expected_size: usize,
		/// Actual size.
		actual_size: usize,
	},
	/// Invalid response size.
	InvalidResponseSize {
		/// Expected size.
		expected: usize,
		/// Actual size.
		actual: usize,
	},
	/// Invalid commitment size.
	InvalidCommitmentSize {
		/// Expected size.
		expected: usize,
		/// Actual size.
		actual: usize,
	},
	/// Invalid public key size.
	InvalidPublicKeySize {
		/// Expected size.
		expected: usize,
		/// Actual size.
		actual: usize,
	},
	/// Commitment verification failed.
	CommitmentVerificationFailed {
		/// Party ID.
		party_id: u32,
	},
	/// Random number generation failed.
	RandomnessError,
	/// Context too long (must be ≤ 255 bytes).
	ContextTooLong {
		/// Length provided.
		length: usize,
	},
	/// Signature combination failed.
	CombinationFailed,
	/// Invalid polynomial coefficient.
	InvalidCoefficient,
	/// Buffer size mismatch.
	BufferSizeMismatch {
		/// Expected size.
		expected: usize,
		/// Actual size.
		actual: usize,
	},
	/// Invalid configuration.
	InvalidConfiguration(String),
	/// Rejection sampling failed (signature attempt rejected due to bounds).
	RejectionSampling,
	/// Constraint violation during signature combination.
	ConstraintViolation,
	/// Invalid data format or structure.
	InvalidData(String),
	/// Invalid signer state for the requested operation.
	InvalidState {
		/// Current state description.
		current: &'static str,
		/// Expected state description.
		expected: &'static str,
	},
	/// Missing broadcast from a party.
	MissingBroadcast {
		/// Party ID that is missing.
		party_id: u32,
	},
	/// Duplicate broadcast from a party.
	DuplicateBroadcast {
		/// Party ID that sent duplicate.
		party_id: u32,
	},
	/// Commitment data does not match commitment hash (HQ2).
	///
	/// This indicates a potential rushing adversary attack where a party
	/// tried to change their commitment after seeing other parties' values.
	CommitmentMismatch {
		/// Party ID with mismatched commitment.
		party_id: u32,
		/// Additional context about the mismatch.
		message: String,
	},
	// ========================================================================
	// DKG-specific errors
	// ========================================================================
	/// DKG protocol error.
	DkgError(String),
	/// DKG commitment hash mismatch.
	DkgCommitmentMismatch {
		/// Party ID with mismatched commitment.
		party_id: u32,
	},
	/// DKG contribution bounds violation.
	DkgInvalidBounds {
		/// Party ID with invalid bounds.
		party_id: u32,
	},
	/// DKG consensus failure - parties disagree on public key.
	DkgConsensusFailure {
		/// Parties with mismatched public keys.
		parties: Vec<u32>,
	},
	/// DKG party reported failure.
	DkgPartyFailure {
		/// Parties that reported failure.
		parties: Vec<u32>,
	},
	/// Failed to unpack signature share data from a party.
	///
	/// This indicates the party sent malformed Round 3 response data that
	/// could not be deserialized. Unlike `InvalidSignatureShare`, this error
	/// occurs during unpacking rather than validation.
	InvalidSignatureShareData {
		/// Party ID that sent the invalid data.
		party_id: u32,
		/// Reason for the failure.
		reason: String,
	},
	/// Failed to unpack commitment data from a party.
	///
	/// This indicates the party sent malformed commitment data that passed
	/// the hash check but could not be deserialized.
	InvalidCommitmentData {
		/// Party ID that sent the invalid data.
		party_id: u32,
		/// Reason for the failure.
		reason: String,
	},
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
			ThresholdError::InvalidPublicKeySize { expected, actual } => {
				write!(f, "Invalid public key size: expected {}, got {}", expected, actual)
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
			ThresholdError::RejectionSampling => {
				write!(f, "Rejection sampling failed - signature attempt rejected")
			},
			ThresholdError::ConstraintViolation => {
				write!(f, "Constraint violation during signature combination")
			},
			ThresholdError::InvalidData(msg) => {
				write!(f, "Invalid data: {}", msg)
			},
			ThresholdError::InvalidState { current, expected } => {
				write!(f, "Invalid signer state: currently {}, expected {}", current, expected)
			},
			ThresholdError::MissingBroadcast { party_id } => {
				write!(f, "Missing broadcast from party {}", party_id)
			},
			ThresholdError::DuplicateBroadcast { party_id } => {
				write!(f, "Duplicate broadcast from party {}", party_id)
			},
			ThresholdError::CommitmentMismatch { party_id, message } => {
				write!(f, "Commitment mismatch for party {}: {}", party_id, message)
			},
			ThresholdError::DkgError(msg) => {
				write!(f, "DKG error: {}", msg)
			},
			ThresholdError::DkgCommitmentMismatch { party_id } => {
				write!(f, "DKG commitment mismatch for party {}", party_id)
			},
			ThresholdError::DkgInvalidBounds { party_id } => {
				write!(f, "DKG invalid coefficient bounds for party {}", party_id)
			},
			ThresholdError::DkgConsensusFailure { parties } => {
				write!(f, "DKG consensus failure, mismatched parties: {:?}", parties)
			},
			ThresholdError::DkgPartyFailure { parties } => {
				write!(f, "DKG party failure: {:?}", parties)
			},
			ThresholdError::InvalidSignatureShareData { party_id, reason } => {
				write!(f, "Invalid signature share data from party {}: {}", party_id, reason)
			},
			ThresholdError::InvalidCommitmentData { party_id, reason } => {
				write!(f, "Invalid commitment data from party {}: {}", party_id, reason)
			},
		}
	}
}

/// Maximum number of parties supported by the threshold scheme.
///
/// This is limited to 6 because the hyperball sampling parameters (r, r')
/// required for secure threshold signing have only been computed for n ≤ 6
/// in the reference Threshold-ML-DSA implementation. For n=7, the required
/// number of parallel signing attempts (K) becomes impractically large
/// (K > 3000 for middle thresholds).
pub const MAX_PARTIES: u32 = 6;

/// Minimum threshold value (at least 2 parties required).
pub const MIN_THRESHOLD: u32 = 2;

/// Validate threshold parameters.
pub fn validate_threshold_params(t: u32, n: u32) -> ThresholdResult<()> {
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

/// Validate context length for ML-DSA.
pub fn validate_context(ctx: &[u8]) -> ThresholdResult<()> {
	if ctx.len() > 255 {
		return Err(ThresholdError::ContextTooLong { length: ctx.len() });
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;
	use alloc::vec;

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
		assert!(validate_threshold_params(3, 8).is_err());

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
