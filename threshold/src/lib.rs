//! # Threshold ML-DSA Signature Scheme
//!
//! This crate implements threshold variants of the ML-DSA (Dilithium) signature scheme
//! as described in "Efficient Threshold ML-DSA up to 6 parties".
//!
//! ## Overview
//!
//! Threshold signatures allow a group of parties to collectively sign a message
//! without any single party having access to the complete signing key. This
//! implementation supports threshold signing with up to 6 parties for ML-DSA-87.
//!
//! ## Security Level
//!
//! The implementation provides ML-DSA-87 (256-bit security, NIST Level 5):
//! - Ring dimension N = 256
//! - Matrix dimensions k = 8, l = 7
//! - Supports (t,n) thresholds where 2 ≤ t ≤ n ≤ 6
//!
//! ## Usage
//!
//! ```rust,ignore
//! use qp_rusty_crystals_threshold::mldsa87::{ThresholdConfig, generate_threshold_key};
//! use rand_core::{CryptoRng, RngCore};
//!
//! // Setup threshold parameters: 3-of-5 threshold scheme
//! let config = ThresholdConfig::new(3, 5).expect("Invalid parameters");
//!
//! // Generate threshold keys (requires a cryptographically secure RNG)
//! // let mut rng = /* your CryptoRng + RngCore implementation */;
//! // let (pk, sks) = generate_threshold_key(&mut rng, &config)
//! //     .expect("Key generation failed");
//!
//! // Threshold signing involves 3 rounds of communication between parties
//! // See individual module documentation for detailed protocol description
//! ```
//!
//! ## Protocol Overview
//!
//! The threshold signing protocol consists of three rounds:
//!
//! 1. **Round 1**: Each party generates and commits to random polynomials
//! 2. **Round 2**: Parties exchange commitments and compute challenge
//! 3. **Round 3**: Parties compute responses and combine into final signature
//!
//! ## Implementation Status
//!
//! This implementation provides:
//! - ✅ Complete 3-round threshold protocol
//! - ✅ Proper ML-DSA-87 signature format compatibility
//! - ✅ Integration with qp-rusty-crystals-dilithium crate
//! - 🚧 Simplified NTT operations (placeholder implementations)
//! - 🚧 Basic constraint validation (relaxed for testing)
//!
//! ## Warning
//!
//! **This implementation is for research and experimentation purposes.**
//! **It has not undergone security review and should not be used in production systems.**

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

// Public API module for ML-DSA-87 security level
pub mod ml_dsa_87;

// Internal modules
mod common;
pub mod field;
pub mod params;

// Re-export common types and errors
pub use common::{ThresholdError, ThresholdResult};

// Convenience re-export for the main security level
pub use ml_dsa_87 as threshold;

// Additional alias for compatibility
pub use ml_dsa_87 as mldsa87;

/// Maximum number of parties supported by the threshold scheme
pub const MAX_PARTIES: u8 = 6;

/// Minimum threshold value (at least 2 parties required)
pub const MIN_THRESHOLD: u8 = 2;

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_constants() {
		assert!(MAX_PARTIES >= MIN_THRESHOLD);
		assert!(MIN_THRESHOLD >= 2);
	}
}
