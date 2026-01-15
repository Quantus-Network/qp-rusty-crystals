//! # Threshold ML-DSA-87 Signature Scheme
//!
//! This crate implements a threshold variant of the ML-DSA-87 (Dilithium)
//! signature scheme, allowing multiple parties to collectively sign messages
//! without any single party having access to the complete signing key.
//!
//! ## Overview
//!
//! In a (t, n) threshold scheme:
//! - There are n total parties
//! - Any t or more parties can cooperate to produce a valid signature
//! - Fewer than t parties cannot produce a signature or learn the secret key
//!
//! This implementation supports configurations up to (7, 7) and produces
//! signatures that are compatible with standard ML-DSA-87 verification.
//!
//! ## Quick Start
//!
//! ```ignore
//! use qp_rusty_crystals_threshold::{
//!     ThresholdConfig, ThresholdSigner, generate_with_dealer,
//!     Round1Broadcast, Round2Broadcast, Round3Broadcast, verify_signature,
//! };
//! use rand::thread_rng;
//!
//! // 1. Setup: Generate keys with a trusted dealer
//! let config = ThresholdConfig::new(2, 3)?;  // 2-of-3 threshold
//! let seed = [0u8; 32];  // Use a secure random seed!
//! let (public_key, shares) = generate_with_dealer(&seed, config)?;
//!
//! // 2. Create signers (in practice, each party runs on a different machine)
//! let mut signers: Vec<_> = shares.into_iter()
//!     .map(|share| ThresholdSigner::new(share, public_key.clone(), config))
//!     .collect::<Result<_, _>>()?;
//!
//! // 3. Round 1: Generate commitments
//! let mut rng = thread_rng();
//! let r1_broadcasts: Vec<_> = signers.iter_mut()
//!     .take(2)  // Only need t=2 parties
//!     .map(|s| s.round1_commit(&mut rng))
//!     .collect::<Result<_, _>>()?;
//!
//! // 4. Round 2: Reveal commitments (exchange r1 broadcasts first)
//! let r2_broadcasts: Vec<_> = signers.iter_mut()
//!     .take(2)
//!     .enumerate()
//!     .map(|(i, s)| {
//!         let others: Vec<_> = r1_broadcasts.iter()
//!             .filter(|r| r.party_id != i as u8)
//!             .cloned()
//!             .collect();
//!         s.round2_reveal(b"message", b"context", &others)
//!     })
//!     .collect::<Result<_, _>>()?;
//!
//! // 5. Round 3: Compute responses (exchange r2 broadcasts first)
//! let r3_broadcasts: Vec<_> = signers.iter_mut()
//!     .take(2)
//!     .enumerate()
//!     .map(|(i, s)| {
//!         let others: Vec<_> = r2_broadcasts.iter()
//!             .filter(|r| r.party_id != i as u8)
//!             .cloned()
//!             .collect();
//!         s.round3_respond(&others)
//!     })
//!     .collect::<Result<_, _>>()?;
//!
//! // 6. Combine into final signature
//! let signature = signers[0].combine_with_message(
//!     b"message", b"context", &r2_broadcasts, &r3_broadcasts
//! )?;
//!
//! // 7. Verify (works with standard ML-DSA-87 verification)
//! assert!(verify_signature(&public_key, b"message", b"context", &signature));
//! ```
//!
//! ## Security Warning
//!
//! **This implementation is for research and experimentation purposes only.**
//! It has not undergone a security audit and should not be used in production
//! systems without thorough review.
//!
//! ## Network Usage
//!
//! In a real distributed system, each party runs on a separate machine:
//!
//! 1. **Key Generation**: A trusted dealer generates shares and securely distributes them to each
//!    party (or use DKG when available).
//!
//! 2. **Round 1**: Each party generates a `Round1Broadcast` and sends it to all other participating
//!    parties.
//!
//! 3. **Round 2**: After receiving all Round 1 broadcasts, each party generates a `Round2Broadcast`
//!    and sends it to all others.
//!
//! 4. **Round 3**: After receiving all Round 2 broadcasts, each party generates a `Round3Broadcast`
//!    and sends it to all others.
//!
//! 5. **Combine**: Any party can combine the broadcasts into a final signature.
//!
//! All broadcast types implement `serde::Serialize` and `serde::Deserialize`
//! (when the `serde` feature is enabled) for easy network transmission.
//!
//! ## Features
//!
//! - `std` (default): Enable standard library support
//! - `serde`: Enable serialization/deserialization of broadcast types

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

// Core modules
pub mod broadcast;
mod config;
mod error;
pub mod keys;
pub mod participants;
mod signer;

// Serde helpers for large arrays
#[cfg(feature = "serde")]
pub(crate) mod serde_helpers;

// Key generation
pub mod keygen;

// Internal protocol implementation
pub(crate) mod protocol;

// Resharing (committee handoff) protocol
pub mod resharing;

// Signing protocol adapter for NEAR MPC integration
pub mod signing_protocol;

// circl_ntt is public for cross-language NTT testing with Go reference
pub mod circl_ntt;

// ============================================================================
// Public API
// ============================================================================

// Configuration
pub use config::ThresholdConfig;

// Error types
pub use error::{ThresholdError, ThresholdResult};

// Participant management
pub use participants::{ParticipantId, ParticipantList};

// Key types
pub use keys::{PrivateKeyShare, PublicKey};

// Broadcast message types
pub use broadcast::{Round1Broadcast, Round2Broadcast, Round3Broadcast, Signature, SIGNATURE_SIZE};

// The main signer
pub use signer::ThresholdSigner;

// Key generation
pub use keygen::generate_with_dealer;

// Verification
pub use verification::verify_signature;

/// Signature verification.
mod verification {
	use crate::{broadcast::Signature, keys::PublicKey};
	use qp_rusty_crystals_dilithium::params as dilithium_params;

	/// Verify a threshold signature.
	///
	/// This function verifies a signature produced by the threshold signing
	/// protocol. The signature is compatible with standard ML-DSA-87, so it
	/// can also be verified using the `qp-rusty-crystals-dilithium` crate.
	///
	/// # Arguments
	///
	/// * `public_key` - The threshold public key
	/// * `message` - The message that was signed
	/// * `context` - The context string used during signing (max 255 bytes)
	/// * `signature` - The signature to verify
	///
	/// # Returns
	///
	/// `true` if the signature is valid, `false` otherwise.
	///
	/// # Example
	///
	/// ```ignore
	/// use qp_rusty_crystals_threshold::{verify_signature, PublicKey, Signature};
	///
	/// let is_valid = verify_signature(&public_key, b"message", b"context", &signature);
	/// if is_valid {
	///     println!("Signature is valid!");
	/// }
	/// ```
	pub fn verify_signature(
		public_key: &PublicKey,
		message: &[u8],
		context: &[u8],
		signature: &Signature,
	) -> bool {
		// Validate context length
		if context.len() > 255 {
			return false;
		}

		// Check signature length
		if signature.as_bytes().len() != dilithium_params::SIGNBYTES {
			return false;
		}

		// Use dilithium crate for verification
		let dilithium_pk = match qp_rusty_crystals_dilithium::ml_dsa_87::PublicKey::from_bytes(
			public_key.as_bytes(),
		) {
			Ok(pk) => pk,
			Err(_) => return false,
		};

		let ctx_option = if context.is_empty() { None } else { Some(context) };

		dilithium_pk.verify(message, signature.as_bytes(), ctx_option)
	}
}

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of parties supported by the threshold scheme.
pub const MAX_PARTIES: u8 = 7;

/// Minimum threshold value (at least 2 parties required).
pub const MIN_THRESHOLD: u8 = 2;

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_constants() {
		assert!(MAX_PARTIES >= MIN_THRESHOLD);
		assert!(MIN_THRESHOLD >= 2);
	}

	#[test]
	fn test_config_creation() {
		let config = ThresholdConfig::new(2, 3);
		assert!(config.is_ok());

		let config = config.unwrap();
		assert_eq!(config.threshold(), 2);
		assert_eq!(config.total_parties(), 3);
	}
}
