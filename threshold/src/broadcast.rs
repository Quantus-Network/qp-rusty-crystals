//! Broadcast message types for threshold signing protocol.
//!
//! These types represent the messages that parties send to each other
//! during the three rounds of the threshold signing protocol.
//!
//! # Network Usage
//!
//! In a distributed setting, each party serializes these messages
//! (using serde if the feature is enabled) and sends them over the network.
//!
//! ```text
//! Round 1: Each party broadcasts Round1Broadcast (commitment hash)
//! Round 2: Each party broadcasts Round2Broadcast (commitment reveal)
//! Round 3: Each party broadcasts Round3Broadcast (signature response)
//! ```
//!
//! After Round 3, any party can combine the broadcasts into a final `Signature`.

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Size of the ML-DSA-87 signature in bytes.
pub const SIGNATURE_SIZE: usize = 4627;

/// Round 1 broadcast message: commitment hash.
///
/// In Round 1, each party generates random values and computes a commitment.
/// Only the hash of the commitment is broadcast, hiding the actual values
/// until Round 2.
///
/// # Security
///
/// The commitment hash prevents parties from changing their random values
/// after seeing other parties' values (which would enable certain attacks).
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Round1Broadcast {
	/// The party ID that generated this broadcast.
	pub party_id: u32,
	/// Hash of the commitment (SHAKE256 output).
	pub commitment_hash: [u8; 32],
}

impl Round1Broadcast {
	/// Create a new Round 1 broadcast.
	pub fn new(party_id: u32, commitment_hash: [u8; 32]) -> Self {
		Self { party_id, commitment_hash }
	}
}

/// Round 2 broadcast message: commitment reveal.
///
/// In Round 2, each party reveals their actual commitment values (the `w`
/// polynomials). Other parties verify these match the Round 1 hashes.
///
/// # Contents
///
/// The `commitment_data` contains K iterations of packed polynomial vectors,
/// where K depends on the threshold configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Round2Broadcast {
	/// The party ID that generated this broadcast.
	pub party_id: u32,
	/// Packed commitment polynomials (K iterations of w values).
	pub commitment_data: Vec<u8>,
}

impl Round2Broadcast {
	/// Create a new Round 2 broadcast.
	pub fn new(party_id: u32, commitment_data: Vec<u8>) -> Self {
		Self { party_id, commitment_data }
	}
}

/// Round 3 broadcast message: signature response.
///
/// In Round 3, each party computes their signature share based on:
/// - Their secret key share
/// - The aggregated commitments from Round 2
/// - The message being signed
///
/// # Contents
///
/// The `response` contains K iterations of packed response polynomials.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Round3Broadcast {
	/// The party ID that generated this broadcast.
	pub party_id: u32,
	/// Packed response polynomials (K iterations of z values).
	pub response: Vec<u8>,
}

impl Round3Broadcast {
	/// Create a new Round 3 broadcast.
	pub fn new(party_id: u32, response: Vec<u8>) -> Self {
		Self { party_id, response }
	}
}

/// A threshold signature in ML-DSA-87 format.
///
/// This is the final output of the threshold signing protocol.
/// It is compatible with standard ML-DSA-87 verification - verifiers
/// do not need to know that the signature was produced by a threshold
/// scheme.
///
/// # Verification
///
/// Use `verify_signature` or the `qp-rusty-crystals-dilithium` crate
/// to verify signatures:
///
/// ```ignore
/// use qp_rusty_crystals_threshold::{verify_signature, PublicKey, Signature};
///
/// let is_valid = verify_signature(&public_key, message, context, &signature);
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Signature {
	/// The signature bytes in standard ML-DSA-87 format.
	bytes: Vec<u8>,
}

impl Signature {
	/// Create a signature from bytes.
	///
	/// # Errors
	///
	/// Returns `None` if the byte slice is not exactly `SIGNATURE_SIZE` bytes.
	pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
		if bytes.len() != SIGNATURE_SIZE {
			return None;
		}
		Some(Self { bytes: bytes.to_vec() })
	}

	/// Create a signature from a vector of bytes.
	///
	/// # Panics
	///
	/// Panics if the vector is not exactly `SIGNATURE_SIZE` bytes.
	/// Use `from_bytes` for a fallible version.
	pub(crate) fn from_vec(bytes: Vec<u8>) -> Self {
		assert_eq!(bytes.len(), SIGNATURE_SIZE, "signature must be {} bytes", SIGNATURE_SIZE);
		Self { bytes }
	}

	/// Get the signature as a byte slice.
	pub fn as_bytes(&self) -> &[u8] {
		&self.bytes
	}

	/// Convert the signature into a byte vector.
	pub fn into_bytes(self) -> Vec<u8> {
		self.bytes
	}
}

impl AsRef<[u8]> for Signature {
	fn as_ref(&self) -> &[u8] {
		&self.bytes
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_round1_broadcast() {
		let hash = [0x42u8; 32];
		let broadcast = Round1Broadcast::new(0, hash);
		assert_eq!(broadcast.party_id, 0);
		assert_eq!(broadcast.commitment_hash, hash);
	}

	#[test]
	fn test_round2_broadcast() {
		let data = vec![1, 2, 3, 4, 5];
		let broadcast = Round2Broadcast::new(1, data.clone());
		assert_eq!(broadcast.party_id, 1);
		assert_eq!(broadcast.commitment_data, data);
	}

	#[test]
	fn test_round3_broadcast() {
		let response = vec![6, 7, 8, 9, 10];
		let broadcast = Round3Broadcast::new(2, response.clone());
		assert_eq!(broadcast.party_id, 2);
		assert_eq!(broadcast.response, response);
	}

	#[test]
	fn test_signature_from_bytes() {
		let bytes = vec![0u8; SIGNATURE_SIZE];
		let sig = Signature::from_bytes(&bytes).unwrap();
		assert_eq!(sig.as_bytes().len(), SIGNATURE_SIZE);
	}

	#[test]
	fn test_signature_from_bytes_invalid_length() {
		let bytes = vec![0u8; 100];
		assert!(Signature::from_bytes(&bytes).is_none());
	}

	#[test]
	fn test_signature_into_bytes() {
		let bytes = vec![0x42u8; SIGNATURE_SIZE];
		let sig = Signature::from_bytes(&bytes).unwrap();
		let recovered = sig.into_bytes();
		assert_eq!(recovered, bytes);
	}

	#[cfg(feature = "serde")]
	mod serde_tests {
		use super::*;

		#[test]
		fn test_round1_broadcast_serde() {
			let broadcast = Round1Broadcast::new(0, [0x42u8; 32]);
			let json = serde_json::to_string(&broadcast).unwrap();
			let recovered: Round1Broadcast = serde_json::from_str(&json).unwrap();
			assert_eq!(broadcast, recovered);
		}

		#[test]
		fn test_round2_broadcast_serde() {
			let broadcast = Round2Broadcast::new(1, vec![1, 2, 3]);
			let json = serde_json::to_string(&broadcast).unwrap();
			let recovered: Round2Broadcast = serde_json::from_str(&json).unwrap();
			assert_eq!(broadcast, recovered);
		}

		#[test]
		fn test_round3_broadcast_serde() {
			let broadcast = Round3Broadcast::new(2, vec![4, 5, 6]);
			let json = serde_json::to_string(&broadcast).unwrap();
			let recovered: Round3Broadcast = serde_json::from_str(&json).unwrap();
			assert_eq!(broadcast, recovered);
		}

		#[test]
		fn test_signature_serde() {
			let sig = Signature::from_bytes(&vec![0u8; SIGNATURE_SIZE]).unwrap();
			let json = serde_json::to_string(&sig).unwrap();
			let recovered: Signature = serde_json::from_str(&json).unwrap();
			assert_eq!(sig, recovered);
		}
	}
}
