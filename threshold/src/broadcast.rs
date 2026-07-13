//! Broadcast message types for threshold signing protocol.
//!
//! These types represent the messages that parties send to each other
//! during the three rounds of the threshold signing protocol.
//!
//! # Network Usage
//!
//! In a distributed setting, each party serializes these messages
//! using borsh and sends them over the network.
//!
//! ```text
//! Round 1: Each party broadcasts Round1Broadcast (commitment hash + ssid)
//! Round 2: Each party broadcasts Round2Broadcast (commitment reveal + ssid)
//! Round 3: Each party broadcasts Round3Broadcast (signature response + ssid)
//! ```
//!
//! After Round 3, any party can combine the broadcasts into a final `Signature`.
//!
//! # Session Identifier (SSID)
//!
//! All broadcast messages include a session identifier (SSID) that binds the
//! message to a specific signing session. This prevents cross-session replay
//! attacks where an attacker could reuse messages from a previous session.
//! Receivers MUST verify that the SSID matches their expected value before
//! processing any message.
//!
//! # Security
//!
//! All broadcast types implement bounded deserialization to prevent memory
//! exhaustion attacks from malicious peers sending oversized payloads.

use alloc::{vec, vec::Vec};

use borsh::{BorshDeserialize, BorshSerialize};

/// Size of the session identifier (SSID) in bytes.
pub const SSID_SIZE: usize = 32;

/// Size of the ML-DSA-87 signature in bytes.
pub const SIGNATURE_SIZE: usize = 4627;

/// Maximum size of commitment data in Round2Broadcast.
///
/// This is derived from: max_k_iterations (1600, for 4-of-6) × single_commitment_size (k ×
/// POLY_Q_SIZE = 8 × 736 = 5888) = 9_420_800 bytes. We round up to 10.5 MB for margin. The 4-of-6
/// resharing-hardened config raised the worst-case k from 380 to 1600; see `config::k_iterations`.
pub const MAX_COMMITMENT_DATA_SIZE: usize = 10_500_000;

/// Maximum size of response data in Round3Broadcast.
///
/// This is derived from: max_k_iterations (1600, for 4-of-6) × single_response_size (L × 640 = 7 ×
/// 640 = 4480) = 7_168_000 bytes. We round up to 8 MB for margin.
pub const MAX_RESPONSE_SIZE: usize = 8_000_000;

/// Read exactly `len` bytes from `reader` without trusting `len` for the up-front
/// allocation size.
///
/// The caller has already rejected `len` values above the per-field maximum, but
/// that maximum can be several megabytes (see [`MAX_COMMITMENT_DATA_SIZE`]). A
/// malicious peer can advertise a large `len` and then truncate the payload;
/// `vec![0u8; len]` would eagerly allocate (and zero) the full claimed size
/// *before* `read_exact` discovers the truncation, letting a few-byte message
/// force a multi-megabyte allocation. Growing the buffer in bounded chunks caps
/// the transient allocation to what the peer actually delivered (plus one chunk)
/// and fails fast on a short payload.
pub(crate) fn read_length_prefixed<R: borsh::io::Read>(
	reader: &mut R,
	len: usize,
) -> borsh::io::Result<Vec<u8>> {
	// Cap per-step growth so `len` alone cannot drive the allocation size.
	const CHUNK: usize = 64 * 1024;
	let mut buf = Vec::new();
	while buf.len() < len {
		let step = (len - buf.len()).min(CHUNK);
		let filled = buf.len();
		buf.resize(filled + step, 0);
		reader.read_exact(&mut buf[filled..])?;
	}
	Ok(buf)
}

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
///
/// The SSID binds this message to the current signing session, preventing
/// cross-session replay attacks.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Round1Broadcast {
	/// Session identifier binding this message to a specific signing session.
	pub ssid: [u8; SSID_SIZE],
	/// The party ID that generated this broadcast.
	pub party_id: u32,
	/// Hash of the commitment (SHAKE256 output).
	pub commitment_hash: [u8; 32],
}

impl Round1Broadcast {
	/// Create a new Round 1 broadcast.
	pub fn new(ssid: [u8; SSID_SIZE], party_id: u32, commitment_hash: [u8; 32]) -> Self {
		Self { ssid, party_id, commitment_hash }
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
///
/// # Security
///
/// The SSID binds this message to the current signing session, preventing
/// cross-session replay attacks.
///
/// # Deserialization Limits
///
/// When deserializing from untrusted input, `commitment_data` is limited to
/// [`MAX_COMMITMENT_DATA_SIZE`] bytes to prevent memory exhaustion attacks.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize)]
pub struct Round2Broadcast {
	/// Session identifier binding this message to a specific signing session.
	pub ssid: [u8; SSID_SIZE],
	/// The party ID that generated this broadcast.
	pub party_id: u32,
	/// Packed commitment polynomials (K iterations of w values).
	pub commitment_data: Vec<u8>,
}

impl BorshDeserialize for Round2Broadcast {
	fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
		// Read SSID
		let mut ssid = [0u8; SSID_SIZE];
		reader.read_exact(&mut ssid)?;

		let party_id = u32::deserialize_reader(reader)?;

		// Read the length prefix for the Vec
		let len = u32::deserialize_reader(reader)? as usize;

		// Check length before allocating to prevent memory exhaustion
		if len > MAX_COMMITMENT_DATA_SIZE {
			return Err(borsh::io::Error::new(
				borsh::io::ErrorKind::InvalidData,
				"commitment_data exceeds maximum allowed size",
			));
		}

		// Read incrementally so a truncated payload cannot force an up-front
		// allocation of the full (attacker-chosen) `len`.
		let commitment_data = read_length_prefixed(reader, len)?;

		Ok(Self { ssid, party_id, commitment_data })
	}
}

impl Round2Broadcast {
	/// Create a new Round 2 broadcast.
	pub fn new(ssid: [u8; SSID_SIZE], party_id: u32, commitment_data: Vec<u8>) -> Self {
		Self { ssid, party_id, commitment_data }
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
///
/// # Security
///
/// The SSID binds this message to the current signing session, preventing
/// cross-session replay attacks.
///
/// # Deserialization Limits
///
/// When deserializing from untrusted input, `response` is limited to
/// [`MAX_RESPONSE_SIZE`] bytes to prevent memory exhaustion attacks.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize)]
pub struct Round3Broadcast {
	/// Session identifier binding this message to a specific signing session.
	pub ssid: [u8; SSID_SIZE],
	/// The party ID that generated this broadcast.
	pub party_id: u32,
	/// Packed response polynomials (K iterations of z values).
	pub response: Vec<u8>,
}

impl BorshDeserialize for Round3Broadcast {
	fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
		// Read SSID
		let mut ssid = [0u8; SSID_SIZE];
		reader.read_exact(&mut ssid)?;

		let party_id = u32::deserialize_reader(reader)?;

		// Read the length prefix for the Vec
		let len = u32::deserialize_reader(reader)? as usize;

		// Check length before allocating to prevent memory exhaustion
		if len > MAX_RESPONSE_SIZE {
			return Err(borsh::io::Error::new(
				borsh::io::ErrorKind::InvalidData,
				"response exceeds maximum allowed size",
			));
		}

		// Read incrementally so a truncated payload cannot force an up-front
		// allocation of the full (attacker-chosen) `len`.
		let response = read_length_prefixed(reader, len)?;

		Ok(Self { ssid, party_id, response })
	}
}

impl Round3Broadcast {
	/// Create a new Round 3 broadcast.
	pub fn new(ssid: [u8; SSID_SIZE], party_id: u32, response: Vec<u8>) -> Self {
		Self { ssid, party_id, response }
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
///
/// # Deserialization Limits
///
/// When deserializing from untrusted input, `bytes` must be exactly
/// [`SIGNATURE_SIZE`] bytes. This prevents both memory exhaustion attacks
/// and ensures only valid-length signatures are accepted.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize)]
pub struct Signature {
	/// The signature bytes in standard ML-DSA-87 format.
	bytes: Vec<u8>,
}

impl BorshDeserialize for Signature {
	fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
		// Read the length prefix for the Vec
		let len = u32::deserialize_reader(reader)? as usize;

		// Signatures must be exactly SIGNATURE_SIZE bytes
		if len != SIGNATURE_SIZE {
			return Err(borsh::io::Error::new(
				borsh::io::ErrorKind::InvalidData,
				"signature must be exactly SIGNATURE_SIZE bytes",
			));
		}

		// Now safe to allocate and read
		let mut bytes = vec![0u8; len];
		reader.read_exact(&mut bytes)?;

		Ok(Self { bytes })
	}
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
	use alloc::vec;

	const TEST_SSID: [u8; SSID_SIZE] = [0xAA; SSID_SIZE];

	#[test]
	fn test_round1_broadcast() {
		let hash = [0x42u8; 32];
		let broadcast = Round1Broadcast::new(TEST_SSID, 0, hash);
		assert_eq!(broadcast.ssid, TEST_SSID);
		assert_eq!(broadcast.party_id, 0);
		assert_eq!(broadcast.commitment_hash, hash);
	}

	#[test]
	fn test_round2_broadcast() {
		let data = vec![1, 2, 3, 4, 5];
		let broadcast = Round2Broadcast::new(TEST_SSID, 1, data.clone());
		assert_eq!(broadcast.ssid, TEST_SSID);
		assert_eq!(broadcast.party_id, 1);
		assert_eq!(broadcast.commitment_data, data);
	}

	#[test]
	fn test_round3_broadcast() {
		let response = vec![6, 7, 8, 9, 10];
		let broadcast = Round3Broadcast::new(TEST_SSID, 2, response.clone());
		assert_eq!(broadcast.ssid, TEST_SSID);
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

	// ========================================================================
	// Bounded deserialization tests (security)
	// ========================================================================

	#[test]
	fn test_round2_deserialize_rejects_oversized_commitment() {
		// Craft a malicious payload with a huge length prefix
		let mut malicious_payload = Vec::new();
		// ssid
		malicious_payload.extend_from_slice(&TEST_SSID);
		// party_id (u32, little-endian)
		malicious_payload.extend_from_slice(&1u32.to_le_bytes());
		// length prefix claiming 100 MB (way over the 2.5 MB limit)
		malicious_payload.extend_from_slice(&(100_000_000u32).to_le_bytes());
		// We don't need actual data - the check should fail before allocation

		let result: Result<Round2Broadcast, _> = borsh::from_slice(&malicious_payload);
		assert!(result.is_err(), "should reject oversized commitment_data");
	}

	#[test]
	fn test_round2_deserialize_accepts_valid_size() {
		let broadcast = Round2Broadcast::new(TEST_SSID, 1, vec![0u8; 1000]);
		let serialized = borsh::to_vec(&broadcast).unwrap();
		let recovered: Round2Broadcast = borsh::from_slice(&serialized).unwrap();
		assert_eq!(recovered, broadcast);
	}

	#[test]
	fn test_round3_deserialize_rejects_oversized_response() {
		// Craft a malicious payload with a huge length prefix
		let mut malicious_payload = Vec::new();
		// ssid
		malicious_payload.extend_from_slice(&TEST_SSID);
		// party_id (u32, little-endian)
		malicious_payload.extend_from_slice(&1u32.to_le_bytes());
		// length prefix claiming 100 MB (way over the 2 MB limit)
		malicious_payload.extend_from_slice(&(100_000_000u32).to_le_bytes());

		let result: Result<Round3Broadcast, _> = borsh::from_slice(&malicious_payload);
		assert!(result.is_err(), "should reject oversized response");
	}

	#[test]
	fn test_round3_deserialize_accepts_valid_size() {
		let broadcast = Round3Broadcast::new(TEST_SSID, 2, vec![0u8; 1000]);
		let serialized = borsh::to_vec(&broadcast).unwrap();
		let recovered: Round3Broadcast = borsh::from_slice(&serialized).unwrap();
		assert_eq!(recovered, broadcast);
	}

	/// A within-bounds length prefix whose body is truncated must fail without
	/// pre-allocating the claimed length. We can only observe the error here (the
	/// bounded-allocation behavior is exercised by `read_length_prefixed`), but
	/// this locks in that a lying-then-truncated payload is rejected.
	#[test]
	fn test_round2_deserialize_rejects_truncated_body() {
		let mut payload = Vec::new();
		payload.extend_from_slice(&TEST_SSID);
		payload.extend_from_slice(&1u32.to_le_bytes()); // party_id
		payload.extend_from_slice(&1000u32.to_le_bytes()); // claims 1000 bytes...
		payload.extend_from_slice(&[0u8; 10]); // ...but only 10 are present

		let result: Result<Round2Broadcast, _> = borsh::from_slice(&payload);
		assert!(result.is_err(), "truncated commitment_data must be rejected");
	}

	#[test]
	fn test_read_length_prefixed_matches_requested_len() {
		let data = [7u8; 200];
		let mut reader = &data[..];
		let out = read_length_prefixed(&mut reader, 200).unwrap();
		assert_eq!(out, data);

		// Short input for the requested length must error, not hang or over-read.
		let short = [1u8; 5];
		let mut reader = &short[..];
		assert!(read_length_prefixed(&mut reader, 1000).is_err());
	}

	#[test]
	fn test_signature_deserialize_rejects_oversized() {
		// Craft a malicious payload with a huge length prefix
		let mut malicious_payload = Vec::new();
		// length prefix claiming 100 MB
		malicious_payload.extend_from_slice(&(100_000_000u32).to_le_bytes());

		let result: Result<Signature, _> = borsh::from_slice(&malicious_payload);
		assert!(result.is_err(), "should reject oversized signature");
	}

	#[test]
	fn test_signature_deserialize_rejects_wrong_size() {
		// Craft a payload with wrong signature size (too small)
		let mut payload = Vec::new();
		// length prefix for 100 bytes (not SIGNATURE_SIZE)
		payload.extend_from_slice(&(100u32).to_le_bytes());
		payload.extend_from_slice(&[0u8; 100]);

		let result: Result<Signature, _> = borsh::from_slice(&payload);
		assert!(result.is_err(), "should reject wrong-sized signature");
	}

	#[test]
	fn test_signature_deserialize_accepts_valid() {
		let sig = Signature::from_bytes(&[0u8; SIGNATURE_SIZE]).unwrap();
		let serialized = borsh::to_vec(&sig).unwrap();
		let recovered: Signature = borsh::from_slice(&serialized).unwrap();
		assert_eq!(recovered, sig);
	}
}
