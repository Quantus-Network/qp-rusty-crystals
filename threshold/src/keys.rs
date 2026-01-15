//! Key types for threshold ML-DSA-87.
//!
//! This module defines the public key and private key share types used in
//! threshold signing. The private key share is intentionally opaque to
//! prevent accidental exposure of secret material.

use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "serde")]
use crate::serde_helpers::{serde_byte_array, serde_poly_vec, serde_u16_hashmap};

/// Size of the packed ML-DSA-87 public key in bytes.
pub const PUBLIC_KEY_SIZE: usize = 2592;

/// Size of the TR hash (public key hash) in bytes.
pub const TR_SIZE: usize = 64;

/// Public key for threshold ML-DSA-87.
///
/// This key is shared among all parties and is used for signature verification.
/// It can be freely distributed - there is no secret material here.
///
/// The public key is compatible with standard ML-DSA-87 verification.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PublicKey {
	/// Packed public key bytes (standard ML-DSA-87 format).
	#[cfg_attr(feature = "serde", serde(with = "serde_byte_array"))]
	bytes: [u8; PUBLIC_KEY_SIZE],
	/// Public key hash (TR), used in signing.
	#[cfg_attr(feature = "serde", serde(with = "serde_byte_array"))]
	tr: [u8; TR_SIZE],
}

impl PublicKey {
	/// Create a new public key from its components.
	pub(crate) fn new(bytes: [u8; PUBLIC_KEY_SIZE], tr: [u8; TR_SIZE]) -> Self {
		Self { bytes, tr }
	}

	/// Get the packed public key bytes.
	///
	/// These bytes are in standard ML-DSA-87 format and can be used
	/// with the `qp-rusty-crystals-dilithium` crate for verification.
	pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_SIZE] {
		&self.bytes
	}

	/// Get the public key hash (TR).
	pub fn tr(&self) -> &[u8; TR_SIZE] {
		&self.tr
	}

	/// Create a public key from bytes.
	///
	/// This recomputes the TR hash from the public key bytes.
	pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
		if bytes.len() != PUBLIC_KEY_SIZE {
			return Err("invalid public key length");
		}

		let mut pk_bytes = [0u8; PUBLIC_KEY_SIZE];
		pk_bytes.copy_from_slice(bytes);

		// Compute TR = SHAKE256(pk)
		let mut tr = [0u8; TR_SIZE];
		let mut state = qp_rusty_crystals_dilithium::fips202::KeccakState::default();
		qp_rusty_crystals_dilithium::fips202::shake256_absorb(&mut state, bytes, bytes.len());
		qp_rusty_crystals_dilithium::fips202::shake256_finalize(&mut state);
		qp_rusty_crystals_dilithium::fips202::shake256_squeeze(&mut tr, TR_SIZE, &mut state);

		Ok(Self { bytes: pk_bytes, tr })
	}
}

/// Private key share for one party in threshold ML-DSA-87.
///
/// **This contains secret material and MUST be kept confidential.**
///
/// Each party in the threshold scheme holds one private key share.
/// The share is intentionally opaque - you cannot access the internal
/// secret values directly. This prevents accidental leakage.
///
/// # Security
///
/// - Never transmit this over an insecure channel
/// - Never log or print this value
/// - Store securely (encrypted at rest)
/// - The `Zeroize` trait ensures memory is cleared on drop
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PrivateKeyShare {
	/// Party identifier (0 to n-1).
	party_id: u8,
	/// Total number of parties.
	total_parties: u8,
	/// Threshold value.
	threshold: u8,
	/// Private key seed.
	key: [u8; 32],
	/// Random seed rho (same as public key).
	rho: [u8; 32],
	/// Hash of public key for signing.
	#[cfg_attr(feature = "serde", serde(with = "serde_byte_array"))]
	tr: [u8; TR_SIZE],
	/// Secret shares for this party, keyed by signer subset ID.
	/// Each share contains (s1_share, s2_share) polynomial vectors.
	/// Uses u16 as subset mask to support up to 16 parties.
	#[cfg_attr(feature = "serde", serde(with = "serde_u16_hashmap"))]
	shares: std::collections::HashMap<u16, SecretShareData>,
}

/// Internal secret share data for a specific signer subset.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub(crate) struct SecretShareData {
	/// Share of s1 polynomial vector (L polynomials).
	#[cfg_attr(feature = "serde", serde(with = "serde_poly_vec"))]
	pub(crate) s1: Vec<[i32; 256]>,
	/// Share of s2 polynomial vector (K polynomials).
	#[cfg_attr(feature = "serde", serde(with = "serde_poly_vec"))]
	pub(crate) s2: Vec<[i32; 256]>,
}

impl Zeroize for SecretShareData {
	fn zeroize(&mut self) {
		for poly in &mut self.s1 {
			poly.zeroize();
		}
		for poly in &mut self.s2 {
			poly.zeroize();
		}
	}
}

impl PrivateKeyShare {
	/// Create a new private key share.
	pub(crate) fn new(
		party_id: u8,
		total_parties: u8,
		threshold: u8,
		key: [u8; 32],
		rho: [u8; 32],
		tr: [u8; TR_SIZE],
		shares: std::collections::HashMap<u16, SecretShareData>,
	) -> Self {
		Self { party_id, total_parties, threshold, key, rho, tr, shares }
	}

	/// Get this party's ID.
	pub fn party_id(&self) -> u8 {
		self.party_id
	}

	/// Get the total number of parties.
	pub fn total_parties(&self) -> u8 {
		self.total_parties
	}

	/// Get the threshold value.
	pub fn threshold(&self) -> u8 {
		self.threshold
	}

	/// Get the random seed rho (for internal use).
	pub(crate) fn rho(&self) -> &[u8; 32] {
		&self.rho
	}

	/// Get the public key hash TR (for internal use).
	pub(crate) fn tr(&self) -> &[u8; TR_SIZE] {
		&self.tr
	}

	/// Get the private key seed (for internal use).
	#[allow(dead_code)]
	pub(crate) fn key(&self) -> &[u8; 32] {
		&self.key
	}

	/// Get the secret shares (for internal use).
	pub(crate) fn shares(&self) -> &std::collections::HashMap<u16, SecretShareData> {
		&self.shares
	}
}

impl Zeroize for PrivateKeyShare {
	fn zeroize(&mut self) {
		self.party_id.zeroize();
		self.total_parties.zeroize();
		self.threshold.zeroize();
		self.key.zeroize();
		self.rho.zeroize();
		self.tr.zeroize();
		for (_, share) in self.shares.iter_mut() {
			share.zeroize();
		}
		self.shares.clear();
	}
}

impl ZeroizeOnDrop for PrivateKeyShare {}

impl std::fmt::Debug for PrivateKeyShare {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("PrivateKeyShare")
			.field("party_id", &self.party_id)
			.field("total_parties", &self.total_parties)
			.field("threshold", &self.threshold)
			.field("key", &"[REDACTED]")
			.field("shares", &format!("{} subsets", self.shares.len()))
			.finish()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_public_key_roundtrip() {
		let bytes = [0x42u8; PUBLIC_KEY_SIZE];
		let pk = PublicKey::from_bytes(&bytes).unwrap();
		assert_eq!(pk.as_bytes(), &bytes);
	}

	#[test]
	fn test_public_key_invalid_length() {
		let bytes = [0u8; 100];
		assert!(PublicKey::from_bytes(&bytes).is_err());
	}

	#[test]
	fn test_private_key_debug_redacts_secrets() {
		let pk_share = PrivateKeyShare::new(
			0,
			3,
			2,
			[0x42u8; 32],
			[0u8; 32],
			[0u8; TR_SIZE],
			std::collections::HashMap::new(),
		);
		let debug_str = format!("{:?}", pk_share);
		assert!(debug_str.contains("REDACTED"));
		assert!(!debug_str.contains("42")); // Should not contain the key bytes
	}

	#[test]
	fn test_private_key_zeroize() {
		let mut pk_share = PrivateKeyShare::new(
			0,
			3,
			2,
			[0x42u8; 32],
			[0x43u8; 32],
			[0x44u8; TR_SIZE],
			std::collections::HashMap::new(),
		);
		pk_share.zeroize();
		assert_eq!(pk_share.key, [0u8; 32]);
		assert_eq!(pk_share.rho, [0u8; 32]);
		assert_eq!(pk_share.tr, [0u8; TR_SIZE]);
	}
}
