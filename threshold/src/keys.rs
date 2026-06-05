//! Key types for threshold ML-DSA-87.
//!
//! This module defines the public key and private key share types used in
//! threshold signing. The private key share is intentionally opaque to
//! prevent accidental exposure of secret material.

use alloc::{collections::BTreeMap, format};
use core::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

use borsh::{BorshDeserialize, BorshSerialize};
use qp_rusty_crystals_dilithium::params::{K, L};

use crate::participants::{ParticipantId, ParticipantList};

/// Size of the packed ML-DSA-87 public key in bytes.
pub const PUBLIC_KEY_SIZE: usize = 2592;

/// Size of the TR hash (public key hash) in bytes.
pub const TR_SIZE: usize = 64;

/// Compute TR = SHAKE256(pk_bytes).
fn compute_tr(bytes: &[u8; PUBLIC_KEY_SIZE]) -> [u8; TR_SIZE] {
	let mut tr = [0u8; TR_SIZE];
	let mut state = qp_rusty_crystals_dilithium::fips202::KeccakState::default();
	qp_rusty_crystals_dilithium::fips202::shake256_absorb(&mut state, bytes);
	qp_rusty_crystals_dilithium::fips202::shake256_finalize(&mut state);
	qp_rusty_crystals_dilithium::fips202::shake256_squeeze(&mut tr, &mut state);
	tr
}

/// Public key for threshold ML-DSA-87.
///
/// This key is shared among all parties and is used for signature verification.
/// It can be freely distributed - there is no secret material here.
///
/// The public key is compatible with standard ML-DSA-87 verification.
///
/// # Serialization
///
/// Only the public key bytes are serialized. The TR hash (used internally for
/// signing) is recomputed from bytes during deserialization. This eliminates
/// the possibility of "poisoned" public keys with mismatched TR values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
	/// Packed public key bytes (standard ML-DSA-87 format).
	bytes: [u8; PUBLIC_KEY_SIZE],
	/// Public key hash (TR), used in signing. Always equals SHAKE256(bytes).
	/// Cached for performance since it's used in hot paths during signing.
	tr: [u8; TR_SIZE],
}

impl BorshSerialize for PublicKey {
	fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
		// Only serialize bytes; tr is recomputed on deserialize
		self.bytes.serialize(writer)
	}
}

impl BorshDeserialize for PublicKey {
	fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
		let bytes = <[u8; PUBLIC_KEY_SIZE]>::deserialize_reader(reader)?;
		let tr = compute_tr(&bytes);
		Ok(Self { bytes, tr })
	}
}

impl PublicKey {
	/// Create a new public key from packed bytes.
	///
	/// TR is computed automatically as `SHAKE256(bytes)`.
	pub(crate) fn new(bytes: [u8; PUBLIC_KEY_SIZE]) -> Self {
		let tr = compute_tr(&bytes);
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
	/// This computes the TR hash from the public key bytes.
	pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
		if bytes.len() != PUBLIC_KEY_SIZE {
			return Err("invalid public key length");
		}

		let mut pk_bytes = [0u8; PUBLIC_KEY_SIZE];
		pk_bytes.copy_from_slice(bytes);

		let tr = compute_tr(&pk_bytes);
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
#[derive(Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct PrivateKeyShare {
	/// Party identifier (can be arbitrary u32, e.g., NEAR participant ID).
	party_id: ParticipantId,
	/// Total number of parties.
	total_parties: u32,
	/// Threshold value.
	threshold: u32,
	/// DKG participants list - maps arbitrary party IDs to sequential indices.
	/// The sequential indices (0, 1, 2, ...) are used for share subset masks.
	dkg_participants: ParticipantList,
	/// Private key seed.
	key: [u8; 32],
	/// Random seed rho (same as public key).
	rho: [u8; 32],
	/// Hash of public key for signing.
	tr: [u8; TR_SIZE],
	/// Secret shares for this party, keyed by signer subset ID.
	/// Each share contains (s1_share, s2_share) polynomial vectors.
	/// Uses u16 as subset mask to support up to 16 parties.
	/// BTreeMap ensures deterministic serialization order.
	shares: BTreeMap<u16, SecretShareData>,
}

/// Internal secret share data for a specific signer subset.
///
/// Uses fixed-size arrays to guarantee exact dimensions at compile time,
/// preventing malformed deserialized data from causing issues downstream.
#[derive(Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize, Zeroize, ZeroizeOnDrop)]
pub(crate) struct SecretShareData {
	/// Share of s1 polynomial vector (exactly L polynomials of 256 coefficients).
	pub(crate) s1: [[i32; 256]; L],
	/// Share of s2 polynomial vector (exactly K polynomials of 256 coefficients).
	pub(crate) s2: [[i32; 256]; K],
}

impl PrivateKeyShare {
	/// Create a new private key share.
	pub(crate) fn new(
		party_id: ParticipantId,
		total_parties: u32,
		threshold: u32,
		key: [u8; 32],
		rho: [u8; 32],
		tr: [u8; TR_SIZE],
		shares: BTreeMap<u16, SecretShareData>,
		dkg_participants: ParticipantList,
	) -> Self {
		Self { party_id, total_parties, threshold, key, rho, tr, shares, dkg_participants }
	}

	/// Get this party's ID (can be arbitrary, e.g., NEAR participant ID).
	pub fn party_id(&self) -> ParticipantId {
		self.party_id
	}

	/// Get this party's DKG index (0 to n-1).
	/// This is used internally for share lookup via subset masks.
	pub fn dkg_index(&self) -> Option<usize> {
		self.dkg_participants.index_of(self.party_id)
	}

	/// Get the DKG participants list.
	/// This maps arbitrary party IDs to sequential indices for share operations.
	pub fn dkg_participants(&self) -> &ParticipantList {
		&self.dkg_participants
	}

	/// Get the total number of parties.
	pub fn total_parties(&self) -> u32 {
		self.total_parties
	}

	/// Get the threshold value.
	pub fn threshold(&self) -> u32 {
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

	/// Get the secret shares (for internal use).
	pub(crate) fn shares(&self) -> &BTreeMap<u16, SecretShareData> {
		&self.shares
	}

	/// Collect all coefficients from all shares, centered in (-Q/2, Q/2].
	///
	/// Returns a vector of all centered coefficient values from all subset shares.
	/// Useful for statistical analysis of coefficient distributions after resharing.
	///
	/// Note: This is primarily intended for testing and analysis, not for normal
	/// protocol operation.
	pub fn collect_all_coefficients(&self) -> Vec<i32> {
		const Q: i64 = 8380417;
		const HALF_Q: i64 = Q / 2;

		let mut coeffs = Vec::new();
		for share_data in self.shares.values() {
			// Collect s1 coefficients
			for poly in &share_data.s1 {
				for &coeff in poly {
					let c = coeff as i64;
					let centered = if c > HALF_Q { c - Q } else { c };
					coeffs.push(centered as i32);
				}
			}
			// Collect s2 coefficients
			for poly in &share_data.s2 {
				for &coeff in poly {
					let c = coeff as i64;
					let centered = if c > HALF_Q { c - Q } else { c };
					coeffs.push(centered as i32);
				}
			}
		}
		coeffs
	}

	/// Compute coefficient statistics across all shares.
	///
	/// Returns `(max_abs_coeff, min_coeff, max_coeff)` where coefficients are
	/// interpreted as centered values in `[-(Q-1)/2, (Q-1)/2]`.
	///
	/// This is useful for monitoring coefficient growth after resharing.
	pub fn coefficient_stats(&self) -> (i32, i32, i32) {
		const Q: i64 = 8380417;
		const HALF_Q: i64 = Q / 2;

		let mut max_abs: i32 = 0;
		let mut min_coeff: i32 = 0;
		let mut max_coeff: i32 = 0;

		for share_data in self.shares.values() {
			// Check s1 coefficients
			for poly in &share_data.s1 {
				for &coeff in poly {
					// Center the coefficient
					let c = coeff as i64;
					let centered = if c > HALF_Q { c - Q } else { c };
					let centered_i32 = centered as i32;

					if centered_i32.abs() > max_abs {
						max_abs = centered_i32.abs();
					}
					if centered_i32 < min_coeff {
						min_coeff = centered_i32;
					}
					if centered_i32 > max_coeff {
						max_coeff = centered_i32;
					}
				}
			}
			// Check s2 coefficients
			for poly in &share_data.s2 {
				for &coeff in poly {
					let c = coeff as i64;
					let centered = if c > HALF_Q { c - Q } else { c };
					let centered_i32 = centered as i32;

					if centered_i32.abs() > max_abs {
						max_abs = centered_i32.abs();
					}
					if centered_i32 < min_coeff {
						min_coeff = centered_i32;
					}
					if centered_i32 > max_coeff {
						max_coeff = centered_i32;
					}
				}
			}
		}

		(max_abs, min_coeff, max_coeff)
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

impl Drop for PrivateKeyShare {
	fn drop(&mut self) {
		self.zeroize();
	}
}

impl ZeroizeOnDrop for PrivateKeyShare {}

impl fmt::Debug for PrivateKeyShare {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
		let dkg_participants = ParticipantList::new(&[0, 1, 2]).unwrap();
		let pk_share = PrivateKeyShare::new(
			0,
			3,
			2,
			[0x42u8; 32],
			[0u8; 32],
			[0u8; TR_SIZE],
			BTreeMap::new(),
			dkg_participants,
		);
		let debug_str = format!("{:?}", pk_share);
		assert!(debug_str.contains("REDACTED"));
		assert!(!debug_str.contains("42")); // Should not contain the key bytes
	}

	#[test]
	fn test_private_key_zeroize() {
		let dkg_participants = ParticipantList::new(&[0, 1, 2]).unwrap();
		let mut pk_share = PrivateKeyShare::new(
			0,
			3,
			2,
			[0x42u8; 32],
			[0x43u8; 32],
			[0x44u8; TR_SIZE],
			BTreeMap::new(),
			dkg_participants,
		);
		pk_share.zeroize();
		assert_eq!(pk_share.key, [0u8; 32]);
		assert_eq!(pk_share.rho, [0u8; 32]);
		assert_eq!(pk_share.tr, [0u8; TR_SIZE]);
	}

	#[test]
	fn test_public_key_borsh_roundtrip() {
		// Valid public key should serialize and deserialize correctly
		let bytes = [0x42u8; PUBLIC_KEY_SIZE];
		let pk = PublicKey::from_bytes(&bytes).unwrap();

		let serialized = borsh::to_vec(&pk).unwrap();
		let deserialized: PublicKey = borsh::from_slice(&serialized).unwrap();

		assert_eq!(pk, deserialized);
		assert_eq!(pk.as_bytes(), deserialized.as_bytes());
		assert_eq!(pk.tr(), deserialized.tr());
	}

	#[test]
	fn test_public_key_serialization_only_includes_bytes() {
		// Verify that only the public key bytes are serialized (not TR)
		let bytes = [0x42u8; PUBLIC_KEY_SIZE];
		let pk = PublicKey::from_bytes(&bytes).unwrap();

		let serialized = borsh::to_vec(&pk).unwrap();

		// Serialized size should be exactly PUBLIC_KEY_SIZE (no TR)
		assert_eq!(serialized.len(), PUBLIC_KEY_SIZE);

		// TR is recomputed on deserialize, so any modification to the
		// serialized bytes will result in a different (but consistent) TR
		let mut modified = serialized.clone();
		modified[0] ^= 0xFF;
		let deserialized: PublicKey = borsh::from_slice(&modified).unwrap();

		// The deserialized key should have different bytes AND different TR
		assert_ne!(deserialized.as_bytes(), pk.as_bytes());
		assert_ne!(deserialized.tr(), pk.tr());
	}
}
