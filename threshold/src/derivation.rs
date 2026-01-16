//! Key derivation utilities for threshold Dilithium.
//!
//! This module provides functions for deriving child keys from master keys
//! in a threshold-secure manner. Unlike ECC schemes where derivation is linear
//! (derived_share = master_share + tweak), Dilithium requires running a full
//! DKG protocol for each derived key.
//!
//! # Architecture
//!
//! For Dilithium key derivation:
//! 1. Each party derives a DKG contribution from their master share + tweak
//! 2. Parties run full DKG using these contributions for randomness
//! 3. The resulting shares are stored (cannot be recomputed on-the-fly)
//! 4. The derived public key is deterministic for the same (master_key, tweak)
//!
//! # Security
//!
//! The DKG contribution uses secret material from the master share, ensuring
//! that outsiders cannot compute the derived shares even though the tweak
//! is public.

use hkdf::Hkdf;
use sha2::Sha256;
use sha3::{Digest, Sha3_256};

use crate::keys::PrivateKeyShare;

/// Domain separator for NEAR MPC Dilithium tweak derivation.
const TWEAK_DERIVATION_PREFIX: &str = "near-mpc-dilithium v1.0 derivation:";

/// Domain separator for DKG contribution derivation.
const DKG_CONTRIBUTION_DOMAIN: &[u8] = b"near-mpc-dilithium-dkg-contribution-v1";

/// Derive a tweak from an account ID and path.
///
/// This follows the same pattern as ECC derivation but with a Dilithium-specific
/// domain separator to ensure derived keys are independent across schemes.
///
/// # Arguments
/// * `account_id` - The NEAR account ID (e.g., "alice.near")
/// * `path` - The derivation path (e.g., "ethereum", "bitcoin/0")
///
/// # Returns
/// A 32-byte tweak value
///
/// # Example
/// ```
/// use qp_rusty_crystals_threshold::derivation::derive_tweak;
///
/// let tweak = derive_tweak("alice.near", "ethereum");
/// assert_eq!(tweak.len(), 32);
///
/// // Same inputs produce same tweak
/// let tweak2 = derive_tweak("alice.near", "ethereum");
/// assert_eq!(tweak, tweak2);
///
/// // Different inputs produce different tweaks
/// let tweak3 = derive_tweak("bob.near", "ethereum");
/// assert_ne!(tweak, tweak3);
/// ```
pub fn derive_tweak(account_id: &str, path: &str) -> [u8; 32] {
	// Use length-prefixed encoding to prevent ambiguity
	// Format: prefix || len(account_id) as u32 || account_id || path
	// This ensures "alice,near" + "eth" differs from "alice" + "near,eth"
	let account_len = account_id.len() as u32;

	let mut hasher = Sha3_256::new();
	hasher.update(TWEAK_DERIVATION_PREFIX.as_bytes());
	hasher.update(&account_len.to_le_bytes());
	hasher.update(account_id.as_bytes());
	hasher.update(path.as_bytes());
	hasher.finalize().into()
}

/// Derive a DKG contribution from a master share and tweak.
///
/// This function produces a deterministic 32-byte value that a party uses
/// as their randomness contribution in the DKG protocol. The contribution
/// incorporates secret material from the master share, ensuring that:
///
/// 1. Only parties with valid master shares can compute their contribution
/// 2. The contribution is deterministic (same share + tweak = same result)
/// 3. Different parties produce different contributions
/// 4. The contribution binds the derived key to the master key
///
/// # Arguments
/// * `master_share` - This party's master private key share
/// * `tweak` - The derivation tweak (from account_id + path)
///
/// # Returns
/// A 32-byte contribution for DKG randomness
///
/// # Security
///
/// The contribution uses HKDF with the master share's secret key material
/// as input. This ensures that even though the tweak is public, only parties
/// holding valid master shares can compute their DKG contributions.
///
/// # Example
/// ```ignore
/// use qp_rusty_crystals_threshold::derivation::{derive_tweak, derive_dkg_contribution};
///
/// let tweak = derive_tweak("alice.near", "ethereum");
/// let contribution = derive_dkg_contribution(&my_master_share, &tweak);
///
/// // Use contribution as seed for DKG randomness
/// ```
pub fn derive_dkg_contribution(master_share: &PrivateKeyShare, tweak: &[u8; 32]) -> [u8; 32] {
	// Get secret material from the master share
	// We use the key field which contains the private key seed
	let secret_material = master_share.key();

	// Include party_id to ensure different parties get different contributions
	// even if they somehow had the same key material
	let party_id_bytes = master_share.party_id().to_le_bytes();

	// Construct input key material: secret || party_id
	let mut ikm = Vec::with_capacity(secret_material.len() + party_id_bytes.len());
	ikm.extend_from_slice(secret_material);
	ikm.extend_from_slice(&party_id_bytes);

	// Use HKDF to derive the contribution
	// Salt: domain separator
	// IKM: secret material from share + party_id
	// Info: the tweak (which binds to account + path)
	let hk = Hkdf::<Sha256>::new(Some(DKG_CONTRIBUTION_DOMAIN), &ikm);
	let mut contribution = [0u8; 32];
	hk.expand(tweak, &mut contribution)
		.expect("32 bytes is a valid HKDF-SHA256 output length");

	contribution
}

/// Identifier for a derived key, used for storage lookup.
///
/// This uniquely identifies a derived key by the domain and tweak.
/// MPC nodes use this to look up stored derived shares.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DerivedKeyId {
	/// The domain ID (identifies the master key)
	pub domain_id: u64,
	/// The derivation tweak (derived from account + path)
	pub tweak: [u8; 32],
}

impl DerivedKeyId {
	/// Create a new derived key identifier.
	pub fn new(domain_id: u64, tweak: [u8; 32]) -> Self {
		Self { domain_id, tweak }
	}

	/// Create a derived key identifier from account and path.
	pub fn from_account_path(domain_id: u64, account_id: &str, path: &str) -> Self {
		let tweak = derive_tweak(account_id, path);
		Self { domain_id, tweak }
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::participants::ParticipantList;

	/// Helper to create a test PrivateKeyShare
	fn create_test_share(party_id: u32, key: [u8; 32]) -> PrivateKeyShare {
		let dkg_participants = ParticipantList::new(&[0, 1, 2]).unwrap();
		PrivateKeyShare::new(
			party_id,
			3, // total_parties
			2, // threshold
			key,
			[0u8; 32],                        // rho
			[0u8; 64],                        // tr
			std::collections::HashMap::new(), // shares
			dkg_participants,
		)
	}

	#[test]
	fn test_derive_tweak_deterministic() {
		let tweak1 = derive_tweak("alice.near", "ethereum");
		let tweak2 = derive_tweak("alice.near", "ethereum");
		assert_eq!(tweak1, tweak2);
	}

	#[test]
	fn test_derive_tweak_different_accounts() {
		let tweak_alice = derive_tweak("alice.near", "ethereum");
		let tweak_bob = derive_tweak("bob.near", "ethereum");
		assert_ne!(tweak_alice, tweak_bob);
	}

	#[test]
	fn test_derive_tweak_different_paths() {
		let tweak_eth = derive_tweak("alice.near", "ethereum");
		let tweak_btc = derive_tweak("alice.near", "bitcoin");
		assert_ne!(tweak_eth, tweak_btc);
	}

	#[test]
	fn test_derive_tweak_path_variations() {
		// Ensure different path formats produce different tweaks
		let tweak1 = derive_tweak("alice.near", "eth");
		let tweak2 = derive_tweak("alice.near", "eth/0");
		let tweak3 = derive_tweak("alice.near", "eth/1");
		assert_ne!(tweak1, tweak2);
		assert_ne!(tweak2, tweak3);
		assert_ne!(tweak1, tweak3);
	}

	#[test]
	fn test_derive_tweak_no_collision_with_separator() {
		// Ensure the comma separator prevents collisions
		// "alice,near" + "eth" should differ from "alice" + "near,eth"
		let tweak1 = derive_tweak("alice,near", "eth");
		let tweak2 = derive_tweak("alice", "near,eth");
		assert_ne!(tweak1, tweak2);
	}

	#[test]
	fn test_derive_dkg_contribution_deterministic() {
		let share = create_test_share(0, [42u8; 32]);
		let tweak = derive_tweak("alice.near", "ethereum");

		let contribution1 = derive_dkg_contribution(&share, &tweak);
		let contribution2 = derive_dkg_contribution(&share, &tweak);
		assert_eq!(contribution1, contribution2);
	}

	#[test]
	fn test_derive_dkg_contribution_different_parties() {
		let tweak = derive_tweak("alice.near", "ethereum");

		// Different party IDs with same key should produce different contributions
		let share0 = create_test_share(0, [42u8; 32]);
		let share1 = create_test_share(1, [42u8; 32]);

		let contribution0 = derive_dkg_contribution(&share0, &tweak);
		let contribution1 = derive_dkg_contribution(&share1, &tweak);
		assert_ne!(contribution0, contribution1);
	}

	#[test]
	fn test_derive_dkg_contribution_different_keys() {
		let tweak = derive_tweak("alice.near", "ethereum");

		// Different key material should produce different contributions
		let share_a = create_test_share(0, [1u8; 32]);
		let share_b = create_test_share(0, [2u8; 32]);

		let contribution_a = derive_dkg_contribution(&share_a, &tweak);
		let contribution_b = derive_dkg_contribution(&share_b, &tweak);
		assert_ne!(contribution_a, contribution_b);
	}

	#[test]
	fn test_derive_dkg_contribution_different_tweaks() {
		let share = create_test_share(0, [42u8; 32]);

		let tweak_eth = derive_tweak("alice.near", "ethereum");
		let tweak_btc = derive_tweak("alice.near", "bitcoin");

		let contribution_eth = derive_dkg_contribution(&share, &tweak_eth);
		let contribution_btc = derive_dkg_contribution(&share, &tweak_btc);
		assert_ne!(contribution_eth, contribution_btc);
	}

	#[test]
	fn test_derived_key_id_from_account_path() {
		let id1 = DerivedKeyId::from_account_path(0, "alice.near", "ethereum");
		let id2 = DerivedKeyId::from_account_path(0, "alice.near", "ethereum");
		assert_eq!(id1, id2);

		let id3 = DerivedKeyId::from_account_path(0, "bob.near", "ethereum");
		assert_ne!(id1, id3);

		let id4 = DerivedKeyId::from_account_path(1, "alice.near", "ethereum");
		assert_ne!(id1, id4); // Different domain
	}

	#[test]
	fn test_derived_key_id_new() {
		let tweak = derive_tweak("alice.near", "ethereum");
		let id1 = DerivedKeyId::new(5, tweak);
		let id2 = DerivedKeyId::from_account_path(5, "alice.near", "ethereum");
		assert_eq!(id1, id2);
	}
}
