//! Key derivation utilities for threshold Dilithium.
//!
//! This module provides functions for deriving DKG contributions from master keys
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
//! # Tweak Computation
//!
//! The tweak should be computed by the caller using the same algorithm as the
//! NEAR MPC contract (`derive_dilithium_tweak`). This ensures consistency between
//! the contract (which stores derived public keys) and the MPC nodes (which run DKG).
//!
//! # Security
//!
//! The DKG contribution uses secret material from the master share, ensuring
//! that outsiders cannot compute the derived shares even though the tweak
//! is public.

use hkdf::Hkdf;
use sha2::Sha256;

use crate::keys::PrivateKeyShare;

/// Domain separator for DKG contribution derivation.
const DKG_CONTRIBUTION_DOMAIN: &[u8] = b"near-mpc-dilithium-dkg-contribution-v1";

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
/// * `tweak` - The derivation tweak (computed from account_id + path by the caller)
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
/// use qp_rusty_crystals_threshold::derivation::derive_dkg_contribution;
///
/// // Tweak is computed by the caller (e.g., from NEAR MPC contract's derive_dilithium_tweak)
/// let tweak: [u8; 32] = compute_tweak("alice.near", "ethereum");
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
	/// The derivation tweak (derived from account + path by the caller)
	pub tweak: [u8; 32],
}

impl DerivedKeyId {
	/// Create a new derived key identifier.
	pub fn new(domain_id: u64, tweak: [u8; 32]) -> Self {
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

	/// Create a test tweak (simulates what the contract would compute)
	fn test_tweak(account: &str, path: &str) -> [u8; 32] {
		use sha2::{Digest, Sha256};
		let mut hasher = Sha256::new();
		hasher.update(b"test-tweak:");
		hasher.update(account.as_bytes());
		hasher.update(b":");
		hasher.update(path.as_bytes());
		hasher.finalize().into()
	}

	#[test]
	fn test_derive_dkg_contribution_deterministic() {
		let share = create_test_share(0, [42u8; 32]);
		let tweak = test_tweak("alice.near", "ethereum");

		let contribution1 = derive_dkg_contribution(&share, &tweak);
		let contribution2 = derive_dkg_contribution(&share, &tweak);
		assert_eq!(contribution1, contribution2);
	}

	#[test]
	fn test_derive_dkg_contribution_different_parties() {
		let tweak = test_tweak("alice.near", "ethereum");

		// Different party IDs with same key should produce different contributions
		let share0 = create_test_share(0, [42u8; 32]);
		let share1 = create_test_share(1, [42u8; 32]);

		let contribution0 = derive_dkg_contribution(&share0, &tweak);
		let contribution1 = derive_dkg_contribution(&share1, &tweak);
		assert_ne!(contribution0, contribution1);
	}

	#[test]
	fn test_derive_dkg_contribution_different_keys() {
		let tweak = test_tweak("alice.near", "ethereum");

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

		let tweak_eth = test_tweak("alice.near", "ethereum");
		let tweak_btc = test_tweak("alice.near", "bitcoin");

		let contribution_eth = derive_dkg_contribution(&share, &tweak_eth);
		let contribution_btc = derive_dkg_contribution(&share, &tweak_btc);
		assert_ne!(contribution_eth, contribution_btc);
	}

	#[test]
	fn test_derived_key_id_new() {
		let tweak = test_tweak("alice.near", "ethereum");
		let id1 = DerivedKeyId::new(5, tweak);
		let id2 = DerivedKeyId::new(5, tweak);
		assert_eq!(id1, id2);

		let id3 = DerivedKeyId::new(6, tweak);
		assert_ne!(id1, id3); // Different domain
	}

	#[test]
	fn test_derived_key_id_different_tweaks() {
		let tweak1 = test_tweak("alice.near", "ethereum");
		let tweak2 = test_tweak("bob.near", "ethereum");

		let id1 = DerivedKeyId::new(5, tweak1);
		let id2 = DerivedKeyId::new(5, tweak2);
		assert_ne!(id1, id2);
	}
}
