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
//! The contribution input is bound to the share's actual secret polynomials
//! (`s1`, `s2`), which are the only true secret material in a `PrivateKeyShare`.
//! The legacy `key` byte string is *not* used here, because in the DKG path it is
//! derived deterministically from public values (`rho`, `party_id`) and therefore
//! provides no secrecy.

use alloc::vec::Vec;

use qp_rusty_crystals_dilithium::fips202;

use crate::keys::PrivateKeyShare;

/// Domain separator for DKG contribution derivation.
const DKG_CONTRIBUTION_DOMAIN: &[u8] = b"near-mpc-dilithium-dkg-contribution-v2";

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
/// The contribution is computed as
/// `SHAKE256(domain || party_id || tweak || H(secret_shares))`,
/// where `secret_shares` is the canonical serialization of every `(subset_mask, s1, s2)`
/// triple in the share. The shares are the actual cryptographic secret of the threshold
/// scheme, so an attacker who does not hold a valid `PrivateKeyShare` cannot compute
/// `derive_dkg_contribution` for any party — even though `party_id`, `tweak`, and
/// `rho` are public.
pub fn derive_dkg_contribution(master_share: &PrivateKeyShare, tweak: &[u8; 32]) -> [u8; 32] {
	let party_id_bytes = master_share.party_id().to_le_bytes();
	let shares_digest = hash_secret_shares(master_share);

	let mut state = fips202::KeccakState::default();
	fips202::shake256_absorb(&mut state, DKG_CONTRIBUTION_DOMAIN, DKG_CONTRIBUTION_DOMAIN.len());
	fips202::shake256_absorb(&mut state, &party_id_bytes, party_id_bytes.len());
	fips202::shake256_absorb(&mut state, tweak, tweak.len());
	fips202::shake256_absorb(&mut state, &shares_digest, shares_digest.len());
	fips202::shake256_finalize(&mut state);

	let mut contribution = [0u8; 32];
	fips202::shake256_squeeze(&mut contribution, 32, &mut state);

	contribution
}

/// Hash all secret share polynomials into a 64-byte digest for use as keying material.
///
/// `BTreeMap` iteration is deterministic by key, so the digest is stable across calls
/// and across machines holding the same share data.
pub(crate) fn hash_secret_shares(master_share: &PrivateKeyShare) -> [u8; 64] {
	let mut state = fips202::KeccakState::default();
	fips202::shake256_absorb(&mut state, b"threshold-share-digest-v1", 25);
	fips202::shake256_absorb(&mut state, &master_share.party_id().to_le_bytes(), 4);

	let mut buf: Vec<u8> = Vec::new();
	for (subset_mask, share_data) in master_share.shares() {
		buf.clear();
		buf.extend_from_slice(&subset_mask.to_le_bytes());
		for poly in &share_data.s1 {
			for coeff in poly {
				buf.extend_from_slice(&coeff.to_le_bytes());
			}
		}
		for poly in &share_data.s2 {
			for coeff in poly {
				buf.extend_from_slice(&coeff.to_le_bytes());
			}
		}
		fips202::shake256_absorb(&mut state, &buf, buf.len());
	}

	fips202::shake256_finalize(&mut state);
	let mut digest = [0u8; 64];
	fips202::shake256_squeeze(&mut digest, 64, &mut state);
	digest
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
	use crate::{keys::SecretShareData, participants::ParticipantList};

	/// Helper to create a test PrivateKeyShare with synthetic share data.
	///
	/// The `key_byte` value is fanned out into both the legacy `key` field and the
	/// (now security-relevant) `s1`/`s2` polynomial coefficients, so callers that
	/// previously distinguished shares by their `key` parameter still get distinct
	/// derivation outputs under the new contribution function.
	fn create_test_share(party_id: u32, key_byte: u8) -> PrivateKeyShare {
		let dkg_participants = ParticipantList::new(&[0, 1, 2]).unwrap();
		let mut shares = std::collections::BTreeMap::new();
		shares.insert(
			0b011,
			SecretShareData {
				s1: vec![[key_byte as i32; 256]; 7],
				s2: vec![[key_byte as i32; 256]; 8],
			},
		);
		PrivateKeyShare::new(
			party_id,
			3,
			2,
			[key_byte; 32],
			[0u8; 32],
			[0u8; 64],
			shares,
			dkg_participants,
		)
	}

	/// Create a test tweak (simulates what the contract would compute)
	fn test_tweak(account: &str, path: &str) -> [u8; 32] {
		let mut state = fips202::KeccakState::default();
		fips202::shake256_absorb(&mut state, b"test-tweak:", 11);
		fips202::shake256_absorb(&mut state, account.as_bytes(), account.len());
		fips202::shake256_absorb(&mut state, b":", 1);
		fips202::shake256_absorb(&mut state, path.as_bytes(), path.len());
		fips202::shake256_finalize(&mut state);

		let mut tweak = [0u8; 32];
		fips202::shake256_squeeze(&mut tweak, 32, &mut state);
		tweak
	}

	#[test]
	fn test_derive_dkg_contribution_deterministic() {
		let share = create_test_share(0, 42);
		let tweak = test_tweak("alice.near", "ethereum");

		let contribution1 = derive_dkg_contribution(&share, &tweak);
		let contribution2 = derive_dkg_contribution(&share, &tweak);
		assert_eq!(contribution1, contribution2);
	}

	#[test]
	fn test_derive_dkg_contribution_different_parties() {
		let tweak = test_tweak("alice.near", "ethereum");

		let share0 = create_test_share(0, 42);
		let share1 = create_test_share(1, 42);

		let contribution0 = derive_dkg_contribution(&share0, &tweak);
		let contribution1 = derive_dkg_contribution(&share1, &tweak);
		assert_ne!(contribution0, contribution1);
	}

	#[test]
	fn test_derive_dkg_contribution_different_keys() {
		let tweak = test_tweak("alice.near", "ethereum");

		let share_a = create_test_share(0, 1);
		let share_b = create_test_share(0, 2);

		let contribution_a = derive_dkg_contribution(&share_a, &tweak);
		let contribution_b = derive_dkg_contribution(&share_b, &tweak);
		assert_ne!(contribution_a, contribution_b);
	}

	#[test]
	fn test_derive_dkg_contribution_different_tweaks() {
		let share = create_test_share(0, 42);

		let tweak_eth = test_tweak("alice.near", "ethereum");
		let tweak_btc = test_tweak("alice.near", "bitcoin");

		let contribution_eth = derive_dkg_contribution(&share, &tweak_eth);
		let contribution_btc = derive_dkg_contribution(&share, &tweak_btc);
		assert_ne!(contribution_eth, contribution_btc);
	}

	#[test]
	fn test_contribution_independent_of_legacy_key_field() {
		// Two shares that differ ONLY in the publicly-derivable `key` byte string
		// must still produce the same contribution, because security comes from the
		// secret polynomial shares, not from `key`.
		let dkg_participants = ParticipantList::new(&[0, 1, 2]).unwrap();
		let mut shares = std::collections::BTreeMap::new();
		shares
			.insert(0b011, SecretShareData { s1: vec![[7i32; 256]; 7], s2: vec![[7i32; 256]; 8] });
		let share_a = PrivateKeyShare::new(
			0,
			3,
			2,
			[1u8; 32],
			[0u8; 32],
			[0u8; 64],
			shares.clone(),
			dkg_participants.clone(),
		);
		let share_b = PrivateKeyShare::new(
			0,
			3,
			2,
			[2u8; 32], // different `key`, same shares
			[0u8; 32],
			[0u8; 64],
			shares,
			dkg_participants,
		);

		let tweak = test_tweak("alice.near", "ethereum");
		assert_eq!(
			derive_dkg_contribution(&share_a, &tweak),
			derive_dkg_contribution(&share_b, &tweak),
			"contribution must depend on secret share polynomials, not on `key` field"
		);
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
