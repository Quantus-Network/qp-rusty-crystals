//! # Wormhole Utilities
//!
//! This module provides functionality for generating and verifying wormhole-based addresses,
//! using Poseidon hashing and a salt-based construction to derive deterministic addresses
//! from secrets or pre-hashed secrets.
//!
//! ## Overview
//!
//! - A `WormholePair` consists of:
//!     - `address`: a Poseidon-derived `[u8; 32]` address.
//!     - `secret`: a 32-byte Poseidon hash derived from entropy or input secret.
//!
//! - You can:
//!     - Generate new wormhole identities using random entropy (`generate_new`).
//!     - Verify if a given secret or pre-hashed secret matches a wormhole address.
//!
//! The hashing strategy ensures determinism while hiding the original secret.
//!
//! ## Integration with HD Wallet
//!
//! This module integrates with the HD wallet system by providing specialized address generation
//! for paths that start with "w/". When such paths are encountered, the wallet system uses
//! this module's functionality to generate wormhole addresses instead of regular HD wallet
//! addresses.
//!
//! The wormhole addresses provide an additional layer of privacy and security by using
//! Poseidon hashing, which is particularly well-suited for zero-knowledge proof systems.

use qp_poseidon_core::{digest_bytes_to_felts, injective_string_to_felts, Poseidon2Core};
extern crate alloc;
use alloc::vec::Vec;

/// Salt used when deriving wormhole addresses.
pub const ADDRESS_SALT: &str = "wormhole";

/// Error types returned from wormhole identity operations.
#[derive(Debug, Eq, PartialEq)]
pub enum WormholeError {
	/// Returned when the input random source fails or is malformed.
	InvalidSecretFormat,
}

/// A struct representing a wormhole identity pair: address + secret.
#[derive(Clone, Eq, PartialEq)]
pub struct WormholePair {
	/// Deterministic Poseidon-derived address.
	pub address: [u8; 32],
	/// First hash of secret
	pub first_hash: [u8; 32],
	/// The hashed secret used to generate this address.
	pub secret: [u8; 32],
}

impl WormholePair {
	/// Generates a new `WormholePair` using secure system entropy (only available with `std`).
	///
	/// # Errors
	/// Returns `WormholeError::InvalidSecretFormat` if entropy collection fails.
	pub fn generate_new(seed: [u8; 32]) -> Result<WormholePair, WormholeError> {
		let poseidon = Poseidon2Core::new();
		let secret = poseidon.hash_no_pad_bytes(&seed);

		Ok(Self::generate_pair_from_secret(&secret))
	}

	/// Verifies whether the given raw secret generates the specified wormhole address.
	///
	/// # Arguments
	/// * `address` - The expected wormhole address.
	/// * `secret` - Raw secret to verify.
	///
	/// # Returns
	/// `true` if the address matches the derived one, `false` otherwise.
	pub fn verify(address: [u8; 32], secret: &[u8; 32]) -> bool {
		let generated_address = Self::generate_pair_from_secret(secret).address;
		generated_address == address
	}

	/// Internal function that generates a `WormholePair` from a given secret.
	///
	/// This function performs a secondary Poseidon hash over the salt + hashed secret
	/// to derive the wormhole address.
	pub fn generate_pair_from_secret(secret: &[u8; 32]) -> WormholePair {
		let mut preimage_felts = Vec::new();
		let salt_felt = injective_string_to_felts(ADDRESS_SALT);
		let secret_felt = digest_bytes_to_felts(secret);
		preimage_felts.extend_from_slice(&salt_felt);
		preimage_felts.extend_from_slice(&secret_felt);
		let poseidon = Poseidon2Core::new();
		let inner_hash = poseidon.hash_no_pad(preimage_felts);
		let second_hash = poseidon.hash_no_pad(digest_bytes_to_felts(&inner_hash));
		WormholePair { address: second_hash, first_hash: inner_hash, secret: *secret }
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use hex_literal::hex;
	use qp_poseidon_core::digest_bytes_to_felts;

	#[test]
	fn test_generate_pair_from_secret() {
		// Arrange
		let secret = [42u8; 32];

		// Act
		let pair = WormholePair::generate_pair_from_secret(&secret);

		// Assert
		assert_eq!(pair.secret, secret);

		// We can't easily predict the exact hash output without mocking Poseidon2Core,
		// but we can verify that it's not zero and that it's deterministic
		assert_ne!(pair.first_hash, [0u8; 32]);
		assert_ne!(pair.address, [0u8; 32]);

		// Verify determinism
		let pair2 = WormholePair::generate_pair_from_secret(&secret);
		assert_eq!(pair.address, pair2.address);
	}

	#[test]
	fn test_verify_valid_secret() {
		// Arrange
		let secret = [1u8; 32];
		let pair = WormholePair::generate_pair_from_secret(&secret);

		// Act
		let result = WormholePair::verify(pair.address, &secret);

		// Assert
		assert!(result);
	}

	#[test]
	fn test_verify_invalid_secret() {
		// Arrange
		let secret = [1u8; 32];
		let wrong_secret = [2u8; 32];
		let pair = WormholePair::generate_pair_from_secret(&secret);

		// Act
		let result = WormholePair::verify(pair.address, &wrong_secret);

		// Assert
		assert!(!result);
	}

	#[test]
	fn test_address_derivation_properties() {
		// Arrange
		let secret = hex!("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
		let secret_felts = digest_bytes_to_felts(&secret);

		// Act - Generate the pair
		let pair = WormholePair::generate_pair_from_secret(&secret);

		// Assert
		// 1. Verify that the secret is stored correctly
		assert_eq!(pair.secret, secret);

		// 2. Verify that the derived address is consistent with our verification method
		assert!(WormholePair::verify(pair.address, &secret));

		// 3. Verify that even a small change in the secret produces a different address
		let mut altered_secret = secret;
		altered_secret[0] ^= 1; // Flip one bit in the first byte
		let altered_pair = WormholePair::generate_pair_from_secret(&altered_secret);
		assert_ne!(pair.address, altered_pair.address);

		// 4. Verify that the process uses the salt
		// (Create a direct hash without salt and ensure it's different)
		let poseidon = Poseidon2Core::new();
		let direct_hash = poseidon.hash_no_pad(secret_felts);
		let direct_hash_felts = digest_bytes_to_felts(&direct_hash);
		let double_hash = poseidon.hash_no_pad(direct_hash_felts);
		assert_ne!(pair.address, double_hash);

		// 5. Verify that each stage of the hash process changes the result
		// (Create a hash with salt but without the second hashing step)
		let mut combined = Vec::with_capacity(ADDRESS_SALT.len() + secret.len());
		combined.extend_from_slice(ADDRESS_SALT.as_bytes());
		combined.extend_from_slice(&secret);
		let combined_felts = digest_bytes_to_felts(&combined);
		let poseidon = Poseidon2Core::new();
		let first_hash = poseidon.hash_no_pad(combined_felts);
		assert_ne!(pair.address, first_hash);
	}

	#[test]
	fn test_different_secrets_produce_different_addresses() {
		// Arrange
		let secret1 = [5u8; 32];
		let secret2 = [6u8; 32];

		// Act
		let pair1 = WormholePair::generate_pair_from_secret(&secret1);
		let pair2 = WormholePair::generate_pair_from_secret(&secret2);

		// Assert
		assert_ne!(pair1.address, pair2.address);
	}

	#[test]
	fn test_generate_new_produces_valid_pair() {
		let seed = [55u8; 32];
		// Act
		let result = WormholePair::generate_new(seed);

		// Assert
		assert!(result.is_ok());
		let pair = result.unwrap();

		// The secret should not be all zeros
		assert_ne!(pair.secret, [0u8; 32]);

		// Address should not be zero
		assert_ne!(pair.address, [0u8; 32]);

		// Verification should work with the generated secret
		let verification = WormholePair::verify(pair.address, &pair.secret);
		assert!(verification);
	}

	#[test]
	fn test_salt_is_used_in_address_generation() {
		// This test verifies that the salt affects the generated address

		// Arrange
		let secret = [7u8; 32];

		// Generate a pair normally (with salt)
		let pair_with_salt = WormholePair::generate_pair_from_secret(&secret);

		// Simulate address generation without salt or with different salt
		let different_salt = b"diffrent";

		let mut combined = Vec::with_capacity(different_salt.len() + secret.len());
		combined.extend_from_slice(different_salt);
		combined.extend_from_slice(&secret);
		let combined_felts = digest_bytes_to_felts(&combined);

		let poseidon = Poseidon2Core::new();
		let first_hash = poseidon.hash_no_pad(combined_felts);
		let first_hash_felts = digest_bytes_to_felts(&first_hash);
		let address_with_different_salt = poseidon.hash_no_pad(first_hash_felts);

		// Assert
		assert_ne!(pair_with_salt.address, address_with_different_salt);
	}
}
