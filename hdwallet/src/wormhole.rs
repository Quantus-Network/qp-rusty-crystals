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

use qp_poseidon_core::{
	double_hash_variable_length, hash_variable_length, hash_variable_length_bytes,
	serialization::{injective_string_to_felts, unsafe_digest_bytes_to_felts},
};
extern crate alloc;
use alloc::vec::Vec;
use qp_rusty_crystals_dilithium::SensitiveBytes32;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Salt used when deriving wormhole addresses.
pub const ADDRESS_SALT: &str = "wormhole";

/// Error types returned from wormhole identity operations.
#[derive(Debug, Eq, PartialEq)]
pub enum WormholeError {
	/// Returned when the input random source fails or is malformed.
	InvalidSecretFormat,
}

/// A struct representing a wormhole identity pair: address + secret.
#[derive(Clone, Eq, PartialEq, ZeroizeOnDrop)]
pub struct WormholePair {
	/// Deterministic Poseidon-derived address.
	pub address: [u8; 32],
	/// First hash of secret
	pub first_hash: [u8; 32],
	/// The hashed secret used to generate this address.
	pub secret: [u8; 32],
}

impl WormholePair {
	/// Generates a new `WormholePair` from user-supplied entropy.
	///
	/// # Errors
	/// Returns `WormholeError::InvalidSecretFormat` if entropy collection fails.
	pub fn generate_new(seed: SensitiveBytes32) -> Result<WormholePair, WormholeError> {
		let mut hashed_seed = hash_variable_length_bytes(seed.as_bytes());
		let secret = SensitiveBytes32::new(&mut hashed_seed);
		let result = Self::generate_pair_from_secret(secret);

		// seed and secret are automatically zeroized when it drops

		Ok(result)
	}

	/// Verifies whether the given raw secret generates the specified wormhole address.
	///
	/// # Arguments
	/// * `address` - The expected wormhole address.
	/// * `secret` - Raw secret to verify.
	///
	/// # Returns
	/// `true` if the address matches the derived one, `false` otherwise.
	pub fn verify(address: [u8; 32], secret: SensitiveBytes32) -> bool {
		let generated_address = Self::generate_pair_from_secret(secret.into()).address;
		// Note: secret is automatically zeroized when the SensitiveBytes32 wrapper drops
		generated_address == address
	}

	/// Internal function that generates a `WormholePair` from a given secret.
	///
	/// This function performs a secondary Poseidon hash over the salt + hashed secret
	/// to derive the wormhole address.
	///
	/// # Security Note
	/// This function takes ownership of the secret for security (move semantics).
	/// The secret parameter is zeroized before returning.
	pub fn generate_pair_from_secret(secret: SensitiveBytes32) -> WormholePair {
		let mut secret_bytes = secret.into_bytes();
		let mut preimage_felts = Vec::new();
		let salt_felt = injective_string_to_felts(ADDRESS_SALT);
		let mut secret_felt = unsafe_digest_bytes_to_felts(&secret_bytes);
		preimage_felts.extend_from_slice(&salt_felt);
		preimage_felts.extend_from_slice(&secret_felt);
		let inner_hash = hash_variable_length(preimage_felts.clone());
		let second_hash = double_hash_variable_length(preimage_felts.clone());

		// Create result with copy of secret before zeroizing
		let result =
			WormholePair { address: second_hash, first_hash: inner_hash, secret: secret_bytes };

		// Manually clear intermediate sensitive data
		for elem in secret_felt.iter_mut() {
			*elem = Default::default();
		}
		preimage_felts.clear();

		// Zeroize the input secret parameter
		secret_bytes.zeroize();

		result
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use hex_literal::hex;
	use qp_poseidon_core::serialization::{injective_bytes_to_felts, unsafe_digest_bytes_to_felts};

	#[test]
	fn test_generate_pair_from_secret() {
		// Arrange
		let mut secret = [42u8; 32];

		// Act
		let pair = WormholePair::generate_pair_from_secret((&mut secret).into());

		// Assert secret was zeroized and pair.secret was not zeroized
		assert_eq!(secret, [0u8; 32]);
		assert_eq!(pair.secret, [42u8; 32]);

		// We can't easily predict the exact hash output without mocking Poseidon2Core,
		// but we can verify that it's not zero and that it's deterministic
		assert_ne!(pair.first_hash, [0u8; 32]);
		assert_ne!(pair.address, [0u8; 32]);

		// Verify determinism
		let mut secret2 = [42u8; 32];
		let pair2 = WormholePair::generate_pair_from_secret((&mut secret2).into());
		assert_eq!(pair.address, pair2.address);
	}

	#[test]
	fn test_verify_valid_secret() {
		// Arrange
		let mut secret = [1u8; 32];
		let pair = WormholePair::generate_pair_from_secret((&mut secret).into());

		// Act
		let mut secret_for_verify = [1u8; 32];
		let result = WormholePair::verify(pair.address, (&mut secret_for_verify).into());

		// Assert
		assert!(result);
	}

	#[test]
	fn test_verify_invalid_secret() {
		// Arrange
		let mut secret = [1u8; 32];
		let mut wrong_secret = [2u8; 32];
		let pair = WormholePair::generate_pair_from_secret((&mut secret).into());

		// Act
		let result = WormholePair::verify(pair.address, (&mut wrong_secret).into());

		// Assert
		assert!(!result);
	}

	#[test]
	fn test_address_derivation_properties() {
		// Arrange
		let secret = hex!("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
		let secret_felts = unsafe_digest_bytes_to_felts(&secret);

		// Act - Generate the pair
		let mut secret_copy = secret;
		let pair = WormholePair::generate_pair_from_secret((&mut secret_copy).into());

		// Assert
		// 1. Verify that the secret is stored correctly
		assert_eq!(pair.secret, secret);

		// 2. Verify that the derived address is consistent with our verification method
		let mut secret_for_verify = secret;
		assert!(WormholePair::verify(pair.address, (&mut secret_for_verify).into()));

		// 3. Verify that even a small change in the secret produces a different address
		let mut altered_secret = secret;
		altered_secret[0] ^= 1; // Flip one bit in the first byte
		let altered_pair = WormholePair::generate_pair_from_secret((&mut altered_secret).into());
		assert_ne!(pair.address, altered_pair.address);

		// 4. Verify that the process uses the salt
		// (Create a direct hash without salt and ensure it's different)
		let double_hash = double_hash_variable_length(secret_felts.to_vec());
		assert_ne!(pair.address, double_hash);

		// 5. Verify that each stage of the hash process changes the result
		// (Create a hash with salt but without the second hashing step)
		let address_salt_felts = injective_string_to_felts(ADDRESS_SALT);
		let mut combined_felts = Vec::with_capacity(address_salt_felts.len() + secret_felts.len());
		combined_felts.extend_from_slice(address_salt_felts.as_ref());
		combined_felts.extend_from_slice(&secret_felts);
		let first_hash = hash_variable_length(combined_felts.to_vec());
		assert_ne!(pair.address, first_hash);
	}

	#[test]
	fn test_different_secrets_produce_different_addresses() {
		// Arrange
		let mut secret1 = [5u8; 32];
		let mut secret2 = [6u8; 32];

		// Act
		let pair1 = WormholePair::generate_pair_from_secret((&mut secret1).into());
		let pair2 = WormholePair::generate_pair_from_secret((&mut secret2).into());

		// Assert
		assert_ne!(pair1.address, pair2.address);
	}

	#[test]
	fn test_generate_new_produces_valid_pair() {
		let mut seed = [55u8; 32];
		// Act
		let result = WormholePair::generate_new((&mut seed).into());

		// Assert
		assert!(result.is_ok());
		let pair = result.unwrap();

		// The secret should not be all zeros
		assert_ne!(pair.secret, [0u8; 32]);

		// Address should not be zero
		assert_ne!(pair.address, [0u8; 32]);

		// Verification should work with the generated secret
		let mut secret_for_verify = pair.secret;
		let verification = WormholePair::verify(pair.address, (&mut secret_for_verify).into());
		assert!(verification);
	}

	#[test]
	fn test_salt_is_used_in_address_generation() {
		// This test verifies that the salt affects the generated address

		// Arrange
		let secret = [7u8; 32];

		let secret_felts = unsafe_digest_bytes_to_felts(&secret);

		// Generate a pair normally (with salt)
		let mut secret_copy = secret;
		let pair_with_salt = WormholePair::generate_pair_from_secret((&mut secret_copy).into());

		// Simulate address generation without salt or with different salt
		let different_salt = b"diffrent";
		let different_salt_felts = injective_bytes_to_felts(different_salt);

		let mut combined_felts =
			Vec::with_capacity(different_salt_felts.len() + secret_felts.len());
		combined_felts.extend_from_slice(&different_salt_felts);
		combined_felts.extend_from_slice(&secret_felts);

		let address_with_different_salt = double_hash_variable_length(combined_felts);

		// Assert
		assert_ne!(pair_with_salt.address, address_with_different_salt);
	}
}
