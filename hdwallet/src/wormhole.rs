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
//!     - Verify a secret against an address by re-deriving (derivation is deterministic, so
//!       re-run `generate_new` with the same input and compare the resulting `address`).
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
	hash_bytes, hash_to_bytes, hash_twice,
	serialization::{bytes_to_digest_lossy, string_to_felts},
	Goldilocks,
};
extern crate alloc;
use alloc::vec::Vec;
use qp_rusty_crystals_dilithium::{ct_eq_32, SensitiveBytes32};
use zeroize::Zeroize;

/// Salt used when deriving wormhole addresses.
pub const ADDRESS_SALT: &str = "wormhole";

/// Overwrite field elements holding secret material with zeros.
///
/// `Goldilocks` is a foreign type without a `Zeroize` impl, so the `zeroize`
/// crate cannot wipe it directly. A plain `*felt = Default::default()` loop is
/// a dead store the optimizer may elide (the buffer is freed right after), so
/// the writes go through `write_volatile`, followed by a compiler fence —
/// the same construction `zeroize` itself uses.
fn zeroize_felts(felts: &mut [Goldilocks]) {
	for felt in felts.iter_mut() {
		// SAFETY: `felt` is a valid, aligned, exclusive reference; writing a
		// plain `Copy` value through it is always sound. Volatile only opts
		// the store out of dead-store elimination.
		unsafe { core::ptr::write_volatile(felt, Goldilocks::default()) };
	}
	core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// A struct representing a wormhole identity pair: address + secret.
///
/// Fields are private (security review) so `address` and `first_hash` are
/// always the values derived from `secret` — a struct literal or field
/// assignment can't assemble an inconsistent tuple. Read via the accessors.
///
/// `Clone` is intentionally not derived because the secret is sensitive. It
/// is stored as a [`SensitiveBytes32`] wrapper rather than a bare `[u8; 32]`:
/// a plain array is `Copy`, so it could silently duplicate the secret
/// (leaving copies in stack frames, logs, or crash dumps) that the pair's
/// own drop-time zeroization can never scrub. The wrapper is move-only and
/// zeroizes on drop, so any duplication must be explicit
/// (`pair.secret().as_bytes()`), making it visible at the call site. Prefer
/// passing `&WormholePair` instead.
pub struct WormholePair {
	/// Deterministic Poseidon-derived address.
	address: [u8; 32],
	/// First hash of secret
	first_hash: [u8; 32],
	/// The hashed secret used to generate this address. Move-only and zeroized
	/// on drop; read the raw bytes via `secret().as_bytes()`.
	secret: SensitiveBytes32,
}

// `secret` is a `SensitiveBytes32` (which is not `PartialEq`), so equality is
// implemented by hand. Every field is compared in constant time and the
// results are combined with non-short-circuiting `&` (security review): `==`
// on the raw bytes may bail out at the first differing byte, and short-
// circuiting between fields skips later comparisons entirely, so comparison
// time would depend on the length of the matching prefix — a timing oracle
// against the secret. `first_hash` gets the same treatment as `secret`: the
// address is the double hash of the same preimage, so the single hash is a
// reveal value, not public data. `SensitiveBytes32` already zeroizes itself
// on drop, so no `ZeroizeOnDrop` derive is needed on `WormholePair`.
impl PartialEq for WormholePair {
	fn eq(&self, other: &Self) -> bool {
		let address_eq = ct_eq_32(&self.address, &other.address);
		let first_hash_eq = ct_eq_32(&self.first_hash, &other.first_hash);
		let secret_eq = self.secret.ct_eq(&other.secret);
		address_eq & first_hash_eq & secret_eq
	}
}

impl Eq for WormholePair {}

impl WormholePair {
	/// Generates a new `WormholePair` from user-supplied entropy.
	///
	/// The seed is borrowed mutably and zeroized in place after use
	/// (security review): taking it by value would move — i.e. copy — it
	/// through a dead stack slot that is never dropped, so `ZeroizeOnDrop`
	/// could not wipe it. The caller's value is all zeros afterwards; the
	/// entropy stack-residue regression test pins this.
	pub fn generate_new(seed: &mut SensitiveBytes32) -> WormholePair {
		let mut hashed_seed = hash_bytes(seed.as_bytes());
		let mut secret = SensitiveBytes32::new(&mut hashed_seed);
		seed.as_mut_bytes().zeroize();

		// Lend the secret rather than moving it (security review): a
		// by-value argument copies the wrapper into the callee's frame and
		// leaves this local's slot dead but never dropped, beyond
		// `ZeroizeOnDrop`. The callee swaps the secret into the returned
		// pair, so `secret` holds zeros when this frame drops (pinned by the
		// release-mode `wormhole_stack_zeroization` probe).
		WormholePair::generate_pair_from_secret(&mut secret)
	}

	/// The deterministic Poseidon-derived address (public data).
	pub fn address(&self) -> &[u8; 32] {
		&self.address
	}

	/// The single hash of the salted preimage. This is a reveal value used
	/// when proving, not public data — borrowed so a copy is an explicit
	/// `*` at the call site.
	pub fn first_hash(&self) -> &[u8; 32] {
		&self.first_hash
	}

	/// Borrow the secret; the pair keeps ownership (and wipes it on drop).
	pub fn secret(&self) -> &SensitiveBytes32 {
		&self.secret
	}

	// There is deliberately no `verify(address, secret)` helper (security
	// review): it took the secret by value (a move that leaves a dead,
	// never-dropped stack copy of the wrapper) and no consumer used it —
	// verification is re-derivation plus an address comparison, which
	// callers that hold the secret can do directly.

	/// Internal function that generates a `WormholePair` from a given secret.
	///
	/// This function performs a secondary Poseidon hash over the salt + hashed secret
	/// to derive the wormhole address.
	///
	/// # Security Note
	/// The secret never leaves its [`SensitiveBytes32`] wrapper (security
	/// review): it is borrowed for the felt encoding and then *swapped* into
	/// the returned pair, leaving the caller's wrapper zeroed. The previous
	/// shape — take the wrapper by value, unwrap it with `into_bytes`, and
	/// re-wrap into a named `result` — left three dead stack copies of the
	/// secret (the moved-from parameter, the extracted plain array's source,
	/// and the moved-from `result`), all beyond `ZeroizeOnDrop`'s reach. The
	/// release-mode `wormhole_stack_zeroization` probe pins the fixed shape.
	fn generate_pair_from_secret(secret: &mut SensitiveBytes32) -> WormholePair {
		let salt_felt = string_to_felts(ADDRESS_SALT);
		// Encode the 32-byte secret as 4 felts via the 8-bytes/felt `bytes_to_digest_lossy`.
		// This encoding is non-injective (limbs ≥ the Goldilocks prime are reduced),
		// which is harmless here: a secret deterministically maps to one canonical
		// felt-tuple, and a collision would only alias the holder's own secret —
		// it cannot forge another user's address without their secret. The same
		// encoding is used when proving, so derivation stays consistent.
		let mut secret_felt = bytes_to_digest_lossy(secret.as_bytes());
		// Exact capacity: growing the vector after the secret felts are in it
		// would reallocate and free a block still holding the secret.
		let mut preimage_felts = Vec::with_capacity(salt_felt.len() + secret_felt.len());
		preimage_felts.extend_from_slice(&salt_felt);
		preimage_felts.extend_from_slice(&secret_felt);
		let inner_hash = hash_to_bytes(&preimage_felts);
		let second_hash = hash_twice(&preimage_felts);

		// Wipe the felt-encoded copies of the secret before their backing
		// memory is released: `clear()`/drop alone would hand the allocator a
		// block that still contains the secret limbs.
		zeroize_felts(&mut secret_felt);
		zeroize_felts(&mut preimage_felts);

		// Tail construction, with the secret swapped straight from the
		// caller's wrapper into the pair: no named local holds the pair (a
		// later return would leave a moved-from copy), and the caller's
		// wrapper is left zeroed rather than dead-with-plaintext.
		WormholePair {
			address: second_hash,
			first_hash: inner_hash,
			secret: core::mem::replace(secret, SensitiveBytes32::zeroed()),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use hex_literal::hex;
	use qp_poseidon_core::serialization::{bytes_to_digest_lossy, bytes_to_felts};

	#[test]
	fn test_generate_pair_from_secret() {
		// Arrange
		let mut secret = [42u8; 32];

		// Act
		let pair = WormholePair::generate_pair_from_secret(&mut (&mut secret).into());

		// Assert secret was zeroized and pair.secret was not zeroized
		assert_eq!(secret, [0u8; 32]);
		assert_eq!(pair.secret.as_bytes(), &[42u8; 32]);

		// We can't easily predict the exact hash output without mocking Poseidon2Core,
		// but we can verify that it's not zero and that it's deterministic
		assert_ne!(pair.first_hash, [0u8; 32]);
		assert_ne!(pair.address, [0u8; 32]);

		// Verify determinism
		let mut secret2 = [42u8; 32];
		let pair2 = WormholePair::generate_pair_from_secret(&mut (&mut secret2).into());
		assert_eq!(pair.address, pair2.address);
	}

	/// Verification is re-derivation: the same secret must reproduce the
	/// address, and a different secret must not.
	#[test]
	fn test_rederivation_verifies_secret() {
		let mut secret = [1u8; 32];
		let pair = WormholePair::generate_pair_from_secret(&mut (&mut secret).into());

		let mut same_secret = [1u8; 32];
		let rederived = WormholePair::generate_pair_from_secret(&mut (&mut same_secret).into());
		assert_eq!(pair.address, rederived.address);

		let mut wrong_secret = [2u8; 32];
		let mismatched = WormholePair::generate_pair_from_secret(&mut (&mut wrong_secret).into());
		assert_ne!(pair.address, mismatched.address);
	}

	#[test]
	fn test_address_derivation_properties() {
		// Arrange
		let secret = hex!("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
		let secret_felts = bytes_to_digest_lossy(&secret);

		// Act - Generate the pair
		let mut secret_copy = secret;
		let pair = WormholePair::generate_pair_from_secret(&mut (&mut secret_copy).into());

		// Assert
		// 1. Verify that the secret is stored correctly
		assert_eq!(pair.secret.as_bytes(), &secret);

		// 2. Verify that re-deriving from the same secret reproduces the address
		let mut secret_for_verify = secret;
		let rederived =
			WormholePair::generate_pair_from_secret(&mut (&mut secret_for_verify).into());
		assert_eq!(pair.address, rederived.address);

		// 3. Verify that even a small change in the secret produces a different address
		let mut altered_secret = secret;
		altered_secret[0] ^= 1; // Flip one bit in the first byte
		let altered_pair =
			WormholePair::generate_pair_from_secret(&mut (&mut altered_secret).into());
		assert_ne!(pair.address, altered_pair.address);

		// 4. Verify that the process uses the salt
		// (Create a direct hash without salt and ensure it's different)
		let double_hash = hash_twice(&secret_felts);
		assert_ne!(pair.address, double_hash);

		// 5. Verify that each stage of the hash process changes the result
		// (Create a hash with salt but without the second hashing step)
		let address_salt_felts = string_to_felts(ADDRESS_SALT);
		let mut combined_felts = Vec::with_capacity(address_salt_felts.len() + secret_felts.len());
		combined_felts.extend_from_slice(address_salt_felts.as_ref());
		combined_felts.extend_from_slice(&secret_felts);
		let first_hash = hash_to_bytes(&combined_felts);
		assert_ne!(pair.address, first_hash);
	}

	#[test]
	fn test_different_secrets_produce_different_addresses() {
		// Arrange
		let mut secret1 = [5u8; 32];
		let mut secret2 = [6u8; 32];

		// Act
		let pair1 = WormholePair::generate_pair_from_secret(&mut (&mut secret1).into());
		let pair2 = WormholePair::generate_pair_from_secret(&mut (&mut secret2).into());

		// Assert
		assert_ne!(pair1.address, pair2.address);
	}

	#[test]
	fn test_generate_new_produces_valid_pair() {
		let mut seed = [55u8; 32];
		// Act
		let pair = WormholePair::generate_new(&mut (&mut seed).into());

		// The secret should not be all zeros
		assert_ne!(pair.secret.as_bytes(), &[0u8; 32]);

		// Address should not be zero
		assert_ne!(pair.address, [0u8; 32]);

		// Re-deriving from the stored secret must reproduce the address
		let mut secret_for_verify = *pair.secret.as_bytes();
		let rederived =
			WormholePair::generate_pair_from_secret(&mut (&mut secret_for_verify).into());
		assert_eq!(pair.address, rederived.address);
	}

	/// Pins the semantics of the constant-time `PartialEq` (security review):
	/// equality must hold exactly when all three fields match, including a
	/// difference in *any single* field — the non-short-circuiting fold must
	/// not drop any comparison.
	#[test]
	fn test_pair_equality_covers_every_field() {
		let make_pair = |address: [u8; 32], first_hash: [u8; 32], secret: [u8; 32]| {
			let mut secret = secret;
			WormholePair { address, first_hash, secret: SensitiveBytes32::new(&mut secret) }
		};

		// `WormholePair` has no `Debug` (it would print the secret), so plain
		// `assert!` is used instead of `assert_eq!`/`assert_ne!`.
		let base = make_pair([1u8; 32], [2u8; 32], [3u8; 32]);
		assert!(base == make_pair([1u8; 32], [2u8; 32], [3u8; 32]));

		assert!(base != make_pair([9u8; 32], [2u8; 32], [3u8; 32]), "address ignored by eq");
		assert!(base != make_pair([1u8; 32], [9u8; 32], [3u8; 32]), "first_hash ignored by eq");
		assert!(base != make_pair([1u8; 32], [2u8; 32], [9u8; 32]), "secret ignored by eq");

		// A difference in only the last byte of the secret must be detected:
		// a truncated comparison would miss it.
		let mut tail_diff = [3u8; 32];
		tail_diff[31] ^= 1;
		assert!(base != make_pair([1u8; 32], [2u8; 32], tail_diff));

		// Pairs derived from the same secret compare equal end-to-end.
		let mut s1 = [42u8; 32];
		let mut s2 = [42u8; 32];
		let p1 = WormholePair::generate_pair_from_secret(&mut (&mut s1).into());
		let p2 = WormholePair::generate_pair_from_secret(&mut (&mut s2).into());
		assert!(p1 == p2);
	}

	#[test]
	fn test_salt_is_used_in_address_generation() {
		// This test verifies that the salt affects the generated address

		// Arrange
		let secret = [7u8; 32];

		let secret_felts = bytes_to_digest_lossy(&secret);

		// Generate a pair normally (with salt)
		let mut secret_copy = secret;
		let pair_with_salt =
			WormholePair::generate_pair_from_secret(&mut (&mut secret_copy).into());

		// Simulate address generation without salt or with different salt
		let different_salt = b"diffrent";
		let different_salt_felts = bytes_to_felts(different_salt);

		let mut combined_felts =
			Vec::with_capacity(different_salt_felts.len() + secret_felts.len());
		combined_felts.extend_from_slice(&different_salt_felts);
		combined_felts.extend_from_slice(&secret_felts);

		let address_with_different_salt = hash_twice(&combined_felts);

		// Assert
		assert_ne!(pair_with_salt.address, address_with_different_salt);
	}
}
