//! # Quantus Network HD Wallet
//!
//! This crate provides hierarchical deterministic (HD) wallet functionality for post-quantum
//! ML-DSA (Dilithium) keys, compatible
#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use bip39::{Language, Mnemonic};
use core::str::FromStr;
use crate::hderive::ExtendedPrivKey;
use qp_rusty_crystals_dilithium::ml_dsa_87::Keypair;

use zeroize::Zeroize;

#[cfg(test)]
mod test_vectors;
#[cfg(test)]
mod tests;

pub mod wormhole;
pub mod hderive;

pub use wormhole::{WormholeError, WormholePair};

// Import and re-export SensitiveBytes types from dilithium
pub use qp_rusty_crystals_dilithium::{SensitiveBytes32, SensitiveBytes64};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum HDLatticeError {
	#[error("BIP39 error: {0}")]
	Bip39Error(String),
	#[error("Key derivation failed: {0}")]
	KeyDerivationFailed(String),
	#[error("Non-hardened keys not supported because lattice")]
	HardenedPathsOnly(),
	#[error("Bad entropy bit count: {0}")]
	BadEntropyBitCount(usize),
	#[error("Mnemonic derivation failed: {0}")]
	MnemonicDerivationFailed(String),
	#[error("Invalid wormhole path: {0}")]
	InvalidWormholePath(String),
	#[error("Invalid BIP44 path: {0}")]
	InvalidPath(String),
	#[error("hderive error: {0:?}")]
	GenericError(hderive::Error),
}

pub const ROOT_PATH: &str = "m";
pub const PURPOSE: &str = "44'";
pub const QUANTUS_DILITHIUM_CHAIN_ID: &str = "189189'";
pub const QUANTUS_WORMHOLE_CHAIN_ID: &str = "189189189'";

/// Convert a BIP39 mnemonic phrase to a seed
///
/// This function takes ownership of the mnemonic string for security.
/// Users must explicitly choose to move or copy their mnemonic:
///
/// ```rust
/// use qp_rusty_crystals_hdwallet::mnemonic_to_seed;
/// let mnemonic = "word word word...".to_string();
///
/// // Move the mnemonic (recommended for single use)
/// let seed = mnemonic_to_seed(mnemonic, None);
/// // mnemonic is now consumed and zeroized
///
/// // Or explicitly copy for multiple uses
/// let mnemonic = "word word word...".to_string();
/// let seed1 = mnemonic_to_seed(mnemonic.clone(), None);
/// let seed2 = mnemonic_to_seed(mnemonic, None); // consumes original
/// ```
///
/// # Security Note
/// This function performs expensive PBKDF2 key stretching (2048 iterations).
/// The mnemonic string is zeroized before returning.
/// The returned seed contains sensitive cryptographic material and should be
/// zeroized when no longer needed.
pub fn mnemonic_to_seed(
	mut mnemonic: String,
	passphrase: Option<&str>,
) -> Result<[u8; 64], HDLatticeError> {
	// Parse the mnemonic
	let parsed_mnemonic = Mnemonic::parse_in_normalized(Language::English, &mnemonic)
		.map_err(|e| HDLatticeError::Bip39Error(e.to_string()))?;

	// Generate seed from mnemonic (expensive PBKDF2 operation)
	let seed: [u8; 64] = parsed_mnemonic.to_seed_normalized(passphrase.unwrap_or(""));

	// Zeroize the mnemonic string
	mnemonic.zeroize();

	Ok(seed)
}

/// Derive a Dilithium keypair from a seed at the given BIP44 path
///
/// # Security Note
/// This function takes ownership of the seed for security (move semantics).
/// The seed parameter is zeroized before returning.
pub fn derive_key_from_seed(seed: SensitiveBytes64, path: &str) -> Result<Keypair, HDLatticeError> {
	// Validate the derivation path
	check_derivation_path(path)?;

	// Derive entropy at the specified path
	let xpriv = ExtendedPrivKey::derive(seed.as_bytes(), path)
		.map_err(|_e| HDLatticeError::KeyDerivationFailed(path.to_string()))?;
	let mut secret = xpriv.secret();
	let derived_entropy = SensitiveBytes32::from(&mut secret);

	// Generate keypair from derived entropy
	let keypair = Keypair::generate(derived_entropy);

	// seed and derived_entropy are automatically zeroized when they drop

	Ok(keypair)
}

/// Keypair derivation from mnemonic with passphrase
pub fn derive_key_from_mnemonic(mnemonic: &str, passphrase: Option<&str>, path: &str) -> Result<Keypair, HDLatticeError> {
	let mut seed = mnemonic_to_seed(mnemonic.to_string(), passphrase)?;
	derive_key_from_seed(SensitiveBytes64::from(&mut seed), path)
}

/// Wormhole pair derivation from mnemonic with passphrase
pub fn derive_wormhole_from_mnemonic(mnemonic: &str, passphrase: Option<&str>, path: &str) -> Result<WormholePair, HDLatticeError> {
	let mut seed = mnemonic_to_seed(mnemonic.to_string(), passphrase)?;
	generate_wormhole_from_seed(SensitiveBytes64::from(&mut seed), path)
}

/// Generate a wormhole pair from a seed at the given path
///
/// # Security Note
/// This function takes ownership of the seed for security (move semantics).
/// The seed parameter is zeroized before returning.
pub fn generate_wormhole_from_seed(
	seed: SensitiveBytes64,
	path: &str,
) -> Result<WormholePair, HDLatticeError> {
	// Validate wormhole path
	if path.split("/").nth(2) != Some(QUANTUS_WORMHOLE_CHAIN_ID) {
		return Err(HDLatticeError::InvalidWormholePath(path.to_string()));
	}

	// Validate the derivation path
	check_derivation_path(path)?;

	// Derive entropy at the specified path
	let xpriv = ExtendedPrivKey::derive(seed.as_bytes(), path)
		.map_err(|_e| HDLatticeError::KeyDerivationFailed(path.to_string()))?;
	let mut secret = xpriv.secret();
	let derived_entropy = SensitiveBytes32::from(&mut secret);

	// Generate wormhole pair
	let wormhole_pair = WormholePair::generate_pair_from_secret(derived_entropy);

	// seed and derived_entropy are automatically zeroized when they drop

	Ok(wormhole_pair)
}

/// Validate a BIP44 derivation path
///
/// Enforces hardened derivation for all indices
/// In quantus_v1 feature, allows the last 2 indices to be non-hardened.
fn check_derivation_path(path: &str) -> Result<(), HDLatticeError> {
	let p = crate::hderive::DerivationPath::from_str(path)
		.map_err(HDLatticeError::GenericError)?;

	#[cfg(feature = "quantus_v1")]
	let hardened_check_count = p.iter().count().saturating_sub(2);
	#[cfg(not(feature = "quantus_v1"))]
	let hardened_check_count = p.iter().count();

	let mut index = 0;
	for element in p.iter() {
		// In quantus_v1, skip hardened check for the last 2 elements
		if index < hardened_check_count && !element.is_hardened() {
			return Err(HDLatticeError::HardenedPathsOnly());
		}
		index += 1;
	}
	Ok(())
}

/// Generate a new random mnemonic with 24 words = 32 bytes
///
/// This function takes ownership of the entropy for security (move semantics).
/// The entropy parameter is zeroized before returning.
///
/// # Security Note
/// Always use cryptographically secure random entropy (e.g., from `getrandom::getrandom()`).
/// Never use predictable strings, timestamps, or user input as entropy sources.
pub fn generate_mnemonic(entropy: SensitiveBytes32) -> Result<String, HDLatticeError> {
	// Create mnemonic from entropy
	let mnemonic = Mnemonic::from_entropy(entropy.as_bytes())
		.map_err(|e| HDLatticeError::MnemonicDerivationFailed(e.to_string()))?;

	let result = mnemonic.word_iter().collect::<Vec<&str>>().join(" ");

	// entropy is automatically zeroized when it drops

	Ok(result)
}
