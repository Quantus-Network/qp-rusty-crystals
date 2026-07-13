//! # Quantus Network HD Wallet
//!
//! This crate provides hierarchical deterministic (HD) wallet functionality for post-quantum
//! ML-DSA (Dilithium) keys, compatible
#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

use crate::hderive::ExtendedPrivKey;
use alloc::{
	string::{String, ToString},
	vec::Vec,
};
use bip39::{Language, Mnemonic};
use core::str::FromStr;
use qp_rusty_crystals_dilithium::ml_dsa_87::Keypair;
use unicode_normalization::{is_nfkd_quick, IsNormalized, UnicodeNormalization};

use zeroize::Zeroizing;

#[cfg(test)]
mod test_vectors;
#[cfg(test)]
mod tests;

pub mod hderive;
pub mod wormhole;

pub use wormhole::WormholePair;

// Import and re-export SensitiveBytes types from dilithium
pub use qp_rusty_crystals_dilithium::{SensitiveBytes32, SensitiveBytes64};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum HDLatticeError {
	#[error("BIP39 error: {0}")]
	Bip39Error(String),
	#[error("Key derivation failed: {0}")]
	KeyDerivationFailed(String),
	#[error("Bad entropy bit count: {0}")]
	BadEntropyBitCount(usize),
	#[error("Mnemonic derivation failed: {0}")]
	MnemonicDerivationFailed(String),
	#[error("Invalid wormhole path: {0}")]
	InvalidWormholePath(String),
	#[error("Invalid BIP44 path: {0}")]
	InvalidPath(String),
	#[error("Derivation path too long: {0} bytes")]
	PathTooLong(usize),
	#[error("Derivation path too deep: {0} segments")]
	PathTooDeep(usize),
	#[error("Mnemonic too long: {0} bytes")]
	MnemonicTooLong(usize),
	#[error("Passphrase too long: {0} bytes")]
	PassphraseTooLong(usize),
	#[error("hderive error: {0:?}")]
	GenericError(hderive::Error),
}

pub const ROOT_PATH: &str = "m";
pub const PURPOSE: &str = "44'";
pub const QUANTUS_DILITHIUM_CHAIN_ID: &str = "189189'";
pub const QUANTUS_WORMHOLE_CHAIN_ID: &str = "189189189'";

/// Maximum number of `/`-separated segments allowed in a derivation path
/// (counts the leading `m/` separator too, so legitimate BIP44 paths sit well below).
/// Bounded to prevent DoS via attacker-controlled deep paths.
pub const MAX_DERIVATION_DEPTH: usize = 16;

/// Maximum raw byte length of an accepted derivation path string.
/// Sized for 16 segments of up to ~14 chars plus the `m/` prefix.
pub const MAX_DERIVATION_PATH_BYTES: usize = 256;

/// Maximum raw byte length of an accepted mnemonic string.
/// The longest valid BIP39 English phrase (24 words of 8 chars plus separators)
/// is ~215 bytes; 1 KiB leaves ample headroom (e.g. exotic whitespace, decomposed
/// Unicode) while bounding the normalization and parsing work an attacker can force.
pub const MAX_MNEMONIC_BYTES: usize = 1024;

/// Maximum raw byte length of an accepted passphrase string.
/// BIP39 places no limit on passphrases, but normalization allocates a full
/// copy and PBKDF2 absorbs the passphrase into its salt, so an unbounded
/// passphrase is a CPU/memory DoS vector. 1 KiB far exceeds any realistic use.
pub const MAX_PASSPHRASE_BYTES: usize = 1024;

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
	mnemonic: String,
	passphrase: Option<&str>,
) -> Result<[u8; 64], HDLatticeError> {
	// Drop guard: zeroizes the mnemonic on every exit path (success, parse error, unwind).
	let mnemonic = Zeroizing::new(mnemonic);
	parse_mnemonic_to_seed(mnemonic.as_str(), passphrase)
}

/// NFKD-normalize a potentially secret string. Returns `None` when the input is already
/// normalized (the common all-ASCII case), so no extra heap copy of the secret is made.
/// When a normalized copy is required it is wrapped in `Zeroizing` so it is wiped on drop.
fn nfkd_owned(s: &str) -> Option<Zeroizing<String>> {
	match is_nfkd_quick(s.chars()) {
		IsNormalized::Yes => None,
		// `Maybe` is treated as not-normalized; NFKD is idempotent, so re-normalizing is safe.
		_ => Some(Zeroizing::new(s.nfkd().collect())),
	}
}

/// Shared parser that does not take ownership of the mnemonic.
/// Used by both `mnemonic_to_seed` (which owns and zeroizes the String) and the
/// `derive_*_from_mnemonic` helpers (which borrow the caller's `&str` and avoid
/// the redundant heap copy a `to_string()` would create).
///
/// BIP39 requires NFKD Unicode normalization of both the mnemonic and the passphrase
/// before PBKDF2. The bip39 crate's `parse_in_normalized`/`to_seed_normalized` APIs
/// assume the *caller* already normalized their inputs, so we normalize here. Without
/// this, canonically equivalent inputs (e.g. a composed "é" vs a decomposed "e"+combining
/// accent in a passphrase) would silently derive different seeds and thus different keys.
///
/// Both inputs are size-capped ([`MAX_MNEMONIC_BYTES`], [`MAX_PASSPHRASE_BYTES`])
/// *before* normalization, so attacker-controlled text cannot drive unbounded
/// allocation, normalization scans, or PBKDF2 work prior to rejection.
fn parse_mnemonic_to_seed(
	mnemonic: &str,
	passphrase: Option<&str>,
) -> Result<[u8; 64], HDLatticeError> {
	if mnemonic.len() > MAX_MNEMONIC_BYTES {
		return Err(HDLatticeError::MnemonicTooLong(mnemonic.len()));
	}
	if let Some(p) = passphrase {
		if p.len() > MAX_PASSPHRASE_BYTES {
			return Err(HDLatticeError::PassphraseTooLong(p.len()));
		}
	}

	let normalized_mnemonic = nfkd_owned(mnemonic);
	let mnemonic = normalized_mnemonic.as_ref().map_or(mnemonic, |m| m.as_str());

	let passphrase = passphrase.unwrap_or("");
	let normalized_passphrase = nfkd_owned(passphrase);
	let passphrase = normalized_passphrase.as_ref().map_or(passphrase, |p| p.as_str());

	let parsed_mnemonic = Mnemonic::parse_in_normalized(Language::English, mnemonic)
		.map_err(|e| HDLatticeError::Bip39Error(e.to_string()))?;
	Ok(parsed_mnemonic.to_seed_normalized(passphrase))
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

/// Keypair derivation from mnemonic with passphrase.
///
/// # Security Note
/// Takes the mnemonic by reference and does not copy it into a heap buffer,
/// avoiding a redundant duplicate of the secret. The caller retains ownership
/// of the `&str` and is responsible for zeroizing the source buffer itself.
pub fn derive_key_from_mnemonic(
	mnemonic: &str,
	passphrase: Option<&str>,
	path: &str,
) -> Result<Keypair, HDLatticeError> {
	let mut seed = parse_mnemonic_to_seed(mnemonic, passphrase)?;
	derive_key_from_seed(SensitiveBytes64::from(&mut seed), path)
}

/// Wormhole pair derivation from mnemonic with passphrase.
///
/// # Security Note
/// Takes the mnemonic by reference and does not copy it into a heap buffer,
/// avoiding a redundant duplicate of the secret. The caller retains ownership
/// of the `&str` and is responsible for zeroizing the source buffer itself.
pub fn derive_wormhole_from_mnemonic(
	mnemonic: &str,
	passphrase: Option<&str>,
	path: &str,
) -> Result<WormholePair, HDLatticeError> {
	let mut seed = parse_mnemonic_to_seed(mnemonic, passphrase)?;
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
	check_derivation_path(path)?;

	if path.split("/").nth(2) != Some(QUANTUS_WORMHOLE_CHAIN_ID) {
		return Err(HDLatticeError::InvalidWormholePath(path.to_string()));
	}

	// Derive entropy at the specified path
	let xpriv = ExtendedPrivKey::derive(seed.as_bytes(), path)
		.map_err(|_e| HDLatticeError::KeyDerivationFailed(path.to_string()))?;
	let mut secret = xpriv.secret();
	let derived_entropy = SensitiveBytes32::from(&mut secret);

	// Generate wormhole pair
	let wormhole_pair = WormholePair::generate_new(derived_entropy);

	// seed and derived_entropy are automatically zeroized when they drop

	Ok(wormhole_pair)
}

/// Validate a derivation path — bounds first, then hardened-only syntax via parsing.
fn check_derivation_path(path: &str) -> Result<(), HDLatticeError> {
	crate::hderive::DerivationPath::from_str(path).map_err(|e| match e {
		hderive::Error::PathTooLong(n) => HDLatticeError::PathTooLong(n),
		hderive::Error::PathTooDeep(n) => HDLatticeError::PathTooDeep(n),
		other => HDLatticeError::GenericError(other),
	})?;
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

	let result = mnemonic.words().collect::<Vec<&str>>().join(" ");

	// entropy is automatically zeroized when it drops

	Ok(result)
}
