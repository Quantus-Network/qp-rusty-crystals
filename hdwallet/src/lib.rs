#![no_std]
extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use alloc::string::String;
use alloc::string::ToString;
use bip39::{Language, Mnemonic};
use nam_tiny_hderive::{bip32::ExtendedPrivKey, Error};
use qp_rusty_crystals_dilithium::ml_dsa_87::Keypair;
use rand_chacha::{
	rand_core::{RngCore as ChaChaCore, SeedableRng},
	ChaCha20Rng,
};
use core::str::FromStr;

#[cfg(test)]
mod test_vectors;
#[cfg(test)]
mod tests;

pub mod wormhole;

pub use wormhole::{WormholeError, WormholePair};

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
	#[error("nam-tinyhderive error")]
	GenericError(Error),
}

/// Manages entropy generation for HD wallets
pub struct HDLattice {
	pub seed: [u8; 64],
	pub master_key: [u8; 32],
}

pub const ROOT_PATH: &str = "m";
pub const PURPOSE: &str = "44'";
pub const QUANTUS_DILITHIUM_CHAIN_ID: &str = "189189'";
pub const QUANTUS_WORMHOLE_CHAIN_ID: &str = "189189189'";

impl HDLattice {
	/// Create new HDEntropy from a master seed
	// #[tarpaulin::skip] // tarpaulin fails - this is covered.
	pub fn from_seed(seed: [u8; 64]) -> Result<Self, HDLatticeError> {
		Ok(Self { seed, master_key: Self::master_key_from_seed(&seed)? })
	}

	/// Create new HDLattice from a BIP39 mnemonic phrase
	pub fn from_mnemonic(phrase: &str, passphrase: Option<&str>) -> Result<Self, HDLatticeError> {
		// Parse the mnemonic
		let mnemonic = Mnemonic::parse_in_normalized(Language::English, phrase)
			.map_err(|e| HDLatticeError::Bip39Error(e.to_string()))?;

		// Generate seed from mnemonic
		let seed: [u8; 64] = mnemonic.to_seed_normalized(passphrase.unwrap_or(""));

		Ok(Self { seed, master_key: Self::master_key_from_seed(&seed)? })
	}

	pub fn master_key_from_seed(seed: &[u8; 64]) -> Result<[u8; 32], HDLatticeError> {
		let ext = ExtendedPrivKey::derive(seed, "m").unwrap();

		Ok(ext.secret())
	}

	pub fn generate_keys(&self) -> Keypair {
		Keypair::generate(Some(&self.seed))
	}

	pub fn generate_derived_keys(&self, path: &str) -> Result<Keypair, HDLatticeError> {
		let derived_entropy = self.derive_entropy(path)?;
		Ok(Keypair::generate(Some(&derived_entropy)))
	}

	pub fn check_path(&self, path: &str) -> Result<(), HDLatticeError> {
		let p = nam_tiny_hderive::bip44::DerivationPath::from_str(path)
			.map_err(HDLatticeError::GenericError)?;
		for element in p.iter() {
			if !element.is_hardened() {
				return Err(HDLatticeError::HardenedPathsOnly())
			}
		}
		Ok(())
	}

	/// Derives entropy from a seed along a given path
	pub fn derive_entropy(&self, path: &str) -> Result<[u8; 32], HDLatticeError> {
		self.check_path(path)?;
		let xpriv = ExtendedPrivKey::derive(&self.seed, path)
			.map_err(|_e| HDLatticeError::KeyDerivationFailed(path.to_string()))?;
		Ok(xpriv.secret())
	}

	/// Generates a wormhole pair from the current entropy state
	pub fn generate_wormhole_pair(&self) -> Result<WormholePair, HDLatticeError> {
		Ok(WormholePair::generate_pair_from_secret(&self.master_key))
	}

	/// Generates a wormhole pair from a specific path
	pub fn generate_wormhole_pair_from_path(
		&self,
		path: &str,
	) -> Result<WormholePair, HDLatticeError> {
		if path.split("/").nth(2) != Some(QUANTUS_WORMHOLE_CHAIN_ID) {
			return Err(HDLatticeError::InvalidWormholePath(path.to_string()))
		}
		let entropy = self.derive_entropy(path)?;
		Ok(WormholePair::generate_pair_from_secret(&entropy))
	}
}

/// Generate a new random mnemonic of the specified word count
pub fn generate_mnemonic(word_count: usize, seed: [u8; 32]) -> Result<String, HDLatticeError> {
	// Calculate entropy bytes needed (12 words = 16 bytes, 24 words = 32 bytes)
	let bits = match word_count {
		12 => 128,
		15 => 160,
		18 => 192,
		21 => 224,
		24 => 256,
		_ => return Err(HDLatticeError::BadEntropyBitCount(word_count)),
	};

	let entropy_bytes = bits / 8;

	// Use seed to initiate chacha stream and fill it
	// NOTE: chacha will "whiten" the entropy provided by the os
	// if an attacker does not 100% control the os entropy, chacha
	// will provide full entropy, due to avalanche effects
	let mut chacha_rng = ChaCha20Rng::from_seed(seed);

	let mut entropy = vec![0u8; entropy_bytes];
	chacha_rng.fill_bytes(&mut entropy);

	// Create mnemonic from entropy
	let mnemonic = Mnemonic::from_entropy(&entropy)
		.map_err(|e| HDLatticeError::MnemonicDerivationFailed(e.to_string()))?;

	Ok(mnemonic.words().collect::<Vec<&str>>().join(" "))
}
