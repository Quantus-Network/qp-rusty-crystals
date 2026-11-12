//! # Quantus Network HD Wallet
//!
//! This crate provides hierarchical deterministic (HD) wallet functionality for post-quantum
//! ML-DSA (Dilithium) keys.
//!
//! ## Parameter sets
//!
//! ML-DSA parameter sets are selected with additive cargo features
//! (`ml-dsa-44`, `ml-dsa-65`, `ml-dsa-87`; default: `ml-dsa-87`). Unlike the
//! threshold crate, the features are not mutually prioritized: enabling
//! several exposes one key-derivation module per variant ([`ml_dsa_44`],
//! [`ml_dsa_65`], [`ml_dsa_87`]) so a wallet can hold keys at multiple
//! security levels. The top-level [`derive_key_from_seed`] /
//! [`derive_key_from_mnemonic`] functions remain the original ML-DSA-87 API.
//!
//! Deriving keys for different parameter sets from the *same* derivation path
//! is cryptographically sound: FIPS 204 key generation absorbs the parameter
//! set's `(k, ℓ)` into the seed expansion (`H(seed || k || ℓ)`), so the same
//! 32 bytes of path-derived entropy yield independent keys per variant.
//!
//! Mnemonic handling and the wormhole module are parameter-set independent
//! and available regardless of which (if any) ML-DSA features are enabled.
#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

use crate::hderive::ExtendedPrivKey;
use alloc::{
	string::{String, ToString},
	vec::Vec,
};
use core::str::FromStr;
#[cfg(feature = "ml-dsa-87")]
use qp_rusty_crystals_dilithium::ml_dsa_87::Keypair;
use unicode_normalization::{is_nfkd_quick, IsNormalized, UnicodeNormalization};

use zeroize::{Zeroize, Zeroizing};

// The historical test suite and its vendored vectors are ML-DSA-87 keys.
#[cfg(all(test, feature = "ml-dsa-87"))]
mod test_vectors;
#[cfg(all(test, feature = "ml-dsa-44"))]
mod test_vectors_44;
#[cfg(all(test, feature = "ml-dsa-65"))]
mod test_vectors_65;
#[cfg(all(test, feature = "ml-dsa-87"))]
mod tests;
#[cfg(test)]
mod tests_variants;

pub mod hderive;
pub mod mnemonic;
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

/// Convert a BIP39 mnemonic phrase to a seed, writing it into the
/// caller-provided self-zeroizing [`SensitiveBytes64`].
///
/// This function takes ownership of the mnemonic string for security.
/// Users must explicitly choose to move or copy their mnemonic:
///
/// ```rust
/// use qp_rusty_crystals_hdwallet::{mnemonic_to_seed, SensitiveBytes64};
/// let mnemonic = "legal winner thank year wave sausage worth useful legal winner thank yellow".to_string();
///
/// // Move the mnemonic (recommended for single use)
/// let mut seed = SensitiveBytes64::zeroed();
/// mnemonic_to_seed(mnemonic, None, &mut seed).unwrap();
/// // mnemonic is now consumed and zeroized; seed wipes itself on drop
/// ```
///
/// # Security Note
/// This function performs expensive PBKDF2 key stretching (2048 iterations).
/// The mnemonic string is zeroized before returning.
///
/// The seed is written in place into the caller's [`SensitiveBytes64`]
/// rather than returned by value (security review). A raw `[u8; 64]` return
/// would require every caller to remember to wipe a complete BIP39 seed
/// manually — and even a self-zeroizing return value would be *moved* out,
/// and Rust moves are copies that leave the moved-from stack slot dead and
/// unwiped (`ZeroizeOnDrop` only wipes the value's final resting place).
/// With an out-parameter the secret only ever exists inside the caller's
/// wiping guard; the stack-residue regression test pins this.
///
/// On error, `seed_out` is untouched.
pub fn mnemonic_to_seed(
	mnemonic: String,
	passphrase: Option<&str>,
	seed_out: &mut SensitiveBytes64,
) -> Result<(), HDLatticeError> {
	// Drop guard: zeroizes the mnemonic on every exit path (success, parse
	// error, unwind).
	let mnemonic = Zeroizing::new(mnemonic);
	parse_mnemonic_to_seed_into(mnemonic.as_str(), passphrase, seed_out.as_mut_bytes())
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
/// before PBKDF2. Without this, canonically equivalent inputs (e.g. a composed "é" vs a
/// decomposed "e"+combining accent in a passphrase) would silently derive different seeds
/// and thus different keys.
///
/// Both inputs are size-capped ([`MAX_MNEMONIC_BYTES`], [`MAX_PASSPHRASE_BYTES`])
/// *before* normalization, so attacker-controlled text cannot drive unbounded
/// allocation, normalization scans, or PBKDF2 work prior to rejection.
///
/// The stretched seed is written through `seed_out` rather than returned by
/// value: a by-value seed would be moved (i.e. copied) across function
/// boundaries, leaving unwiped copies in dead stack slots. Callers pass the
/// interior of a self-zeroizing `SensitiveBytes64`, so the seed only ever
/// lives inside a wiping guard. On error, `seed_out` is untouched.
fn parse_mnemonic_to_seed_into(
	mnemonic: &str,
	passphrase: Option<&str>,
	seed_out: &mut [u8; 64],
) -> Result<(), HDLatticeError> {
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

	mnemonic::validate(mnemonic).map_err(|e| HDLatticeError::Bip39Error(e.to_string()))?;

	// The PBKDF2 password is the canonical phrase: the validated words joined
	// by single spaces. Seed stretching is done in-crate so that the seed is
	// only ever written into the caller's wiping buffer.
	let password = mnemonic::canonical_phrase(mnemonic);

	hderive::pbkdf2_hmac_sha512(
		password.as_bytes(),
		&[b"mnemonic", passphrase.as_bytes()],
		2048,
		seed_out,
	);
	Ok(())
}

/// Derive the 32 bytes of keypair entropy at the given BIP44 path, writing
/// them into the caller-provided `out`.
///
/// This is the parameter-set-independent half of key derivation: path
/// validation plus HMAC-SHA512 tree derivation. The derived entropy is what
/// each variant's `Keypair::generate` consumes (FIPS 204 domain-separates the
/// subsequent seed expansion by `(k, ℓ)`, so feeding the same entropy to
/// different parameter sets yields independent keys).
///
/// The entropy is written in place rather than returned by value (security
/// review): a by-value return is moved — i.e. copied — through dead stack
/// slots that are never dropped, so `ZeroizeOnDrop` could not wipe them.
/// On error, `out` is untouched.
fn derive_entropy_from_seed(
	seed: &SensitiveBytes64,
	path: &str,
	out: &mut SensitiveBytes32,
) -> Result<(), HDLatticeError> {
	// Validate the derivation path
	check_derivation_path(path)?;

	// Derive entropy at the specified path
	let mut xpriv = ExtendedPrivKey::zeroed();
	ExtendedPrivKey::derive(seed.as_bytes(), path, &mut xpriv)
		.map_err(|_e| HDLatticeError::KeyDerivationFailed(path.to_string()))?;
	// Deliberate guarded copy: filled in place inside the caller's
	// self-zeroizing wrapper, so the secret never exists outside a wiping
	// guard (`xpriv` wipes its own storage when it drops below).
	out.as_mut_bytes().copy_from_slice(xpriv.secret().as_bytes());
	Ok(())
}

/// Stamp a per-variant key-derivation module mirroring the dilithium crate's
/// frontend layout. Each module exposes the variant's `Keypair` plus
/// `derive_key_from_seed` / `derive_key_from_mnemonic` with the same
/// contract as the top-level (ML-DSA-87) functions.
macro_rules! mldsa_variant_module {
	($mod_name:ident, $feature:literal, $doc_name:literal) => {
		#[cfg(feature = $feature)]
		#[doc = concat!("HD key derivation for ", $doc_name, ".")]
		pub mod $mod_name {
			pub use qp_rusty_crystals_dilithium::$mod_name::Keypair;

			use crate::{HDLatticeError, SensitiveBytes32, SensitiveBytes64};

			#[doc = concat!("Derive an ", $doc_name, " keypair from a seed at the given BIP44 path.")]
			///
			/// # Security Note
			/// The seed is borrowed, not consumed (security review): taking
			/// `SensitiveBytes64` by value moves it, and a move is a copy
			/// that leaves the caller's original stack slot dead but never
			/// dropped — outside the reach of `ZeroizeOnDrop`. Borrowing
			/// keeps the seed in the caller's self-zeroizing storage, which
			/// is wiped in place when the caller drops it (pinned by the
			/// seed stack-zeroization probe).
			///
			/// The keypair is written in place into the caller-provided
			/// `out` (start from [`Keypair::zeroed`]) rather than returned
			/// by value, for the same reason (security review): a
			/// `Result<Keypair, _>` return is moved out of a temporary that
			/// is never dropped, which left the complete packed secret key
			/// in dead stack memory (pinned by the keypair
			/// stack-zeroization probe). On error, `out` is untouched.
			pub fn derive_key_from_seed(
				seed: &SensitiveBytes64,
				path: &str,
				out: &mut Keypair,
			) -> Result<(), HDLatticeError> {
				// The entropy is filled in place and lent to `generate_into`,
				// which wipes it; it never crosses a boundary by value.
				let mut entropy = SensitiveBytes32::zeroed();
				crate::derive_entropy_from_seed(seed, path, &mut entropy)?;
				Keypair::generate_into(&mut entropy, out);
				Ok(())
			}

			#[doc = concat!("Derive an ", $doc_name, " keypair from a mnemonic with passphrase.")]
			///
			/// The derivation path is validated *before* BIP39 seed stretching, so a
			/// request that is guaranteed to fail path validation cannot force the
			/// expensive PBKDF2 work.
			///
			/// # Security Note
			/// Takes the mnemonic by reference and does not copy it into a heap buffer,
			/// avoiding a redundant duplicate of the secret. The caller retains ownership
			/// of the `&str` and is responsible for zeroizing the source buffer itself.
			///
			/// The keypair is written in place into the caller-provided
			/// `out`; see [`derive_key_from_seed`]. On error, `out` is
			/// untouched.
			pub fn derive_key_from_mnemonic(
				mnemonic: &str,
				passphrase: Option<&str>,
				path: &str,
				out: &mut Keypair,
			) -> Result<(), HDLatticeError> {
				crate::check_derivation_path(path)?;
				// The stretched seed is filled in place and lent to
				// `derive_key_from_seed`; moving it there by value left this
				// local's stack slot unwiped (pinned by the seed
				// stack-zeroization probe). It drops — and wipes — here.
				let mut seed = SensitiveBytes64::zeroed();
				crate::parse_mnemonic_to_seed_into(mnemonic, passphrase, seed.as_mut_bytes())?;
				derive_key_from_seed(&seed, path, out)
			}
		}
	};
}

mldsa_variant_module!(ml_dsa_44, "ml-dsa-44", "ML-DSA-44");
mldsa_variant_module!(ml_dsa_65, "ml-dsa-65", "ML-DSA-65");
mldsa_variant_module!(ml_dsa_87, "ml-dsa-87", "ML-DSA-87");

/// Derive a Dilithium (ML-DSA-87) keypair from a seed at the given BIP44 path
///
/// This is the original single-variant API and is equivalent to
/// [`ml_dsa_87::derive_key_from_seed`]; the per-variant modules cover the
/// other parameter sets.
///
/// # Security Note
/// The seed is borrowed, not consumed: a by-value `SensitiveBytes64` would
/// be moved — copied into the callee while the caller's original stack slot
/// stays dead and unwiped, outside the reach of `ZeroizeOnDrop`. The seed
/// stays in the caller's self-zeroizing storage and is wiped in place when
/// the caller drops it.
///
/// The keypair is likewise written in place into the caller-provided `out`
/// (start from [`Keypair::zeroed`]) rather than returned by value: the
/// temporary a `Result<Keypair, _>` is moved out of is never dropped, which
/// left the complete packed secret key in dead stack memory. On error, `out`
/// is untouched.
#[cfg(feature = "ml-dsa-87")]
pub fn derive_key_from_seed(
	seed: &SensitiveBytes64,
	path: &str,
	out: &mut Keypair,
) -> Result<(), HDLatticeError> {
	ml_dsa_87::derive_key_from_seed(seed, path, out)
}

/// Keypair (ML-DSA-87) derivation from mnemonic with passphrase.
///
/// Equivalent to [`ml_dsa_87::derive_key_from_mnemonic`]; the per-variant
/// modules cover the other parameter sets.
///
/// The derivation path is validated *before* BIP39 seed stretching, so a
/// request that is guaranteed to fail path validation cannot force the
/// expensive PBKDF2 work (the seed-based entrypoints reject bad paths before
/// any derivation; the mnemonic wrappers must not be a cheaper DoS target).
///
/// # Security Note
/// Takes the mnemonic by reference and does not copy it into a heap buffer,
/// avoiding a redundant duplicate of the secret. The caller retains ownership
/// of the `&str` and is responsible for zeroizing the source buffer itself.
///
/// The keypair is written in place into the caller-provided `out`; see
/// [`derive_key_from_seed`]. On error, `out` is untouched.
#[cfg(feature = "ml-dsa-87")]
pub fn derive_key_from_mnemonic(
	mnemonic: &str,
	passphrase: Option<&str>,
	path: &str,
	out: &mut Keypair,
) -> Result<(), HDLatticeError> {
	ml_dsa_87::derive_key_from_mnemonic(mnemonic, passphrase, path, out)
}

/// Wormhole pair derivation from mnemonic with passphrase.
///
/// The derivation path (including the wormhole chain-ID requirement) is
/// validated *before* BIP39 seed stretching; see [`derive_key_from_mnemonic`].
///
/// # Security Note
/// Takes the mnemonic by reference and does not copy it into a heap buffer,
/// avoiding a redundant duplicate of the secret. The caller retains ownership
/// of the `&str` and is responsible for zeroizing the source buffer itself.
///
/// The pair is written in place into the caller-provided `out`; see
/// [`generate_wormhole_from_seed`]. On error, `out` is untouched.
pub fn derive_wormhole_from_mnemonic(
	mnemonic: &str,
	passphrase: Option<&str>,
	path: &str,
	out: &mut WormholePair,
) -> Result<(), HDLatticeError> {
	check_wormhole_path(path)?;
	// The stretched seed is filled in place and lent to
	// `generate_wormhole_from_seed`; moving it there by value left this
	// local's stack slot unwiped (pinned by the seed stack-zeroization
	// probe). It drops — and wipes — here.
	let mut seed = SensitiveBytes64::zeroed();
	parse_mnemonic_to_seed_into(mnemonic, passphrase, seed.as_mut_bytes())?;
	generate_wormhole_from_seed(&seed, path, out)
}

/// Generate a wormhole pair from a seed at the given path
///
/// # Security Note
/// The seed is borrowed, not consumed: a by-value `SensitiveBytes64` would
/// be moved — copied into the callee while the caller's original stack slot
/// stays dead and unwiped, outside the reach of `ZeroizeOnDrop`. The seed
/// stays in the caller's self-zeroizing storage and is wiped in place when
/// the caller drops it.
///
/// The pair is likewise written in place into the caller-provided `out`
/// (start from [`WormholePair::zeroed`]) rather than returned by value: the
/// temporary a `Result<WormholePair, _>` is moved out of is never dropped,
/// which left the wormhole `secret` and `first_hash` in dead stack memory
/// (pinned by the wormhole stack-zeroization probe). On error, `out` is
/// untouched.
pub fn generate_wormhole_from_seed(
	seed: &SensitiveBytes64,
	path: &str,
	out: &mut WormholePair,
) -> Result<(), HDLatticeError> {
	check_wormhole_path(path)?;

	// Same HMAC-SHA512 tree derivation as the keypair entrypoints; only the
	// consumer of the entropy differs. (`derive_entropy_from_seed` re-runs
	// the generic path validation `check_wormhole_path` already performed —
	// cheap and idempotent.) Seed and entropy are self-zeroizing.
	let mut entropy = SensitiveBytes32::zeroed();
	derive_entropy_from_seed(seed, path, &mut entropy)?;
	WormholePair::generate_into(&mut entropy, out);
	Ok(())
}

/// Validate a wormhole derivation path: generic path checks plus the
/// wormhole chain-ID requirement in the third segment.
fn check_wormhole_path(path: &str) -> Result<(), HDLatticeError> {
	check_derivation_path(path)?;
	if path.split("/").nth(2) != Some(QUANTUS_WORMHOLE_CHAIN_ID) {
		return Err(HDLatticeError::InvalidWormholePath(path.to_string()));
	}
	Ok(())
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
/// The entropy is borrowed mutably and zeroized in place after use (security
/// review): taking it by value would move — i.e. copy — it through a dead
/// stack slot that is never dropped, so `ZeroizeOnDrop` could not wipe it.
/// The caller's value is all zeros afterwards; the bip39 stack-residue
/// regression test pins this.
///
/// The phrase is returned inside a [`Zeroizing`] wrapper (security review):
/// the recovery phrase yields the entire HD wallet, so it must not outlive
/// its logical lifetime in freed heap memory. A plain `String` return left
/// erasure to the caller with no type-level hint; `Zeroizing<String>` wipes
/// the backing allocation when the caller drops it. (Moving the wrapper only
/// copies the pointer/len/cap triple — the secret heap contents are never
/// duplicated — so returning it by value is safe, unlike fixed-size secret
/// arrays, which are wiped in place via out-parameters elsewhere in this
/// crate.) The heap-zeroization regression test pins this.
///
/// # Security Note
/// Always use cryptographically secure random entropy (e.g., from `getrandom::getrandom()`).
/// Never use predictable strings, timestamps, or user input as entropy sources.
pub fn generate_mnemonic(
	entropy: &mut SensitiveBytes32,
) -> Result<Zeroizing<String>, HDLatticeError> {
	// The secret word indices live only in this wiping buffer, which is
	// filled in place and never moved (see the `mnemonic` module).
	let mut indices = Zeroizing::new([0u16; mnemonic::MAX_WORDS]);
	mnemonic::encode_256(entropy.as_bytes(), &mut indices);
	entropy.as_mut_bytes().zeroize();

	// Collect the word pointers in one tight pass, then `join` — do NOT
	// stream straight into a growing String: an iterator borrowing the
	// secret index buffer kept alive across String appends made release
	// codegen spill an unwiped copy of the index array into a dead stack
	// slot (caught by the bip39 stack probe). `join` allocates the phrase
	// exactly once and moving it into `Zeroizing::new` transfers the same
	// allocation.
	let mut words: Vec<&str> =
		indices.iter().map(|&i| mnemonic::WORD_LIST[usize::from(i)]).collect();
	let result = Zeroizing::new(words.join(" "));

	// The Vec buffer now holds 24 fat pointers into the *static* word list.
	// The addresses are fixed per process image, so the freed pointer
	// sequence decodes right back to the phrase — an alternate
	// representation the byte-level phrase probe cannot see (the
	// word-pointer heap-zeroization test pins it). Scrub the buffer in
	// place before the Vec frees it by overwriting every slot with the
	// empty string (a valid `&str`, so no unsafe needed). Plain stores
	// right before a deallocation are candidates for dead-store
	// elimination, so `black_box` forces the compiler to assume the buffer
	// is observed after the overwrite; the word-pointer heap probe runs in
	// CI against both debug and optimized builds to pin that this scrub
	// actually reaches memory.
	for word in words.iter_mut() {
		*word = "";
	}
	core::hint::black_box(&mut words);
	drop(words);

	Ok(result)
}
