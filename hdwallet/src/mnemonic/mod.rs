//! BIP-0039 mnemonic encoding and validation (English word list).
//!
//! Implemented in-crate rather than through the `bip39` crate because its
//! `Mnemonic` type carries the secret word indices and is returned by value
//! from `from_entropy` and `parse_in_normalized`. A by-value return is moved
//! (copied) through the callee's return slot and the `Result` payload; those
//! moved-from stack slots are dead but never dropped, so `ZeroizeOnDrop`
//! cannot wipe them, and whether the compiler elides the copies is a codegen
//! detail (the bip39 stack probe caught an unwiped copy on one platform).
//! Here the indices only ever live in a caller-owned wiping buffer that is
//! passed by reference and never moved.
//!
//! The word list is the official `english.txt` (SHA-256
//! `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`). The
//! `bip39` crate remains a dev-dependency as the reference implementation the
//! tests compare against.

use alloc::string::String;
use core::fmt;

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

mod words;

pub use words::WORD_LIST;

/// Longest phrase (256 bits of entropy).
pub const MAX_WORDS: usize = 24;

/// Index of `word` in [`WORD_LIST`], if it is a BIP-0039 English word.
pub fn word_index(word: &str) -> Option<u16> {
	WORD_LIST.binary_search(&word).ok().map(|i| i as u16)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MnemonicError {
	/// Not 12, 15, 18, 21 or 24 words.
	BadWordCount(usize),
	/// Word at this zero-based position is not in the list.
	UnknownWord(usize),
	InvalidChecksum,
}

impl fmt::Display for MnemonicError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			MnemonicError::BadWordCount(c) => write!(
				f,
				"mnemonic has an invalid word count: {c}. Word count must be 12, 15, 18, 21, or 24"
			),
			MnemonicError::UnknownWord(i) =>
				write!(f, "mnemonic contains an unknown word (word {i})"),
			MnemonicError::InvalidChecksum => write!(f, "the mnemonic has an invalid checksum"),
		}
	}
}

#[cfg(feature = "std")]
impl std::error::Error for MnemonicError {}

/// Word indices for 32 bytes of entropy: the 256 entropy bits followed by
/// the first 8 bits of `SHA-256(entropy)`, read as 24 big-endian 11-bit
/// groups. Written in place into `indices`.
pub(crate) fn encode_256(entropy: &[u8; 32], indices: &mut [u16; MAX_WORDS]) {
	let checksum = Sha256::digest(entropy)[0];
	for (i, index) in indices.iter_mut().enumerate() {
		let mut v = 0u16;
		for bit in i * 11..(i + 1) * 11 {
			let byte = if bit < 256 { entropy[bit / 8] } else { checksum };
			v = (v << 1) | u16::from((byte >> (7 - bit % 8)) & 1);
		}
		*index = v;
	}
}

/// Validate a phrase that is already NFKD-normalised: words separated by
/// whitespace, each in the list, 12 to 24 in multiples of 3, with a correct
/// checksum. Returns the word count. The indices and recovered entropy are
/// held in wiping buffers for the duration of the check.
pub(crate) fn validate(phrase: &str) -> Result<usize, MnemonicError> {
	let count = phrase.split_whitespace().count();
	if !(12..=MAX_WORDS).contains(&count) || !count.is_multiple_of(3) {
		return Err(MnemonicError::BadWordCount(count));
	}
	let mut indices = Zeroizing::new([0u16; MAX_WORDS]);
	for (i, word) in phrase.split_whitespace().enumerate() {
		indices[i] = word_index(word).ok_or(MnemonicError::UnknownWord(i))?;
	}

	// The 11-bit groups concatenated are `entropy_bytes * 8` entropy bits
	// followed by `entropy_bytes / 4` checksum bits.
	let bit = |b: usize| (indices[b / 11] >> (10 - b % 11)) & 1;
	let entropy_bytes = count / 3 * 4;
	let mut entropy = Zeroizing::new([0u8; 32]);
	for (i, byte) in entropy[..entropy_bytes].iter_mut().enumerate() {
		*byte = (0..8).fold(0u8, |acc, j| (acc << 1) | bit(i * 8 + j) as u8);
	}
	let digest = Sha256::digest(&entropy[..entropy_bytes]);
	let ok = (0..entropy_bytes / 4)
		.all(|i| bit(entropy_bytes * 8 + i) == u16::from((digest[i / 8] >> (7 - i % 8)) & 1));
	if ok {
		Ok(count)
	} else {
		Err(MnemonicError::InvalidChecksum)
	}
}

/// The canonical form of a validated phrase: its words joined by single
/// spaces. This is the PBKDF2 password in BIP-0039 seed stretching.
pub(crate) fn canonical_phrase(phrase: &str) -> Zeroizing<String> {
	let mut out = Zeroizing::new(String::with_capacity(phrase.len()));
	for (i, word) in phrase.split_whitespace().enumerate() {
		if i > 0 {
			out.push(' ');
		}
		out.push_str(word);
	}
	out
}

#[cfg(test)]
mod tests {
	use alloc::{string::ToString, vec::Vec};

	use bip39::{Language, Mnemonic};
	use rand::{rngs::StdRng, Rng, SeedableRng};

	use super::*;

	#[test]
	fn word_list_matches_bip39() {
		assert_eq!(&WORD_LIST[..], &Language::English.word_list()[..]);
		assert!(WORD_LIST.windows(2).all(|w| w[0] < w[1]));
		for (i, w) in WORD_LIST.iter().enumerate() {
			assert_eq!(word_index(w), Some(i as u16));
		}
		assert_eq!(word_index("abandonn"), None);
		assert_eq!(word_index(""), None);
	}

	#[test]
	fn encoding_matches_bip39() {
		let mut rng = StdRng::from_seed([9u8; 32]);
		for _ in 0..50 {
			let mut entropy = [0u8; 32];
			rng.fill_bytes(&mut entropy);
			let reference: Vec<u16> = Mnemonic::from_entropy(&entropy)
				.unwrap()
				.word_indices()
				.map(|i| i as u16)
				.collect();
			let mut indices = [0u16; MAX_WORDS];
			encode_256(&entropy, &mut indices);
			assert_eq!(&indices[..], &reference[..]);
		}
	}

	#[test]
	fn validation_matches_bip39() {
		let mut rng = StdRng::from_seed([10u8; 32]);
		for &bytes in &[16usize, 20, 24, 28, 32] {
			for _ in 0..10 {
				let mut entropy = [0u8; 32];
				rng.fill_bytes(&mut entropy);
				let phrase = Mnemonic::from_entropy(&entropy[..bytes]).unwrap().to_string();
				assert_eq!(validate(&phrase), Ok(bytes * 3 / 4));
				assert_eq!(*canonical_phrase(&phrase), phrase);

				// Any single-word substitution breaks the checksum or the
				// word, exactly as bip39 reports.
				let mut words: Vec<&str> = phrase.split_whitespace().collect();
				let original = words[3];
				words[3] = if original == "abandon" { "zoo" } else { "abandon" };
				let broken = words.join(" ");
				let ours = validate(&broken);
				let theirs = Mnemonic::parse_in_normalized(Language::English, &broken);
				assert_eq!(ours.is_ok(), theirs.is_ok(), "{broken}");
				if let (Err(a), Err(b)) = (ours, theirs) {
					assert_eq!(a.to_string(), b.to_string());
				}
			}
		}
	}

	#[test]
	fn validation_errors() {
		let twelve = Mnemonic::from_entropy(&[0u8; 16]).unwrap().to_string();
		assert_eq!(validate(&twelve), Ok(12), "{twelve}");
		assert_eq!(validate(""), Err(MnemonicError::BadWordCount(0)));
		assert_eq!(validate("abandon abandon"), Err(MnemonicError::BadWordCount(2)));
		let thirteen = twelve.clone() + " abandon";
		assert_eq!(validate(&thirteen), Err(MnemonicError::BadWordCount(13)));
		let unknown = twelve.replacen("abandon", "abandoned", 1);
		assert_eq!(validate(&unknown), Err(MnemonicError::UnknownWord(0)));
		let bad_checksum = twelve.rsplit_once(' ').unwrap().0.to_string() + " zoo";
		assert_eq!(validate(&bad_checksum), Err(MnemonicError::InvalidChecksum));
		// Whitespace is normalised to single spaces.
		let spaced = twelve.replace(' ', "  \t");
		assert_eq!(validate(&spaced), Ok(12));
		assert_eq!(*canonical_phrase(&spaced), twelve);
		assert_eq!(
			MnemonicError::BadWordCount(7).to_string(),
			"mnemonic has an invalid word count: 7. Word count must be 12, 15, 18, 21, or 24"
		);
	}
}
