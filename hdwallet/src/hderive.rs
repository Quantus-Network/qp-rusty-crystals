use alloc::vec::Vec;
use core::{ops::Deref, str::FromStr};
use hmac::{Hmac, Mac};
use sha2::Sha512;

use crate::{SensitiveBytes32, MAX_DERIVATION_DEPTH, MAX_DERIVATION_PATH_BYTES};

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Error {
	InvalidChildNumber,
	InvalidDerivationPath,
	NotHardened,
	PathTooLong(usize),
	PathTooDeep(usize),
}

const HARDENED_BIT: u32 = 1 << 31;

/// Reject paths whose raw byte length or `/`-segment count exceed the workspace caps.
/// Runs before any allocation so attacker-controlled paths cannot drive memory or CPU.
pub(crate) fn check_path_bounds(path: &str) -> Result<(), Error> {
	if path.len() > MAX_DERIVATION_PATH_BYTES {
		return Err(Error::PathTooLong(path.len()));
	}
	let depth = path.bytes().filter(|b| *b == b'/').count();
	if depth > MAX_DERIVATION_DEPTH {
		return Err(Error::PathTooDeep(depth));
	}
	Ok(())
}

/// A child number for a derived key
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct ChildNumber(u32);

impl ChildNumber {
	pub fn to_bytes(&self) -> [u8; 4] {
		self.0.to_be_bytes()
	}

	pub fn hardened_from_u32(index: u32) -> Self {
		ChildNumber(index | HARDENED_BIT)
	}
}

impl FromStr for ChildNumber {
	type Err = Error;

	fn from_str(child: &str) -> Result<ChildNumber, Error> {
		let child = child.strip_suffix('\'').ok_or(Error::NotHardened)?;

		// Enforce a canonical decimal encoding before parsing. `u32::from_str`
		// tolerates a leading '+' and any number of leading zeros, so "44'",
		// "+44'", "0044'" and "000000044'" would all decode to the same child
		// index. Since the child index (not the string) feeds the HMAC step,
		// those distinct path strings would derive byte-identical keys and
		// addresses — collapsing textually distinct paths onto one identity.
		// Require: non-empty, ASCII digits only, and no redundant leading zero.
		if child.is_empty() || !child.bytes().all(|b| b.is_ascii_digit()) {
			return Err(Error::InvalidChildNumber);
		}
		if child.len() > 1 && child.starts_with('0') {
			return Err(Error::InvalidChildNumber);
		}

		let index: u32 = child.parse().map_err(|_| Error::InvalidChildNumber)?;
		if index & HARDENED_BIT != 0 {
			return Err(Error::InvalidChildNumber);
		}
		Ok(ChildNumber(index | HARDENED_BIT))
	}
}

#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct DerivationPath {
	path: Vec<ChildNumber>,
}

impl FromStr for DerivationPath {
	type Err = Error;

	fn from_str(path: &str) -> Result<DerivationPath, Error> {
		check_path_bounds(path)?;

		let mut parts = path.split('/');

		if parts.next() != Some("m") {
			return Err(Error::InvalidDerivationPath);
		}

		Ok(DerivationPath {
			path: parts.map(str::parse).collect::<Result<Vec<ChildNumber>, Error>>()?,
		})
	}
}

impl Deref for DerivationPath {
	type Target = [ChildNumber];

	fn deref(&self) -> &Self::Target {
		&self.path
	}
}

impl<T> AsRef<T> for DerivationPath
where
	T: ?Sized,
	<DerivationPath as Deref>::Target: AsRef<T>,
{
	fn as_ref(&self) -> &T {
		self.deref().as_ref()
	}
}

impl DerivationPath {
	pub fn iter(&self) -> impl Iterator<Item = &ChildNumber> {
		self.path.iter()
	}
}

pub trait IntoDerivationPath {
	fn into(self) -> Result<DerivationPath, Error>;
}

impl IntoDerivationPath for DerivationPath {
	fn into(self) -> Result<DerivationPath, Error> {
		Ok(self)
	}
}

impl IntoDerivationPath for &str {
	fn into(self) -> Result<DerivationPath, Error> {
		self.parse()
	}
}
pub struct ExtendedPrivKey {
	// Debug intentionally omitted to avoid leaking key material.
	// Clone intentionally omitted: the embedded SensitiveBytes32 fields are move-only.
	secret_key: SensitiveBytes32,
	chain_code: SensitiveBytes32,
}

impl ExtendedPrivKey {
	/// Attempts to derive an extended private key from a path.
	pub fn derive<Path>(seed: &[u8], path: Path) -> Result<ExtendedPrivKey, Error>
	where
		Path: IntoDerivationPath,
	{
		let mut hmac: Hmac<Sha512> =
			Hmac::new_from_slice(b"Dilithium seed").expect("seed is always correct; qed");
		hmac.update(seed);

		let result = hmac.finalize().into_bytes();
		let (secret_key, chain_code) = result.split_at(32);

		let mut sk = ExtendedPrivKey {
			secret_key: SensitiveBytes32::from(&mut secret_key.try_into().unwrap()),
			chain_code: SensitiveBytes32::from(&mut chain_code.try_into().unwrap()),
		};

		for child in path.into()?.as_ref() {
			sk = sk.child(*child)?;
		}

		Ok(sk)
	}

	pub fn secret(&self) -> [u8; 32] {
		*self.secret_key.as_bytes()
	}

	pub fn child(&self, child: ChildNumber) -> Result<ExtendedPrivKey, Error> {
		let mut hmac: Hmac<Sha512> = Hmac::new_from_slice(self.chain_code.as_bytes())
			.map_err(|_| Error::InvalidChildNumber)?;

		hmac.update(&[0]);
		hmac.update(&self.secret());

		hmac.update(&child.to_bytes());

		let result = hmac.finalize().into_bytes();
		let (secret_key, chain_code) = result.split_at(32);

		Ok(ExtendedPrivKey {
			secret_key: SensitiveBytes32::from(&mut secret_key.try_into().unwrap()),
			chain_code: SensitiveBytes32::from(&mut chain_code.try_into().unwrap()),
		})
	}
}

impl core::fmt::Debug for ExtendedPrivKey {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
		f.debug_struct("ExtendedPrivKey").finish_non_exhaustive()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use alloc::vec;
	use bip39::{Language, Mnemonic};

	#[test]
	fn bip39_to_address() {
		let phrase = "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside";

		let expected_secret_key = b"\x2f\xbd\x41\x6a\x34\xc0\xac\x40\x98\xea\xad\xd0\x8c\x07\xc7\x09\xad\xf4\xd8\x7e\x7a\xa8\x12\x44\xa4\xbf\x2b\xf9\xfb\xfb\xbf\x76";

		let mnemonic = Mnemonic::parse_in_normalized(Language::English, phrase).unwrap();
		let seed = mnemonic.to_seed_normalized("");

		let account = ExtendedPrivKey::derive(&seed, "m/44'/60'/0'/0'/0'").unwrap();

		assert_eq!(expected_secret_key, &account.secret(), "Secret key is invalid");
	}

	#[test]
	fn derive_path() {
		let path: DerivationPath = "m/44'/60'/0'".parse().unwrap();
		assert_eq!(
			path,
			DerivationPath {
				path: vec![
					ChildNumber(44 | HARDENED_BIT),
					ChildNumber(60 | HARDENED_BIT),
					ChildNumber(HARDENED_BIT),
				],
			}
		);
	}

	#[test]
	fn non_hardened_path_rejected() {
		assert_eq!("m/44'/60'/0".parse::<DerivationPath>().unwrap_err(), Error::NotHardened);
		assert_eq!("0".parse::<ChildNumber>().unwrap_err(), Error::NotHardened);
	}

	// Non-canonical decimal spellings must be rejected. Otherwise "+44'",
	// "0044'", etc. would alias to the same child index as "44'" and derive
	// byte-identical keys/addresses, collapsing distinct path strings onto one
	// on-chain identity.
	#[test]
	fn non_canonical_child_numbers_rejected() {
		// The canonical form still works.
		assert_eq!("44'".parse::<ChildNumber>().unwrap(), ChildNumber(44 | HARDENED_BIT));
		assert_eq!("0'".parse::<ChildNumber>().unwrap(), ChildNumber(HARDENED_BIT));

		for bad in ["+44'", "0044'", "000000044'", "+0'", "00'", " 44'", "44 '", "4_4'"] {
			assert_eq!(
				bad.parse::<ChildNumber>().unwrap_err(),
				Error::InvalidChildNumber,
				"non-canonical child number {:?} must be rejected",
				bad
			);
		}

		// And the same via a full path so the aliasing can't slip in mid-path.
		assert_eq!(
			"m/44'/189189189'/+0'".parse::<DerivationPath>().unwrap_err(),
			Error::InvalidChildNumber
		);
	}
}
