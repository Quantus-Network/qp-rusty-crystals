use alloc::vec::Vec;
use core::{ops::Deref, str::FromStr};
use hmac::{Hmac, Mac};
use sha2::Sha512;

use crate::SensitiveBytes32;

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Error {
	InvalidChildNumber,
	InvalidDerivationPath,
	NotHardened,
}

const HARDENED_BIT: u32 = 1 << 31;

/// A child number for a derived key
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct ChildNumber(u32);

impl ChildNumber {
	pub fn is_hardened(&self) -> bool {
		self.0 & HARDENED_BIT == HARDENED_BIT
	}

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
		let (child, mask) = if let Some(child) = child.strip_suffix('\'') {
			(child, HARDENED_BIT)
		} else {
			(child, 0)
		};

		let index: u32 = child.parse().map_err(|_| Error::InvalidChildNumber)?;

		if index & HARDENED_BIT == 0 {
			Ok(ChildNumber(index | mask))
		} else {
			Err(Error::InvalidChildNumber)
		}
	}
}

#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct DerivationPath {
	path: Vec<ChildNumber>,
}

impl FromStr for DerivationPath {
	type Err = Error;

	fn from_str(path: &str) -> Result<DerivationPath, Error> {
		let mut path = path.split('/');

		if path.next() != Some("m") {
			return Err(Error::InvalidDerivationPath);
		}

		Ok(DerivationPath {
			path: path.map(str::parse).collect::<Result<Vec<ChildNumber>, Error>>()?,
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
#[derive(Clone)]
pub struct ExtendedPrivKey {
	// Debug intentionally omitted to avoid leaking key material
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
			Hmac::new_from_slice(b"Bitcoin seed").expect("seed is always correct; qed");
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
		if !child.is_hardened() {
			return Err(Error::NotHardened);
		}
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

		let expected_secret_key = b"\xaf\x03\x67\xec\x66\x0c\x9e\x24\x34\x60\xfe\x97\xb2\x3e\x11\x62\xaa\x56\xd4\xd0\x39\x20\xd1\xeb\xe5\x00\xff\x0b\x34\x83\x71\x74";

		let mnemonic = Mnemonic::parse_in_normalized(Language::English, phrase).unwrap();
		let seed = mnemonic.to_seed_normalized("");

		let account = ExtendedPrivKey::derive(&seed, "m/44'/60'/0'/0'/0'").unwrap();

		assert_eq!(expected_secret_key, &account.secret(), "Secret key is invalid");
	}

	#[test]
	fn derive_path() {
		let path: DerivationPath = "m/44'/60'/0'/0".parse().unwrap();

		assert_eq!(
			path,
			DerivationPath {
				path: vec![
					ChildNumber(44 | HARDENED_BIT),
					ChildNumber(60 | HARDENED_BIT),
					ChildNumber(HARDENED_BIT),
					ChildNumber(0),
				],
			}
		);
	}
}
