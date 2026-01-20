use alloc::vec::Vec;
use core::{fmt, ops::Deref, str::FromStr};
use hmac::{Hmac, Mac};
use k256::{elliptic_curve::sec1::ToEncodedPoint, SecretKey};
use sha2::Sha512;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Error {
	Secp256k1(k256::elliptic_curve::Error),
	InvalidChildNumber,
	InvalidDerivationPath,
	InvalidExtendedPrivKey,
	ZeroChildKey,
}

const HARDENED_BIT: u32 = 1 << 31;

/// A child number for a derived key
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct ChildNumber(u32);

impl ChildNumber {
	pub fn is_hardened(&self) -> bool {
		self.0 & HARDENED_BIT == HARDENED_BIT
	}

	pub fn is_normal(&self) -> bool {
		self.0 & HARDENED_BIT == 0
	}

	pub fn to_bytes(&self) -> [u8; 4] {
		self.0.to_be_bytes()
	}

	pub fn hardened_from_u32(index: u32) -> Self {
		ChildNumber(index | HARDENED_BIT)
	}

	pub fn non_hardened_from_u32(index: u32) -> Self {
		ChildNumber(index)
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

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Protected([u8; 32]);

impl<Data: AsRef<[u8]>> From<Data> for Protected {
	fn from(data: Data) -> Protected {
		let mut buf = [0u8; 32];
		buf.copy_from_slice(data.as_ref());
		Protected(buf)
	}
}

impl Deref for Protected {
	type Target = [u8];

	fn deref(&self) -> &[u8] {
		&self.0
	}
}

impl fmt::Debug for Protected {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "Protected")
	}
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ExtendedPrivKey {
	secret_key: SecretKey,
	chain_code: Protected,
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
			secret_key: SecretKey::from_slice(secret_key).map_err(Error::Secp256k1)?,
			chain_code: Protected::from(chain_code),
		};

		for child in path.into()?.as_ref() {
			sk = sk.child(*child)?;
		}

		Ok(sk)
	}

	pub fn secret(&self) -> [u8; 32] {
		self.secret_key.to_bytes().into()
	}

	pub fn child(&self, child: ChildNumber) -> Result<ExtendedPrivKey, Error> {
		let mut hmac: Hmac<Sha512> =
			Hmac::new_from_slice(&self.chain_code).map_err(|_| Error::InvalidChildNumber)?;

		if child.is_normal() {
			hmac.update(self.secret_key.public_key().to_encoded_point(true).as_bytes());
		} else {
			hmac.update(&[0]);
			hmac.update(&self.secret());
		}

		hmac.update(&child.to_bytes());

		let result = hmac.finalize().into_bytes();
		let (secret_key, chain_code) = result.split_at(32);

		let mut secret_key = SecretKey::from_slice(secret_key).map_err(Error::Secp256k1)?;
		let raw = *secret_key.as_scalar_primitive() + self.secret_key.as_scalar_primitive();
		if raw.is_zero().into() {
			return Err(Error::ZeroChildKey);
		}
		secret_key = SecretKey::new(raw);

		Ok(ExtendedPrivKey { secret_key, chain_code: Protected::from(&chain_code) })
	}
}

impl FromStr for ExtendedPrivKey {
	type Err = Error;

	fn from_str(xprv: &str) -> Result<ExtendedPrivKey, Error> {
		let data = bs58::decode(xprv).into_vec().map_err(|_| Error::InvalidExtendedPrivKey)?;

		if data.len() != 82 {
			return Err(Error::InvalidExtendedPrivKey);
		}

		Ok(ExtendedPrivKey {
			chain_code: Protected::from(&data[13..45]),
			secret_key: SecretKey::from_slice(&data[46..78]).map_err(Error::Secp256k1)?,
		})
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

		let expected_secret_key = b"\xff\x1e\x68\xeb\x7b\xf2\xf4\x86\x51\xc4\x7e\xf0\x17\x7e\xb8\x15\x85\x73\x22\x25\x7c\x58\x94\xbb\x4c\xfd\x11\x76\xc9\x98\x93\x14";

		let mnemonic = Mnemonic::parse_in_normalized(Language::English, phrase).unwrap();
		let seed = mnemonic.to_seed_normalized("");

		let account = ExtendedPrivKey::derive(&seed, "m/44'/60'/0'/0/0").unwrap();

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
