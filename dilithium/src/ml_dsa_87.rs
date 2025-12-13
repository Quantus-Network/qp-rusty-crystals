use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
	errors::{KeyParsingError, KeyParsingError::BadSecretKey, SignatureError},
	params, SensitiveBytes32,
};
use alloc::vec;
use core::fmt;

pub const SECRETKEYBYTES: usize = crate::params::SECRETKEYBYTES;
pub const PUBLICKEYBYTES: usize = crate::params::PUBLICKEYBYTES;
pub const SIGNBYTES: usize = crate::params::SIGNBYTES;
pub const KEYPAIRBYTES: usize = SECRETKEYBYTES + PUBLICKEYBYTES;

pub type Signature = [u8; SIGNBYTES];

/// A pair of private and public keys.
#[derive(Clone)]
pub struct Keypair {
	pub secret: SecretKey,
	pub public: PublicKey,
}

impl Keypair {
	/// Generate a Keypair instance.
	///
	/// # Arguments
	///
	/// * 'entropy' - bytes for determining the generation process (must be at least 32 bytes)
	///
	/// Note: The entropy is moved here and zeroized after use, along with the derived secret key.
	pub fn generate(entropy: SensitiveBytes32) -> Keypair {
		let mut pk = [0u8; PUBLICKEYBYTES];
		let mut sk = [0u8; SECRETKEYBYTES];
		crate::sign::keypair(&mut pk, &mut sk, entropy);
		let keypair = Keypair {
			secret: SecretKey::from_bytes(&sk).expect("Should never fail"),
			public: PublicKey::from_bytes(&pk).expect("Should never fail"),
		};
		sk.zeroize();
		// entropy is automatically zeroized when it drops (ZeroizeOnDrop)
		keypair
	}

	/// Convert a Keypair to a bytes array.
	///
	/// Returns an array containing private and public keys bytes
	pub fn to_bytes(&self) -> [u8; KEYPAIRBYTES] {
		let mut result = [0u8; KEYPAIRBYTES];
		result[..SECRETKEYBYTES].copy_from_slice(&self.secret.to_bytes());
		result[SECRETKEYBYTES..].copy_from_slice(&self.public.to_bytes());
		result
	}

	/// Create a Keypair from bytes.
	///
	/// # Arguments
	///
	/// * 'bytes' - private and public keys bytes
	///
	/// Returns a Keypair
	pub fn from_bytes(bytes: &[u8]) -> Result<Keypair, KeyParsingError> {
		if bytes.len() != SECRETKEYBYTES + PUBLICKEYBYTES {
			return Err(KeyParsingError::BadKeypair);
		}
		let (secret_bytes, public_bytes) = bytes.split_at(SECRETKEYBYTES);
		let secret =
			SecretKey::from_bytes(secret_bytes).map_err(|_| KeyParsingError::BadKeypair)?;
		let public =
			PublicKey::from_bytes(public_bytes).map_err(|_| KeyParsingError::BadKeypair)?;
		Ok(Keypair { secret, public })
	}

	/// Compute a signature for a given message.
	///
	/// # Arguments
	///
	/// * 'msg' - message to sign
	///
	/// Returns Result<Signature, SignatureError>
	pub fn sign(
		&self,
		msg: &[u8],
		ctx: Option<&[u8]>,
		hedge: Option<[u8; params::SEEDBYTES]>,
	) -> Result<Signature, SignatureError> {
		self.secret.sign(msg, ctx, hedge)
	}

	/// Verify a signature for a given message with a public key.
	///
	/// # Arguments
	///
	/// * 'msg' - message that is claimed to be signed
	/// * 'sig' - signature to verify
	///
	/// Returns 'true' if the verification process was successful, 'false' otherwise
	pub fn verify(&self, msg: &[u8], sig: &[u8], ctx: Option<&[u8]>) -> bool {
		self.public.verify(msg, sig, ctx)
	}
}

impl fmt::Debug for Keypair {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("Keypair").field("public", &self.public).finish()
	}
}

/// Private key.
#[derive(Clone, ZeroizeOnDrop)]
pub struct SecretKey {
	pub bytes: [u8; SECRETKEYBYTES],
}

impl SecretKey {
	/// Returns a copy of underlying bytes.
	pub fn to_bytes(&self) -> [u8; SECRETKEYBYTES] {
		self.bytes
	}

	/// Create a SecretKey from bytes.
	///
	/// # Arguments
	///
	/// * 'bytes' - private key bytes
	///
	/// Returns a SecretKey
	pub fn from_bytes(bytes: &[u8]) -> Result<SecretKey, KeyParsingError> {
		let result = bytes.try_into();
		match result {
			Ok(bytes) => Ok(SecretKey { bytes }),
			Err(_) => Err(BadSecretKey),
		}
	}

	/// Compute a signature for a given message.
	///
	/// # Arguments
	///
	/// * 'msg' - message to sign
	/// * 'ctx' - context string
	/// * 'hedged' - wether to use RNG or not
	///
	/// Returns Option<Signature>
	pub fn sign(
		&self,
		msg: &[u8],
		ctx: Option<&[u8]>,
		hedge: Option<[u8; params::SEEDBYTES]>,
	) -> Result<Signature, SignatureError> {
		match ctx {
			Some(x) => {
				if x.len() > 255 {
					return Err(SignatureError::ContextTooLong);
				}
				let x_len = x.len();
				let msg_len = msg.len();
				let mut m = vec![0; msg_len + 2 + x_len];
				m[1] = x_len as u8;
				m[2..2 + x_len].copy_from_slice(x);
				m[2 + x_len..].copy_from_slice(msg);
				let mut sig: Signature = [0u8; SIGNBYTES];
				crate::sign::signature(&mut sig, m.as_slice(), &self.bytes, hedge);
				Ok(sig)
			},
			None => {
				let mut sig: Signature = [0u8; SIGNBYTES];
				// Prefix 2 zero bytes (domain_sep=0, context_len=0) for pure signatures
				let mut m = vec![0u8; msg.len() + 2];
				m[2..2 + msg.len()].copy_from_slice(msg);
				crate::sign::signature(&mut sig, m.as_slice(), &self.bytes, hedge);
				Ok(sig)
			},
		}
	}
}

#[derive(Eq, Clone, PartialEq, Debug, Hash, PartialOrd, Ord)]
pub struct PublicKey {
	pub bytes: [u8; PUBLICKEYBYTES],
}

impl PublicKey {
	/// Returns a copy of underlying bytes.
	pub fn to_bytes(&self) -> [u8; PUBLICKEYBYTES] {
		self.bytes
	}

	/// Create a PublicKey from bytes.
	///
	/// # Arguments
	///
	/// * 'bytes' - public key bytes
	///
	/// Returns a PublicKey
	pub fn from_bytes(bytes: &[u8]) -> Result<PublicKey, KeyParsingError> {
		let result = bytes.try_into();
		match result {
			Ok(bytes) => Ok(PublicKey { bytes }),
			Err(_) => Err(KeyParsingError::BadPublicKey),
		}
	}

	/// Verify a signature for a given message with a public key.
	///
	/// # Arguments
	///
	/// * 'msg' - message that is claimed to be signed
	/// * 'sig' - signature to verify
	/// * 'ctx' - context string
	///
	/// Returns 'true' if the verification process was successful, 'false' otherwise
	pub fn verify(&self, msg: &[u8], sig: &[u8], ctx: Option<&[u8]>) -> bool {
		if sig.len() != SIGNBYTES {
			return false;
		}
		match ctx {
			Some(x) => {
				if x.len() > 255 {
					return false;
				}
				let x_len = x.len();
				let msg_len = msg.len();
				let mut m = vec![0; msg_len + 2 + x_len];
				m[1] = x_len as u8;
				m[2..2 + x_len].copy_from_slice(x);
				m[2 + x_len..].copy_from_slice(msg);
				crate::sign::verify(sig, m.as_slice(), &self.bytes)
			},
			None => {
				let mut m = vec![0; msg.len() + 2];
				m[2..2 + msg.len()].copy_from_slice(msg);
				crate::sign::verify(sig, m.as_slice(), &self.bytes)
			},
		}
	}
}

#[cfg(test)]
mod tests {
	use super::Keypair;
	use crate::SensitiveBytes32;
	use rand::Rng;

	fn get_random_bytes() -> SensitiveBytes32 {
		let mut rng = rand::rng();
		let mut bytes = [0u8; 32];
		rng.fill(&mut bytes);
		(&mut bytes).into()
	}

	fn get_random_msg() -> [u8; 128] {
		let mut rng = rand::rng();
		let mut bytes = [0u8; 128];
		rng.fill(&mut bytes);
		bytes
	}

	#[test]
	fn self_verify_hedged() {
		let msg = get_random_msg();
		let entropy = get_random_bytes();
		let keys = Keypair::generate(entropy);
		let hedge = get_random_bytes();
		let sig = keys.sign(&msg, None, Some(hedge.0)).unwrap();
		assert!(keys.verify(&msg, &sig, None));
	}

	#[test]
	fn self_verify() {
		let msg = get_random_msg();
		let entropy = get_random_bytes();
		let keys = Keypair::generate(entropy);
		let hedge = get_random_bytes();
		let sig = keys.sign(&msg, None, Some(hedge.0)).unwrap();
		assert!(keys.verify(&msg, &sig, None));
	}

	#[test]
	fn verify_fails_with_different_context() {
		let msg = get_random_msg();
		let entropy = get_random_bytes();
		let keys = Keypair::generate(entropy);
		let hedge = get_random_bytes();

		// Sign with context "test1"
		let ctx1 = b"test1";
		let sig = keys.sign(&msg, Some(ctx1), Some(hedge.0)).unwrap();

		// Try to verify with different context "test2" - should fail
		let ctx2 = b"test2";
		assert!(!keys.verify(&msg, &sig, Some(ctx2)));

		// Verify with correct context should still work
		assert!(keys.verify(&msg, &sig, Some(ctx1)));
	}
}
