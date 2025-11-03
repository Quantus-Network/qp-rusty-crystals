use sha2::{Digest, Sha256, Sha512};

use crate::errors::{KeyParsingError, KeyParsingError::BadSecretKey};
use alloc::{vec, vec::Vec};
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
	/// * 'entropy' - optional bytes for determining the generation process
	///
	/// Returns an instance of Keypair
	pub fn generate(entropy: Option<&[u8]>) -> Keypair {
		let mut pk = [0u8; PUBLICKEYBYTES];
		let mut sk = [0u8; SECRETKEYBYTES];
		crate::sign::keypair(&mut pk, &mut sk, entropy);
		Keypair {
			secret: SecretKey::from_bytes(&sk).expect("Should never fail"),
			public: PublicKey::from_bytes(&pk).expect("Should never fail"),
		}
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
	/// Returns Option<Signature>
	pub fn sign(&self, msg: &[u8], ctx: Option<&[u8]>, hedged: bool) -> Signature {
		self.secret.sign(msg, ctx, hedged)
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

	/// Compute a signature for a given message.
	///
	/// # Arguments
	///
	/// * 'msg' - message to sign
	///
	/// Returns Option<Signature>
	#[cfg(feature = "std")]
	pub fn prehash_sign(
		&self,
		msg: &[u8],
		ctx: Option<&[u8]>,
		hedged: bool,
		ph: crate::PH,
	) -> Option<Signature> {
		self.secret.prehash_sign(msg, ctx, hedged, ph)
	}

	/// Verify a signature for a given message with a public key.
	///
	/// # Arguments
	///
	/// * 'msg' - message that is claimed to be signed
	/// * 'sig' - signature to verify
	///
	/// Returns 'true' if the verification process was successful, 'false' otherwise
	pub fn prehash_verify(
		&self,
		msg: &[u8],
		sig: &[u8],
		ctx: Option<&[u8]>,
		ph: crate::PH,
	) -> bool {
		self.public.prehash_verify(msg, sig, ctx, ph)
	}
}

impl fmt::Debug for Keypair {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("Keypair").field("public", &self.public).finish()
	}
}

/// Private key.
#[derive(Clone)]
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
	pub fn sign(&self, msg: &[u8], ctx: Option<&[u8]>, hedged: bool) -> Signature {
		match ctx {
			Some(x) => {
				if x.len() > 255 {
					panic!("ctx length must not be larger than 255");
				}
				let x_len = x.len();
				let msg_len = msg.len();
				let mut m = vec![0; msg_len + 2 + x_len];
				m[1] = x_len as u8;
				m[2..2 + x_len].copy_from_slice(x);
				m[2 + x_len..].copy_from_slice(msg);
				let mut sig: Signature = [0u8; SIGNBYTES];
				crate::sign::signature(&mut sig, m.as_slice(), &self.bytes, hedged);
				sig
			},
			None => {
				let msg_len = msg.len();
				let mut m = vec![0; msg_len + 2];
				m[2..].copy_from_slice(msg);
				let mut sig: Signature = [0u8; SIGNBYTES];
				crate::sign::signature(&mut sig, m.as_slice(), &self.bytes, hedged);
				sig
			},
		}
	}

	/// Compute a signature for a given message.
	///
	/// # Arguments
	///
	/// * 'msg' - message to sign
	/// * 'ctx' - context string
	/// * 'hedged' - wether to use RNG or not
	/// * 'ph' - pre-hash function
	///
	/// Returns Option<Signature>
	#[cfg(feature = "std")]
	pub fn prehash_sign(
		&self,
		msg: &[u8],
		ctx: Option<&[u8]>,
		hedged: bool,
		ph: crate::PH,
	) -> Option<Signature> {
		let mut oid = [0u8; 11];
		let mut phm: Vec<u8> = Vec::new();
		match ph {
			crate::PH::SHA256 => {
				oid.copy_from_slice(&[
					0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
				]);
				phm.extend_from_slice(Sha256::digest(msg).as_slice());
			},
			crate::PH::SHA512 => {
				oid.copy_from_slice(&[
					0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
				]);
				phm.extend_from_slice(Sha512::digest(msg).as_slice());
			},
		}
		match ctx {
			Some(x) => {
				if x.len() > 255 {
					return None;
				}
				let x_len = x.len();
				let phm_len = phm.len();
				let mut m = vec![0; 2 + x_len + 11 + phm_len];
				m[0] = 1;
				m[1] = x_len as u8;
				m[2..2 + x_len].copy_from_slice(x);
				m[2 + x_len..2 + x_len + 11].copy_from_slice(&oid);
				m[2 + x_len + 11..].copy_from_slice(phm.as_slice());
				let mut sig: Signature = [0u8; SIGNBYTES];
				crate::sign::signature(&mut sig, m.as_slice(), &self.bytes, hedged);
				Some(sig)
			},
			None => {
				let phm_len = phm.len();
				let mut m = vec![0; 2 + 11 + phm_len];
				m[0] = 1;
				m[2..2 + 11].copy_from_slice(&oid);
				m[2 + 11..].copy_from_slice(phm.as_slice());
				let mut sig: Signature = [0u8; SIGNBYTES];
				crate::sign::signature(&mut sig, m.as_slice(), &self.bytes, hedged);
				Some(sig)
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
				let msg_len = msg.len();
				let mut m = vec![0; msg_len + 2];
				m[2..].copy_from_slice(msg);
				crate::sign::verify(sig, m.as_slice(), &self.bytes)
			},
		}
	}

	/// Verify a signature for a given message with a public key.
	///
	/// # Arguments
	///
	/// * 'msg' - message that is claimed to be signed
	/// * 'sig' - signature to verify
	/// * 'ctx' - context string
	/// * 'ph' - pre-hash function
	///
	/// Returns 'true' if the verification process was successful, 'false' otherwise
	pub fn prehash_verify(
		&self,
		msg: &[u8],
		sig: &[u8],
		ctx: Option<&[u8]>,
		ph: crate::PH,
	) -> bool {
		if sig.len() != SIGNBYTES {
			return false;
		}
		let mut oid = [0u8; 11];
		let mut phm: Vec<u8> = Vec::new();
		match ph {
			crate::PH::SHA256 => {
				oid.copy_from_slice(&[
					0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
				]);
				phm.extend_from_slice(Sha256::digest(msg).as_slice());
			},
			crate::PH::SHA512 => {
				oid.copy_from_slice(&[
					0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
				]);
				phm.extend_from_slice(Sha512::digest(msg).as_slice());
			},
		}
		match ctx {
			Some(x) => {
				if x.len() > 255 {
					return false;
				}
				let x_len = x.len();
				let phm_len = phm.len();
				let mut m = vec![0; 2 + x_len + 11 + phm_len];
				m[0] = 1;
				m[1] = x_len as u8;
				m[2..2 + x_len].copy_from_slice(x);
				m[2 + x_len..2 + x_len + 11].copy_from_slice(&oid);
				m[2 + x_len + 11..].copy_from_slice(phm.as_slice());
				crate::sign::verify(sig, m.as_slice(), &self.bytes)
			},
			None => {
				let phm_len = phm.len();
				let mut m = vec![0; 2 + 11 + phm_len];
				m[0] = 1;
				m[2..2 + 11].copy_from_slice(&oid);
				m[2 + 11..].copy_from_slice(phm.as_slice());
				crate::sign::verify(sig, m.as_slice(), &self.bytes)
			},
		}
	}
}

#[cfg(test)]
mod tests {
	use super::Keypair;
	#[test]
	fn self_verify_hedged() {
		const MSG_BYTES: usize = 94;
		let mut msg = [0u8; MSG_BYTES];
		crate::random_bytes(&mut msg, MSG_BYTES);
		let keys = Keypair::generate(None);
		let sig = keys.sign(&msg, None, true);
		assert!(keys.verify(&msg, &sig, None));
	}
	#[test]
	fn self_verify() {
		const MSG_BYTES: usize = 94;
		let mut msg = [0u8; MSG_BYTES];
		crate::random_bytes(&mut msg, MSG_BYTES);
		let keys = Keypair::generate(None);
		let sig = keys.sign(&msg, None, false);
		assert!(keys.verify(&msg, &sig, None));
	}
	#[test]
	fn self_verify_prehash_hedged() {
		const MSG_BYTES: usize = 94;
		let mut msg = [0u8; MSG_BYTES];
		crate::random_bytes(&mut msg, MSG_BYTES);
		let keys = Keypair::generate(None);
		let sig = keys.prehash_sign(&msg, None, true, crate::PH::SHA256);
		assert!(keys.prehash_verify(&msg, &sig.unwrap(), None, crate::PH::SHA256));
	}
	#[test]
	fn self_verify_prehash() {
		const MSG_BYTES: usize = 94;
		let mut msg = [0u8; MSG_BYTES];
		crate::random_bytes(&mut msg, MSG_BYTES);
		let keys = Keypair::generate(None);
		let sig = keys.prehash_sign(&msg, None, false, crate::PH::SHA256);
		assert!(keys.prehash_verify(&msg, &sig.unwrap(), None, crate::PH::SHA256));
	}
}
