//! The public API shared by every parameter-set module.

use alloc::{boxed::Box, vec};

use crate::errors::SignatureError;

/// Hash functions approved for HashSLH-DSA (FIPS 205 section 10.2).
///
/// FIPS 205 requires a pre-hash with at least `8n` bits of collision
/// strength for a parameter set with security parameter `n`. The caller must
/// pick one. It is not checked, because NIST's ACVP vectors use every hash
/// with every parameter set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreHash {
	Sha2_224,
	Sha2_256,
	Sha2_384,
	Sha2_512,
	Sha2_512_224,
	Sha2_512_256,
	Sha3_224,
	Sha3_256,
	Sha3_384,
	Sha3_512,
	Shake128,
	Shake256,
}

impl PreHash {
	/// Byte length of the digest that is signed.
	pub const fn digest_bytes(self) -> usize {
		match self {
			Self::Sha2_224 | Self::Sha2_512_224 | Self::Sha3_224 => 28,
			Self::Sha2_256 | Self::Sha2_512_256 | Self::Sha3_256 | Self::Shake128 => 32,
			Self::Sha2_384 | Self::Sha3_384 => 48,
			Self::Sha2_512 | Self::Sha3_512 | Self::Shake256 => 64,
		}
	}

	/// DER encoding of the hash function's object identifier.
	pub const fn oid(self) -> [u8; 11] {
		let last = match self {
			Self::Sha2_256 => 1,
			Self::Sha2_384 => 2,
			Self::Sha2_512 => 3,
			Self::Sha2_224 => 4,
			Self::Sha2_512_224 => 5,
			Self::Sha2_512_256 => 6,
			Self::Sha3_224 => 7,
			Self::Sha3_256 => 8,
			Self::Sha3_384 => 9,
			Self::Sha3_512 => 10,
			Self::Shake128 => 11,
			Self::Shake256 => 12,
		};
		[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, last]
	}
}

/// The two bytes that start the signed message: the domain separator (0 for
/// pure signing, 1 for pre-hash signing) and the context length.
pub(crate) fn message_header(domain: u8, ctx: &[u8]) -> Result<[u8; 2], SignatureError> {
	let ctx_len = u8::try_from(ctx.len()).map_err(|_| SignatureError::ContextTooLong)?;
	Ok([domain, ctx_len])
}

pub(crate) fn check_digest(pre_hash: PreHash, digest: &[u8]) -> Result<(), SignatureError> {
	if digest.len() != pre_hash.digest_bytes() {
		return Err(SignatureError::BadDigestLength);
	}
	Ok(())
}

pub(crate) fn zeroed_box<const LEN: usize>() -> Box<[u8; LEN]> {
	vec![0u8; LEN].into_boxed_slice().try_into().expect("the vector has LEN bytes")
}

macro_rules! define_slh_dsa {
	($params:path) => {
		use alloc::boxed::Box;
		use core::fmt;
		use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

		use $crate::{
			errors::{KeyParsingError, SignatureError},
			frontend::{check_digest, message_header, zeroed_box},
			params::Params,
			slh, PreHash,
		};

		pub(crate) const PARAMS: &Params = &$params;

		/// The FIPS 205 name of the parameter set.
		pub const ALGORITHM: &str = PARAMS.name;
		/// The security parameter `n`.
		pub const N: usize = PARAMS.n;
		/// Key generation input: `SK.seed || SK.prf || PK.seed`.
		pub const SEEDBYTES: usize = 3 * N;
		pub const PUBLICKEYBYTES: usize = 2 * N;
		pub const SECRETKEYBYTES: usize = 4 * N;
		pub const SIGNBYTES: usize = PARAMS.sig_bytes();

		pub type Signature = [u8; SIGNBYTES];

		/// A secret key and its public key. Not `Clone`: the secret key is
		/// wiped on drop and lives in its own heap block, so moving a
		/// keypair never copies it.
		pub struct Keypair {
			secret: SecretKey,
			public: PublicKey,
		}

		impl Keypair {
			/// `slh_keygen_internal`. `seed` is wiped.
			pub fn generate(seed: &mut [u8; SEEDBYTES]) -> Keypair {
				let mut keypair = Keypair::zeroed();
				Keypair::generate_into(seed, &mut keypair);
				keypair
			}

			/// A placeholder for [`Keypair::generate_into`]. Not a usable key.
			pub fn zeroed() -> Keypair {
				Keypair {
					secret: SecretKey { bytes: zeroed_box() },
					public: PublicKey { bytes: [0u8; PUBLICKEYBYTES] },
				}
			}

			/// [`Keypair::generate`] into existing storage.
			pub fn generate_into(seed: &mut [u8; SEEDBYTES], out: &mut Keypair) {
				slh::keygen(PARAMS, &seed[..], &mut out.secret.bytes[..]);
				seed.zeroize();
				out.public = out.secret.public_key();
			}

			pub fn from_secret(secret: SecretKey) -> Keypair {
				let public = secret.public_key();
				Keypair { secret, public }
			}

			pub fn secret(&self) -> &SecretKey {
				&self.secret
			}

			pub fn public(&self) -> &PublicKey {
				&self.public
			}

			/// See [`SecretKey::sign`].
			pub fn sign(
				&self,
				msg: &[u8],
				ctx: Option<&[u8]>,
				addrnd: Option<&[u8; N]>,
			) -> Result<Box<Signature>, SignatureError> {
				self.secret.sign(msg, ctx, addrnd)
			}

			/// See [`PublicKey::verify`].
			pub fn verify(&self, msg: &[u8], sig: &[u8], ctx: Option<&[u8]>) -> bool {
				self.public.verify(msg, sig, ctx)
			}
		}

		impl fmt::Debug for Keypair {
			fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
				f.debug_struct("Keypair").field("public", &self.public).finish()
			}
		}

		/// `SK.seed || SK.prf || PK.seed || PK.root`, wiped on drop.
		#[derive(Zeroize, ZeroizeOnDrop)]
		pub struct SecretKey {
			bytes: Box<[u8; SECRETKEYBYTES]>,
		}

		impl SecretKey {
			pub fn to_bytes(&self) -> Zeroizing<[u8; SECRETKEYBYTES]> {
				Zeroizing::new(*self.bytes)
			}

			/// Rejects a key whose `PK.root` does not belong to its seeds.
			/// The check costs one key generation.
			pub fn from_bytes(bytes: &[u8]) -> Result<SecretKey, KeyParsingError> {
				if bytes.len() != SECRETKEYBYTES {
					return Err(KeyParsingError::BadSecretKey);
				}
				let mut secret = SecretKey { bytes: zeroed_box() };
				slh::keygen(PARAMS, &bytes[..SEEDBYTES], &mut secret.bytes[..]);
				if secret.bytes[SEEDBYTES..] != bytes[SEEDBYTES..] {
					return Err(KeyParsingError::BadSecretKey);
				}
				Ok(secret)
			}

			pub fn public_key(&self) -> PublicKey {
				let mut bytes = [0u8; PUBLICKEYBYTES];
				bytes.copy_from_slice(&self.bytes[2 * N..]);
				PublicKey { bytes }
			}

			/// `slh_sign`. `ctx` is at most 255 bytes. With `addrnd` the
			/// signature is hedged with that randomness, without it the
			/// signature is deterministic.
			pub fn sign(
				&self,
				msg: &[u8],
				ctx: Option<&[u8]>,
				addrnd: Option<&[u8; N]>,
			) -> Result<Box<Signature>, SignatureError> {
				let ctx = ctx.unwrap_or(&[]);
				let header = message_header(0, ctx)?;
				Ok(self.sign_internal(&[&header, ctx, msg], addrnd))
			}

			/// `hash_slh_sign` over `digest`, the `pre_hash` digest of the
			/// message.
			pub fn sign_prehash(
				&self,
				pre_hash: PreHash,
				digest: &[u8],
				ctx: Option<&[u8]>,
				addrnd: Option<&[u8; N]>,
			) -> Result<Box<Signature>, SignatureError> {
				check_digest(pre_hash, digest)?;
				let ctx = ctx.unwrap_or(&[]);
				let header = message_header(1, ctx)?;
				Ok(self.sign_internal(&[&header, ctx, &pre_hash.oid(), digest], addrnd))
			}

			fn sign_internal(&self, message: &[&[u8]], addrnd: Option<&[u8; N]>) -> Box<Signature> {
				let mut sig: Box<Signature> = zeroed_box();
				let addrnd = addrnd.map(|bytes| &bytes[..]);
				slh::sign(PARAMS, &self.bytes[..], message, addrnd, &mut sig[..]);
				sig
			}
		}

		/// `PK.seed || PK.root`.
		#[derive(Eq, Clone, PartialEq, Debug, Hash, PartialOrd, Ord)]
		pub struct PublicKey {
			pub bytes: [u8; PUBLICKEYBYTES],
		}

		impl PublicKey {
			pub fn to_bytes(&self) -> [u8; PUBLICKEYBYTES] {
				self.bytes
			}

			pub fn from_bytes(bytes: &[u8]) -> Result<PublicKey, KeyParsingError> {
				let bytes = bytes.try_into().map_err(|_| KeyParsingError::BadPublicKey)?;
				Ok(PublicKey { bytes })
			}

			/// `slh_verify`. False for any invalid or malformed input.
			pub fn verify(&self, msg: &[u8], sig: &[u8], ctx: Option<&[u8]>) -> bool {
				let ctx = ctx.unwrap_or(&[]);
				let Ok(header) = message_header(0, ctx) else {
					return false;
				};
				slh::verify(PARAMS, &self.bytes, &[&header, ctx, msg], sig)
			}

			/// `hash_slh_verify` over `digest`, the `pre_hash` digest of the
			/// message.
			pub fn verify_prehash(
				&self,
				pre_hash: PreHash,
				digest: &[u8],
				sig: &[u8],
				ctx: Option<&[u8]>,
			) -> bool {
				let ctx = ctx.unwrap_or(&[]);
				let (Ok(()), Ok(header)) = (check_digest(pre_hash, digest), message_header(1, ctx))
				else {
					return false;
				};
				slh::verify(PARAMS, &self.bytes, &[&header, ctx, &pre_hash.oid(), digest], sig)
			}
		}
	};
}

pub(crate) use define_slh_dsa;

#[cfg(test)]
mod tests {
	use crate::{KeyParsingError, PreHash, SignatureError};

	macro_rules! api_tests {
		($module:ident, $pk:literal, $sk:literal, $sig:literal) => {
			mod $module {
				use super::*;
				use crate::$module::*;

				fn keypair() -> Keypair {
					Keypair::generate(&mut [0x42; SEEDBYTES])
				}

				#[test]
				fn sizes_match_fips_205() {
					assert_eq!((PUBLICKEYBYTES, SECRETKEYBYTES, SIGNBYTES), ($pk, $sk, $sig));
				}

				#[test]
				fn signs_and_verifies() {
					let keypair = keypair();
					let sig = keypair.sign(b"message", Some(b"ctx"), None).unwrap();
					assert!(keypair.verify(b"message", &sig[..], Some(b"ctx")));
					assert!(!keypair.verify(b"other", &sig[..], Some(b"ctx")));
					assert!(!keypair.verify(b"message", &sig[..], Some(b"other")));
					assert!(!keypair.verify(b"message", &sig[..], None));
					assert!(!keypair.verify(b"message", &sig[1..], Some(b"ctx")));
					for position in [0, N, SIGNBYTES - 1] {
						let mut tampered = sig.clone();
						tampered[position] ^= 1;
						assert!(!keypair.verify(b"message", &tampered[..], Some(b"ctx")));
					}
					let other = Keypair::generate(&mut [0x43; SEEDBYTES]);
					assert!(!other.verify(b"message", &sig[..], Some(b"ctx")));
				}

				#[test]
				fn hedged_signature_differs_and_verifies() {
					let keypair = keypair();
					let deterministic = keypair.sign(b"message", None, None).unwrap();
					assert_eq!(deterministic, keypair.sign(b"message", None, None).unwrap());
					let hedged = keypair.sign(b"message", None, Some(&[7; N])).unwrap();
					assert_ne!(deterministic, hedged);
					assert!(keypair.verify(b"message", &hedged[..], None));
				}

				#[test]
				fn rejects_long_context() {
					let keypair = keypair();
					let ctx = [0u8; 256];
					assert_eq!(
						keypair.sign(b"message", Some(&ctx), None),
						Err(SignatureError::ContextTooLong)
					);
					let sig = keypair.sign(b"message", Some(&ctx[..255]), None).unwrap();
					assert!(keypair.verify(b"message", &sig[..], Some(&ctx[..255])));
					assert!(!keypair.verify(b"message", &sig[..], Some(&ctx)));
				}

				#[test]
				fn prehash_signs_and_verifies() {
					let keypair = keypair();
					let (secret, public) = (keypair.secret(), keypair.public());
					let digest = [9u8; 64];
					let sig = secret.sign_prehash(PreHash::Sha2_512, &digest, None, None).unwrap();
					assert!(public.verify_prehash(PreHash::Sha2_512, &digest, &sig[..], None));
					assert!(!public.verify_prehash(PreHash::Sha3_512, &digest, &sig[..], None));
					assert!(!public.verify_prehash(PreHash::Sha2_512, &[8; 64], &sig[..], None));
					assert!(!public.verify_prehash(
						PreHash::Sha2_512,
						&digest[..32],
						&sig[..],
						None
					));
					assert!(!public.verify(&digest, &sig[..], None));
					assert_eq!(
						secret.sign_prehash(PreHash::Sha2_256, &digest, None, None),
						Err(SignatureError::BadDigestLength)
					);
				}

				#[test]
				fn keys_round_trip() {
					let keypair = keypair();
					let secret = SecretKey::from_bytes(&keypair.secret().to_bytes()[..]).unwrap();
					assert_eq!(secret.public_key(), *keypair.public());
					let restored = Keypair::from_secret(secret);
					assert_eq!(restored.public(), keypair.public());
					assert_eq!(restored.secret().to_bytes(), keypair.secret().to_bytes());
					assert_eq!(
						PublicKey::from_bytes(&keypair.public().to_bytes()).unwrap(),
						*keypair.public()
					);

					let mut filled = Keypair::zeroed();
					Keypair::generate_into(&mut [0x42; SEEDBYTES], &mut filled);
					assert_eq!(filled.secret().to_bytes(), keypair.secret().to_bytes());
					assert_eq!(filled.public(), keypair.public());
				}

				#[test]
				fn rejects_bad_keys() {
					let good = keypair().secret().to_bytes();
					for position in [0, 2 * N, SECRETKEYBYTES - 1] {
						let mut bad = *good;
						bad[position] ^= 1;
						assert_eq!(
							SecretKey::from_bytes(&bad).err(),
							Some(KeyParsingError::BadSecretKey)
						);
					}
					assert_eq!(
						SecretKey::from_bytes(&good[1..]).err(),
						Some(KeyParsingError::BadSecretKey)
					);
					assert_eq!(
						PublicKey::from_bytes(&good[..PUBLICKEYBYTES - 1]),
						Err(KeyParsingError::BadPublicKey)
					);
				}
			}
		};
	}

	api_tests!(slh_dsa_sha2_128f, 32, 64, 17088);
	api_tests!(slh_dsa_shake_128f, 32, 64, 17088);
	api_tests!(slh_dsa_sha2_192f, 48, 96, 35664);
	api_tests!(slh_dsa_shake_192f, 48, 96, 35664);
	api_tests!(slh_dsa_sha2_256f, 64, 128, 49856);
	api_tests!(slh_dsa_shake_256f, 64, 128, 49856);

	#[test]
	fn small_sets_have_fips_205_sizes() {
		use crate::*;
		assert_eq!(slh_dsa_sha2_128s::SIGNBYTES, 7856);
		assert_eq!(slh_dsa_shake_128s::SIGNBYTES, 7856);
		assert_eq!(slh_dsa_sha2_192s::SIGNBYTES, 16224);
		assert_eq!(slh_dsa_shake_192s::SIGNBYTES, 16224);
		assert_eq!(slh_dsa_sha2_256s::SIGNBYTES, 29792);
		assert_eq!(slh_dsa_shake_256s::SIGNBYTES, 29792);
	}

	#[test]
	fn prehash_oids_are_distinct() {
		let all = [
			PreHash::Sha2_224,
			PreHash::Sha2_256,
			PreHash::Sha2_384,
			PreHash::Sha2_512,
			PreHash::Sha2_512_224,
			PreHash::Sha2_512_256,
			PreHash::Sha3_224,
			PreHash::Sha3_256,
			PreHash::Sha3_384,
			PreHash::Sha3_512,
			PreHash::Shake128,
			PreHash::Shake256,
		];
		for (i, a) in all.iter().enumerate() {
			for b in &all[i + 1..] {
				assert_ne!(a.oid(), b.oid());
			}
		}
	}
}
