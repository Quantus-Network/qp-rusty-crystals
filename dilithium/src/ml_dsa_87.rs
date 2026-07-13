use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
	errors::{KeyParsingError, KeyParsingError::BadSecretKey, SignatureError},
	params, SensitiveBytes32,
};
use core::fmt;

pub const SECRETKEYBYTES: usize = crate::params::SECRETKEYBYTES;
pub const PUBLICKEYBYTES: usize = crate::params::PUBLICKEYBYTES;
pub const SIGNBYTES: usize = crate::params::SIGNBYTES;
pub const KEYPAIRBYTES: usize = SECRETKEYBYTES + PUBLICKEYBYTES;

/// Maximum message size for signing/verification (64 MiB).
///
/// This limit prevents denial-of-service attacks via memory exhaustion from
/// oversized messages. The limit is generous enough for any legitimate use case.
pub const MAX_MESSAGE_SIZE: usize = 64 * 1024 * 1024;

pub type Signature = [u8; SIGNBYTES];

/// A pair of private and public keys.
///
/// `Clone` is intentionally not derived because the embedded `SecretKey` is sensitive.
/// To explicitly copy a keypair (e.g. to move it into a closure), serialize and
/// reconstruct: `Keypair::from_bytes(&keypair.to_bytes())?`. This forces the
/// duplication of secret material to be visible at every call site.
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
	///
	/// # Consistency check
	///
	/// The public half is re-derived from the secret half and must match the
	/// supplied public-key bytes exactly; otherwise this returns
	/// [`KeyParsingError::BadKeypair`]. This prevents importing a keypair whose
	/// public key does not correspond to its secret key — which would otherwise
	/// let an object sign with one key while advertising an unrelated public key
	/// (e.g. a receive address the victim cannot spend from).
	///
	/// The secret key's internal invariants are checked as well: the stored
	/// `t0` must match the low bits re-derived from `(rho, s1, s2)`, and the
	/// stored `tr` must equal `SHAKE256(pk)`. Signing uses both fields, so a
	/// blob corrupted in those regions would otherwise import cleanly and then
	/// produce signatures that fail under the advertised public key.
	///
	/// Note: the `secret` and `public` fields are public, so callers can still
	/// construct or mutate a `Keypair` with mismatched halves directly. This
	/// check only guards the deserialization/import path.
	pub fn from_bytes(bytes: &[u8]) -> Result<Keypair, KeyParsingError> {
		if bytes.len() != SECRETKEYBYTES + PUBLICKEYBYTES {
			return Err(KeyParsingError::BadKeypair);
		}
		let (secret_bytes, public_bytes) = bytes.split_at(SECRETKEYBYTES);
		let secret =
			SecretKey::from_bytes(secret_bytes).map_err(|_| KeyParsingError::BadKeypair)?;
		let public =
			PublicKey::from_bytes(public_bytes).map_err(|_| KeyParsingError::BadKeypair)?;

		// Enforce the cross-field invariants: the secret key must be internally
		// consistent (tr, t0) and the public key must be the one that corresponds
		// to it. The derived pk is public data, so a non-constant-time comparison
		// is fine.
		let derived_public = crate::sign::public_key_from_secret(&secret.bytes)
			.ok_or(KeyParsingError::BadKeypair)?;
		if derived_public != public.bytes {
			return Err(KeyParsingError::BadKeypair);
		}

		Ok(Keypair { secret, public })
	}

	/// Compute a signature for a given message.
	///
	/// # Arguments
	///
	/// * 'msg' - message to sign (max 64 MiB)
	/// * 'ctx' - optional context string (max 255 bytes)
	/// * 'hedge' - optional random bytes for hedged signing
	///
	/// # Errors
	///
	/// Returns `SignatureError::MessageTooLong` if the message exceeds 64 MiB.
	/// Returns `SignatureError::ContextTooLong` if the context exceeds 255 bytes.
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
	/// * 'msg' - message that is claimed to be signed (max 64 MiB)
	/// * 'sig' - signature to verify
	/// * 'ctx' - optional context string (max 255 bytes)
	///
	/// Returns 'true' if the verification process was successful, 'false' otherwise.
	/// Returns 'false' if the message exceeds 64 MiB, the context exceeds 255 bytes,
	/// or the signature length is incorrect.
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
///
/// `Clone` is intentionally not derived because the underlying bytes are sensitive.
/// To explicitly copy a secret key, use `SecretKey::from_bytes(&sk.to_bytes())?`,
/// which makes the duplication of secret material visible at every call site.
#[derive(ZeroizeOnDrop)]
pub struct SecretKey {
	bytes: [u8; SECRETKEYBYTES],
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
	/// * 'msg' - message to sign (max 64 MiB)
	/// * 'ctx' - context string (max 255 bytes)
	/// * 'hedged' - wether to use RNG or not
	///
	/// # Errors
	///
	/// Returns `SignatureError::MessageTooLong` if the message exceeds 64 MiB.
	/// Returns `SignatureError::ContextTooLong` if the context exceeds 255 bytes.
	pub fn sign(
		&self,
		msg: &[u8],
		ctx: Option<&[u8]>,
		hedge: Option<[u8; params::SEEDBYTES]>,
	) -> Result<Signature, SignatureError> {
		if msg.len() > MAX_MESSAGE_SIZE {
			return Err(SignatureError::MessageTooLong);
		}
		// The message is hashed as `domain_prefix || msg`. Only the small (<= 257
		// byte) domain prefix is materialized; `msg` is passed by reference and
		// absorbed directly, so an attacker-sized message is never copied.
		match ctx {
			Some(x) => {
				if x.len() > 255 {
					return Err(SignatureError::ContextTooLong);
				}
				let x_len = x.len();
				let mut prefix = [0u8; 2 + 255];
				prefix[1] = x_len as u8;
				prefix[2..2 + x_len].copy_from_slice(x);
				let mut sig: Signature = [0u8; SIGNBYTES];
				crate::sign::signature(&mut sig, &prefix[..2 + x_len], msg, &self.bytes, hedge);
				Ok(sig)
			},
			None => {
				let mut sig: Signature = [0u8; SIGNBYTES];
				// Prefix 2 zero bytes (domain_sep=0, context_len=0) for pure signatures
				crate::sign::signature(&mut sig, &[0u8, 0u8], msg, &self.bytes, hedge);
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
		let bytes: [u8; PUBLICKEYBYTES] =
			bytes.try_into().map_err(|_| KeyParsingError::BadPublicKey)?;

		// Reject the degenerate all-zero t1 public key. With t1 = 0 the challenge term in the
		// verification relation vanishes, letting an attacker forge signatures without any
		// secret key (see `sign::verify`). Honest key generation never produces t1 = 0, so
		// this only rejects malformed/malicious keys and never a legitimate one.
		let mut rho = [0u8; params::SEEDBYTES];
		let mut t1 = crate::polyvec::Polyveck::default();
		crate::packing::unpack_pk(&mut rho, &mut t1, &bytes);
		if t1.vec.iter().all(|p| p.coeffs.iter().all(|&c| c == 0)) {
			return Err(KeyParsingError::BadPublicKey);
		}

		Ok(PublicKey { bytes })
	}

	/// Verify a signature for a given message with a public key.
	///
	/// # Arguments
	///
	/// * 'msg' - message that is claimed to be signed (max 64 MiB)
	/// * 'sig' - signature to verify
	/// * 'ctx' - context string (max 255 bytes)
	///
	/// Returns 'true' if the verification process was successful, 'false' otherwise.
	/// Returns 'false' early if the message exceeds 64 MiB or context exceeds 255 bytes.
	pub fn verify(&self, msg: &[u8], sig: &[u8], ctx: Option<&[u8]>) -> bool {
		// Validate signature length first
		let sig: &[u8; SIGNBYTES] = match sig.try_into() {
			Ok(s) => s,
			Err(_) => return false,
		};
		if msg.len() > MAX_MESSAGE_SIZE {
			return false;
		}
		// As in `sign`, only the small domain prefix is materialized; the message
		// is absorbed by reference rather than copied into a full-size buffer.
		match ctx {
			Some(x) => {
				if x.len() > 255 {
					return false;
				}
				let x_len = x.len();
				let mut prefix = [0u8; 2 + 255];
				prefix[1] = x_len as u8;
				prefix[2..2 + x_len].copy_from_slice(x);
				crate::sign::verify(sig, &prefix[..2 + x_len], msg, &self.bytes)
			},
			None => crate::sign::verify(sig, &[0u8, 0u8], msg, &self.bytes),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::{Keypair, MAX_MESSAGE_SIZE, SIGNBYTES};
	use crate::{errors::SignatureError, SensitiveBytes32};
	use alloc::vec;
	use rand::RngExt;

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

	#[test]
	fn sign_rejects_oversized_message() {
		let keys = Keypair::generate(get_random_bytes());
		let big_msg = vec![0u8; MAX_MESSAGE_SIZE + 1];
		let result = keys.sign(&big_msg, None, None);
		assert!(matches!(result, Err(SignatureError::MessageTooLong)));
	}

	#[test]
	fn verify_rejects_oversized_message() {
		let keys = Keypair::generate(get_random_bytes());
		let big_msg = vec![0u8; MAX_MESSAGE_SIZE + 1];
		assert!(!keys.verify(&big_msg, &[0u8; SIGNBYTES], None));
	}

	// A keypair blob whose public half does not correspond to its secret half must
	// be rejected. Otherwise an imported keypair could sign with one key while
	// advertising an unrelated public key (e.g. an unspendable receive address).
	#[test]
	fn from_bytes_rejects_mismatched_public_key() {
		use super::{Keypair, KeyParsingError, KEYPAIRBYTES, SECRETKEYBYTES};

		let keys_a = Keypair::generate(get_random_bytes());
		let keys_b = Keypair::generate(get_random_bytes());

		// Genuine keypair bytes must round-trip.
		let good = keys_a.to_bytes();
		assert!(Keypair::from_bytes(&good).is_ok(), "honest keypair must be accepted");

		// Splice A's secret key with B's (unrelated) public key.
		let mut forged = [0u8; KEYPAIRBYTES];
		forged[..SECRETKEYBYTES].copy_from_slice(&keys_a.secret.to_bytes());
		forged[SECRETKEYBYTES..].copy_from_slice(&keys_b.public.to_bytes());

		assert!(
			matches!(Keypair::from_bytes(&forged), Err(KeyParsingError::BadKeypair)),
			"public key not derived from the secret key must be rejected"
		);
	}

	// The packed secret key stores tr = SHAKE256(pk) and t0 (low bits of
	// A·s1 + s2) alongside (rho, s1, s2). Signing uses the stored tr and t0, so
	// a blob with honest rho/s1/s2/pk but a corrupted tr or t0 region would
	// import cleanly and then produce signatures that fail under the advertised
	// public key. `from_bytes` must reject such blobs at import.
	#[test]
	fn from_bytes_rejects_corrupted_tr_or_t0() {
		use super::{Keypair, KeyParsingError, SECRETKEYBYTES};
		use crate::params::{POLYT0_PACKEDBYTES, SEEDBYTES, TR_BYTES};

		let keys = Keypair::generate(get_random_bytes());
		let good = keys.to_bytes();
		assert!(Keypair::from_bytes(&good).is_ok(), "honest keypair must be accepted");

		// SK layout: rho (32) || key (32) || tr (64) || s1 || s2 || t0.
		let tr_offset = 2 * SEEDBYTES;
		let t0_offset = SECRETKEYBYTES - crate::params::K * POLYT0_PACKEDBYTES;

		// Corrupt one byte inside the stored tr region only.
		let mut bad_tr = good;
		bad_tr[tr_offset + TR_BYTES / 2] ^= 0x01;
		assert!(
			matches!(Keypair::from_bytes(&bad_tr), Err(KeyParsingError::BadKeypair)),
			"secret key with corrupted tr must be rejected"
		);

		// Corrupt one byte inside the stored t0 region only.
		let mut bad_t0 = good;
		bad_t0[t0_offset] ^= 0x01;
		assert!(
			matches!(Keypair::from_bytes(&bad_t0), Err(KeyParsingError::BadKeypair)),
			"secret key with corrupted t0 must be rejected"
		);
	}

	// Malicious-key forgery defense: a public key with an all-zero t1 makes verification
	// independent of the challenge, enabling signature forgery without a secret key.
	// `from_bytes` must reject such a key so it can never be constructed or stored.
	#[test]
	fn from_bytes_rejects_zero_t1_public_key() {
		use super::{KeyParsingError, PublicKey, PUBLICKEYBYTES};

		// Arbitrary rho, all-zero t1 region.
		let mut pk = [0u8; PUBLICKEYBYTES];
		pk[..crate::params::SEEDBYTES].copy_from_slice(&[0x42u8; crate::params::SEEDBYTES]);

		assert!(matches!(PublicKey::from_bytes(&pk), Err(KeyParsingError::BadPublicKey)));

		// A genuine public key must still round-trip through from_bytes.
		let keys = Keypair::generate(get_random_bytes());
		let good = keys.public.to_bytes();
		assert!(PublicKey::from_bytes(&good).is_ok());
	}
}
