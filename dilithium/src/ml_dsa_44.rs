//! ML-DSA-44 (FIPS 204 category 2) public API.
//!
//! Thin frontend over the const-generic signing core, instantiated at the
//! [`crate::params::ml_dsa_44`] parameter set.

crate::frontend::define_ml_dsa!(crate::params::ml_dsa_44);

#[cfg(test)]
mod tests {
	use super::{Keypair, PublicKey, MAX_MESSAGE_SIZE, SIGNBYTES};
	use crate::{errors::SignatureError, SensitiveBytes32};
	use alloc::vec;
	use rand::RngExt;

	fn entropy() -> SensitiveBytes32 {
		let mut rng = rand::rng();
		let mut bytes = [0u8; 32];
		rng.fill(&mut bytes);
		(&mut bytes).into()
	}

	#[test]
	fn self_verify_roundtrip() {
		let keys = Keypair::generate(entropy());
		let msg = b"ml-dsa-44 smoke test";
		let sig = keys.sign(msg, None, None).unwrap();
		assert!(keys.verify(msg, &sig, None));
		assert_eq!(sig.len(), SIGNBYTES);
		assert_eq!(SIGNBYTES, 2420);
		assert_eq!(super::PUBLICKEYBYTES, 1312);
		assert_eq!(super::SECRETKEYBYTES, 2560);
	}

	#[test]
	fn hedged_and_context() {
		let keys = Keypair::generate(entropy());
		let msg = b"ctx";
		let h1 = entropy();
		let h2 = entropy();
		let s1 = keys.sign(msg, Some(b"a"), Some(h1.0)).unwrap();
		let s2 = keys.sign(msg, Some(b"a"), Some(h2.0)).unwrap();
		assert_ne!(s1, s2);
		assert!(keys.verify(msg, &s1, Some(b"a")));
		assert!(!keys.verify(msg, &s1, Some(b"b")));
	}

	#[test]
	fn rejects_oversized_message() {
		let keys = Keypair::generate(entropy());
		let big = vec![0u8; MAX_MESSAGE_SIZE + 1];
		assert!(matches!(keys.sign(&big, None, None), Err(SignatureError::MessageTooLong)));
		assert!(!keys.verify(&big, &[0u8; SIGNBYTES], None));
	}

	#[test]
	fn rejects_zero_t1_public_key() {
		use crate::params;
		let mut pk = [0u8; super::PUBLICKEYBYTES];
		pk[..params::SEEDBYTES].copy_from_slice(&[0x42u8; params::SEEDBYTES]);
		assert!(matches!(
			PublicKey::from_bytes(&pk),
			Err(crate::errors::KeyParsingError::BadPublicKey)
		));
	}
}
