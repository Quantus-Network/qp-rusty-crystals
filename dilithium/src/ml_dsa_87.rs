//! ML-DSA-87 (FIPS 204 category 5) public API.
//!
//! Thin frontend over the const-generic signing core, instantiated at the
//! [`crate::params::ml_dsa_87`] parameter set.

crate::frontend::define_ml_dsa!(crate::params::ml_dsa_87);

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
		let mut entropy = get_random_bytes();
		let keys = Keypair::generate(&mut entropy);
		let hedge = get_random_bytes();
		let sig = keys.sign(&msg, None, Some(&hedge)).unwrap();
		assert!(keys.verify(&msg, &sig, None));
	}

	#[test]
	fn self_verify() {
		let msg = get_random_msg();
		let mut entropy = get_random_bytes();
		let keys = Keypair::generate(&mut entropy);
		let hedge = get_random_bytes();
		let sig = keys.sign(&msg, None, Some(&hedge)).unwrap();
		assert!(keys.verify(&msg, &sig, None));
	}

	#[test]
	fn verify_fails_with_different_context() {
		let msg = get_random_msg();
		let mut entropy = get_random_bytes();
		let keys = Keypair::generate(&mut entropy);
		let hedge = get_random_bytes();

		// Sign with context "test1"
		let ctx1 = b"test1";
		let sig = keys.sign(&msg, Some(ctx1), Some(&hedge)).unwrap();

		// Try to verify with different context "test2" - should fail
		let ctx2 = b"test2";
		assert!(!keys.verify(&msg, &sig, Some(ctx2)));

		// Verify with correct context should still work
		assert!(keys.verify(&msg, &sig, Some(ctx1)));
	}

	#[test]
	fn sign_rejects_oversized_message() {
		let keys = Keypair::generate(&mut get_random_bytes());
		let big_msg = vec![0u8; MAX_MESSAGE_SIZE + 1];
		let result = keys.sign(&big_msg, None, None);
		assert!(matches!(result, Err(SignatureError::MessageTooLong)));
	}

	#[test]
	fn verify_rejects_oversized_message() {
		let keys = Keypair::generate(&mut get_random_bytes());
		let big_msg = vec![0u8; MAX_MESSAGE_SIZE + 1];
		assert!(!keys.verify(&big_msg, &[0u8; SIGNBYTES], None));
	}

	crate::frontend::adversarial_import_tests!();
}
