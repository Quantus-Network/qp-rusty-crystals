// tests/sign_integration_tests.rs

use qp_rusty_crystals_hdwallet::{derive_key_from_seed, generate_mnemonic, mnemonic_to_seed};
use rand::{rngs::OsRng, Rng, RngCore};

fn get_random_bytes() -> [u8; 32] {
	let mut rng = rand::thread_rng();
	let mut bytes = [0u8; 32];
	rng.fill(&mut bytes);
	bytes
}

#[test]
fn test_sign() {
	let mut entropy = get_random_bytes();

	// Step 1: Generate a random mnemonic and derive Dilithium keypair
	let mnemonic = generate_mnemonic((&mut entropy).into()).expect("Failed to generate mnemonic");
	let mut seed = mnemonic_to_seed(mnemonic, None).expect("Failed to create seed from mnemonic");
	let dilithium_keypair =
		derive_key_from_seed((&mut seed).into(), "m/44'/0'/0'/0/0").expect("Failed to derive key");

	// Step 2: Define the message to sign
	let message = b"Hello, Dilithium!";

	// Step 3: Sign the message using the secret key
	let signature = dilithium_keypair.sign(message, None, None).unwrap();

	// Step 4: Verify the signature using the public key
	let verify_result = dilithium_keypair.verify(message, &signature, None);

	assert!(verify_result, "Signature verification failed",);
}

#[test]
fn test_sign_multiple_messages() {
	let mut entropy = [0u8; 32];
	OsRng.fill_bytes(&mut entropy);

	let mnemonic = generate_mnemonic((&mut entropy).into()).expect("Failed to generate mnemonic");
	let mut seed = mnemonic_to_seed(mnemonic, None).expect("Failed to create seed from mnemonic");
	let dilithium_keypair =
		derive_key_from_seed((&mut seed).into(), "m/44'/0'/0'/0/0").expect("Failed to derive key");

	let messages = [
		b"First message".as_slice(),
		b"Second message",
		b"A much longer message that tests the signing of various message lengths in the integration test suite",
		b"",
		b"Single char: X",
		&[0u8; 1000], // Large message with zeros
	];

	for (i, message) in messages.iter().enumerate() {
		let signature = dilithium_keypair.sign(message, None, None).unwrap();
		let verify_result = dilithium_keypair.verify(message, &signature, None);
		assert!(verify_result, "Signature verification failed for message {}", i);
	}
}

#[test]
fn test_hedged_vs_deterministic_signing() {
	let mut entropy = [0u8; 32];
	OsRng.fill_bytes(&mut entropy);

	let mnemonic = generate_mnemonic((&mut entropy).into()).expect("Failed to generate mnemonic");
	let mut seed = mnemonic_to_seed(mnemonic, None).expect("Failed to create seed from mnemonic");
	let dilithium_keypair =
		derive_key_from_seed((&mut seed).into(), "m/44'/0'/0'/0/0").expect("Failed to derive key");

	let message = b"Test message for hedged vs deterministic";

	// Test deterministic signing
	let sig1_det = dilithium_keypair.sign(message, None, None).unwrap();
	let sig2_det = dilithium_keypair.sign(message, None, None).unwrap();

	// Deterministic signatures should be identical
	assert_eq!(sig1_det, sig2_det, "Deterministic signatures should be identical");

	// Test hedged signing
	let hedge1 = get_random_bytes();
	let hedge2 = get_random_bytes();
	let sig1_hedge = dilithium_keypair.sign(message, None, Some(hedge1)).unwrap();
	let sig2_hedge = dilithium_keypair.sign(message, None, Some(hedge2)).unwrap();

	// Hedged signatures should be different (with very high probability)
	assert_ne!(sig1_hedge, sig2_hedge, "Hedged signatures should be different");

	// All signatures should verify
	assert!(dilithium_keypair.verify(message, &sig1_det, None));
	assert!(dilithium_keypair.verify(message, &sig2_det, None));
	assert!(dilithium_keypair.verify(message, &sig1_hedge, None));
	assert!(dilithium_keypair.verify(message, &sig2_hedge, None));
}

#[test]
fn test_cross_keypair_verification_fails() {
	let mut entropy1 = [0u8; 32];
	let mut entropy2 = [0u8; 32];
	OsRng.fill_bytes(&mut entropy1);
	OsRng.fill_bytes(&mut entropy2);

	let mnemonic1 =
		generate_mnemonic((&mut entropy1).into()).expect("Failed to generate mnemonic 1");
	let mnemonic2 =
		generate_mnemonic((&mut entropy2).into()).expect("Failed to generate mnemonic 2");

	let mut seed1 =
		mnemonic_to_seed(mnemonic1, None).expect("Failed to create seed from mnemonic 1");
	let mut seed2 =
		mnemonic_to_seed(mnemonic2, None).expect("Failed to create seed from mnemonic 2");

	let keypair1 = derive_key_from_seed((&mut seed1).into(), "m/44'/0'/0'/0/0")
		.expect("Failed to derive key 1");
	let keypair2 = derive_key_from_seed((&mut seed2).into(), "m/44'/0'/0'/0/0")
		.expect("Failed to derive key 2");

	let message = b"Cross-verification test message";

	let signature1 = keypair1.sign(message, None, None).unwrap();
	let signature2 = keypair2.sign(message, None, None).unwrap();

	// Each signature should verify with its own keypair
	assert!(keypair1.verify(message, &signature1, None));
	assert!(keypair2.verify(message, &signature2, None));

	// Cross-verification should fail
	assert!(!keypair1.verify(message, &signature2, None));
	assert!(!keypair2.verify(message, &signature1, None));
}

#[test]
fn test_corrupted_signature_fails() {
	let mut entropy = [0u8; 32];
	OsRng.fill_bytes(&mut entropy);

	let mnemonic = generate_mnemonic((&mut entropy).into()).expect("Failed to generate mnemonic");
	let mut seed = mnemonic_to_seed(mnemonic, None).expect("Failed to create seed from mnemonic");
	let dilithium_keypair =
		derive_key_from_seed((&mut seed).into(), "m/44'/0'/0'/0/0").expect("Failed to derive key");

	let message = b"Message for corruption test";
	let mut signature = dilithium_keypair.sign(message, None, None).unwrap();

	// Original signature should verify
	assert!(dilithium_keypair.verify(message, &signature, None));

	// Test corruption at different positions
	let positions_to_test = [0, signature.len() / 4, signature.len() / 2, signature.len() - 1];

	for &pos in &positions_to_test {
		let original_byte = signature[pos];

		// Flip a bit
		signature[pos] ^= 0x01;
		assert!(
			!dilithium_keypair.verify(message, &signature, None),
			"Corrupted signature at position {} should not verify",
			pos
		);

		// Restore original byte
		signature[pos] = original_byte;
		assert!(
			dilithium_keypair.verify(message, &signature, None),
			"Restored signature should verify"
		);
	}
}

#[test]
fn test_same_seed_produces_same_keypair() {
	let mut entropy1 = [0x42u8; 32];
	let mut entropy2 = [0x42u8; 32];

	let mnemonic1 =
		generate_mnemonic((&mut entropy1).into()).expect("Failed to generate mnemonic 1");
	let mnemonic2 =
		generate_mnemonic((&mut entropy2).into()).expect("Failed to generate mnemonic 2");

	// Same seed should produce same mnemonic
	assert_eq!(mnemonic1, mnemonic2);

	let mut seed1 =
		mnemonic_to_seed(mnemonic1, None).expect("Failed to create seed from mnemonic 1");
	let mut seed2 =
		mnemonic_to_seed(mnemonic2, None).expect("Failed to create seed from mnemonic 2");

	let keypair1 = derive_key_from_seed((&mut seed1).into(), "m/44'/0'/0'/0/0")
		.expect("Failed to derive key 1");
	let keypair2 = derive_key_from_seed((&mut seed2).into(), "m/44'/0'/0'/0/0")
		.expect("Failed to derive key 2");

	// Same mnemonic should produce same keypair
	let message = b"Test message";
	let sig1 = keypair1.sign(message, None, None).unwrap();
	let sig2 = keypair2.sign(message, None, None).unwrap();

	// Deterministic signatures should be identical
	assert_eq!(sig1, sig2);

	// Cross-verification should work
	assert!(keypair1.verify(message, &sig2, None));
	assert!(keypair2.verify(message, &sig1, None));
}

#[test]
fn test_stress_multiple_signatures() {
	let mut entropy = [0u8; 32];
	OsRng.fill_bytes(&mut entropy);

	let mnemonic = generate_mnemonic((&mut entropy).into()).expect("Failed to generate mnemonic");
	let mut seed = mnemonic_to_seed(mnemonic, None).expect("Failed to create seed from mnemonic");
	let dilithium_keypair =
		derive_key_from_seed((&mut seed).into(), "m/44'/0'/0'/0/0").expect("Failed to derive key");

	// Sign and verify many messages
	for i in 0..50 {
		let message = format!("Message number {}", i);
		let signature = dilithium_keypair.sign(message.as_bytes(), None, None).unwrap();
		let verify_result = dilithium_keypair.verify(message.as_bytes(), &signature, None);
		assert!(verify_result, "Failed to verify signature for message {}", i);
	}
}
