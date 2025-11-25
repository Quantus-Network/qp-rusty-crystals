// tests/sign_integration_tests.rs

use qp_rusty_crystals_hdwallet::{generate_mnemonic, HDLattice};
use rand::{rngs::OsRng, Rng, RngCore};

fn get_random_bytes() -> [u8; 32] {
	let mut rng = rand::thread_rng();
	let mut bytes = [0u8; 32];
	rng.fill(&mut bytes);
	bytes
}

#[test]
fn test_sign() {
	let seed = get_random_bytes();

	// Step 1: Generate a random mnemonic and derive Dilithium keypair
	let mnemonic = generate_mnemonic(seed).expect("Failed to generate mnemonic");
	let hd_lattice = HDLattice::from_mnemonic(&mnemonic, None)
		.expect("Failed to create HDLattice from mnemonic");

	let dilithium_keypair = hd_lattice.generate_keys();

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
	let mut seed = [0u8; 32];
	OsRng.fill_bytes(&mut seed);

	let mnemonic = generate_mnemonic(seed).expect("Failed to generate mnemonic");
	let hd_lattice = HDLattice::from_mnemonic(&mnemonic, None)
		.expect("Failed to create HDLattice from mnemonic");
	let dilithium_keypair = hd_lattice.generate_keys();

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
	let mut seed = [0u8; 32];
	OsRng.fill_bytes(&mut seed);

	let mnemonic = generate_mnemonic(seed).expect("Failed to generate mnemonic");
	let hd_lattice = HDLattice::from_mnemonic(&mnemonic, None)
		.expect("Failed to create HDLattice from mnemonic");
	let dilithium_keypair = hd_lattice.generate_keys();

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
	let mut seed1 = [0u8; 32];
	let mut seed2 = [0u8; 32];
	OsRng.fill_bytes(&mut seed1);
	OsRng.fill_bytes(&mut seed2);

	let mnemonic1 = generate_mnemonic(seed1).expect("Failed to generate mnemonic 1");
	let mnemonic2 = generate_mnemonic(seed2).expect("Failed to generate mnemonic 2");

	let hd_lattice1 =
		HDLattice::from_mnemonic(&mnemonic1, None).expect("Failed to create HDLattice 1");
	let hd_lattice2 =
		HDLattice::from_mnemonic(&mnemonic2, None).expect("Failed to create HDLattice 2");

	let keypair1 = hd_lattice1.generate_keys();
	let keypair2 = hd_lattice2.generate_keys();

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
	let mut seed = [0u8; 32];
	OsRng.fill_bytes(&mut seed);

	let mnemonic = generate_mnemonic(seed).expect("Failed to generate mnemonic");
	let hd_lattice = HDLattice::from_mnemonic(&mnemonic, None)
		.expect("Failed to create HDLattice from mnemonic");
	let dilithium_keypair = hd_lattice.generate_keys();

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
	let seed = [0x42u8; 32];

	let mnemonic1 = generate_mnemonic(seed).expect("Failed to generate mnemonic 1");
	let mnemonic2 = generate_mnemonic(seed).expect("Failed to generate mnemonic 2");

	// Same seed should produce same mnemonic
	assert_eq!(mnemonic1, mnemonic2);

	let hd_lattice1 =
		HDLattice::from_mnemonic(&mnemonic1, None).expect("Failed to create HDLattice 1");
	let hd_lattice2 =
		HDLattice::from_mnemonic(&mnemonic2, None).expect("Failed to create HDLattice 2");

	let keypair1 = hd_lattice1.generate_keys();
	let keypair2 = hd_lattice2.generate_keys();

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
	let mut seed = [0u8; 32];
	OsRng.fill_bytes(&mut seed);

	let mnemonic = generate_mnemonic(seed).expect("Failed to generate mnemonic");
	let hd_lattice = HDLattice::from_mnemonic(&mnemonic, None)
		.expect("Failed to create HDLattice from mnemonic");
	let dilithium_keypair = hd_lattice.generate_keys();

	// Sign and verify many messages
	for i in 0..50 {
		let message = format!("Message number {}", i);
		let signature = dilithium_keypair.sign(message.as_bytes(), None, None).unwrap();
		let verify_result = dilithium_keypair.verify(message.as_bytes(), &signature, None);
		assert!(verify_result, "Failed to verify signature for message {}", i);
	}
}
