// tests/sign_integration_tests.rs

use qp_rusty_crystals_hdwallet::{generate_mnemonic, HDLattice};
use rand::{rngs::OsRng, RngCore};

#[test]
fn test_sign() {
	let mut seed = [0u8; 32];

	// Use os rng to make seed
	OsRng.fill_bytes(&mut seed);
	// Step 1: Generate a random mnemonic and derive Dilithium keypair
	let mnemonic = generate_mnemonic(24, seed).expect("Failed to generate mnemonic");
	let hd_lattice = HDLattice::from_mnemonic(&mnemonic, None)
		.expect("Failed to create HDLattice from mnemonic");

	let dilithium_keypair = hd_lattice.generate_keys();

	// Step 2: Define the message to sign
	let message = b"Hello, Dilithium!";

	// Step 3: Sign the message using the secret key
	let signature = dilithium_keypair.sign(message, None, false);

	// Step 4: Verify the signature using the public key
	let verify_result = dilithium_keypair.verify(message, &signature, None);

	assert!(verify_result, "Signature verification failed",);
}
