// tests/verify_integration_test.rs

mod helpers;

use helpers::kat::{parse_test_vectors, TestVector};
use rand::{thread_rng, Rng};
use rusty_crystals_dilithium::ml_dsa_87::{Keypair, PUBLICKEYBYTES};

fn keypair_from_test(test: &TestVector) -> Keypair {
	let total_len = test.sk.len() + test.pk.len();
	let mut result = vec![0; total_len];
	result[..test.sk.len()].copy_from_slice(&test.sk);
	result[test.sk.len()..].copy_from_slice(&test.pk);
	Keypair::from_bytes(&result).unwrap()
}

#[test]
fn test_nist_kat() {
	let kat_data = include_str!("../test_vectors/PQCsignKAT_Dilithium5.rsp");
	let test_vectors = parse_test_vectors(kat_data);
	for test in test_vectors {
		verify_test_vector(&test);
	}
}

/// Verifies a single test vector for Falcon-1024 (padded).
///
/// # Arguments
///
/// * `test` - A reference to the `TestVector` struct containing all the necessary fields.
fn verify_test_vector(test: &TestVector) {
	// Check if the fields have correct lengths
	assert_eq!(test.msg.len(), test.mlen, "Message length mismatch from test vector");
	assert_eq!(test.sm.len(), test.smlen, "Signed message length mismatch from test vector");
	// Check public key length for Dilithium5
	assert_eq!(test.pk.len(), PUBLICKEYBYTES, "Public key length mismatch");

	let signature = test.extract_signature();

	// Now call verify with the extracted signature

	let keypair = keypair_from_test(test);
	let result = keypair.verify(&test.msg, signature, None);

	assert!(result, "Signature verification failed",);

	// Fuzzing loop: randomly modify signature and verify it fails
	let mut rng = thread_rng();
	let num_fuzz_attempts = 20; // Number of random modifications to test

	for _ in 0..num_fuzz_attempts {
		let mut fuzzed_signature = signature.to_vec();

		// Skip if signature is empty
		if fuzzed_signature.is_empty() {
			continue;
		}

		// Randomly choose modification type
		let modification_type = rng.gen_range(0..4);

		match modification_type {
			0 => {
				// Flip a random bit
				let byte_index = rng.gen_range(0..fuzzed_signature.len());
				let bit_index = rng.gen_range(0..8);
				fuzzed_signature[byte_index] ^= 1 << bit_index;
			},
			1 => {
				// Replace a random byte with a random value
				let byte_index = rng.gen_range(0..fuzzed_signature.len());
				let previous = fuzzed_signature[byte_index];
				let mut new_value = rng.gen();
				// Make sure it is actually different
				while new_value == previous {
					new_value = rng.gen();
				}
				fuzzed_signature[byte_index] = new_value;
			},
			2 => {
				// Zero out a random byte (only if it's not already zero)
				let byte_index = rng.gen_range(0..fuzzed_signature.len());
				if fuzzed_signature[byte_index] != 0 {
					println!("Zero out byte at index {}", byte_index);
					fuzzed_signature[byte_index] = 0;
				} else {
					// If it's already zero, set it to a non-zero value
					println!("Byte at index {} was already zero, setting to non-zero", byte_index);
					fuzzed_signature[byte_index] = rng.gen_range(1..=255);
				}
			},
			3 => {
				// Modify multiple bytes (1-5 bytes)
				let num_bytes_to_modify = rng.gen_range(1..=5.min(fuzzed_signature.len()));
				println!("Modifying {} bytes", num_bytes_to_modify);
				for _ in 0..num_bytes_to_modify {
					let byte_index = rng.gen_range(0..fuzzed_signature.len());
					let previous = fuzzed_signature[byte_index];
					let mut new_value = rng.gen();
					while new_value == previous {
						new_value = rng.gen();
					}
					fuzzed_signature[byte_index] = new_value;
				}
			},
			_ => unreachable!(),
		}

		// Verify that the fuzzed signature fails verification
		let fuzzed_result = keypair.verify(&test.msg, &fuzzed_signature, None);
		assert!(
            !fuzzed_result,
            "Fuzzed signature unexpectedly passed verification! Original signature length: {}, fuzzed signature length: {}",
            signature.len(),
            fuzzed_signature.len()
        );
	}
}

#[test]
fn test_verify_invalid_signature() {
	// Generate Dilithium keypair
	let keys_1 = Keypair::generate(None);
	let keys_2 = Keypair::generate(None);
	let keys_3 = Keypair::generate(None);

	// Message to sign
	let message = b"Hello, Quantus!";
	// Sign the message
	let signature = keys_2.sign(message, None, false);

	// Verify the signature with wrong key
	let result = keys_1.verify(&signature, message, None);

	assert!(!result, "Expected verification to fail, but it succeeded");

	let result = keys_3.verify(&signature, message, None);

	assert!(!result, "Expected verification to fail, but it succeeded");
}
