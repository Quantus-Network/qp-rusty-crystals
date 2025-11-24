use alloc::string::String;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct TestVector {
	pub(crate) seed: String,
	pub(crate) path: String,
	pub(crate) private_key: String,
}

#[cfg(test)]
mod hdwallet_tests {
	use crate::{
		generate_mnemonic,
		test_vectors::{
			get_test_vectors, load_known_private_keys, str_to_32_bytes, str_to_64_bytes,
		},
		HDLattice, HDLatticeError,
	};
	use alloc::{
		borrow::ToOwned,
		format,
		string::{String, ToString},
		vec::Vec,
	};
	use core::str::FromStr;
	use nam_tiny_hderive::{bip32::ExtendedPrivKey, bip44::ChildNumber};
	use qp_rusty_crystals_dilithium::ml_dsa_87::Keypair;
	use rand_chacha::ChaCha20Rng;
	use rand_core::{RngCore, SeedableRng};

	// For test-only functionality that needs std
	#[cfg(test)]
	extern crate std;
	#[cfg(test)]
	use std::dbg;
	#[cfg(test)]
	use std::println;

	#[test]
	fn test_from_seed() {
		let mnemonic = "rocket primary way job input cactus submit menu zoo burger rent impose";
		let hd1 = HDLattice::from_mnemonic(mnemonic, None).unwrap();
		let hd2 = HDLattice::from_seed(hd1.seed).unwrap();
		assert_eq!(hd1.master_key, hd2.master_key);
		assert_eq!(hd1.seed, hd2.seed);
	}

	#[test]
	fn test_mnemonic_creation() {
		let seed = [43u8; 32];

		// Test generating new mnemonic
		let mnemonic = dbg!(generate_mnemonic(seed).unwrap());
		assert_eq!(mnemonic.split_whitespace().count(), 24);
		// println!("Generated mnemonic: {}", mnemonic);
		// Test creating HDEntropy from mnemonic
		let hd = HDLattice::from_mnemonic(&mnemonic, None).unwrap();
		let hd2 = HDLattice::from_mnemonic(&mnemonic, None).unwrap();
		let hd3 = HDLattice::from_mnemonic(&mnemonic, Some("password")).unwrap();
		// println!("Generated hd: {:?}", hd.master_key);

		// Derive some child seeds
		let master_key = hd.generate_keys();
		let key2 = hd2.generate_keys();
		let key3 = hd3.generate_keys();
		// println!("Generated key: {:?}", master_key.public.to_bytes());

		// // Seeds should be different but deterministic
		assert_ne!(master_key.secret.bytes, key3.secret.bytes, "password has no effect");
		assert_eq!(master_key.secret.bytes, key2.secret.bytes, "keys are not deterministic");

		let derived_key = hd.generate_derived_keys("m/0'/2147483647'/1'").unwrap();
		assert_ne!(master_key.secret.bytes, derived_key.secret.bytes, "derived key not derived");

		// UNCOMMENT THIS AND RUN WITH `cargo test -- --nocapture` TO GENERATE TEST VECTORS
		// let vecs = generate_test_vectors(10);
		// print_keys_mnemonics_paths_as_test_vector(&vecs);
	}

	#[test]
	fn test_same_mnemonic_same_path_deterministic() {
		let mnemonic = "rocket primary way job input cactus submit menu zoo burger rent impose";
		let hd1 = HDLattice::from_mnemonic(mnemonic, None).unwrap();
		let hd2 = HDLattice::from_mnemonic(mnemonic, None).unwrap();
		let paths = ["", "m", "m/0'/2147483647'/1'", "m/44'/60'/0'/0/0", "m/1'/2'/3'"];
		for p in paths {
			let k1 = if p.is_empty() || p == "m" {
				hd1.generate_keys()
			} else {
				hd1.generate_derived_keys(p).unwrap()
			};
			let k2 = if p.is_empty() || p == "m" {
				hd2.generate_keys()
			} else {
				hd2.generate_derived_keys(p).unwrap()
			};
			assert_eq!(k1.secret.bytes, k2.secret.bytes);
			assert_eq!(k1.public.bytes, k2.public.bytes);
		}
	}

	#[allow(dead_code)]
	fn generate_test_vectors(n: u8) -> Vec<(Keypair, String, String)> {
		let mut seed = [0u8; 32];
		(0..n)
			.map(|_| {
				let mut rng = ChaCha20Rng::from_seed(seed);
				rng.fill_bytes(&mut seed);
				let mnemonic = generate_mnemonic(seed).unwrap();
				let hd = HDLattice::from_mnemonic(&mnemonic, None).unwrap();
				let path = generate_random_path();
				let k = hd.generate_derived_keys(&path).unwrap();
				(k, mnemonic, path)
			})
			.collect()
	}

	#[test]
	fn test_derive_seed() {
		for (expected_keys, mnemonic_str, derivation_path) in get_test_vectors() {
			let hd = HDLattice::from_mnemonic(mnemonic_str, None).unwrap();
			// println!("Deriving seed for path: {}", derivation_path);
			// Generate keys based on the derivation path
			let generated_keys = if derivation_path.is_empty() {
				hd.generate_keys()
			} else {
				hd.generate_derived_keys(derivation_path).unwrap()
			};

			// Compare secret keys
			assert_eq!(
				generated_keys.secret.bytes, expected_keys.secret.bytes,
				"Secret key mismatch for path: {derivation_path}"
			);

			// Compare public keys
			assert_eq!(
				generated_keys.public.bytes, expected_keys.public.bytes,
				"Public key mismatch for path: {derivation_path}"
			);
		}
	}

	#[allow(dead_code)]
	fn generate_random_path() -> String {
		let seed = [11u8; 32];
		let mut rng = ChaCha20Rng::from_seed(seed);
		// Generate length between 5 and 15 using RngCore
		let length = (rng.next_u32() % 10) + 5;

		"m/".to_owned() +
			&(0..length)
				.map(|_| (rng.next_u32() % 99) + 1) // Generate number between 1 and 99
				.map(|num| num.to_string() + "\'")
				.collect::<Vec<_>>()
				.join("/")
	}

	// Leave this in, we may need to generate new test vectors
	#[allow(dead_code)]
	fn print_keys_mnemonics_paths_as_test_vector(keys: &[(Keypair, String, String)]) {
		let mut vector_str = String::from("[\n");
		for (key, mnemonic, path) in keys.iter() {
			vector_str.push_str(&format!(
				"    (Keypair::from_bytes(&*vec![{}]).expect(\"Should not fail\"), \"{}\", \"{}\"),\n",
				key.to_bytes()
					.iter()
					.map(|b| format!("0x{b:02x}"))
					.collect::<Vec<String>>()
					.join(", "),
				mnemonic,
				path
			));
		}
		vector_str.push(']');

		println!("{vector_str}");
	}

	#[test]
	fn test_generate_mnemonic_valid_length() {
		// Use a deterministic seed for testing
		let mut seed = [42u8; 32];
		let mut rng = ChaCha20Rng::from_seed(seed);
		rng.fill_bytes(&mut seed);
		let mnemonic = generate_mnemonic(seed)
			.unwrap_or_else(|_| panic!("Failed to generate mnemonic for 24 words"));

		// Split mnemonic into words and count them
		let word_count_result = mnemonic.split_whitespace().count();

		// Assert the word count matches the expected
		assert_eq!(
			word_count_result, 24,
			"Expected 24 words, but got {word_count_result}"
		);
	}

	#[test]
	fn test_derive_invalid_path() {
		// Create a sample HDLattice instance
		let mnemonic = "rocket primary way job input cactus submit menu zoo burger rent impose";
		let hd = HDLattice::from_mnemonic(mnemonic, None).unwrap();

		// Attempt to derive a key with an invalid path
		let result = hd.derive_entropy("abc");

		assert_eq!(
			result.err().unwrap(),
			HDLatticeError::GenericError(nam_tiny_hderive::Error::InvalidDerivationPath),
			"Expected InvalidChildNumber error"
		);
	}

	#[test]
	fn test_derive_invalid_index() {
		// Create a sample HDLattice instance
		let mnemonic = "rocket primary way job input cactus submit menu zoo burger rent impose";
		let hd = HDLattice::from_mnemonic(mnemonic, None).unwrap();

		// Attempt to derive a key with an invalid index
		let result = hd.derive_entropy("m/2147483648'"); // Index exceeds HARDENED_OFFSET (2^31)

		assert!(result.is_err());
		assert_eq!(
			result.err().unwrap(),
			HDLatticeError::GenericError(nam_tiny_hderive::Error::InvalidChildNumber),
			"Expected InvalidChildNumber error"
		);
	}

	#[test]
	fn test_derive_with_non_integer_path() {
		let mnemonic = "rocket primary way job input cactus submit menu zoo burger rent impose";
		let hd = HDLattice::from_mnemonic(mnemonic, None).unwrap();

		// Valid derivation path with multiple levels
		let result = hd.derive_entropy("1/a/2");

		assert!(result.is_err());
		assert_eq!(
			result.err().unwrap(),
			HDLatticeError::GenericError(nam_tiny_hderive::Error::InvalidDerivationPath),
			"Expected InvalidChildNumber error"
		);
	}

	#[test]
	fn test_generate_derived_keys_0() {
		// Rename test since it's no longer about 'm' path
		let mnemonic = "rocket primary way job input cactus submit menu zoo burger rent impose";
		let hd = HDLattice::from_mnemonic(mnemonic, None).unwrap();

		// Test with empty string instead of "m"
		let derived_key_0 = hd.derive_entropy("m").unwrap();

		assert_eq!(
			hd.master_key, derived_key_0,
			"Derived key from empty path should match the master seed"
		);
	}

	#[test]
	fn test_tiny_hderive_api() {
		let mnemonic = "rocket primary way job input cactus submit menu zoo burger rent impose";
		let _hd = HDLattice::from_mnemonic(mnemonic, None).unwrap();

		// Test that nam-tiny-hderive works with our seed format
		let seed: &[u8] = &[42; 64];
		let path = "m/44'/60'/0'/0/0";
		let ext = ExtendedPrivKey::derive(seed, path).unwrap();
		assert_eq!(&ext.secret(), b"\x98\x84\xbf\x56\x24\xfa\xdd\x7f\xb2\x80\x4c\xfb\x0c\xb6\xf7\x1f\x28\x9e\x21\x1f\xcf\x0d\xe8\x36\xa3\x84\x17\x57\xda\xd9\x70\xd0");

		let base_ext = ExtendedPrivKey::derive(seed, "m/44'/60'/0'/0").unwrap();
		let child_ext = base_ext.child(ChildNumber::from_str("0").unwrap()).unwrap();
		assert_eq!(ext, child_ext);
	}

	#[test]
	fn test_wormhole_derivation() {
		let mnemonic = "rocket primary way job input cactus submit menu zoo burger rent impose";
		let hd = HDLattice::from_mnemonic(mnemonic, None).unwrap();

		let result = hd.generate_wormhole_pair_from_path("m/44'/60'/0'");
		assert!(result.is_err());

		let result2 = hd.generate_wormhole_pair_from_path("m/44'/189189189'");
		assert!(result2.is_ok());

		let result3 = hd.generate_wormhole_pair();
		assert!(result3.is_ok());
	}

	#[test]
	fn test_master_key_from_seed() {
		let mnemonic = "rocket primary way job input cactus submit menu zoo burger rent impose";
		let hd = HDLattice::from_mnemonic(mnemonic, None).unwrap();
		let master = HDLattice::master_key_from_seed(&hd.seed).unwrap();
		assert_eq!(master, hd.master_key, "Master key from seed should match the master key");
	}

	#[test]
	fn test_entropy_from_seeds() {
		let vectors = load_known_private_keys("./json/bip44_test_vectors.json").unwrap();

		// For demonstration: print the parsed vectors
		for vector in vectors {
			println!("{vector:?}");
			let hd = HDLattice::from_seed(str_to_64_bytes(&vector.seed)).unwrap();
			let entropy = hd.derive_entropy(&vector.path).unwrap();
			assert_eq!(
				entropy,
				str_to_32_bytes(&vector.private_key),
				"Expected private keys to match python's bip-utils"
			);
		}
	}
}
