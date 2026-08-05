#[cfg(test)]
mod hdwallet_tests {
	use crate::{
		derive_key_from_seed, generate_mnemonic, generate_wormhole_from_seed,
		hderive::{ChildNumber, ExtendedPrivKey},
		mnemonic_to_seed,
		test_vectors::get_test_vectors,
		HDLatticeError, SensitiveBytes64,
	};
	use alloc::{
		borrow::ToOwned,
		format,
		string::{String, ToString},
		vec::Vec,
	};
	use core::str::FromStr;
	use qp_rusty_crystals_dilithium::ml_dsa_87::Keypair;
	use rand::{rngs::StdRng, Rng, SeedableRng};

	// For test-only functionality that needs std
	#[cfg(test)]
	extern crate std;
	#[cfg(test)]
	use std::println;

	/// Test helper: stretch a known-valid mnemonic into a fresh seed.
	fn seed_from(mnemonic: String, passphrase: Option<&str>) -> SensitiveBytes64 {
		let mut seed = SensitiveBytes64::zeroed();
		mnemonic_to_seed(mnemonic, passphrase, &mut seed).expect("valid mnemonic");
		seed
	}

	#[test]
	fn test_from_seed() {
		// Single use pattern - mnemonic gets consumed
		let mnemonic1 =
			"rocket primary way job input cactus submit menu zoo burger rent impose".to_string();
		let seed1 = seed_from(mnemonic1, None);

		// Multi-use pattern - explicitly clone when needed
		let mnemonic2 =
			"rocket primary way job input cactus submit menu zoo burger rent impose".to_string();
		let seed2 = seed_from(mnemonic2.clone(), None);
		// mnemonic2 still available here, gets consumed when dropped

		// Seeds from same mnemonic should be identical
		assert_eq!(seed1.as_bytes(), seed2.as_bytes());

		// Should be able to derive same keys from same seed
		let key1 = derive_key_from_seed(&seed1, "m/44'/0'/0'/0'/0'").unwrap();
		let key2 = derive_key_from_seed(&seed2, "m/44'/0'/0'/0'/0'").unwrap();
		assert_eq!(key1.secret().to_bytes(), key2.secret().to_bytes());
	}

	#[test]
	fn test_mnemonic_creation() {
		let mut entropy = [43u8; 32];

		// Test generating new mnemonic (returned inside a Zeroizing wrapper)
		let mnemonic = generate_mnemonic((&mut entropy).into()).unwrap();
		assert_eq!(mnemonic.split_whitespace().count(), 24);

		// Test creating seeds from mnemonic - demonstrate explicit copying
		let seed1 = seed_from(mnemonic.to_string(), None);
		let seed2 = seed_from(mnemonic.to_string(), None);
		let seed3 = seed_from(mnemonic.to_string(), Some("password"));

		// Seeds from same mnemonic should be identical
		assert_eq!(
			seed1.as_bytes(),
			seed2.as_bytes(),
			"seeds from same mnemonic should be identical"
		);

		// Different passphrase should produce different seed
		assert_ne!(seed1.as_bytes(), seed3.as_bytes(), "password should affect seed");

		let master_key1 = derive_key_from_seed(&seed1, "m/44'/0'/0'/0'/0'").unwrap();
		let master_key2 = derive_key_from_seed(&seed2, "m/44'/0'/0'/0'/0'").unwrap();
		let master_key3 = derive_key_from_seed(&seed3, "m/44'/0'/0'/0'/0'").unwrap();

		// Keys from same seed should be identical
		assert_eq!(
			master_key1.secret().to_bytes(),
			master_key2.secret().to_bytes(),
			"keys are not deterministic"
		);

		// Keys from different seeds should be different
		assert_ne!(
			master_key1.secret().to_bytes(),
			master_key3.secret().to_bytes(),
			"password has no effect"
		);

		// Derive a different path - need a fresh seed since seed1 was already consumed
		let seed_for_derive = seed_from(mnemonic.to_string(), None);
		let derived_key = derive_key_from_seed(&seed_for_derive, "m/0'/2147483647'/1'").unwrap();
		assert_ne!(
			master_key1.secret().to_bytes(),
			derived_key.secret().to_bytes(),
			"derived key not derived"
		);

		// UNCOMMENT THIS AND RUN WITH `cargo test -- --nocapture` TO GENERATE TEST VECTORS
		// let vecs = generate_test_vectors(10);
		// print_keys_mnemonics_paths_as_test_vector(&vecs);
	}

	#[test]
	fn test_same_mnemonic_same_path_deterministic() {
		let paths =
			["m/44'/0'/0'/0'/0'", "m/0'/2147483647'/1'", "m/44'/60'/0'/0'/0'", "m/1'/2'/3'"];

		for p in paths {
			// Show proper mnemonic ownership - each call creates new String
			let mnemonic1 =
				"rocket primary way job input cactus submit menu zoo burger rent impose"
					.to_string();
			let mnemonic2 =
				"rocket primary way job input cactus submit menu zoo burger rent impose"
					.to_string();

			let seed1 = seed_from(mnemonic1, None);
			let seed2 = seed_from(mnemonic2, None);

			let k1 = derive_key_from_seed(&seed1, p).unwrap();
			let k2 = derive_key_from_seed(&seed2, p).unwrap();

			assert_eq!(k1.secret().to_bytes(), k2.secret().to_bytes());
			assert_eq!(k1.public().to_bytes(), k2.public().to_bytes());
		}
	}

	#[allow(dead_code)]
	fn generate_test_vectors(n: u8) -> Vec<(Keypair, String, String)> {
		let mut seed = [0u8; 32];
		(0..n)
			.map(|_| {
				let mut rng = StdRng::from_seed(seed);
				rng.fill_bytes(&mut seed);
				let mnemonic = generate_mnemonic((&mut seed).into()).unwrap();
				let path = generate_random_path();
				let seed = seed_from(mnemonic.to_string(), None);
				let k = derive_key_from_seed(&seed, &path).unwrap();
				(k, mnemonic.to_string(), path)
			})
			.collect()
	}

	#[test]
	fn test_derive_seed() {
		for (expected_keys, mnemonic_str, derivation_path) in get_test_vectors() {
			let seed = seed_from(mnemonic_str.to_string(), None);
			let generated_keys = if derivation_path.is_empty() || derivation_path == "m" {
				// Use a default path for empty or "m" path
				derive_key_from_seed(&seed, "m/44'/0'/0'/0'/0'").unwrap()
			} else {
				derive_key_from_seed(&seed, derivation_path).unwrap()
			};

			// Compare secret keys
			assert_eq!(
				generated_keys.secret().to_bytes(),
				expected_keys.secret().to_bytes(),
				"Secret key mismatch for path: {derivation_path}"
			);

			// Compare public keys
			assert_eq!(
				generated_keys.public().to_bytes(),
				expected_keys.public().to_bytes(),
				"Public key mismatch for path: {derivation_path}"
			);
		}
	}

	#[allow(dead_code)]
	fn generate_random_path() -> String {
		let seed = [11u8; 32];
		let mut rng = StdRng::from_seed(seed);
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
		let mut rng = StdRng::from_seed(seed);
		rng.fill_bytes(&mut seed);
		let mnemonic = generate_mnemonic((&mut seed).into())
			.unwrap_or_else(|_| panic!("Failed to generate mnemonic for 24 words"));

		// Split mnemonic into words and count them
		let word_count_result = mnemonic.split_whitespace().count();

		// Assert the word count matches the expected
		assert_eq!(word_count_result, 24, "Expected 24 words, but got {word_count_result}");
	}

	#[test]
	fn test_derive_invalid_path() {
		let mnemonic =
			"rocket primary way job input cactus submit menu zoo burger rent impose".to_string();
		let seed = seed_from(mnemonic, None);

		// Attempt to derive a key with an invalid path
		let result = derive_key_from_seed(&seed, "abc");

		assert_eq!(
			result.err().unwrap(),
			HDLatticeError::GenericError(crate::hderive::Error::InvalidDerivationPath),
			"Expected InvalidChildNumber error"
		);
	}

	#[test]
	fn test_derive_invalid_index() {
		let mnemonic =
			"rocket primary way job input cactus submit menu zoo burger rent impose".to_string();
		let seed = seed_from(mnemonic, None);

		// Attempt to derive a key with an invalid index
		let result = derive_key_from_seed(&seed, "m/2147483648'"); // Index exceeds HARDENED_OFFSET (2^31)

		assert!(result.is_err());
		assert_eq!(
			result.err().unwrap(),
			HDLatticeError::GenericError(crate::hderive::Error::InvalidChildNumber),
			"Expected InvalidChildNumber error"
		);
	}

	#[test]
	fn test_derive_with_non_integer_path() {
		let mnemonic =
			"rocket primary way job input cactus submit menu zoo burger rent impose".to_string();
		let seed = seed_from(mnemonic, None);

		// Invalid derivation path with non-integer components
		let result = derive_key_from_seed(&seed, "1/a/2");

		assert!(result.is_err());
		assert_eq!(
			result.err().unwrap(),
			HDLatticeError::GenericError(crate::hderive::Error::InvalidDerivationPath),
			"Expected InvalidChildNumber error"
		);
	}

	#[test]
	fn test_derive_master_path() {
		let mnemonic =
			"rocket primary way job input cactus submit menu zoo burger rent impose".to_string();
		let seed = seed_from(mnemonic.clone(), None);

		// Test deriving at master path "m"
		let key1 = derive_key_from_seed(&seed, "m/44'/0'/0'/0'/0'").unwrap();

		let seed2 = seed_from(mnemonic, None);
		let key2 = derive_key_from_seed(&seed2, "m/44'/0'/0'/0'/0'").unwrap();

		// Keys derived from same path should be identical
		assert_eq!(
			key1.secret().to_bytes(),
			key2.secret().to_bytes(),
			"Keys derived from same path should be identical"
		);
	}

	#[test]
	fn test_tiny_hderive_api() {
		// Test that nam-tiny-hderive works with our seed format
		let seed: &[u8] = &[42; 64];
		let path = "m/44'/60'/0'/0'/0'";
		let mut ext = ExtendedPrivKey::zeroed();
		ExtendedPrivKey::derive(seed, path, &mut ext).unwrap();
		assert_eq!(ext.secret().as_bytes(), b"\xfc\x29\xd9\xfc\x63\x5b\x32\x72\x63\x1b\x43\x02\xf7\x9b\xe4\x07\xa7\xf6\x77\xef\x73\x4a\xf2\xc4\x52\x7c\x90\x88\x97\xcd\xaa\x86");

		// Stepping the parent in place must agree with the full-path derivation.
		let mut stepped = ExtendedPrivKey::zeroed();
		ExtendedPrivKey::derive(seed, "m/44'/60'/0'/0'", &mut stepped).unwrap();
		stepped.child_in_place(ChildNumber::from_str("0'").unwrap());
		assert_eq!(ext.secret().as_bytes(), stepped.secret().as_bytes());
	}

	// End-to-end known-answer test: pins the full mnemonic -> seed -> wormhole pipeline.
	// Regenerate with `print_wormhole_golden` if the derivation is intentionally changed.
	#[test]
	fn test_wormhole_known_values() {
		use crate::derive_wormhole_from_mnemonic;
		use hex_literal::hex;

		let mnemonic = "rocket primary way job input cactus submit menu zoo burger rent impose";
		let w = derive_wormhole_from_mnemonic(mnemonic, None, "m/44'/189189189'/0'").unwrap();

		assert_eq!(
			*w.address(),
			hex!("6a2f0d3abe4390e0b05f6dea4ba10670676cda7c00d49526ddde59f16c85269f"),
			"wormhole address derivation changed"
		);
		assert_eq!(
			*w.first_hash(),
			hex!("890ff21aa4fda75dc56c6c322c164d3c21a18ca7853d368c28cf158affc8b5b1"),
			"wormhole first_hash derivation changed"
		);
		assert_eq!(
			w.secret().as_bytes(),
			&hex!("30051cfa3abd462d3bc26da2d660e90ba8af6080b7fe95d9fd3f3b37c7d9ce4b"),
			"wormhole secret derivation changed"
		);
	}

	#[test]
	#[ignore]
	fn print_wormhole_golden() {
		use crate::derive_wormhole_from_mnemonic;
		let mnemonic = "rocket primary way job input cactus submit menu zoo burger rent impose";
		let w = derive_wormhole_from_mnemonic(mnemonic, None, "m/44'/189189189'/0'").unwrap();
		let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
		println!("address    = {}", hex(w.address()));
		println!("first_hash = {}", hex(w.first_hash()));
		println!("secret     = {}", hex(w.secret().as_bytes()));
	}

	#[test]
	fn test_wormhole_derivation() {
		let mnemonic =
			"rocket primary way job input cactus submit menu zoo burger rent impose".to_string();

		// Test invalid wormhole path (wrong chain ID)
		let seed1 = seed_from(mnemonic.clone(), None);
		let result = generate_wormhole_from_seed(&seed1, "m/44'/60'/0'");
		assert!(result.is_err());

		// Test valid wormhole path
		let seed2 = seed_from(mnemonic.clone(), None);
		let result2 = generate_wormhole_from_seed(&seed2, "m/44'/189189189'/0'");
		assert!(result2.is_ok());

		// Test another valid wormhole path
		let seed3 = seed_from(mnemonic, None);
		let result3 = generate_wormhole_from_seed(&seed3, "m/44'/189189189'/1'");
		assert!(result3.is_ok());
	}

	#[test]
	fn test_master_key_derivation() {
		let mnemonic =
			"rocket primary way job input cactus submit menu zoo burger rent impose".to_string();
		let seed1 = seed_from(mnemonic.clone(), None);
		let seed2 = seed_from(mnemonic, None);

		// Derive keys from master path - should be deterministic
		let key1 = derive_key_from_seed(&seed1, "m/44'/0'/0'/0'/0'").unwrap();
		let key2 = derive_key_from_seed(&seed2, "m/44'/0'/0'/0'/0'").unwrap();

		assert_eq!(
			key1.secret().to_bytes(),
			key2.secret().to_bytes(),
			"Master key derivation should be deterministic"
		);
	}

	#[test]
	fn test_mnemonic_to_seed() {
		// Single-use pattern
		let mnemonic1 =
			"rocket primary way job input cactus submit menu zoo burger rent impose".to_string();
		let seed1 = seed_from(mnemonic1, None);

		let mnemonic2 =
			"rocket primary way job input cactus submit menu zoo burger rent impose".to_string();
		let seed2 = seed_from(mnemonic2, None);

		// Same mnemonic should produce same seed
		assert_eq!(seed1.as_bytes(), seed2.as_bytes());
		assert_eq!(seed1.as_bytes().len(), 64);

		// Different passphrase should produce different seed
		let mnemonic3 =
			"rocket primary way job input cactus submit menu zoo burger rent impose".to_string();
		let seed3 = seed_from(mnemonic3, Some("password"));
		assert_ne!(seed1.as_bytes(), seed3.as_bytes());
	}

	#[test]
	fn test_passphrase_unicode_normalization() {
		// BIP39 mandates NFKD normalization before PBKDF2: canonically equivalent
		// passphrases must derive the same seed. "café" spelled with a precomposed
		// U+00E9 vs a decomposed "e" + U+0301 combining acute accent.
		let mnemonic = "rocket primary way job input cactus submit menu zoo burger rent impose";
		let composed = "caf\u{00e9}";
		let decomposed = "cafe\u{0301}";
		assert_ne!(composed.as_bytes(), decomposed.as_bytes());

		let seed_composed = seed_from(mnemonic.to_string(), Some(composed));
		let seed_decomposed = seed_from(mnemonic.to_string(), Some(decomposed));
		assert_eq!(
			seed_composed.as_bytes(),
			seed_decomposed.as_bytes(),
			"canonically equivalent passphrases must derive the same seed"
		);

		// The normalized form must feed PBKDF2 (NFKD of both spellings is the
		// decomposed byte string), matching what standard BIP39 tooling computes.
		let reference = bip39::Mnemonic::parse_in_normalized(bip39::Language::English, mnemonic)
			.unwrap()
			.to_seed_normalized(decomposed);
		assert_eq!(seed_composed.as_bytes(), &reference);

		// Same guarantee through the borrowing derivation helpers.
		let key_composed =
			crate::derive_key_from_mnemonic(mnemonic, Some(composed), "m/44'/189189'/0'/0'/0'")
				.unwrap();
		let key_decomposed =
			crate::derive_key_from_mnemonic(mnemonic, Some(decomposed), "m/44'/189189'/0'/0'/0'")
				.unwrap();
		assert_eq!(key_composed.secret().to_bytes(), key_decomposed.secret().to_bytes());
	}

	#[test]
	fn test_mnemonic_unicode_normalization() {
		// NFKD also applies to the mnemonic itself: U+00A0 (no-break space) has a
		// compatibility decomposition to a plain space, so a mnemonic pasted with
		// non-breaking separators must parse and derive identically.
		let ascii = "rocket primary way job input cactus submit menu zoo burger rent impose";
		let nbsp = ascii.replace(' ', "\u{00a0}");
		assert_ne!(ascii.as_bytes(), nbsp.as_bytes());

		let seed_ascii = seed_from(ascii.to_string(), None);
		let mut seed_nbsp = SensitiveBytes64::zeroed();
		mnemonic_to_seed(nbsp, None, &mut seed_nbsp)
			.expect("NFKD-equivalent mnemonic must parse after normalization");
		assert_eq!(seed_ascii.as_bytes(), seed_nbsp.as_bytes());
	}

	#[test]
	fn test_derive_key_from_seed_different_paths() {
		let mnemonic =
			"rocket primary way job input cactus submit menu zoo burger rent impose".to_string();
		let seed = seed_from(mnemonic, None);

		// Derive keys at different paths - need separate seeds since they get consumed
		let seed1 = seed;
		let seed2 = seed_from(
			"rocket primary way job input cactus submit menu zoo burger rent impose".to_string(),
			None,
		);
		let key1 = derive_key_from_seed(&seed1, "m/44'/0'/0'/0'/0'").unwrap();
		let key2 = derive_key_from_seed(&seed2, "m/44'/0'/0'/0'/1'").unwrap();

		// Keys should be different
		assert_ne!(key1.secret().to_bytes(), key2.secret().to_bytes());
		assert_ne!(key1.public().to_bytes(), key2.public().to_bytes());
	}

	#[test]
	fn test_derive_key_deterministic() {
		let path = "m/44'/0'/0'/0'/0'";

		let mnemonic1 =
			"rocket primary way job input cactus submit menu zoo burger rent impose".to_string();
		let mnemonic2 =
			"rocket primary way job input cactus submit menu zoo burger rent impose".to_string();

		let seed1 = seed_from(mnemonic1, None);
		let seed2 = seed_from(mnemonic2, None);

		let key1 = derive_key_from_seed(&seed1, path).unwrap();
		let key2 = derive_key_from_seed(&seed2, path).unwrap();

		// Same seed and path should produce same keys
		assert_eq!(key1.secret().to_bytes(), key2.secret().to_bytes());
		assert_eq!(key1.public().to_bytes(), key2.public().to_bytes());
	}

	#[test]
	fn test_generate_wormhole_from_seed() {
		let mnemonic =
			"rocket primary way job input cactus submit menu zoo burger rent impose".to_string();
		let seed = seed_from(mnemonic, None);

		let wormhole = generate_wormhole_from_seed(&seed, "m/44'/189189189'/0'").unwrap();

		// Verify wormhole pair has expected structure
		assert_eq!(wormhole.secret().as_bytes().len(), 32);
		assert_eq!(wormhole.address().len(), 32);
		assert_eq!(wormhole.first_hash().len(), 32);
		assert_ne!(wormhole.secret().as_bytes(), &[0u8; 32]);
		assert_ne!(*wormhole.address(), [0u8; 32]);
	}

	#[test]
	fn test_wormhole_invalid_path() {
		let mnemonic =
			"rocket primary way job input cactus submit menu zoo burger rent impose".to_string();
		let seed = seed_from(mnemonic, None);

		// Should fail with invalid wormhole chain ID
		let result = generate_wormhole_from_seed(&seed, "m/44'/60'/0'");
		assert!(result.is_err());
		assert_eq!(
			result.err().unwrap(),
			HDLatticeError::InvalidWormholePath("m/44'/60'/0'".to_string())
		);
	}

	#[test]
	fn test_invalid_derivation_path() {
		let mnemonic =
			"rocket primary way job input cactus submit menu zoo burger rent impose".to_string();
		let seed = seed_from(mnemonic, None);

		let result = derive_key_from_seed(&seed, "m/44/60/0");
		assert!(result.is_err());
		assert_eq!(
			result.err().unwrap(),
			HDLatticeError::GenericError(crate::hderive::Error::NotHardened)
		);
	}

	#[test]
	fn test_seed_centric_api_deterministic() {
		// Test that API produces deterministic results
		let mnemonic = "rocket primary way job input cactus submit menu zoo burger rent impose";
		let path = "m/44'/0'/0'/0'/0'";

		// First derivation
		let seed1 = seed_from(mnemonic.to_string(), None);
		let key1 = derive_key_from_seed(&seed1, path).unwrap();

		// Second derivation
		let seed2 = seed_from(mnemonic.to_string(), None);
		let key2 = derive_key_from_seed(&seed2, path).unwrap();

		// Should produce identical results
		assert_eq!(key1.secret().to_bytes(), key2.secret().to_bytes());
		assert_eq!(key1.public().to_bytes(), key2.public().to_bytes());
	}

	#[test]
	fn test_move_semantics_enforcement() {
		// Test that SensitiveBytes wrappers enforce move semantics
		use qp_rusty_crystals_dilithium::{SensitiveBytes32, SensitiveBytes64};

		// Create sensitive data
		let mut entropy = [42u8; 32];
		let mut seed_bytes = [1u8; 64];

		// Wrap in SensitiveBytes - this zeroizes the original data
		let sensitive_entropy = SensitiveBytes32::from(&mut entropy);
		let sensitive_seed = SensitiveBytes64::from(&mut seed_bytes);

		// Use the wrapped data - generate_mnemonic moves the entropy;
		// derive_key_from_seed borrows the seed (security review: a by-value
		// move would leave the caller's slot dead and unwiped), so the same
		// seed holder can derive at several paths and is wiped when dropped.
		let mnemonic = generate_mnemonic(sensitive_entropy).unwrap();
		let seed_from_mnemonic = seed_from(mnemonic.to_string(), None);
		let _key = derive_key_from_seed(&sensitive_seed, "m/44'/0'/0'/0'/0'").unwrap();
		let _key_again = derive_key_from_seed(&sensitive_seed, "m/44'/0'/0'/0'/1'").unwrap();

		// After this point, sensitive_entropy is consumed.
		// The following would not compile if uncommented:
		// let _mnemonic2 = generate_mnemonic(sensitive_entropy);

		// Test that regular arrays still work with auto-conversion
		let mut raw_seed = [2u8; 64];
		let _key2 = derive_key_from_seed(&(&mut raw_seed).into(), "m/44'/0'/0'/0'/0'").unwrap();
		// raw_seed was zeroized by the conversion

		assert_eq!(seed_from_mnemonic.as_bytes().len(), 64);
	}

	// For reference and in case test vectors need to be regenerated
	// ignored during normal test runs
	#[test]
	#[ignore]
	fn regenerate_rust_vectors() {
		use std::io::Write;
		let vecs = generate_test_vectors(10);
		let mut out = String::from("use crate::Keypair;\n#[cfg(test)]\nuse alloc::{vec, vec::Vec};\n\n#[cfg(test)]\npub fn get_test_vectors() -> Vec<(Keypair, &'static str, &'static str)> {\n\tvec![\n");
		for (key, mnemonic, path) in vecs.iter() {
			out.push_str("\t\t(\n\t\t\tKeypair::from_bytes(&vec![\n");
			let bytes = key.to_bytes();
			for chunk in bytes.chunks(14) {
				out.push_str("\t\t\t\t");
				out.push_str(
					&chunk.iter().map(|b| format!("0x{b:02x}")).collect::<Vec<_>>().join(", "),
				);
				out.push_str(",\n");
			}
			out.push_str("\t\t\t])\n\t\t\t.expect(\"Should not fail\"),\n");
			out.push_str(&format!("\t\t\t\"{mnemonic}\",\n"));
			out.push_str(&format!("\t\t\t\"{path}\",\n"));
			out.push_str("\t\t),\n");
		}
		out.push_str("\t]\n}\n");
		let mut f = std::fs::File::create("./src/test_vectors.rs").unwrap();
		f.write_all(out.as_bytes()).unwrap();
		println!("Wrote updated Rust test vectors");
	}

	#[test]
	fn test_derive_rejects_oversized_path() {
		use crate::{generate_wormhole_from_seed, MAX_DERIVATION_PATH_BYTES};

		let mnemonic =
			"rocket primary way job input cactus submit menu zoo burger rent impose".to_string();
		let mut oversized = String::from("m");
		while oversized.len() <= MAX_DERIVATION_PATH_BYTES {
			oversized.push_str("/1'");
		}
		assert!(oversized.len() > MAX_DERIVATION_PATH_BYTES);

		let seed1 = seed_from(mnemonic.clone(), None);
		let err1 = derive_key_from_seed(&seed1, &oversized).unwrap_err();
		assert!(matches!(err1, HDLatticeError::PathTooLong(_)), "got {err1:?}");

		let seed2 = seed_from(mnemonic, None);
		match generate_wormhole_from_seed(&seed2, &oversized) {
			Err(HDLatticeError::PathTooLong(_)) => {},
			Err(other) => panic!("expected PathTooLong, got {other:?}"),
			Ok(_) => panic!("expected PathTooLong, got Ok"),
		}
	}

	#[test]
	fn test_derive_rejects_too_deep_path() {
		use crate::{generate_wormhole_from_seed, MAX_DERIVATION_DEPTH};

		let mnemonic =
			"rocket primary way job input cactus submit menu zoo burger rent impose".to_string();
		let mut too_deep = String::from("m");
		for _ in 0..=MAX_DERIVATION_DEPTH {
			too_deep.push_str("/1'");
		}

		let seed1 = seed_from(mnemonic.clone(), None);
		let err1 = derive_key_from_seed(&seed1, &too_deep).unwrap_err();
		assert!(matches!(err1, HDLatticeError::PathTooDeep(_)), "got {err1:?}");

		let seed2 = seed_from(mnemonic, None);
		match generate_wormhole_from_seed(&seed2, &too_deep) {
			Err(HDLatticeError::PathTooDeep(_)) => {},
			Err(other) => panic!("expected PathTooDeep, got {other:?}"),
			Ok(_) => panic!("expected PathTooDeep, got Ok"),
		}
	}

	/// The mnemonic-based helpers must validate the derivation path *before*
	/// BIP39 seed stretching, matching the seed-based entrypoints. The error
	/// precedence makes the ordering observable: with a bogus mnemonic AND a
	/// bad path, a path error proves the cheap check ran first, while a
	/// Bip39Error would prove the expensive mnemonic work ran first.
	#[test]
	fn test_mnemonic_helpers_validate_path_before_seed_stretching() {
		use crate::{
			derive_key_from_mnemonic, derive_wormhole_from_mnemonic, MAX_DERIVATION_PATH_BYTES,
		};

		let bogus_mnemonic = "not a valid bip39 mnemonic phrase at all";
		let mut oversized = String::from("m");
		while oversized.len() <= MAX_DERIVATION_PATH_BYTES {
			oversized.push_str("/1'");
		}

		let err = derive_key_from_mnemonic(bogus_mnemonic, None, &oversized).unwrap_err();
		assert!(
			matches!(err, HDLatticeError::PathTooLong(_)),
			"path must be rejected before seed stretching, got {err:?}"
		);

		// WormholePair has no Debug impl (it holds a secret), so match instead
		// of unwrap_err.
		match derive_wormhole_from_mnemonic(bogus_mnemonic, None, &oversized) {
			Err(HDLatticeError::PathTooLong(_)) => {},
			Err(other) => panic!("path must be rejected before seed stretching, got {other:?}"),
			Ok(_) => panic!("expected PathTooLong, got Ok"),
		}

		// The wormhole chain-ID check must also precede seed work: this path is
		// syntactically valid but uses the Dilithium chain ID, not the wormhole one.
		match derive_wormhole_from_mnemonic(bogus_mnemonic, None, "m/44'/189189'/0'") {
			Err(HDLatticeError::InvalidWormholePath(_)) => {},
			Err(other) => {
				panic!("wrong chain ID must be rejected before seed stretching, got {other:?}")
			},
			Ok(_) => panic!("expected InvalidWormholePath, got Ok"),
		}
	}

	/// Mnemonic and passphrase inputs must be size-capped before Unicode
	/// normalization and seed derivation, mirroring the derivation-path caps.
	/// Without bounds, a caller-controlled huge passphrase (or a huge
	/// non-normalized mnemonic) drives unbounded allocation, normalization
	/// scans, and PBKDF2 work before any rejection.
	#[test]
	fn test_rejects_oversized_mnemonic_and_passphrase() {
		use crate::{derive_key_from_mnemonic, MAX_MNEMONIC_BYTES, MAX_PASSPHRASE_BYTES};

		let valid = "rocket primary way job input cactus submit menu zoo burger rent impose";

		let mut seed = SensitiveBytes64::zeroed();

		// A valid mnemonic paired with an oversized passphrase must be rejected
		// up front instead of deriving a seed over attacker-sized input.
		let huge_passphrase = "p".repeat(MAX_PASSPHRASE_BYTES + 1);
		let err = mnemonic_to_seed(valid.to_string(), Some(&huge_passphrase), &mut seed)
			.expect_err("oversized passphrase must be rejected");
		assert!(matches!(err, HDLatticeError::PassphraseTooLong(_)), "got {err:?}");

		// An oversized mnemonic must be rejected before normalization/parsing.
		// Use a non-NFKD char so the pre-fix code path would also allocate a
		// normalized copy of the whole input.
		let huge_mnemonic = "\u{00e9} ".repeat(MAX_MNEMONIC_BYTES / 2 + 1);
		let err = mnemonic_to_seed(huge_mnemonic, None, &mut seed)
			.expect_err("oversized mnemonic must be rejected");
		assert!(matches!(err, HDLatticeError::MnemonicTooLong(_)), "got {err:?}");

		// The borrowed-mnemonic helpers share the same parser and must enforce
		// the same caps.
		let err = derive_key_from_mnemonic(valid, Some(&huge_passphrase), "m/44'/189189'/0'")
			.expect_err("oversized passphrase must be rejected in derive_key_from_mnemonic");
		assert!(matches!(err, HDLatticeError::PassphraseTooLong(_)), "got {err:?}");

		// Inputs at exactly the caps must still be accepted.
		let max_passphrase = "p".repeat(MAX_PASSPHRASE_BYTES);
		mnemonic_to_seed(valid.to_string(), Some(&max_passphrase), &mut seed)
			.expect("passphrase at exactly MAX_PASSPHRASE_BYTES must be accepted");
	}

	#[test]
	fn test_mnemonic_to_seed_zeroizes_on_parse_failure() {
		let bogus = "not a valid bip39 mnemonic phrase at all".to_string();
		let mut seed = SensitiveBytes64::zeroed();
		let err =
			mnemonic_to_seed(bogus, None, &mut seed).expect_err("bogus mnemonic must be rejected");
		assert!(matches!(err, HDLatticeError::Bip39Error(_)), "got {err:?}");
		// On error the seed buffer is untouched (still all zeros).
		assert_eq!(seed.as_bytes(), &[0u8; 64]);
	}

	#[test]
	fn test_derive_accepts_max_depth() {
		use crate::MAX_DERIVATION_DEPTH;

		let mnemonic =
			"rocket primary way job input cactus submit menu zoo burger rent impose".to_string();
		let mut max_depth = String::from("m");
		for _ in 0..MAX_DERIVATION_DEPTH {
			max_depth.push_str("/1'");
		}

		let seed = seed_from(mnemonic, None);
		derive_key_from_seed(&seed, &max_depth)
			.expect("path at exactly MAX_DERIVATION_DEPTH must succeed");
	}
}
