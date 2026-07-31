//! Multi-variant key-derivation tests.
//!
//! The historical suite in `tests.rs` (and its vendored vectors) is
//! ML-DSA-87-only; these tests cover the per-variant modules and compile for
//! whichever `ml-dsa-*` features are enabled.

use alloc::string::ToString;

const MNEMONIC: &str = "rocket primary way job input cactus submit menu zoo burger rent impose";
const PATH: &str = "m/44'/189189'/0'/0'/0'";

/// Test helper: stretch [`MNEMONIC`] into a fresh seed.
fn test_seed() -> crate::SensitiveBytes64 {
	let mut seed = crate::SensitiveBytes64::zeroed();
	crate::mnemonic_to_seed(MNEMONIC.to_string(), None, &mut seed).expect("valid mnemonic");
	seed
}

/// Per-variant coverage: derivation is deterministic, mnemonic and seed
/// entrypoints agree, and the derived keypair signs and verifies.
macro_rules! variant_tests {
	($mod_name:ident, $feature:literal) => {
		#[cfg(feature = $feature)]
		mod $mod_name {
			use super::{test_seed, MNEMONIC, PATH};
			use crate::$mod_name::derive_key_from_mnemonic;

			#[test]
			fn derivation_is_deterministic_and_matches_seed_entrypoint() {
				let key1 = derive_key_from_mnemonic(MNEMONIC, None, PATH).unwrap();
				let key2 = derive_key_from_mnemonic(MNEMONIC, None, PATH).unwrap();
				assert_eq!(key1.secret().to_bytes(), key2.secret().to_bytes());
				assert_eq!(key1.public().bytes, key2.public().bytes);

				let key3 = crate::$mod_name::derive_key_from_seed(test_seed(), PATH).unwrap();
				assert_eq!(key1.secret().to_bytes(), key3.secret().to_bytes());
			}

			#[test]
			fn derived_key_signs_and_verifies() {
				let keypair = derive_key_from_mnemonic(MNEMONIC, None, PATH).unwrap();
				let message = b"hdwallet multi-variant test message";
				let signature = keypair.sign(message, None, None).expect("signing");
				assert!(keypair.verify(message, &signature, None));
				assert!(!keypair.verify(b"different message", &signature, None));
			}

			#[test]
			fn different_paths_derive_different_keys() {
				let other =
					derive_key_from_mnemonic(MNEMONIC, None, "m/44'/189189'/1'/0'/0'").unwrap();
				let base = derive_key_from_mnemonic(MNEMONIC, None, PATH).unwrap();
				assert_ne!(base.public().bytes.to_vec(), other.public().bytes.to_vec());
			}

			#[test]
			fn invalid_path_is_rejected() {
				assert!(derive_key_from_mnemonic(MNEMONIC, None, "not-a-path").is_err());
			}
		}
	};
}

variant_tests!(ml_dsa_44, "ml-dsa-44");
variant_tests!(ml_dsa_65, "ml-dsa-65");
variant_tests!(ml_dsa_87, "ml-dsa-87");

/// The same mnemonic and path must yield *independent* keys per parameter set
/// (FIPS 204 keygen absorbs `(k, ℓ)` into the seed expansion, so this holds by
/// construction; the assertion pins it).
#[cfg(all(feature = "ml-dsa-44", feature = "ml-dsa-65", feature = "ml-dsa-87"))]
#[test]
fn same_path_yields_independent_keys_per_variant() {
	let k44 = crate::ml_dsa_44::derive_key_from_mnemonic(MNEMONIC, None, PATH).unwrap();
	let k65 = crate::ml_dsa_65::derive_key_from_mnemonic(MNEMONIC, None, PATH).unwrap();
	let k87 = crate::ml_dsa_87::derive_key_from_mnemonic(MNEMONIC, None, PATH).unwrap();

	// Sizes differ per variant; compare the leading bytes of the packed keys
	// (rho, the first 32 bytes, is derived from H(seed || k || l) and must
	// already diverge).
	assert_ne!(k44.public().bytes[..32], k65.public().bytes[..32]);
	assert_ne!(k44.public().bytes[..32], k87.public().bytes[..32]);
	assert_ne!(k65.public().bytes[..32], k87.public().bytes[..32]);
}

/// The top-level (historical) API must remain byte-identical to the
/// `ml_dsa_87` module it now delegates to.
#[cfg(feature = "ml-dsa-87")]
#[test]
fn top_level_api_is_ml_dsa_87() {
	let via_top = crate::derive_key_from_mnemonic(MNEMONIC, None, PATH).unwrap();
	let via_module = crate::ml_dsa_87::derive_key_from_mnemonic(MNEMONIC, None, PATH).unwrap();
	assert_eq!(via_top.secret().to_bytes(), via_module.secret().to_bytes());
	assert_eq!(via_top.public().bytes, via_module.public().bytes);
}

/// Wormhole and mnemonic handling are parameter-set independent and must work
/// on builds with no ML-DSA feature at all.
#[test]
fn variant_independent_surface_available() {
	let pair =
		crate::generate_wormhole_from_seed(test_seed(), "m/44'/189189189'/0'/0'/0'").unwrap();
	// Determinism of the variant-independent path.
	let pair2 =
		crate::generate_wormhole_from_seed(test_seed(), "m/44'/189189189'/0'/0'/0'").unwrap();
	assert_eq!(pair.address, pair2.address);
}

/// Fixed (mnemonic, path) cases shared by the 44/65 golden-vector suites.
const GOLDEN_CASES: &[(&str, &str)] = &[
	(
		"rocket primary way job input cactus submit menu zoo burger rent impose",
		"m/44'/189189'/0'/0'/0'",
	),
	(
		"legal winner thank year wave sausage worth useful legal winner thank yellow",
		"m/44'/189189'/1'/0'/0'",
	),
	(
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		"m/44'/189189'/0'/1'/0'",
	),
];

/// Pin derived keypairs against the vendored golden vectors so a silent
/// derivation change cannot land unnoticed.
macro_rules! golden_vector_tests {
	($test_mod:ident, $mod_name:ident, $feature:literal, $vectors_mod:ident) => {
		#[cfg(feature = $feature)]
		mod $test_mod {
			use super::GOLDEN_CASES;
			use crate::$mod_name::{derive_key_from_mnemonic, Keypair};

			#[test]
			fn golden_vectors_match_derived_keys() {
				assert_eq!(
					crate::$vectors_mod::VECTORS.len(),
					GOLDEN_CASES.len(),
					"golden vector count must match GOLDEN_CASES"
				);
				for (i, &(mnemonic, path)) in GOLDEN_CASES.iter().enumerate() {
					let (expected_bytes, expected_mnemonic, expected_path) =
						&crate::$vectors_mod::VECTORS[i];
					assert_eq!(*expected_mnemonic, mnemonic);
					assert_eq!(*expected_path, path);
					let derived = derive_key_from_mnemonic(mnemonic, None, path).unwrap();
					let expected = Keypair::from_bytes(expected_bytes).expect("golden keypair");
					assert_eq!(
						derived.secret().to_bytes(),
						expected.secret().to_bytes(),
						"secret mismatch for {path}"
					);
					assert_eq!(
						derived.public().to_bytes(),
						expected.public().to_bytes(),
						"public mismatch for {path}"
					);
				}
			}
		}
	};
}

golden_vector_tests!(golden_44, ml_dsa_44, "ml-dsa-44", test_vectors_44);
golden_vector_tests!(golden_65, ml_dsa_65, "ml-dsa-65", test_vectors_65);

/// Regenerate `test_vectors_{44,65}.rs`. Run with:
/// `cargo test -p qp-rusty-crystals-hdwallet --features ml-dsa-44,ml-dsa-65 -- --ignored
/// regenerate_variant_golden_vectors --nocapture`
#[cfg(all(feature = "ml-dsa-44", feature = "ml-dsa-65"))]
#[test]
#[ignore]
fn regenerate_variant_golden_vectors() {
	extern crate std;
	use alloc::string::String;
	use std::{fs::File, io::Write, path::PathBuf};

	fn emit(filename: &str, label: &str, derive: impl Fn(&str, &str) -> alloc::vec::Vec<u8>) {
		let mut out = String::new();
		out.push_str("//! Golden HD-derivation vectors for ");
		out.push_str(label);
		out.push_str(".\n//!\n//! Regenerated by `regenerate_variant_golden_vectors`.\n\n");
		out.push_str("#[cfg(test)]\npub const VECTORS: &[(&[u8], &str, &str)] = &[\n");
		for &(mnemonic, path) in GOLDEN_CASES {
			let bytes = derive(mnemonic, path);
			out.push_str("\t(\n\t\t&[\n");
			for chunk in bytes.chunks(14) {
				out.push_str("\t\t\t");
				out.push_str(
					&chunk
						.iter()
						.map(|b| alloc::format!("0x{b:02x}"))
						.collect::<alloc::vec::Vec<_>>()
						.join(", "),
				);
				out.push_str(",\n");
			}
			out.push_str("\t\t],\n");
			out.push_str(&alloc::format!("\t\t\"{mnemonic}\",\n"));
			out.push_str(&alloc::format!("\t\t\"{path}\",\n"));
			out.push_str("\t),\n");
		}
		out.push_str("];\n");
		let mut dest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
		dest.push("src");
		dest.push(filename);
		File::create(&dest).unwrap().write_all(out.as_bytes()).unwrap();
		std::println!("wrote {label} vectors to {}", dest.display());
	}

	emit("test_vectors_44.rs", "ML-DSA-44", |m, p| {
		crate::ml_dsa_44::derive_key_from_mnemonic(m, None, p)
			.unwrap()
			.to_bytes()
			.to_vec()
	});
	emit("test_vectors_65.rs", "ML-DSA-65", |m, p| {
		crate::ml_dsa_65::derive_key_from_mnemonic(m, None, p)
			.unwrap()
			.to_bytes()
			.to_vec()
	});
}
