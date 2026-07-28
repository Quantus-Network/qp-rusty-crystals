//! Multi-variant key-derivation tests.
//!
//! The historical suite in `tests.rs` (and its vendored vectors) is
//! ML-DSA-87-only; these tests cover the per-variant modules and compile for
//! whichever `ml-dsa-*` features are enabled.

use alloc::string::ToString;

const MNEMONIC: &str = "rocket primary way job input cactus submit menu zoo burger rent impose";
const PATH: &str = "m/44'/189189'/0'/0'/0'";

/// Per-variant coverage: derivation is deterministic, mnemonic and seed
/// entrypoints agree, and the derived keypair signs and verifies.
macro_rules! variant_tests {
	($mod_name:ident, $feature:literal) => {
		#[cfg(feature = $feature)]
		mod $mod_name {
			use super::{MNEMONIC, PATH};
			use crate::{mnemonic_to_seed, $mod_name::derive_key_from_mnemonic};

			#[test]
			fn derivation_is_deterministic_and_matches_seed_entrypoint() {
				let key1 = derive_key_from_mnemonic(MNEMONIC, None, PATH).unwrap();
				let key2 = derive_key_from_mnemonic(MNEMONIC, None, PATH).unwrap();
				assert_eq!(key1.secret.to_bytes(), key2.secret.to_bytes());
				assert_eq!(key1.public.bytes, key2.public.bytes);

				let mut seed = mnemonic_to_seed(MNEMONIC.to_string(), None).unwrap();
				let key3 =
					crate::$mod_name::derive_key_from_seed((&mut seed).into(), PATH).unwrap();
				assert_eq!(key1.secret.to_bytes(), key3.secret.to_bytes());
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
				assert_ne!(base.public.bytes.to_vec(), other.public.bytes.to_vec());
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
	assert_ne!(k44.public.bytes[..32], k65.public.bytes[..32]);
	assert_ne!(k44.public.bytes[..32], k87.public.bytes[..32]);
	assert_ne!(k65.public.bytes[..32], k87.public.bytes[..32]);
}

/// The top-level (historical) API must remain byte-identical to the
/// `ml_dsa_87` module it now delegates to.
#[cfg(feature = "ml-dsa-87")]
#[test]
fn top_level_api_is_ml_dsa_87() {
	let via_top = crate::derive_key_from_mnemonic(MNEMONIC, None, PATH).unwrap();
	let via_module = crate::ml_dsa_87::derive_key_from_mnemonic(MNEMONIC, None, PATH).unwrap();
	assert_eq!(via_top.secret.to_bytes(), via_module.secret.to_bytes());
	assert_eq!(via_top.public.bytes, via_module.public.bytes);
}

/// Wormhole and mnemonic handling are parameter-set independent and must work
/// on builds with no ML-DSA feature at all.
#[test]
fn variant_independent_surface_available() {
	let mut seed = crate::mnemonic_to_seed(MNEMONIC.to_string(), None).unwrap();
	let pair = crate::generate_wormhole_from_seed((&mut seed).into(), "m/44'/189189189'/0'/0'/0'")
		.unwrap();
	// Determinism of the variant-independent path.
	let mut seed2 = crate::mnemonic_to_seed(MNEMONIC.to_string(), None).unwrap();
	let pair2 =
		crate::generate_wormhole_from_seed((&mut seed2).into(), "m/44'/189189189'/0'/0'/0'")
			.unwrap();
	assert_eq!(pair.address, pair2.address);
}
