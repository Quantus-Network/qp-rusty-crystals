//! SLH-DSA key-derivation tests.

use alloc::{
	format,
	string::{String, ToString},
};
use hex_literal::hex;
use sha3::digest::{ExtendableOutput, Update, XofReader};

use crate::{
	hderive::{Error, ExtendedPrivKey},
	slh_dsa_shake_128f::{derive_key_from_mnemonic, derive_key_from_seed, Keypair, ADDRESS_INDEX},
	tests_variants::{test_seed, MNEMONIC},
	HDLatticeError, SensitiveBytes32,
};

fn path(index: &str) -> String {
	format!("m/44'/189189'/0'/0'/{index}")
}

macro_rules! per_set_tests {
	($($module:ident, $index:literal => $public:literal;)*) => {
		mod pinned_public_key {
			use super::*;
			$(
				#[test]
				fn $module() {
					use crate::$module::{derive_key_from_seed, Keypair};
					let mut keypair = Keypair::zeroed();
					derive_key_from_seed(&test_seed(), &path($index), &mut keypair).unwrap();
					assert_eq!(keypair.public().bytes, hex!($public));
				}
			)*
		}

		mod accepts_only_its_own_index {
			use super::*;
			$(
				#[test]
				fn $module() {
					use crate::$module::{derive_key_from_seed, Keypair, ADDRESS_INDEX};
					assert_eq!(ADDRESS_INDEX, $index);
					for index in 0..16 {
						let path = path(&format!("{index}'"));
						let result = derive_key_from_seed(&test_seed(), &path, &mut Keypair::zeroed());
						if format!("{index}'") == ADDRESS_INDEX {
							assert_eq!(result, Ok(()));
						} else {
							assert_eq!(result, Err(HDLatticeError::InvalidSlhDsaPath(path)));
						}
					}
				}
			)*
		}

		#[test]
		fn indices_are_2_to_13_in_fips_205_order() {
			let indices = [$($index),*];
			for (position, index) in indices.iter().enumerate() {
				assert_eq!(*index, format!("{}'", position + 2));
			}
			assert_eq!(indices.len(), 12);
		}
	};
}

per_set_tests! {
	slh_dsa_sha2_128s, "2'" => "3c6f07ac0eaa0a6daf3d117268af9f886823437854185f1acb837f6e67f6e38f";
	slh_dsa_shake_128s, "3'" => "a60c14b940ea2a83d6ee1ced1c6f5695f01435f28855b6f5ef2abc26d856b0f8";
	slh_dsa_sha2_128f, "4'" => "47f8d6e8c5cccfd7a6818a938d09feb14e6d9c911f5da25a09009274e3bff40c";
	slh_dsa_shake_128f, "5'" => "e2dd256eb8c9b6e995e3893f4cb97d946db9182d74583044335405c682c013ae";
	slh_dsa_sha2_192s, "6'" => "3b2811491f0e38ee90ff7bdd0d8a71c073407375077ee45283c02605221a087e61cf1a8735c0679e4deff087121c5d61";
	slh_dsa_shake_192s, "7'" => "32c715f172c36e3206a5b32ae595cfee9c54d984629458e46263347fe7c22850a1e32703fac76bd6cebdae68a7eaf718";
	slh_dsa_sha2_192f, "8'" => "5a4327e2a17230c6fae5a588e01a2be5a1f8037dd848eaf1814fd6ac99ce2e117580bb2a14d0d96d88d2cacf4873fe58";
	slh_dsa_shake_192f, "9'" => "904301f8788cf1446aebf28421341f3ab7fa7173b4f5be6c8ae95a96f8e96a129e6793b791420f0612bc90d512ee01fb";
	slh_dsa_sha2_256s, "10'" => "2abb3cc15577a0c0e297e1697c6660dd020fe88be96bd2d07de94bc5b165f0c673470ea73d10f0dddc17fc99a9e19d525b8a2512a6be3b04d6c7a7006eccb9a0";
	slh_dsa_shake_256s, "11'" => "d12528079d6e36e79b356ad03d8fcac48d915401d69bd10c91450e33f994f508b94e929d54b7fc658b7f37e6fa75ee79f3de63d04b17459781a5e03b1e27be2b";
	slh_dsa_sha2_256f, "12'" => "76804e0055fc19ee6efe4482edf5c08e21467a4fd0039236c8b70d941a74c36eb33b80c2fbe1b766da289e90cebcdf1059496992ce6017435c3049863e0b324e";
	slh_dsa_shake_256f, "13'" => "de97a09225bd09b89cf6e80a884570794fbc2cbadd90613de0a71234c77a8699bf01d20885f466c6f695bb5b214ebd1d620b9b3829f37946b0533e5e1d651969";
}

/// Rebuilds the key from the documented steps with an independent SHAKE256.
#[test]
fn key_matches_the_documented_construction() {
	use qp_rusty_crystals_sphincs::slh_dsa_shake_128f::{ALGORITHM, SEEDBYTES};

	let path = path(ADDRESS_INDEX);
	let mut xpriv = ExtendedPrivKey::zeroed();
	ExtendedPrivKey::derive(test_seed().as_bytes(), &path, &mut xpriv).unwrap();
	let mut shake = sha3::Shake256::default();
	shake.update(b"qp-rusty-crystals-hdwallet/slh-dsa-seed/");
	shake.update(ALGORITHM.as_bytes());
	shake.update(xpriv.secret().as_bytes());
	let mut seed = [0u8; SEEDBYTES];
	shake.finalize_xof().read(&mut seed);
	let expected = Keypair::generate(&mut seed);

	let mut derived = Keypair::zeroed();
	derive_key_from_seed(&test_seed(), &path, &mut derived).unwrap();
	assert_eq!(derived.secret().to_bytes(), expected.secret().to_bytes());
	assert_eq!(derived.public(), expected.public());
}

#[test]
fn rejects_malformed_paths() {
	let paths = [
		"m/44'/189189189'/0'/0'/5'",
		"m/44'/189189'/5'/0'/0'",
		"m/44'/189189'/0'/5'",
		"m/44'/189189'/0'/0'/5'/0'",
		"m/44'/189189'/0'/0'/0'/5'",
	];
	for path in paths {
		let error = Err(HDLatticeError::InvalidSlhDsaPath(path.to_string()));
		let mut keypair = Keypair::zeroed();
		assert_eq!(derive_key_from_seed(&test_seed(), path, &mut keypair), error);
		assert_eq!(derive_key_from_mnemonic(MNEMONIC, None, path, &mut keypair), error);
		assert_eq!(derive_key_from_mnemonic("not a mnemonic", None, path, &mut keypair), error);
		assert_eq!(keypair.public().bytes, [0u8; 32]);
	}
}

#[test]
fn keeps_generic_path_errors() {
	let mut keypair = Keypair::zeroed();
	assert_eq!(
		derive_key_from_seed(&test_seed(), "m/44'/189189'/0'/0'/5", &mut keypair),
		Err(HDLatticeError::GenericError(Error::NotHardened))
	);
}

#[test]
fn seed_expansion_separates_parameter_sets() {
	let entropy = SensitiveBytes32::zeroed();
	let mut seeds = [[0u8; 48]; 3];
	for (seed, name) in seeds.iter_mut().zip(["SLH-DSA-SHA2-128f", "SLH-DSA-SHAKE-128f", ""]) {
		crate::expand_slh_dsa_seed(name, &entropy, seed);
	}
	assert_ne!(seeds[0][..16], seeds[1][..16]);
	assert_ne!(seeds[0][..16], seeds[2][..16]);
	assert_ne!(seeds[1][..16], seeds[2][..16]);
}
